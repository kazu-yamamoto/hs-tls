-- |
-- Module      : Network.TLS.Receiving
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Receiving module contains calls related to unmarshalling packets according
-- to the TLS state
--
{-# LANGUAGE FlexibleContexts #-}

module Network.TLS.Receiving2
    ( processPacket2
    , switchRxEncryption
    ) where

import Control.Monad.State
import Control.Concurrent.MVar

import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.Struct2
import Network.TLS.ErrT
import Network.TLS.Record.Types2
import Network.TLS.Packet
import Network.TLS.Packet2
import Network.TLS.Wire
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Util

processPacket2 :: Context -> Record2 -> IO (Either TLSError Packet2)
processPacket2 _ (Record2 ContentType_AppData fragment) = return $ Right $ AppData2 fragment
processPacket2 _ (Record2 ContentType_Alert fragment) = return (Alert2 `fmapEither` (decodeAlerts fragment))
processPacket2 ctx (Record2 ContentType_Handshake fragment) = do
    usingState ctx $ do
        mCont <- gets stHandshakeRecordCont2
        modify (\st -> st { stHandshakeRecordCont2 = Nothing })
        hss   <- parseMany mCont fragment
        return $ Handshake2 hss (Just fragment)
  where parseMany mCont bs =
            case maybe decodeHandshakeRecord2 id mCont $ bs of
                GotError err                -> throwError err
                GotPartial cont             -> modify (\st -> st { stHandshakeRecordCont2 = Just cont }) >> return []
                GotSuccess (ty,content)     ->
                    either throwError (return . (:[])) $ decodeHandshake2 ty content
                GotSuccessRemaining (ty,content) left ->
                    case decodeHandshake2 ty content of
                        Left err -> throwError err
                        Right hh -> (hh:) `fmap` parseMany Nothing left

switchRxEncryption :: Context -> IO ()
switchRxEncryption ctx = do
    rx <- fromJust "rx-state" <$> usingHState ctx (gets hstPendingRxState)
    modifyMVar_ (ctxRxState ctx) (\_ -> return rx)
