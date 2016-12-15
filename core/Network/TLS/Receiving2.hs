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

module Network.TLS.Receiving2 (processPacket2) where

import Control.Monad
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
    ehss <- usingState ctx $ do
        mCont <- gets stHandshakeRecordCont2
        modify (\st -> st { stHandshakeRecordCont2 = Nothing })
        parseMany mCont fragment
    case ehss of
      Left e    -> return $ Left e
      Right hss -> do
          forM_ hss $ \hs -> usingHState ctx $ do
              let encoded = encodeHandshake2 hs
              updateHandshakeDigest encoded
              addHandshakeMessage encoded
          return $ Right $ Handshake2 hss
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
