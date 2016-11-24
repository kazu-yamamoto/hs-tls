-- |
-- Module      : Network.TLS.Sending
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Sending module contains calls related to marshalling packets according
-- to the TLS state
--
module Network.TLS.Sending2 (writePacket2, switchTxEncryption) where

import Control.Applicative
import Control.Monad.State
import Control.Concurrent.MVar

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Struct
import Network.TLS.Struct2
import Network.TLS.Record (RecordM)
import Network.TLS.Record.Types2
import Network.TLS.Record.Engage2
import Network.TLS.Packet
import Network.TLS.Packet2
import Network.TLS.Context.Internal
import Network.TLS.Handshake.State
import Network.TLS.Util
import Network.TLS.Wire

makeRecord :: Packet2 -> RecordM Record2
makeRecord pkt = return $ Record2 (contentType pkt) $ writePacketContent pkt
  where writePacketContent (Handshake2 hss _)  = encodeHandshakes2 hss
        writePacketContent (Alert2 a)          = encodeAlerts a
        writePacketContent (AppData2 x)        = x

encodeRecord :: Record2 -> RecordM ByteString
encodeRecord (Record2 ct bytes) = return ebytes
  where
    ebytes = runPut $ do
        putWord8 $ fromIntegral $ valOfType ct
        putWord16 0x0301
        putWord16 $ fromIntegral $ B.length bytes
        putBytes bytes

writePacket2 :: Context -> Packet2 -> IO (Either TLSError ByteString)
writePacket2 ctx pkt@(Handshake2 hss _) = do
    forM_ hss (usingHState ctx . updateHandshakeDigest . encodeHandshake2)
    prepareRecord ctx (makeRecord pkt >>= engageRecord >>= encodeRecord)
writePacket2 ctx pkt = prepareRecord ctx (makeRecord pkt >>= engageRecord >>= encodeRecord)

prepareRecord :: Context -> RecordM a -> IO (Either TLSError a)
prepareRecord = runTxState

switchTxEncryption :: Context -> IO ()
switchTxEncryption ctx = do
    tx <- usingHState ctx (fromJust "tx-state" <$> gets hstPendingTxState)
    liftIO $ modifyMVar_ (ctxTxState ctx) (\_ -> return tx)
