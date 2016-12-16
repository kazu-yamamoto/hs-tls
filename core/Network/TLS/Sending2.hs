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
module Network.TLS.Sending2 (writePacket2, writeHandshakePacket2) where

import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Struct
import Network.TLS.Struct2
import Network.TLS.Record (RecordM)
import Network.TLS.Record.Types2
import Network.TLS.Record.Engage2
import Network.TLS.Packet
import Network.TLS.Packet2
import Network.TLS.Hooks
import Network.TLS.Context.Internal
import Network.TLS.Handshake.State
import Network.TLS.Wire

makeRecord :: Packet2 -> RecordM Record2
makeRecord pkt = return $ Record2 (contentType pkt) $ writePacketContent pkt
  where writePacketContent (Handshake2 hss) = encodeHandshakes2 hss
        writePacketContent (Alert2 a)       = encodeAlerts a
        writePacketContent (AppData2 x)     = x

encodeRecord :: Record2 -> RecordM ByteString
encodeRecord (Record2 ct bytes) = return ebytes
  where
    ebytes = runPut $ do
        putWord8 $ fromIntegral $ valOfType ct
        putWord16 0x0301
        putWord16 $ fromIntegral $ B.length bytes
        putBytes bytes

writePacket2 :: Context -> Packet2 -> IO (Either TLSError ByteString)
writePacket2 ctx pkt@(Handshake2 hss) = do
    forM_ hss $ \hs -> usingHState ctx $ do
        let encoded = encodeHandshake2 hs
        updateHandshakeDigest encoded
        addHandshakeMessage encoded
    prepareRecord ctx (makeRecord pkt >>= engageRecord >>= encodeRecord)
writePacket2 ctx pkt = prepareRecord ctx (makeRecord pkt >>= engageRecord >>= encodeRecord)

writeHandshakePacket2 :: MonadIO m => Context -> Handshake2 -> m Bytes
writeHandshakePacket2 ctx hdsk = do
    let pkt = Handshake2 [hdsk]
    edataToSend <- liftIO $ do
        withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
        writePacket2 ctx pkt
    case edataToSend of
        Left err         -> throwCore err
        Right dataToSend -> return dataToSend

prepareRecord :: Context -> RecordM a -> IO (Either TLSError a)
prepareRecord = runTxState
