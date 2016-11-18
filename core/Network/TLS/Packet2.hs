{-# LANGUAGE BangPatterns #-}

module Network.TLS.Packet2 where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Network.TLS.Struct
import Network.TLS.Struct2
import Network.TLS.Packet
import Network.TLS.Extension
import Network.TLS.Wire
import Data.X509 (CertificateChainRaw(..), encodeCertificateChain)

encodeHandshakes2 :: [Handshake2] -> ByteString
encodeHandshakes2 hss = B.concat $ map encodeHandshake2 hss

encodeHandshake2 :: Handshake2 -> ByteString
encodeHandshake2 hdsk = pkt
  where
    !tp = typeOfHandshake2 hdsk
    !content = encodeHandshake2' hdsk
    !len = fromIntegral $ B.length content
    !header = encodeHandshakeHeader2 tp len
    !pkt = B.concat [header, content]

encodeHandshake2' :: Handshake2 -> ByteString
encodeHandshake2' (ServerHello2 ver random cipherId exts) = runPut $ do
    putVersion' ver
    putServerRandom32 random
    putWord16 cipherId
    putExtensions exts
encodeHandshake2' (EncryptedExtensions2 []) = runPut $ putWord16 0
encodeHandshake2' (EncryptedExtensions2 exts) = runPut $ putExtensions exts
encodeHandshake2' (Certificate2 reqctx cc) = runPut $ do
    putOpaque8 reqctx
    putOpaque24 (runPut $ mapM_ putCert certs)
  where
    CertificateChainRaw certs = encodeCertificateChain cc
    putCert c = do
        putOpaque24 c
        putWord16 0 -- FIXME: extensions
encodeHandshake2' (CertVerify2 sigAlgo signature) = runPut $ do
    encodeSignatureScheme sigAlgo
    putOpaque16 signature
encodeHandshake2' (Finished2 dat) = runPut $ putBytes dat
encodeHandshake2' _ = error "encodeHandshake2'"

encodeHandshakeHeader2 :: HandshakeType2 -> Int -> ByteString
encodeHandshakeHeader2 ty len = runPut $ do
    putWord8 (valOfType ty)
    putWord24 len


{- decode and encode HANDSHAKE -}
getHandshakeType2 :: Get HandshakeType2
getHandshakeType2 = do
    ty <- getWord8
    case valToType ty of
        Nothing -> fail ("invalid handshake type: " ++ show ty)
        Just t  -> return t

decodeHandshakeRecord2 :: ByteString -> GetResult (HandshakeType2, Bytes)
decodeHandshakeRecord2 = runGet "handshake-record" $ do
    ty      <- getHandshakeType2
    content <- getOpaque24
    return (ty, content)

decodeHandshake2 :: HandshakeType2 -> ByteString -> Either TLSError Handshake2
decodeHandshake2 ty = runGetErr ("handshake[" ++ show ty ++ "]") $ case ty of
    HandshakeType_Finished2 -> decodeFinished2
    _                       -> error "decodeHandshake2" -- fixme

decodeFinished2 :: Get Handshake2
decodeFinished2 = Finished2 <$> (remaining >>= getBytes)
