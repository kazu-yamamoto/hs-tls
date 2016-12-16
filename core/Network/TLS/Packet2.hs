{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Packet2 where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Network.TLS.Struct
import Network.TLS.Struct2
import Network.TLS.Packet
import Network.TLS.Extension
import Network.TLS.Wire
import Data.X509 (CertificateChainRaw(..), encodeCertificateChain, decodeCertificateChain)

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

-- TLS 1.3 does not use "select (extensions_present)".
putExtensions :: [ExtensionRaw] -> Put
putExtensions es = putOpaque16 (runPut $ mapM_ putExtension es)

encodeHandshake2' :: Handshake2 -> ByteString
encodeHandshake2' (HelloRetryRequest2 ver exts) = runPut $ do
    putVersion' ver
    putExtensions exts
encodeHandshake2' (ServerHello2 ver random cipherId exts) = runPut $ do
    putVersion' ver
    putServerRandom32 random
    putWord16 cipherId
    putExtensions exts
encodeHandshake2' (EncryptedExtensions2 exts) = runPut $ putExtensions exts
encodeHandshake2' (Certificate2 reqctx cc ess) = runPut $ do
    putOpaque8 reqctx
    putOpaque24 (runPut $ mapM_ putCert $ zip certs ess)
  where
    CertificateChainRaw certs = encodeCertificateChain cc
    putCert (certRaw,exts) = do
        putOpaque24 certRaw
        putExtensions exts
encodeHandshake2' (CertVerify2 sigAlgo signature) = runPut $ do
    encodeSignatureScheme sigAlgo
    putOpaque16 signature
encodeHandshake2' (Finished2 dat) = runPut $ putBytes dat
encodeHandshake2' (NewSessionTicket2 life ageadd ticket exts) = runPut $ do
    putWord32 life
    putWord32 ageadd
    putOpaque16 ticket
    putExtensions exts
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
    HandshakeType_Finished2            -> decodeFinished2
    HandshakeType_EncryptedExtensions2 -> decodeEncryptedExtensions2
    HandshakeType_Certificate2         -> decodeCertificate2
    HandshakeType_CertVerify2          -> decodeCertVerify2
    HandshakeType_NewSessionTicket2    -> decodeNewSessionTicket2
    _x                                 -> error $ "decodeHandshake2 " ++ show _x

decodeFinished2 :: Get Handshake2
decodeFinished2 = Finished2 <$> (remaining >>= getBytes)

decodeEncryptedExtensions2 :: Get Handshake2
decodeEncryptedExtensions2 = EncryptedExtensions2 <$> do
    len <- fromIntegral <$> getWord16
    getExtensions len

decodeCertificate2 :: Get Handshake2
decodeCertificate2 = do
    reqctx <- getOpaque8
    len <- fromIntegral <$> getWord24
    (certRaws, ess) <- unzip <$> getList len getCert
    let Right certs = decodeCertificateChain $ CertificateChainRaw certRaws -- fixme
    return $ Certificate2 reqctx certs ess
  where
    getCert = do
        l <- fromIntegral <$> getWord24
        cert <- getBytes l
        len <- fromIntegral <$> getWord16
        exts <- getExtensions len
        return (3 + l + 2 + len, (cert, exts))

decodeCertVerify2 :: Get Handshake2
decodeCertVerify2 = do
    Just sigAlgo <- decodeSignatureScheme -- fixme
    signature <- getOpaque16
    return $ CertVerify2 sigAlgo signature

decodeNewSessionTicket2 :: Get Handshake2
decodeNewSessionTicket2 = do
    life <- getWord32
    ageadd <- getWord32
    ticket <- getOpaque16
    len <- fromIntegral <$> getWord16
    exts <- getExtensions len
    return $ NewSessionTicket2 life ageadd ticket exts
