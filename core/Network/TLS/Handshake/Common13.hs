{-# LANGUAGE OverloadedStrings, BangPatterns #-}

module Network.TLS.Handshake.Common13 where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import qualified Network.TLS.Crypto.IES as IES
import Network.TLS.Extension
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Handshake.Signature
import Network.TLS.Imports
import Network.TLS.KeySchedule
import Network.TLS.MAC
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Wire
import Data.Time

----------------------------------------------------------------

makeFinished :: Context -> Hash -> ByteString -> IO Handshake13
makeFinished ctx usedHash baseKey = do
    transcript <- transcriptHash ctx
    return $ Finished13 $ makeVerifyData usedHash baseKey transcript

makeVerifyData :: Hash -> ByteString -> ByteString -> ByteString
makeVerifyData usedHash baseKey hashValue = hmac usedHash finishedKey hashValue
  where
    hashSize = hashDigestSize usedHash
    finishedKey = hkdfExpandLabel usedHash baseKey "finished" "" hashSize

----------------------------------------------------------------

makeServerKeyShare :: Context -> KeyShareEntry -> IO (ByteString, KeyShareEntry)
makeServerKeyShare ctx (KeyShareEntry grp wcpub) = case ecpub of
  Left  e    -> throwCore $ Error_Protocol (show e, True, HandshakeFailure)
  Right cpub -> do
      Just (spub, share) <- generateECDHEShared ctx cpub -- fixme
      let wspub = IES.encodeGroupPublic spub
          serverKeyShare = KeyShareEntry grp wspub
          key = BA.convert share
      return (key, serverKeyShare)
  where
    ecpub = IES.decodeGroupPublic grp wcpub

makeClientKeyShare :: Context -> Group -> IO (IES.GroupPrivate, KeyShareEntry)
makeClientKeyShare ctx grp = do
    (cpri, cpub) <- generateECDHE ctx grp
    let wcpub = IES.encodeGroupPublic cpub
        clientKeyShare = KeyShareEntry grp wcpub
    return (cpri, clientKeyShare)

fromServerKeyShare :: KeyShareEntry -> IES.GroupPrivate -> IO ByteString
fromServerKeyShare (KeyShareEntry grp wspub) cpri = case espub of
  Left  e    -> throwCore $ Error_Protocol (show e, True, HandshakeFailure)
  Right spub -> case IES.groupGetShared spub cpri of
    Just shared -> return $ BA.convert shared
    Nothing     -> throwCore $ Error_Protocol ("cannote generate a shared secret on (EC)DH", True, HandshakeFailure)
  where
    espub = IES.decodeGroupPublic grp wspub

----------------------------------------------------------------

serverContextString :: ByteString
serverContextString = "TLS 1.3, server CertificateVerify"

clientContextString :: ByteString
clientContextString = "TLS 1.3, client CertificateVerify"

makeServerCertVerify :: Context -> HashAndSignatureAlgorithm -> PrivKey -> ByteString -> IO Handshake13
makeServerCertVerify ctx hs privKey hashValue =
    CertVerify13 hs <$> sign ctx hs privKey target
  where
    target = makeTarget serverContextString hashValue

makeClientCertVerify :: Context -> HashAndSignatureAlgorithm -> PrivKey -> ByteString -> IO Handshake13
makeClientCertVerify ctx hs privKey hashValue =
    CertVerify13 hs <$> sign ctx hs privKey target
 where
    target = makeTarget clientContextString hashValue

checkServerCertVerify :: HashAndSignatureAlgorithm -> ByteString -> PubKey -> ByteString -> IO ()
checkServerCertVerify hs signature pubKey hashValue =
    unless ok $ error "fixme"
  where
    Just sig = fromPubKey pubKey -- fixme
    sigParams = signatureParams sig (Just hs)
    target = makeTarget serverContextString hashValue
    ok = kxVerify pubKey sigParams target signature

makeTarget :: ByteString -> ByteString -> ByteString
makeTarget contextString hashValue = runPut $ do
    putBytes $ B.pack $ replicate 64 32
    putBytes contextString
    putWord8 0
    putBytes hashValue

sign :: Context -> HashAndSignatureAlgorithm -> PrivKey -> ByteString -> IO ByteString
sign ctx hs privKey target = usingState_ ctx $ do
    r <- withRNG $ kxSign privKey sigParams target
    case r of
        Left err       -> fail ("sign failed: " ++ show err)
        Right econtent -> return econtent
  where
    Just sig = fromPrivKey privKey -- fixme
    sigParams = signatureParams sig (Just hs)

----------------------------------------------------------------

makePSKBinder :: Context -> ByteString -> Hash -> Int -> Maybe ByteString -> IO ByteString
makePSKBinder ctx earlySecret usedHash truncLen mch = do
    rmsgs0 <- usingHState ctx getHandshakeMessagesRev -- XXX
    let rmsgs = case mch of
          Just ch -> trunc ch : rmsgs0
          Nothing -> trunc (head rmsgs0) : tail rmsgs0
        hChTruncated = hash usedHash $ B.concat $ reverse rmsgs
        binderKey = deriveSecret usedHash earlySecret "resumption psk binder key" (hash usedHash "")
    return $ makeVerifyData usedHash binderKey hChTruncated
  where
    trunc x = B.take takeLen x
      where
        totalLen = B.length x
        takeLen = totalLen - truncLen

replacePSKBinder :: ByteString -> ByteString -> ByteString
replacePSKBinder pskz binder = identities `B.append` binders
  where
    bindersSize = B.length binder + 3
    identities  = B.take (B.length pskz - bindersSize) pskz
    binders     = runPut $ putOpaque16 $ runPut $ putOpaque8 binder

----------------------------------------------------------------

createTLS13TicketInfo :: Word32 -> Either Context Word32 -> IO TLS13TicketInfo
createTLS13TicketInfo life ecw = do
    -- Left:  serverSendTime
    -- Right: clientReceiveTime
    bTime <- millisecondsFromBase <$> getCurrentTime
    add <- case ecw of
        Left ctx -> B.foldl' (*+) 0 <$> usingState_ ctx (genRandom 4)
        Right ad -> return ad
    return $ TLS13TicketInfo life add bTime
  where
    x *+ y = x * 256 + fromIntegral y

ageToObfuscatedAge :: Word32 -> TLS13TicketInfo -> Word32
ageToObfuscatedAge age tinfo = obfage
  where
    !obfage = age + ageAdd tinfo

obfuscatedAgeToAge :: Word32 -> TLS13TicketInfo -> Word32
obfuscatedAgeToAge obfage tinfo = age
  where
    !age = obfage - ageAdd tinfo

isAgeValid :: Word32 -> TLS13TicketInfo -> Bool
isAgeValid age tinfo = age <= lifetime tinfo * 1000

getAge :: TLS13TicketInfo -> IO Word32
getAge tinfo = do
    let clientReceiveTime = txrxTime tinfo
    clientSendTime <- millisecondsFromBase <$> getCurrentTime
    return $! fromIntegral (clientSendTime - clientReceiveTime) -- milliseconds

getTripTime :: TLS13TicketInfo -> IO Word32
getTripTime (TLS13TicketInfo _ _ serverSendTime) = do
    serverReceiveTime <- millisecondsFromBase <$> getCurrentTime
    return $! fromIntegral (serverReceiveTime - serverSendTime) -- milliseconds

-- diffTimeToPicoseconds is not available in old time package
millisecondsFromBase :: UTCTime -> Word64
millisecondsFromBase d = fromInteger ms
  where
    ss = realToFrac (diffUTCTime d base) :: Double -- xyz.abc second
    ms = truncate (ss * 1000)
    base = UTCTime (fromGregorian 2017 1 1) 0
