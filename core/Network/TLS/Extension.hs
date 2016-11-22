{-# LANGUAGE BangPatterns #-}
-- |
-- Module      : Network.TLS.Extension
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- basic extensions are defined in RFC 6066
--
module Network.TLS.Extension
    ( Extension(..)
    , supportedExtensions
    , definedExtensions
    -- all extensions ID supported
    , extensionID_ServerName
    , extensionID_MaxFragmentLength
    , extensionID_SecureRenegotiation
    , extensionID_NextProtocolNegotiation
    , extensionID_ApplicationLayerProtocolNegotiation
    , extensionID_Groups
    , extensionID_EcPointFormats
    , extensionID_Heartbeat
    , extensionID_SignatureAlgorithms
    , extensionID_KeyShare
    , extensionID_PreSharedKey
    , extensionID_EarlyData
    , extensionID_SupportedVersions
    , extensionID_Cookie
    , extensionID_PskKeyExchangeModes
    , extensionID_TicketEarlyDataInfo
    -- all implemented extensions
    , ServerNameType(..)
    , ServerName(..)
    , MaxFragmentLength(..)
    , MaxFragmentEnum(..)
    , SecureRenegotiation(..)
    , NextProtocolNegotiation(..)
    , ApplicationLayerProtocolNegotiation(..)
    , SupportedGroups(..)
    , Group(..)
    , EcPointFormatsSupported(..)
    , EcPointFormat(..)
    , SessionTicket(..)
    , HeartBeat(..)
    , HeartBeatMode(..)
    , SignatureAlgorithms(..)
    , SupportedVersions(..)
    , KeyShare(..)
    , KeyShareEntry(..)
    , SignatureScheme(..)
    , SignatureSchemes(..)
    , encodeSignatureScheme
    , MessageType(..)
    , PskKexMode(..)
    , PskKeyExchangeModes(..)
    ) where

import Control.Monad

import Data.Word
import Data.Maybe (fromMaybe, catMaybes)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Network.TLS.Types (Version(..))
import Network.TLS.Crypto.Types
import Network.TLS.Struct (ExtensionID, EnumSafe8(..), HashAndSignatureAlgorithm)
import Network.TLS.Wire
import Network.TLS.Imports
import Network.TLS.Packet (putSignatureHashAlgorithm, getSignatureHashAlgorithm, putVersion', getVersion')

type HostName = String

-- central list defined in <http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.txt>
extensionID_ServerName
  , extensionID_MaxFragmentLength
  , extensionID_ClientCertificateUrl
  , extensionID_TrustedCAKeys
  , extensionID_TruncatedHMAC
  , extensionID_StatusRequest
  , extensionID_UserMapping
  , extensionID_ClientAuthz
  , extensionID_ServerAuthz
  , extensionID_CertType
  , extensionID_Groups
  , extensionID_EcPointFormats
  , extensionID_SRP
  , extensionID_SignatureAlgorithms
  , extensionID_SRTP
  , extensionID_Heartbeat
  , extensionID_ApplicationLayerProtocolNegotiation
  , extensionID_StatusRequestv2
  , extensionID_SignedCertificateTimestamp
  , extensionID_ClientCertificateType
  , extensionID_ServerCertificateType
  , extensionID_Padding
  , extensionID_EncryptThenMAC
  , extensionID_ExtendedMasterSecret
  , extensionID_SessionTicket
  , extensionID_KeyShare
  , extensionID_PreSharedKey
  , extensionID_EarlyData
  , extensionID_SupportedVersions
  , extensionID_Cookie
  , extensionID_PskKeyExchangeModes
  , extensionID_TicketEarlyDataInfo
  , extensionID_NextProtocolNegotiation
  , extensionID_SecureRenegotiation :: ExtensionID
extensionID_ServerName                          = 0x0 -- RFC6066
extensionID_MaxFragmentLength                   = 0x1 -- RFC6066
extensionID_ClientCertificateUrl                = 0x2 -- RFC6066
extensionID_TrustedCAKeys                       = 0x3 -- RFC6066
extensionID_TruncatedHMAC                       = 0x4 -- RFC6066
extensionID_StatusRequest                       = 0x5 -- RFC6066
extensionID_UserMapping                         = 0x6 -- RFC4681
extensionID_ClientAuthz                         = 0x7 -- RFC5878
extensionID_ServerAuthz                         = 0x8 -- RFC5878
extensionID_CertType                            = 0x9 -- RFC6091
extensionID_Groups                              = 0xa -- RFC4492, TLS 1.3 supported groups
extensionID_EcPointFormats                      = 0xb -- RFC4492
extensionID_SRP                                 = 0xc -- RFC5054
extensionID_SignatureAlgorithms                 = 0xd -- RFC5246, TLS 1.3
extensionID_SRTP                                = 0xe -- RFC5764
extensionID_Heartbeat                           = 0xf -- RFC6520
extensionID_ApplicationLayerProtocolNegotiation = 0x10 -- RFC7301
extensionID_StatusRequestv2                     = 0x11 -- RFC6961
extensionID_SignedCertificateTimestamp          = 0x12 -- RFC6962
extensionID_ClientCertificateType               = 0x13 -- RFC7250
extensionID_ServerCertificateType               = 0x14 -- RFC7250
extensionID_Padding                             = 0x15 -- draft-agl-tls-padding. expires 2015-03-12
extensionID_EncryptThenMAC                      = 0x16 -- RFC7366
extensionID_ExtendedMasterSecret                = 0x17 -- draft-ietf-tls-session-hash. expires 2015-09-26
extensionID_SessionTicket                       = 0x23 -- RFC4507
extensionID_KeyShare                            = 0x28 -- TLS 1.3
extensionID_PreSharedKey                        = 0x29 -- TLS 1.3
extensionID_EarlyData                           = 0x2a -- TLS 1.3
extensionID_SupportedVersions                   = 0x2b -- TLS 1.3
extensionID_Cookie                              = 0x2c -- TLS 1.3
extensionID_PskKeyExchangeModes                 = 0x2d -- TLS 1.3
extensionID_TicketEarlyDataInfo                 = 0x2e -- TLS 1.3
extensionID_NextProtocolNegotiation             = 0x3374 -- obsolete
extensionID_SecureRenegotiation                 = 0xff01 -- RFC5746

definedExtensions :: [ExtensionID]
definedExtensions =
    [ extensionID_ServerName
    , extensionID_MaxFragmentLength
    , extensionID_ClientCertificateUrl
    , extensionID_TrustedCAKeys
    , extensionID_TruncatedHMAC
    , extensionID_StatusRequest
    , extensionID_UserMapping
    , extensionID_ClientAuthz
    , extensionID_ServerAuthz
    , extensionID_CertType
    , extensionID_Groups
    , extensionID_EcPointFormats
    , extensionID_SRP
    , extensionID_SignatureAlgorithms
    , extensionID_SRTP
    , extensionID_Heartbeat
    , extensionID_ApplicationLayerProtocolNegotiation
    , extensionID_StatusRequestv2
    , extensionID_SignedCertificateTimestamp
    , extensionID_ClientCertificateType
    , extensionID_ServerCertificateType
    , extensionID_Padding
    , extensionID_EncryptThenMAC
    , extensionID_ExtendedMasterSecret
    , extensionID_SessionTicket
    , extensionID_NextProtocolNegotiation
    , extensionID_SecureRenegotiation
    ]

-- | all supported extensions by the implementation
supportedExtensions :: [ExtensionID]
supportedExtensions = [ extensionID_ServerName
                      , extensionID_MaxFragmentLength
                      , extensionID_ApplicationLayerProtocolNegotiation
                      , extensionID_SecureRenegotiation
                      , extensionID_NextProtocolNegotiation
                      , extensionID_Groups
                      , extensionID_EcPointFormats
                      , extensionID_SignatureAlgorithms
                      , extensionID_KeyShare
                      , extensionID_PreSharedKey
                      , extensionID_EarlyData
                      , extensionID_SupportedVersions
                      , extensionID_Cookie
                      , extensionID_PskKeyExchangeModes
                      , extensionID_TicketEarlyDataInfo
                      ]

data MessageType = MsgTClinetHello
                 | MsgTServerHello
                 | MsgTHelloRetryRequest
                 deriving (Eq,Show)

-- | Extension class to transform bytes to and from a high level Extension type.
class Extension a where
    extensionID     :: a -> ExtensionID
    extensionDecode :: MessageType -> ByteString -> Maybe a
    extensionEncode :: a -> ByteString

-- | Server Name extension including the name type and the associated name.
-- the associated name decoding is dependant of its name type.
-- name type = 0 : hostname
data ServerName = ServerName [ServerNameType]
    deriving (Show,Eq)

data ServerNameType = ServerNameHostName HostName
                    | ServerNameOther    (Word8, ByteString)
                    deriving (Show,Eq)

instance Extension ServerName where
    extensionID _ = extensionID_ServerName
    extensionEncode (ServerName l) = runPut $ putOpaque16 (runPut $ mapM_ encodeNameType l)
        where encodeNameType (ServerNameHostName hn)       = putWord8 0  >> putOpaque16 (BC.pack hn) -- FIXME: should be puny code conversion
              encodeNameType (ServerNameOther (nt,opaque)) = putWord8 nt >> putBytes opaque
    extensionDecode _ = runGetMaybe (getWord16 >>= \len -> getList (fromIntegral len) getServerName >>= return . ServerName)
        where getServerName = do
                  ty    <- getWord8
                  sname <- getOpaque16
                  return (1+2+B.length sname, case ty of
                      0 -> ServerNameHostName $ BC.unpack sname -- FIXME: should be puny code conversion
                      _ -> ServerNameOther (ty, sname))

-- | Max fragment extension with length from 512 bytes to 4096 bytes
data MaxFragmentLength = MaxFragmentLength MaxFragmentEnum
    deriving (Show,Eq)
data MaxFragmentEnum = MaxFragment512 | MaxFragment1024 | MaxFragment2048 | MaxFragment4096
    deriving (Show,Eq)

instance Extension MaxFragmentLength where
    extensionID _ = extensionID_MaxFragmentLength
    extensionEncode (MaxFragmentLength e) = B.singleton $ marshallSize e
        where marshallSize MaxFragment512  = 1
              marshallSize MaxFragment1024 = 2
              marshallSize MaxFragment2048 = 3
              marshallSize MaxFragment4096 = 4
    extensionDecode _ = runGetMaybe (MaxFragmentLength . unmarshallSize <$> getWord8)
        where unmarshallSize 1 = MaxFragment512
              unmarshallSize 2 = MaxFragment1024
              unmarshallSize 3 = MaxFragment2048
              unmarshallSize 4 = MaxFragment4096
              unmarshallSize n = error ("unknown max fragment size " ++ show n)

-- | Secure Renegotiation
data SecureRenegotiation = SecureRenegotiation ByteString (Maybe ByteString)
    deriving (Show,Eq)

instance Extension SecureRenegotiation where
    extensionID _ = extensionID_SecureRenegotiation
    extensionEncode (SecureRenegotiation cvd svd) =
        runPut $ putOpaque8 (cvd `B.append` fromMaybe B.empty svd)
    extensionDecode msgtype = runGetMaybe $ do
        opaque <- getOpaque8
        case msgtype of
          MsgTServerHello -> let (cvd, svd) = B.splitAt (B.length opaque `div` 2) opaque
                             in return $ SecureRenegotiation cvd (Just svd)
          MsgTClinetHello -> return $ SecureRenegotiation opaque Nothing
          _               -> error "decoding SecureRenegotiation for HRR"

-- | Next Protocol Negotiation
data NextProtocolNegotiation = NextProtocolNegotiation [ByteString]
    deriving (Show,Eq)

instance Extension NextProtocolNegotiation where
    extensionID _ = extensionID_NextProtocolNegotiation
    extensionEncode (NextProtocolNegotiation bytes) =
        runPut $ mapM_ putOpaque8 bytes
    extensionDecode _ = runGetMaybe (NextProtocolNegotiation <$> getNPN)
        where getNPN = do
                 avail <- remaining
                 case avail of
                     0 -> return []
                     _ -> do liftM2 (:) getOpaque8 getNPN

-- | Application Layer Protocol Negotiation (ALPN)
data ApplicationLayerProtocolNegotiation = ApplicationLayerProtocolNegotiation [ByteString]
    deriving (Show,Eq)

instance Extension ApplicationLayerProtocolNegotiation where
    extensionID _ = extensionID_ApplicationLayerProtocolNegotiation
    extensionEncode (ApplicationLayerProtocolNegotiation bytes) =
        runPut $ putOpaque16 $ runPut $ mapM_ putOpaque8 bytes
    extensionDecode _ = runGetMaybe (ApplicationLayerProtocolNegotiation <$> getALPN)
        where getALPN = do
                 _ <- getWord16
                 getALPN'
              getALPN' = do
                 avail <- remaining
                 case avail of
                     0 -> return []
                     _ -> (:) <$> getOpaque8 <*> getALPN'

data SupportedGroups = SupportedGroups [Group]
    deriving (Show,Eq)

-- on decode, filter all unknown curves
instance Extension SupportedGroups where
    extensionID _ = extensionID_Groups
    extensionEncode (SupportedGroups groups) = runPut $ putWords16 $ map fromGroup groups
    extensionDecode _ = runGetMaybe (SupportedGroups . catMaybes . map toGroup <$> getWords16)

data EcPointFormatsSupported = EcPointFormatsSupported [EcPointFormat]
    deriving (Show,Eq)

data EcPointFormat =
      EcPointFormat_Uncompressed
    | EcPointFormat_AnsiX962_compressed_prime
    | EcPointFormat_AnsiX962_compressed_char2
    deriving (Show,Eq)

instance EnumSafe8 EcPointFormat where
    fromEnumSafe8 EcPointFormat_Uncompressed = 0
    fromEnumSafe8 EcPointFormat_AnsiX962_compressed_prime = 1
    fromEnumSafe8 EcPointFormat_AnsiX962_compressed_char2 = 2

    toEnumSafe8 0 = Just EcPointFormat_Uncompressed
    toEnumSafe8 1 = Just EcPointFormat_AnsiX962_compressed_prime
    toEnumSafe8 2 = Just EcPointFormat_AnsiX962_compressed_char2
    toEnumSafe8 _ = Nothing

-- on decode, filter all unknown formats
instance Extension EcPointFormatsSupported where
    extensionID _ = extensionID_EcPointFormats
    extensionEncode (EcPointFormatsSupported formats) = runPut $ putWords8 $ map fromEnumSafe8 formats
    extensionDecode _ = runGetMaybe (EcPointFormatsSupported . catMaybes . map toEnumSafe8 <$> getWords8)

data SessionTicket = SessionTicket
    deriving (Show,Eq)

instance Extension SessionTicket where
    extensionID _ = extensionID_SessionTicket
    extensionEncode (SessionTicket {}) = runPut $ return ()
    extensionDecode _ = runGetMaybe (return SessionTicket)

data HeartBeat = HeartBeat HeartBeatMode
    deriving (Show,Eq)

data HeartBeatMode =
      HeartBeat_PeerAllowedToSend
    | HeartBeat_PeerNotAllowedToSend
    deriving (Show,Eq)

instance EnumSafe8 HeartBeatMode where
    fromEnumSafe8 HeartBeat_PeerAllowedToSend    = 1
    fromEnumSafe8 HeartBeat_PeerNotAllowedToSend = 2

    toEnumSafe8 1 = Just HeartBeat_PeerAllowedToSend
    toEnumSafe8 2 = Just HeartBeat_PeerNotAllowedToSend
    toEnumSafe8 _ = Nothing

instance Extension HeartBeat where
    extensionID _ = extensionID_Heartbeat
    extensionEncode (HeartBeat mode) = runPut $ putWord8 $ fromEnumSafe8 mode
    extensionDecode _ bs =
        case runGetMaybe (toEnumSafe8 <$> getWord8) bs of
            Just (Just mode) -> Just $ HeartBeat mode
            _                -> Nothing

-- for TLS 1.2
data SignatureAlgorithms = SignatureAlgorithms [HashAndSignatureAlgorithm]
    deriving (Show,Eq)

instance Extension SignatureAlgorithms where
    extensionID _ = extensionID_SignatureAlgorithms
    extensionEncode (SignatureAlgorithms algs) =
        runPut $ putWord16 (fromIntegral (length algs * 2)) >> mapM_ putSignatureHashAlgorithm algs
    extensionDecode _ =
        runGetMaybe $ do
            len <- getWord16
            SignatureAlgorithms <$> getList (fromIntegral len) (getSignatureHashAlgorithm >>= \sh -> return (2, sh))

-- for TLS 1.3
data SignatureScheme =
      SigScheme_RSApkcs1SHA1
    | SigScheme_RSApkcs1SHA256
    | SigScheme_RSApkcs1SHA384
    | SigScheme_RSApkcs1SHA512
    | SigScheme_ECDSAp256SHA256
    | SigScheme_ECDSAp384SHA384
    | SigScheme_ECDSAp512SHA512
    | SigScheme_RSApssSHA256
    | SigScheme_RSApssSHA384
    | SigScheme_RSApssSHA512
    | SigScheme_Ed25519
    | SigScheme_Ed448
    deriving (Eq,Show)

toSignatureScheme :: Word16 -> Maybe SignatureScheme
toSignatureScheme 0x0201 = Just SigScheme_RSApkcs1SHA1
toSignatureScheme 0x0401 = Just SigScheme_RSApkcs1SHA256
toSignatureScheme 0x0501 = Just SigScheme_RSApkcs1SHA384
toSignatureScheme 0x0601 = Just SigScheme_RSApkcs1SHA512
toSignatureScheme 0x0403 = Just SigScheme_ECDSAp256SHA256
toSignatureScheme 0x0503 = Just SigScheme_ECDSAp384SHA384
toSignatureScheme 0x0603 = Just SigScheme_ECDSAp512SHA512
toSignatureScheme 0x0804 = Just SigScheme_RSApssSHA256
toSignatureScheme 0x0805 = Just SigScheme_RSApssSHA384
toSignatureScheme 0x0806 = Just SigScheme_RSApssSHA512
toSignatureScheme 0x0807 = Just SigScheme_Ed25519
toSignatureScheme 0x0808 = Just SigScheme_Ed448
toSignatureScheme _      = Nothing

fromSignatureScheme :: SignatureScheme -> Word16
fromSignatureScheme SigScheme_RSApkcs1SHA1    = 0x0201
fromSignatureScheme SigScheme_RSApkcs1SHA256  = 0x0401
fromSignatureScheme SigScheme_RSApkcs1SHA384  = 0x0501
fromSignatureScheme SigScheme_RSApkcs1SHA512  = 0x0601
fromSignatureScheme SigScheme_ECDSAp256SHA256 = 0x0402
fromSignatureScheme SigScheme_ECDSAp384SHA384 = 0x0503
fromSignatureScheme SigScheme_ECDSAp512SHA512 = 0x0603
fromSignatureScheme SigScheme_RSApssSHA256    = 0x0804
fromSignatureScheme SigScheme_RSApssSHA384    = 0x0805
fromSignatureScheme SigScheme_RSApssSHA512    = 0x0806
fromSignatureScheme SigScheme_Ed25519         = 0x0807
fromSignatureScheme SigScheme_Ed448           = 0x0808

encodeSignatureScheme :: SignatureScheme -> Put
encodeSignatureScheme = putWord16 . fromSignatureScheme

data SignatureSchemes = SignatureSchemes [SignatureScheme]
    deriving (Show,Eq)

instance Extension SignatureSchemes where
    extensionID _ = extensionID_SignatureAlgorithms
    extensionEncode (SignatureSchemes algs) =
        runPut $ putWord16 (fromIntegral (length algs * 2)) >> mapM_ encodeSignatureScheme algs
    extensionDecode _ =
        runGetMaybe $ do
            len <- getWord16
            SignatureSchemes . catMaybes <$> getList (fromIntegral len) ((\mss -> (2,mss)) . toSignatureScheme <$> getWord16)

data SupportedVersions = SupportedVersions [Version]
    deriving (Show,Eq)

instance Extension SupportedVersions where
    extensionID _ = extensionID_SupportedVersions
    extensionEncode (SupportedVersions vers) =
        runPut $ putWord8 (fromIntegral (length vers * 2)) >> mapM_ putVersion' vers
    extensionDecode _ =
        runGetMaybe $ do
            len <- getWord8
            SupportedVersions . catMaybes <$> getList (fromIntegral len) ((\ver -> (2, ver)) <$> getVersion')

data KeyShareEntry = KeyShareEntry Group ByteString
    deriving (Show,Eq)

getKeyShareEntry :: Get (Int, Maybe KeyShareEntry)
getKeyShareEntry = do
    g <- getWord16
    l <- fromIntegral <$> getWord16
    key <- getBytes l
    let !len = l + 4
    case toGroup g of
      Nothing  -> return (len, Nothing)
      Just grp -> return (len, Just $ KeyShareEntry grp key)

putKeyShareEntry :: KeyShareEntry -> Put
putKeyShareEntry (KeyShareEntry grp key) = do
    putWord16 $ fromGroup grp
    putWord16 $ fromIntegral $ B.length key
    putBytes key

data KeyShare =
    KeyShareClientHello [KeyShareEntry]
  | KeyShareServerHello KeyShareEntry
  | KeyShareHRR Group
    deriving (Show,Eq)

instance Extension KeyShare where
    extensionID _ = extensionID_KeyShare
    extensionEncode (KeyShareClientHello kses) = runPut $ do
        let !len = sum $ map (\(KeyShareEntry _ key) -> B.length key) kses
        putWord16 $ fromIntegral len
        mapM_ putKeyShareEntry kses
    extensionEncode (KeyShareServerHello kse) = runPut $ putKeyShareEntry kse
    extensionEncode (KeyShareHRR grp) = runPut $ putWord16 $ fromGroup grp
    extensionDecode MsgTServerHello  = runGetMaybe $ do
        (_, ment) <- getKeyShareEntry
        case ment of
            Nothing  -> fail "decoding KeyShare for ServerHello"
            Just ent -> return $ KeyShareServerHello ent
    extensionDecode MsgTClinetHello = runGetMaybe $ do
        len <- fromIntegral <$> getWord16
        grps <- getList len getKeyShareEntry
        return $ KeyShareClientHello $ catMaybes grps
    extensionDecode MsgTHelloRetryRequest = runGetMaybe $ do
        mgrp <- toGroup <$> getWord16
        case mgrp of
          Nothing  -> fail "decoding KeyShare for HRR"
          Just grp -> return $ KeyShareHRR grp

data PskKexMode = PSK_KE | PSK_DHE_KE deriving (Eq, Show)

fromPskKexMode :: PskKexMode -> Word8
fromPskKexMode PSK_KE     = 0
fromPskKexMode PSK_DHE_KE = 1

toPskKexMode :: Word8 -> Maybe PskKexMode
toPskKexMode 0 = Just PSK_KE
toPskKexMode 1 = Just PSK_DHE_KE
toPskKexMode _ = Nothing

data PskKeyExchangeModes = PskKeyExchangeModes [PskKexMode] deriving (Eq, Show)

instance Extension PskKeyExchangeModes where
    extensionID _ = extensionID_PskKeyExchangeModes
    extensionEncode (PskKeyExchangeModes pkms) = runPut $ do
        let bytes = B.pack $ map fromPskKexMode pkms
        putOpaque8 bytes
    extensionDecode _ = runGetMaybe $ do
        len <- getWord8
        PskKeyExchangeModes . catMaybes <$> getList (fromIntegral len) ((\x -> (1, toPskKexMode x)) <$> getWord8)
