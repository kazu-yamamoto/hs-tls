module Network.TLS.Struct2 where

import Data.ByteString (ByteString)
import Data.X509 (CertificateChain)
import Network.TLS.Extension (SignatureScheme)
import Network.TLS.Struct
import Network.TLS.Types
import Network.TLS.Crypto.ECDH

data Packet2 =
      Handshake2 [Handshake2] (Maybe Bytes)
    | Alert2 [(AlertLevel, AlertDescription)]
    | AppData2 ByteString
    deriving (Show,Eq)

data CertificateEntry2 = CertificateEntry2 [ExtensionRaw]
    deriving (Show,Eq)

data Handshake2 =
      ClientHello2 !Version !ClientRandom ![CipherID] [ExtensionRaw]
    | ServerHello2 !Version !ServerRandom !CipherID [ExtensionRaw]
    | NewSessionTicket2 Word {-Bytes-} Bytes [ExtensionRaw] -- fixme
    | HelloRetryRequest2 !Version [ExtensionRaw]
    | EncryptedExtensions2 [ExtensionRaw]
    | CertRequest2 -- fixme
    | Certificate2 ByteString CertificateChain -- fixme: extensions
    | CertVerify2 SignatureScheme ByteString
    | Finished2 FinishedData
    | KeyUpdate2 -- fixme
    deriving (Show,Eq)

data HandshakeType2 =
      HandshakeType_ClientHello2
    | HandshakeType_ServerHello2
    | HandshakeType_NewSessionTicket2
    | HandshakeType_HelloRetryRequest2
    | HandshakeType_EncryptedExtensions2
    | HandshakeType_CertRequest2
    | HandshakeType_Certificate2
    | HandshakeType_CertVerify2
    | HandshakeType_Finished2
    | HandshakeType_KeyUpdate2
    deriving (Show,Eq)

typeOfHandshake2 :: Handshake2 -> HandshakeType2
typeOfHandshake2 (ClientHello2 {})         = HandshakeType_ClientHello2
typeOfHandshake2 (ServerHello2 {})         = HandshakeType_ServerHello2
typeOfHandshake2 (NewSessionTicket2 {})    = HandshakeType_NewSessionTicket2
typeOfHandshake2 (HelloRetryRequest2 {})   = HandshakeType_HelloRetryRequest2
typeOfHandshake2 (EncryptedExtensions2 {}) = HandshakeType_EncryptedExtensions2
typeOfHandshake2 (CertRequest2 {})         = HandshakeType_CertRequest2
typeOfHandshake2 (Certificate2 {})         = HandshakeType_Certificate2
typeOfHandshake2 (CertVerify2 {})          = HandshakeType_CertVerify2
typeOfHandshake2 (Finished2 {})            = HandshakeType_Finished2
typeOfHandshake2 (KeyUpdate2 {})           = HandshakeType_KeyUpdate2

instance TypeValuable HandshakeType2 where
  valOfType HandshakeType_ClientHello2         = 1
  valOfType HandshakeType_ServerHello2         = 2
  valOfType HandshakeType_NewSessionTicket2    = 4
  valOfType HandshakeType_HelloRetryRequest2   = 6
  valOfType HandshakeType_EncryptedExtensions2 = 8
  valOfType HandshakeType_CertRequest2         = 13
  valOfType HandshakeType_Certificate2         = 11
  valOfType HandshakeType_CertVerify2          = 15
  valOfType HandshakeType_Finished2            = 20
  valOfType HandshakeType_KeyUpdate2           = 24

  valToType 1  = Just HandshakeType_ClientHello2
  valToType 2  = Just HandshakeType_ServerHello2
  valToType 4  = Just HandshakeType_NewSessionTicket2
  valToType 6  = Just HandshakeType_HelloRetryRequest2
  valToType 8  = Just HandshakeType_EncryptedExtensions2
  valToType 13 = Just HandshakeType_CertRequest2
  valToType 11 = Just HandshakeType_Certificate2
  valToType 15 = Just HandshakeType_CertVerify2
  valToType 20 = Just HandshakeType_Finished2
  valToType 24 = Just HandshakeType_KeyUpdate2
  valToType _  = Nothing

data KeyExchange2 = ECDHE2 ECDHPublic

data ContentType =
      ContentType_Alert
    | ContentType_Handshake
    | ContentType_AppData
    deriving (Eq, Show)


instance TypeValuable ContentType where
    valOfType ContentType_Alert               = 21
    valOfType ContentType_Handshake           = 22
    valOfType ContentType_AppData             = 23

    valToType 21 = Just ContentType_Alert
    valToType 22 = Just ContentType_Handshake
    valToType 23 = Just ContentType_AppData
    valToType _  = Nothing

contentType :: Packet2 -> ContentType
contentType (Handshake2 _ _)  = ContentType_Handshake
contentType (Alert2 _)        = ContentType_Alert
contentType (AppData2 _)      = ContentType_AppData

protoToContent :: ProtocolType -> ContentType
protoToContent ProtocolType_Alert     = ContentType_Alert
protoToContent ProtocolType_Handshake = ContentType_Handshake
protoToContent ProtocolType_AppData   = ContentType_AppData
protoToContent _                      = error "protoToContent"
