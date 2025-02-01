{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Network.TLS.ECH.KEM where

import Crypto.ECC
import Crypto.Error
import Crypto.Hash.Algorithms
import qualified Crypto.PubKey.Curve25519 as X25519
import Data.ByteArray
import Data.ByteString
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as C8
import Data.Proxy
import Data.String

import Network.TLS.ECH.HPKE
import Network.TLS.ECH.KDF

type PublicKey curve = Point curve
type SecretKey curve = Scalar curve

newtype EncodedPublicKey = EncodedPublicKey ByteString deriving (Eq)

instance Show EncodedPublicKey where
    show (EncodedPublicKey pk) = showBS16 pk

instance IsString EncodedPublicKey where
    fromString = EncodedPublicKey . fromString

showBS16 :: ByteString -> String
showBS16 bs = "\"" <> s16 <> "\""
  where
    s16 = C8.unpack $ B16.encode bs

instance IsString X25519.PublicKey where
    fromString = \s ->
        let bs = fromString s :: ByteString
         in throwCryptoError $ X25519.publicKey bs

instance IsString X25519.SecretKey where
    fromString = \s ->
        let bs = fromString s :: ByteString
         in throwCryptoError $ X25519.secretKey bs

instance Show SharedSecret where
    show (SharedSecret sb) = showBS16 $ convert sb

-- |
--
-- >>> :set -XOverloadedStrings
-- >>> let pkEm = "\x37\xfd\xa3\x56\x7b\xdb\xd6\x28\xe8\x86\x68\xc3\xc8\xd7\xe9\x7d\x1d\x12\x53\xb6\xd4\xea\x6d\x44\xc1\x50\xf7\x41\xf1\xbf\x44\x31" :: PublicKey Curve_X25519
-- >>> let skEm = "\x52\xc4\xa7\x58\xa8\x02\xcd\x8b\x93\x6e\xce\xea\x31\x44\x32\x79\x8d\x5b\xaf\x2d\x7e\x92\x35\xdc\x08\x4a\xb1\xb9\xcf\xa2\xf7\x36" :: SecretKey Curve_X25519
-- >>> let pkRm = "\x39\x48\xcf\xe0\xad\x1d\xdb\x69\x5d\x78\x0e\x59\x07\x71\x95\xda\x6c\x56\x50\x6b\x02\x73\x29\x79\x4a\xb0\x2b\xca\x80\x81\x5c\x4d" :: PublicKey Curve_X25519
-- >>> encap Curve_X25519 SHA256 DHKEM_X25519_HKDF_SHA256 pkRm skEm pkEm
-- CryptoPassed ("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc","37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
encap
    :: forall curve h
     . (EllipticCurve curve, EllipticCurveDH curve, HashAlgorithm h, KDF h)
    => curve
    -> h
    -> KEM_ID
    -> PublicKey curve -- peer
    -> SecretKey curve -- mine
    -> PublicKey curve -- mine
    -> CryptoFailable (SharedSecret, EncodedPublicKey)
encap _curve h kem_id pkR skE pkE = do
    let proxy = Proxy :: Proxy curve
    dh <- ecdh proxy skE pkR
    let enc = encodePoint proxy pkE
    let pkRm = encodePoint proxy pkR
    let kem_context = enc <> pkRm
        suite = suite1 kem_id
        shared_secret = SharedSecret $ convert $ extractAndExpand h suite dh kem_context
    return (shared_secret, EncodedPublicKey enc)

-- |
--
-- >>> :set -XOverloadedStrings
-- >>> let skRm = "\x46\x12\xc5\x50\x26\x3f\xc8\xad\x58\x37\x5d\xf3\xf5\x57\xaa\xc5\x31\xd2\x68\x50\x90\x3e\x55\xa9\xf2\x3f\x21\xd8\x53\x4e\x8a\xc8" :: SecretKey Curve_X25519
-- >>> let pkRm = "\x39\x48\xcf\xe0\xad\x1d\xdb\x69\x5d\x78\x0e\x59\x07\x71\x95\xda\x6c\x56\x50\x6b\x02\x73\x29\x79\x4a\xb0\x2b\xca\x80\x81\x5c\x4d" :: PublicKey Curve_X25519
-- >>> let enc = "\x37\xfd\xa3\x56\x7b\xdb\xd6\x28\xe8\x86\x68\xc3\xc8\xd7\xe9\x7d\x1d\x12\x53\xb6\xd4\xea\x6d\x44\xc1\x50\xf7\x41\xf1\xbf\x44\x31" :: EncodedPublicKey
-- >>> decap Curve_X25519 SHA256 DHKEM_X25519_HKDF_SHA256 enc skRm pkRm
-- CryptoPassed "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"
decap
    :: forall curve h
     . (EllipticCurve curve, EllipticCurveDH curve, HashAlgorithm h, KDF h)
    => curve
    -> h
    -> KEM_ID
    -> EncodedPublicKey -- peer
    -> SecretKey curve -- mine
    -> PublicKey curve -- mine
    -> CryptoFailable SharedSecret
decap _curve h kem_id (EncodedPublicKey enc) skR pkR = do
    let proxy = Proxy :: Proxy curve
    pkE <- decodePoint proxy enc
    dh <- ecdh proxy skR pkE
    let pkRm = encodePoint proxy pkR
    let kem_context = enc <> pkRm
        suite = suite1 kem_id
        shared_secret = SharedSecret $ convert $ extractAndExpand h suite dh kem_context
    return shared_secret
