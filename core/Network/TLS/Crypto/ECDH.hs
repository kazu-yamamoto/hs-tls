module Network.TLS.Crypto.ECDH
    (
      ECDHPublic
    , ECDHPrivate
    , ECDHKey
    -- * ECDH methods
    , ecdhGenerateKeyPair
    , ecdhGetPubShared
    , ecdhGetShared
    , encodeECDHPublic
    , decodeECDHPublic
    , ecdhPrivateGroup
    ) where

import Control.Arrow
import Crypto.ECC
import Crypto.PubKey.ECIES
import Network.TLS.Imports
import Network.TLS.RNG
import Network.TLS.Crypto.Types

data ECDHPrivate = ECDHPri_P256 (Scalar Curve_P256R1)
                 | ECDHPri_P384 (Scalar Curve_P384R1)
                 | ECDHPri_P521 (Scalar Curve_P521R1)
                 | ECDHPri_X255 (Scalar Curve_X25519)
                 deriving (Eq, Show)

data ECDHPublic = ECDHPub_P256 (Point Curve_P256R1)
                | ECDHPub_P384 (Point Curve_P384R1)
                | ECDHPub_P521 (Point Curve_P521R1)
                | ECDHPub_X255 (Point Curve_X25519)
                deriving (Eq, Show)

type ECDHKey = SharedSecret

ecdhGenerateKeyPair :: MonadRandom r => Group -> r (ECDHPrivate, ECDHPublic)
ecdhGenerateKeyPair P256   =
    (ECDHPri_P256,ECDHPub_P256) `fs` curveGenerateKeyPair
ecdhGenerateKeyPair P384   =
    (ECDHPri_P384,ECDHPub_P384) `fs` curveGenerateKeyPair
ecdhGenerateKeyPair P521   =
    (ECDHPri_P521,ECDHPub_P521) `fs` curveGenerateKeyPair
ecdhGenerateKeyPair X25519 =
    (ECDHPri_X255,ECDHPub_X255) `fs` curveGenerateKeyPair
ecdhGenerateKeyPair _ = error "ecdhGenerateKeyPair"

fs :: MonadRandom r
   => (Scalar a -> ECDHPrivate, Point a -> ECDHPublic)
   -> r (KeyPair a)
   -> r (ECDHPrivate, ECDHPublic)
(t1, t2) `fs` action = do
    keypair <- action
    let pub = keypairGetPublic keypair
        pri = keypairGetPrivate keypair
    return (t1 pri, t2 pub)

ecdhGetPubShared :: MonadRandom r => ECDHPublic -> r (ECDHPublic, ECDHKey)
ecdhGetPubShared (ECDHPub_P256 pub) =
    first ECDHPub_P256 <$> deriveEncrypt pub
ecdhGetPubShared (ECDHPub_P384 pub) =
    first ECDHPub_P384 <$> deriveEncrypt pub
ecdhGetPubShared (ECDHPub_P521 pub) =
    first ECDHPub_P521 <$> deriveEncrypt pub
ecdhGetPubShared (ECDHPub_X255 pub) =
    first ECDHPub_X255 <$> deriveEncrypt pub

ecdhGetShared ::  ECDHPublic -> ECDHPrivate -> ECDHKey
ecdhGetShared (ECDHPub_P256 pub) (ECDHPri_P256 pri) = deriveDecrypt pub pri
ecdhGetShared (ECDHPub_P384 pub) (ECDHPri_P384 pri) = deriveDecrypt pub pri
ecdhGetShared (ECDHPub_P521 pub) (ECDHPri_P521 pri) = deriveDecrypt pub pri
ecdhGetShared (ECDHPub_X255 pub) (ECDHPri_X255 pri) = deriveDecrypt pub pri
ecdhGetShared _ _ = error "ecdhGetShared"

encodeECDHPublic :: ECDHPublic -> (Group, Bytes)
encodeECDHPublic (ECDHPub_P256 p) = (P256, encodePoint p)
encodeECDHPublic (ECDHPub_P384 p) = (P384, encodePoint p)
encodeECDHPublic (ECDHPub_P521 p) = (P521, encodePoint p)
encodeECDHPublic (ECDHPub_X255 p) = (X25519, encodePoint p)

decodeECDHPublic :: Group -> Bytes -> ECDHPublic
decodeECDHPublic P256   bs = ECDHPub_P256 $ decodePoint bs
decodeECDHPublic P384   bs = ECDHPub_P384 $ decodePoint bs
decodeECDHPublic P521   bs = ECDHPub_P521 $ decodePoint bs
decodeECDHPublic X25519 bs = ECDHPub_X255 $ decodePoint bs
decodeECDHPublic _      _  = error "decodeECDHPublic"

ecdhPrivateGroup :: ECDHPrivate -> Group
ecdhPrivateGroup (ECDHPri_P256 _) = P256
ecdhPrivateGroup (ECDHPri_P384 _) = P384
ecdhPrivateGroup (ECDHPri_P521 _) = P521
ecdhPrivateGroup (ECDHPri_X255 _) = X25519
