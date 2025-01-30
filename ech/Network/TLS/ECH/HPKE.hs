{-# LANGUAGE PatternSynonyms #-}

module Network.TLS.ECH.HPKE where

import Data.Word
import Text.Printf

data HpkeError
    = ValidationError
    | DeserializeError
    | EncapError
    | DecapError
    | OpenError
    | MessageLimitReachedError
    | DeriveKeyPairError
    deriving (Eq, Show)

----------------------------------------------------------------
-- Hybrid Public Key Encryption (RFC 9180)

-- should be included in "crypton"?

newtype HpkeKemId = HpkeKemId Word16 deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern DHKEM_P_256_HKDF_SHA256  :: HpkeKemId
pattern DHKEM_P_256_HKDF_SHA256   = HpkeKemId 0x0010
pattern DHKEM_P_384_HKDF_SHA384  :: HpkeKemId
pattern DHKEM_P_384_HKDF_SHA384   = HpkeKemId 0x0011
pattern DHKEM_P_512_HKDF_SHA512  :: HpkeKemId
pattern DHKEM_P_512_HKDF_SHA512   = HpkeKemId 0x0012
pattern DHKEM_X25519_HKDF_SHA256 :: HpkeKemId
pattern DHKEM_X25519_HKDF_SHA256  = HpkeKemId 0x0020
pattern DHKEM_X448_HKDF_SHA512   :: HpkeKemId
pattern DHKEM_X448_HKDF_SHA512    = HpkeKemId 0x0021

instance Show HpkeKemId where
    show DHKEM_P_256_HKDF_SHA256  = "DHKEM(P-256, HKDF-SHA256)"
    show DHKEM_P_384_HKDF_SHA384  = "DHKEM(P-384, HKDF-SHA384)"
    show DHKEM_P_512_HKDF_SHA512  = "DHKEM(P-521, HKDF-SHA512)"
    show DHKEM_X25519_HKDF_SHA256 = "DHKEM(X25519, HKDF-SHA256)"
    show DHKEM_X448_HKDF_SHA512   = "DHKEM(X448, HKDF-SHA512)"
    show (HpkeKemId n)            = "DHKEM 0x" ++ printf "%04x" n
{- FOURMOLU_ENABLE -}

newtype HpkeKdfId = HpkeKdfId Word16 deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern HKDF_SHA256 :: HpkeKdfId
pattern HKDF_SHA256  = HpkeKdfId 0x0001
pattern HKDF_SHA384 :: HpkeKdfId
pattern HKDF_SHA384  = HpkeKdfId 0x0002
pattern HKDF_SHA512 :: HpkeKdfId
pattern HKDF_SHA512  = HpkeKdfId 0x0003

instance Show HpkeKdfId where
    show HKDF_SHA256   = "HKDF_SHA256"
    show HKDF_SHA384   = "HKDF_SHA384"
    show HKDF_SHA512   = "HKDF_SHA512"
    show (HpkeKdfId n) = "HKDF 0x" ++ printf "%04x" n
{- FOURMOLU_ENABLE -}

newtype HpkeAeadId = HpkeAeadId Word16 deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern AES_128_GCM      :: HpkeAeadId
pattern AES_128_GCM       = HpkeAeadId 0x0001
pattern AES_256_GCM      :: HpkeAeadId
pattern AES_256_GCM       = HpkeAeadId 0x0002
pattern ChaCha20Poly1305 :: HpkeAeadId
pattern ChaCha20Poly1305  = HpkeAeadId 0x0003

instance Show HpkeAeadId where
    show AES_128_GCM      = "AES_128_GCM"
    show AES_256_GCM      = "AES_256_GCM"
    show ChaCha20Poly1305 = "ChaCha20Poly1305"
    show (HpkeAeadId n)   = "HpkeAeadId 0x" ++ printf "%04x" n
{- FOURMOLU_ENABLE -}
