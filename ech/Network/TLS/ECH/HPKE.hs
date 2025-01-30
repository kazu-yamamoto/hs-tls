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

newtype KEM_ID = KEM_ID {fromKEM_ID :: Word16} deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern DHKEM_P_256_HKDF_SHA256  :: KEM_ID
pattern DHKEM_P_256_HKDF_SHA256   = KEM_ID 0x0010
pattern DHKEM_P_384_HKDF_SHA384  :: KEM_ID
pattern DHKEM_P_384_HKDF_SHA384   = KEM_ID 0x0011
pattern DHKEM_P_512_HKDF_SHA512  :: KEM_ID
pattern DHKEM_P_512_HKDF_SHA512   = KEM_ID 0x0012
pattern DHKEM_X25519_HKDF_SHA256 :: KEM_ID
pattern DHKEM_X25519_HKDF_SHA256  = KEM_ID 0x0020
pattern DHKEM_X448_HKDF_SHA512   :: KEM_ID
pattern DHKEM_X448_HKDF_SHA512    = KEM_ID 0x0021

instance Show KEM_ID where
    show DHKEM_P_256_HKDF_SHA256  = "DHKEM(P-256, HKDF-SHA256)"
    show DHKEM_P_384_HKDF_SHA384  = "DHKEM(P-384, HKDF-SHA384)"
    show DHKEM_P_512_HKDF_SHA512  = "DHKEM(P-521, HKDF-SHA512)"
    show DHKEM_X25519_HKDF_SHA256 = "DHKEM(X25519, HKDF-SHA256)"
    show DHKEM_X448_HKDF_SHA512   = "DHKEM(X448, HKDF-SHA512)"
    show (KEM_ID n)               = "DHKEM_ID 0x" ++ printf "%04x" n
{- FOURMOLU_ENABLE -}

newtype KDF_ID = KDF_ID Word16 deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern HKDF_SHA256 :: KDF_ID
pattern HKDF_SHA256  = KDF_ID 0x0001
pattern HKDF_SHA384 :: KDF_ID
pattern HKDF_SHA384  = KDF_ID 0x0002
pattern HKDF_SHA512 :: KDF_ID
pattern HKDF_SHA512  = KDF_ID 0x0003

instance Show KDF_ID where
    show HKDF_SHA256 = "HKDF_SHA256"
    show HKDF_SHA384 = "HKDF_SHA384"
    show HKDF_SHA512 = "HKDF_SHA512"
    show (KDF_ID n)  = "HKDF_ID 0x" ++ printf "%04x" n
{- FOURMOLU_ENABLE -}

newtype AEAD_ID = AEAD_ID Word16 deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern AES_128_GCM      :: AEAD_ID
pattern AES_128_GCM       = AEAD_ID 0x0001
pattern AES_256_GCM      :: AEAD_ID
pattern AES_256_GCM       = AEAD_ID 0x0002
pattern ChaCha20Poly1305 :: AEAD_ID
pattern ChaCha20Poly1305  = AEAD_ID 0x0003

instance Show AEAD_ID where
    show AES_128_GCM      = "AES_128_GCM"
    show AES_256_GCM      = "AES_256_GCM"
    show ChaCha20Poly1305 = "ChaCha20Poly1305"
    show (AEAD_ID n)      = "AEAD_ID 0x" ++ printf "%04x" n
{- FOURMOLU_ENABLE -}
