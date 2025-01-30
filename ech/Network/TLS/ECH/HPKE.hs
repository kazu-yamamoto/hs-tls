{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RankNTypes #-}

module Network.TLS.ECH.HPKE where

import Crypto.Cipher.AES
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly1305
import Crypto.Cipher.Types hiding (Cipher, cipherName)
import Crypto.Error
import qualified Crypto.MAC.Poly1305 as Poly1305
import Data.ByteArray
import Data.Tuple (swap)
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

----------------------------------------------------------------

data Key
data Nonce
data AssociatedData
data PlainText
data CipherText -- including AuthTag
data AuthTag

class HpkeAead a where
    initialize :: Key -> Nonce -> a
    seal :: a -> Key -> Nonce -> AssociatedData -> PlainText -> CipherText
    open :: a -> Key -> Nonce -> AssociatedData -> CipherText -> PlainText

type Aead =
    forall a t
     . ( ByteArrayAccess a
       , ByteArray t
       )
    => a -> t -> (t, Crypto.Cipher.Types.AuthTag)

type AeadInit =
    forall iv key
     . (ByteArrayAccess iv, ByteArrayAccess key) => key -> iv -> ChaChaPoly1305.State

newtype StateChaCha20Poly1305 = StateChaCha20Poly1305 ChaChaPoly1305.State

initChacha20poly1305
    :: (ByteArrayAccess k, ByteArrayAccess n) => k -> n -> StateChaCha20Poly1305
initChacha20poly1305 key nonce = StateChaCha20Poly1305 st
  where
    st = noFail (ChaChaPoly1305.nonce12 nonce >>= ChaChaPoly1305.initialize key)

sealChacha20poly1305 :: StateChaCha20Poly1305 -> Aead
sealChacha20poly1305 (StateChaCha20Poly1305 st) = encrypt
  where
    encrypt aad plain = (cipher, AuthTag tag)
      where
        st2 = ChaChaPoly1305.finalizeAAD $ ChaChaPoly1305.appendAAD aad st
        (cipher, st3) = ChaChaPoly1305.encrypt plain st2
        Poly1305.Auth tag = ChaChaPoly1305.finalize st3

openChacha20poly1305 :: StateChaCha20Poly1305 -> Aead
openChacha20poly1305 (StateChaCha20Poly1305 st) = decrypt
  where
    decrypt aad cipher = (plain, AuthTag tag)
      where
        st2 = ChaChaPoly1305.finalizeAAD $ ChaChaPoly1305.appendAAD aad st
        (plain, st3) = ChaChaPoly1305.decrypt cipher st2
        Poly1305.Auth tag = ChaChaPoly1305.finalize st3

noFail :: CryptoFailable a -> a
noFail = throwCryptoError

newtype StateAES128 = StateAES128 (AEAD AES128)

initAes128gcm :: (ByteArray k, ByteArrayAccess n) => k -> n -> StateAES128
initAes128gcm key nonce = StateAES128 st1
  where
    st0 = noFail (cipherInit key) :: AES128
    st1 = noFail $ aeadInit AEAD_GCM st0 nonce

sealAes128gcm :: StateAES128 -> Aead
sealAes128gcm (StateAES128 st) = encrypt
  where
    encrypt aad plain = swap $ aeadSimpleEncrypt st aad plain 16

openAes128gcm :: StateAES128 -> Aead
openAes128gcm (StateAES128 st) = decrypt
  where
    decrypt aad cipher = simpleDecrypt st aad cipher 16

simpleDecrypt
    :: (ByteArrayAccess n, ByteArray t)
    => AEAD cipher -> n -> t -> Int -> (t, Crypto.Cipher.Types.AuthTag)
simpleDecrypt aeadIni nonce cipher taglen = (plain, tag)
  where
    aead = aeadAppendHeader aeadIni nonce
    (plain, aeadFinal) = aeadDecrypt aead cipher
    tag = aeadFinalize aeadFinal taglen
