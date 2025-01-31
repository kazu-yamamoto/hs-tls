{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeSynonymInstances #-}

module Network.TLS.ECH.AEAD where

import Crypto.Cipher.AES
import qualified Crypto.Cipher.ChaChaPoly1305 as CCP
import Crypto.Cipher.Types (AEAD (..), AEADModeImpl (..), AuthTag (..))
import qualified Crypto.Cipher.Types as Cipher
import Crypto.Error
import qualified Crypto.MAC.Poly1305 as Poly1305
import Data.ByteArray
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Tuple (swap)

import Network.TLS.ECH.HPKE

----------------------------------------------------------------

type Key = ByteString
type Nonce = ByteString
type AssociatedData = ByteString
type PlainText = ByteString
type CipherText = ByteString -- including AuthTag

class Aead a where
    initialize :: Key -> Nonce -> AEAD a
    seal :: AEAD a -> AssociatedData -> PlainText -> CipherText
    open :: AEAD a -> AssociatedData -> CipherText -> Either HpkeError PlainText

mkSeal
    :: (st -> AeadEncrypt)
    -> st
    -> AssociatedData
    -> PlainText
    -> CipherText
mkSeal enc st aad plain = cipher <> convert tag
  where
    (cipher, AuthTag tag) = enc st aad plain

mkOpen
    :: (st -> AeadDecrypt)
    -> Int
    -> st
    -> AssociatedData
    -> CipherText
    -> Either HpkeError PlainText
mkOpen dec len st aad cipher
    | tag == convert tag' = Right plain
    | otherwise = Left OpenError
  where
    brkpt = BS.length cipher - len
    (cipher', tag') = BS.splitAt brkpt cipher
    (plain, AuthTag tag) = dec st aad cipher'

----------------------------------------------------------------

type AeadEncrypt =
    forall a t
     . ( ByteArrayAccess a
       , ByteArray t
       )
    => a -> t -> (t, AuthTag)

type AeadDecrypt =
    forall a t
     . ( ByteArrayAccess a
       , ByteArray t
       )
    => a -> t -> (t, AuthTag)

----------------------------------------------------------------

-- | From RFC 9180 A.1
--
-- >>> :set -XOverloadedStrings
-- >>> let key = "\x45\x31\x68\x5d\x41\xd6\x5f\x03\xdc\x48\xf6\xb8\x30\x2c\x05\xb0" :: ByteString
-- >>> let nonce = "\x56\xd8\x90\xe5\xac\xca\xaf\x01\x1c\xff\x4b\x7d" :: ByteString
-- >>> let aad = "\x43\x6f\x75\x6e\x74\x2d\x30" :: ByteString
-- >>> let plain = "The quick brown fox jumps over the very lazy dog." :: ByteString
-- >>> let st = initialize key nonce :: AEAD AES128
-- >>> open st aad $ seal st aad plain
-- Right "The quick brown fox jumps over the very lazy dog."
instance Aead AES128 where
    initialize = initAes128gcm
    seal = mkSeal encryptAes128gcm
    open = mkOpen decryptAes128gcm aes128tagLength

initAes128gcm :: (ByteArray k, ByteArrayAccess n) => k -> n -> AEAD AES128
initAes128gcm key nonce = st1
  where
    st0 = noFail (Cipher.cipherInit key) :: AES128
    st1 = noFail $ Cipher.aeadInit Cipher.AEAD_GCM st0 nonce

encryptAes128gcm :: AEAD AES128 -> AeadEncrypt
encryptAes128gcm st = encrypt
  where
    encrypt aad plain = simpleEncrypt st aad plain aes128tagLength

decryptAes128gcm :: AEAD AES128 -> AeadDecrypt
decryptAes128gcm st = decrypt
  where
    decrypt aad cipher = simpleDecrypt st aad cipher aes128tagLength

aes128tagLength :: Int
aes128tagLength = 16

----------------------------------------------------------------

-- | From RFC 9180 A.6
--
-- >>> :set -XOverloadedStrings
-- >>> let key = "\x75\x1e\x34\x6c\xe8\xf0\xdd\xb2\x30\x5c\x8a\x2a\x85\xc7\x0d\x5c\xf5\x59\xc5\x30\x93\x65\x6b\xe6\x36\xb9\x40\x6d\x4d\x7d\x1b\x70" :: ByteString
-- >>> let nonce = "\x55\xff\x7a\x7d\x73\x9c\x69\xf4\x4b\x25\x44\x7b" :: ByteString
-- >>> let aad = "\x43\x6f\x75\x6e\x74\x2d\x30" :: ByteString
-- >>> let plain = "The quick brown fox jumps over the very lazy dog." :: ByteString
-- >>> let st = initialize key nonce :: AEAD AES256
-- >>> open st aad $ seal st aad plain
-- Right "The quick brown fox jumps over the very lazy dog."
instance Aead AES256 where
    initialize = initAes256gcm
    seal = mkSeal encryptAes256gcm
    open = mkOpen decryptAes256gcm aes256tagLength

initAes256gcm :: (ByteArray k, ByteArrayAccess n) => k -> n -> AEAD AES256
initAes256gcm key nonce = st1
  where
    st0 = noFail (Cipher.cipherInit key) :: AES256
    st1 = noFail $ Cipher.aeadInit Cipher.AEAD_GCM st0 nonce

encryptAes256gcm :: AEAD AES256 -> AeadEncrypt
encryptAes256gcm st = encrypt
  where
    encrypt aad plain = simpleEncrypt st aad plain aes256tagLength

decryptAes256gcm :: AEAD AES256 -> AeadDecrypt
decryptAes256gcm st = decrypt
  where
    decrypt aad cipher = simpleDecrypt st aad cipher aes256tagLength

aes256tagLength :: Int
aes256tagLength = 16

----------------------------------------------------------------

-- | From RFC 9180 A.5
--
-- >>> :set -XOverloadedStrings
-- >>> let key = "\xa8\xf4\x54\x90\xa9\x2a\x3b\x04\xd1\xdb\xf6\xcf\x2c\x39\x39\xad\x8b\xfc\x9b\xfc\xb9\x7c\x04\xbf\xfe\x11\x67\x30\xc9\xdf\xe3\xfc" :: ByteString
-- >>> let nonce = "\x72\x6b\x43\x90\xed\x22\x09\x80\x9f\x58\xc6\x93" :: ByteString
-- >>> let aad = "\x43\x6f\x75\x6e\x74\x2d\x30" :: ByteString
-- >>> let plain = "The quick brown fox jumps over the very lazy dog." :: ByteString
-- >>> let st = initialize key nonce :: AEAD ChaCha20Poly1305
-- >>> open st aad $ seal st aad plain
-- Right "The quick brown fox jumps over the very lazy dog."
instance Aead ChaCha20Poly1305 where
    initialize = initChacha20poly1305
    seal = mkSeal encryptChacha20poly1305
    open = mkOpen decryptChacha20poly1305 chacha20poly1305tagLength

type ChaCha20Poly1305 = CCP.State

initChacha20poly1305
    :: (ByteArrayAccess k, ByteArrayAccess n) => k -> n -> AEAD ChaCha20Poly1305
initChacha20poly1305 key nonce = st
  where
    st = aeadChacha20poly1305Init key nonce

aeadChacha20poly1305Init
    :: (ByteArrayAccess k, ByteArrayAccess n)
    => k -> n -> AEAD ChaCha20Poly1305
aeadChacha20poly1305Init key nonce = AEAD model st0
  where
    st0 = noFail (CCP.nonce12 nonce >>= CCP.initialize key)
    model =
        AEADModeImpl
            { aeadImplAppendHeader = \st aad -> CCP.finalizeAAD $ CCP.appendAAD aad st
            , aeadImplEncrypt = \st plain -> CCP.encrypt plain st
            , aeadImplDecrypt = \st cipher -> CCP.decrypt cipher st
            , aeadImplFinalize = \st _ -> let Poly1305.Auth tag = CCP.finalize st in AuthTag tag
            }

encryptChacha20poly1305 :: AEAD ChaCha20Poly1305 -> AeadEncrypt
encryptChacha20poly1305 st = encrypt
  where
    encrypt aad plain = simpleEncrypt st aad plain chacha20poly1305tagLength

decryptChacha20poly1305 :: AEAD ChaCha20Poly1305 -> AeadDecrypt
decryptChacha20poly1305 st = decrypt
  where
    decrypt aad cipher = simpleDecrypt st aad cipher chacha20poly1305tagLength

chacha20poly1305tagLength :: Int
chacha20poly1305tagLength = 16

----------------------------------------------------------------

simpleEncrypt
    :: (ByteArrayAccess a, ByteArray t)
    => AEAD cipher -> a -> t -> Int -> (t, AuthTag)
simpleEncrypt st aad plain taglen =
    swap $ Cipher.aeadSimpleEncrypt st aad plain taglen

simpleDecrypt
    :: (ByteArrayAccess a, ByteArray t)
    => AEAD cipher -> a -> t -> Int -> (t, AuthTag)
simpleDecrypt st aad cipher taglen = (plain, tag)
  where
    st2 = Cipher.aeadAppendHeader st aad
    (plain, st3) = Cipher.aeadDecrypt st2 cipher
    tag = Cipher.aeadFinalize st3 taglen

noFail :: CryptoFailable a -> a
noFail = throwCryptoError
