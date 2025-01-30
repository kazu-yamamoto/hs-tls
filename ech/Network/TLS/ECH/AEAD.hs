{-# LANGUAGE RankNTypes #-}

module Network.TLS.ECH.AEAD where

import Crypto.Cipher.AES
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly1305
import Crypto.Cipher.Types hiding (Cipher, cipherName)
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

class HpkeAead a where
    initialize :: Key -> Nonce -> a
    seal :: a -> AssociatedData -> PlainText -> CipherText
    open :: a -> AssociatedData -> CipherText -> Either HpkeError PlainText

mkSeal :: (st -> Aead) -> st -> AssociatedData -> PlainText -> CipherText
mkSeal enc st aad plain = cipher <> convert tag
  where
    (cipher, AuthTag tag) = enc st aad plain

mkOpen
    :: (st -> Aead)
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

type Aead =
    forall a t
     . ( ByteArrayAccess a
       , ByteArray t
       )
    => a -> t -> (t, AuthTag)

----------------------------------------------------------------

instance HpkeAead StateAES128 where
    initialize = initAes128gcm
    seal = mkSeal encryptAes128gcm
    open = mkOpen decryptAes128gcm aes128tagLength

newtype StateAES128 = StateAES128 (AEAD AES128)

initAes128gcm :: (ByteArray k, ByteArrayAccess n) => k -> n -> StateAES128
initAes128gcm key nonce = StateAES128 st1
  where
    st0 = noFail (cipherInit key) :: AES128
    st1 = noFail $ aeadInit AEAD_GCM st0 nonce

encryptAes128gcm :: StateAES128 -> Aead
encryptAes128gcm (StateAES128 st) = encrypt
  where
    encrypt aad plain = swap $ aeadSimpleEncrypt st aad plain aes128tagLength

decryptAes128gcm :: StateAES128 -> Aead
decryptAes128gcm (StateAES128 st) = decrypt
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

aes128tagLength :: Int
aes128tagLength = 16

----------------------------------------------------------------

instance HpkeAead StateChaCha20Poly1305 where
    initialize = initChacha20poly1305
    seal = mkSeal encryptChacha20poly1305
    open = mkOpen decryptChacha20poly1305 chacha20poly1305tagLength

newtype StateChaCha20Poly1305 = StateChaCha20Poly1305 ChaChaPoly1305.State

initChacha20poly1305
    :: (ByteArrayAccess k, ByteArrayAccess n) => k -> n -> StateChaCha20Poly1305
initChacha20poly1305 key nonce = StateChaCha20Poly1305 st
  where
    st = noFail (ChaChaPoly1305.nonce12 nonce >>= ChaChaPoly1305.initialize key)

encryptChacha20poly1305 :: StateChaCha20Poly1305 -> Aead
encryptChacha20poly1305 (StateChaCha20Poly1305 st) = encrypt
  where
    encrypt aad plain = (cipher, AuthTag tag)
      where
        st2 = ChaChaPoly1305.finalizeAAD $ ChaChaPoly1305.appendAAD aad st
        (cipher, st3) = ChaChaPoly1305.encrypt plain st2
        Poly1305.Auth tag = ChaChaPoly1305.finalize st3

decryptChacha20poly1305 :: StateChaCha20Poly1305 -> Aead
decryptChacha20poly1305 (StateChaCha20Poly1305 st) = decrypt
  where
    decrypt aad cipher = (plain, AuthTag tag)
      where
        st2 = ChaChaPoly1305.finalizeAAD $ ChaChaPoly1305.appendAAD aad st
        (plain, st3) = ChaChaPoly1305.decrypt cipher st2
        Poly1305.Auth tag = ChaChaPoly1305.finalize st3

chacha20poly1305tagLength :: Int
chacha20poly1305tagLength = 16

----------------------------------------------------------------

noFail :: CryptoFailable a -> a
noFail = throwCryptoError
