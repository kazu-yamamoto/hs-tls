{-# LANGUAGE RankNTypes #-}

module Network.TLS.ECH.AEAD where

import Crypto.Cipher.AES
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly1305
import Crypto.Cipher.Types (AuthTag (..))
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

class AEAD a where
    initialize :: Key -> Nonce -> a
    seal :: a -> AssociatedData -> PlainText -> CipherText
    open :: a -> AssociatedData -> CipherText -> Either HpkeError PlainText

mkSeal
    :: (st -> AEADEncrypt)
    -> st
    -> AssociatedData
    -> PlainText
    -> CipherText
mkSeal enc st aad plain = cipher <> convert tag
  where
    (cipher, AuthTag tag) = enc st aad plain

mkOpen
    :: (st -> AEADDecrypt)
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

type AEADEncrypt =
    forall a t
     . ( ByteArrayAccess a
       , ByteArray t
       )
    => a -> t -> (t, AuthTag)

type AEADDecrypt =
    forall a t
     . ( ByteArrayAccess a
       , ByteArray t
       )
    => a -> t -> (t, AuthTag)

----------------------------------------------------------------

instance AEAD AEAD_AES_128_GCM where
    initialize = initAes128gcm
    seal = mkSeal encryptAes128gcm
    open = mkOpen decryptAes128gcm aes128tagLength

newtype AEAD_AES_128_GCM = AEAD_AES_128_GCM (Cipher.AEAD AES128)

initAes128gcm :: (ByteArray k, ByteArrayAccess n) => k -> n -> AEAD_AES_128_GCM
initAes128gcm key nonce = AEAD_AES_128_GCM st1
  where
    st0 = noFail (Cipher.cipherInit key) :: AES128
    st1 = noFail $ Cipher.aeadInit Cipher.AEAD_GCM st0 nonce

encryptAes128gcm :: AEAD_AES_128_GCM -> AEADEncrypt
encryptAes128gcm (AEAD_AES_128_GCM st) = encrypt
  where
    encrypt aad plain = swap $ Cipher.aeadSimpleEncrypt st aad plain aes128tagLength

decryptAes128gcm :: AEAD_AES_128_GCM -> AEADDecrypt
decryptAes128gcm (AEAD_AES_128_GCM st) = decrypt
  where
    decrypt aad cipher = simpleDecrypt st aad cipher 16

simpleDecrypt
    :: (ByteArrayAccess a, ByteArray t)
    => Cipher.AEAD cipher -> a -> t -> Int -> (t, AuthTag)
simpleDecrypt st aad cipher taglen = (plain, tag)
  where
    st2 = Cipher.aeadAppendHeader st aad
    (plain, st3) = Cipher.aeadDecrypt st2 cipher
    tag = Cipher.aeadFinalize st3 taglen

aes128tagLength :: Int
aes128tagLength = 16

----------------------------------------------------------------

instance AEAD AEAD_ChaCha20Poly1305 where
    initialize = initChacha20poly1305
    seal = mkSeal encryptChacha20poly1305
    open = mkOpen decryptChacha20poly1305 chacha20poly1305tagLength

newtype AEAD_ChaCha20Poly1305 = AEAD_ChaCha20Poly1305 ChaChaPoly1305.State

initChacha20poly1305
    :: (ByteArrayAccess k, ByteArrayAccess n) => k -> n -> AEAD_ChaCha20Poly1305
initChacha20poly1305 key nonce = AEAD_ChaCha20Poly1305 st
  where
    st = noFail (ChaChaPoly1305.nonce12 nonce >>= ChaChaPoly1305.initialize key)

encryptChacha20poly1305 :: AEAD_ChaCha20Poly1305 -> AEADEncrypt
encryptChacha20poly1305 (AEAD_ChaCha20Poly1305 st) = encrypt
  where
    encrypt aad plain = (cipher, AuthTag tag)
      where
        st2 = ChaChaPoly1305.finalizeAAD $ ChaChaPoly1305.appendAAD aad st
        (cipher, st3) = ChaChaPoly1305.encrypt plain st2
        Poly1305.Auth tag = ChaChaPoly1305.finalize st3

decryptChacha20poly1305 :: AEAD_ChaCha20Poly1305 -> AEADDecrypt
decryptChacha20poly1305 (AEAD_ChaCha20Poly1305 st) = decrypt
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
