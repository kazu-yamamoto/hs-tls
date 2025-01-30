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
