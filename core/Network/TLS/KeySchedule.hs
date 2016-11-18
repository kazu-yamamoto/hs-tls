{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}

module Network.TLS.KeySchedule (
    hkdfExtract
  , hkdfExpandLabel
  , deriveSecret
  , PRKey
  , fromPRKeytoByteString
  , fromByteStringToPRKey
  ) where

import Network.TLS.Crypto
import qualified Crypto.Hash as H
import Crypto.KDF.HKDF
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Network.TLS.Wire

----------------------------------------------------------------

data PRKey = forall a . H.HashAlgorithm a => PRKey (PRK a)

instance Show PRKey where
    show (PRKey prk) = show prk

fromPRKeytoByteString :: PRKey -> ByteString
fromPRKeytoByteString (PRKey prf) = toByteString prf

fromByteStringToPRKey :: Hash -> ByteString -> PRKey
fromByteStringToPRKey SHA1   bs = PRKey ((fromByteString bs) :: PRK H.SHA1)
fromByteStringToPRKey SHA256 bs = PRKey ((fromByteString bs) :: PRK H.SHA256)
fromByteStringToPRKey SHA384 bs = PRKey ((fromByteString bs) :: PRK H.SHA384)
fromByteStringToPRKey SHA512 bs = PRKey ((fromByteString bs) :: PRK H.SHA512)
fromByteStringToPRKey _ _       = error "fromByteStringToPRKey"

----------------------------------------------------------------

hkdfExtract :: Hash -> ByteString -> ByteString -> PRKey
hkdfExtract SHA1   salt ikm = PRKey ((hkdfExtract' salt ikm) :: PRK H.SHA1)
hkdfExtract SHA256 salt ikm = PRKey ((hkdfExtract' salt ikm) :: PRK H.SHA256)
hkdfExtract SHA384 salt ikm = PRKey ((hkdfExtract' salt ikm) :: PRK H.SHA384)
hkdfExtract SHA512 salt ikm = PRKey ((hkdfExtract' salt ikm) :: PRK H.SHA512)
hkdfExtract _ _ _           = error "hkdfExtract: unsupported hash"

hkdfExtract' :: H.HashAlgorithm a
             => ByteString -- salt
             -> ByteString -- input key material
             -> PRK a
hkdfExtract' = extract

----------------------------------------------------------------

deriveSecret :: PRKey -> ByteString -> ByteString -> ByteString
deriveSecret (PRKey secret) label hashedMsgs =
    deriveSecret' secret label hashedMsgs

deriveSecret' :: forall a. H.HashAlgorithm a => PRK a -> ByteString -> ByteString -> ByteString
deriveSecret' secret label hashedMsgs =
    hkdfExpandLabel' secret label hashedMsgs len
  where
    len = H.hashDigestSize (undefined :: a)

----------------------------------------------------------------

hkdfExpandLabel :: PRKey
                -> ByteString
                -> ByteString
                -> Int
                -> ByteString
hkdfExpandLabel (PRKey secret) label hashValue len =
    hkdfExpandLabel' secret label hashValue len

hkdfExpandLabel' :: H.HashAlgorithm a
                 => PRK a
                 -> ByteString
                 -> ByteString
                 -> Int
                 -> ByteString
hkdfExpandLabel' secret label hashValue len =
    expand secret hkdfLabel len
  where
    hkdfLabel :: ByteString
    hkdfLabel = runPut $ do
        putWord16 $ fromIntegral len
        let tlsLabel = "TLS 1.3, " `BS.append` label
            tlsLabelLen = BS.length tlsLabel
            hashLen = BS.length hashValue -- not equal to len
        putWord8 $ fromIntegral tlsLabelLen
        putBytes $ tlsLabel
        putWord8 $ fromIntegral hashLen
        putBytes $ hashValue

----------------------------------------------------------------
