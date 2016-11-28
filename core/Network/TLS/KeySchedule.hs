{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.KeySchedule (
    hkdfExtract
  , hkdfExpandLabel
  , deriveSecret
  ) where

import Network.TLS.Crypto
import qualified Crypto.Hash as H
import Crypto.KDF.HKDF
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Network.TLS.Wire

----------------------------------------------------------------

hkdfExtract :: Hash -> ByteString -> ByteString -> ByteString
hkdfExtract SHA1   salt ikm = toByteString ((extract salt ikm) :: PRK H.SHA1)
hkdfExtract SHA256 salt ikm = toByteString ((extract salt ikm) :: PRK H.SHA256)
hkdfExtract SHA384 salt ikm = toByteString ((extract salt ikm) :: PRK H.SHA384)
hkdfExtract SHA512 salt ikm = toByteString ((extract salt ikm) :: PRK H.SHA512)
hkdfExtract _ _ _           = error "hkdfExtract: unsupported hash"

----------------------------------------------------------------

deriveSecret :: Hash -> ByteString -> ByteString -> ByteString -> ByteString
deriveSecret h secret label hashedMsgs =
    hkdfExpandLabel h secret label hashedMsgs len
  where
    len = hashDigestSize h

----------------------------------------------------------------

hkdfExpandLabel :: Hash
                -> ByteString
                -> ByteString
                -> ByteString
                -> Int
                -> ByteString
hkdfExpandLabel h secret label hashValue len = expand' h secret hkdfLabel len
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

expand' :: Hash -> ByteString -> ByteString -> Int -> ByteString
expand' SHA1   secret label len = expand ((fromByteString secret) :: PRK H.SHA1) label len
expand' SHA256 secret label len = expand ((fromByteString secret) :: PRK H.SHA256) label len
expand' SHA384 secret label len = expand ((fromByteString secret) :: PRK H.SHA384) label len
expand' SHA512 secret label len = expand ((fromByteString secret) :: PRK H.SHA512) label len
expand' _ _ _ _ = error "expand'"

----------------------------------------------------------------
