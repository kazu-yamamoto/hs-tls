{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.ECH.KDF where

import Crypto.Hash.Algorithms (SHA256, SHA384, SHA512)
import Crypto.KDF.HKDF (PRK)
import qualified Crypto.KDF.HKDF as HKDF
import Crypto.Number.Serialize (i2ospOf_)
import Data.ByteString (ByteString)

import Network.TLS.ECH.HPKE

type Salt = ByteString
type IKM = ByteString -- Input Keying Material
type Info = ByteString
type Key = ByteString

class KDF a where
    extract :: Salt -> IKM -> PRK a
    expand :: PRK a -> Info -> Int -> Key

instance KDF SHA256 where
    extract = HKDF.extract
    expand = HKDF.expand

instance KDF SHA384 where
    extract = HKDF.extract
    expand = HKDF.expand

instance KDF SHA512 where
    extract = HKDF.extract
    expand = HKDF.expand

suite_id :: KEM_ID -> ByteString
suite_id kem_id = "KEM" <> i
  where
    i = i2ospOf_ 2 $ fromIntegral (fromKEM_ID kem_id)

labeledExtract :: KDF a => KEM_ID -> Salt -> ByteString -> IKM -> PRK a
labeledExtract kem_id salt label ikm = extract salt labeled_ikm
  where
    labeled_ikm = "HPKE-v1" <> suite_id kem_id <> label <> ikm

labeledExpand
    :: KDF a => KEM_ID -> PRK a -> ByteString -> ByteString -> Int -> Key
labeledExpand kem_id prk label info len = expand prk labeled_info len
  where
    labeled_info =
        i2ospOf_ 2 (fromIntegral len) <> "HPKE-v1" <> suite_id kem_id <> label <> info
