{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.TLS.ECH.KDF (
    KDF (..),
    SHA256,
    SHA384,
    SHA512,
    PRK,
    suite1,
    extractAndExpand,
)
where

import Crypto.Hash.Algorithms (
    HashAlgorithm,
    SHA256 (..),
    SHA384 (..),
    SHA512 (..),
 )
import Crypto.Hash.IO (hashDigestSize)
import Crypto.KDF.HKDF (PRK)
import qualified Crypto.KDF.HKDF as HKDF
import Crypto.Number.Serialize (i2ospOf_)
import Data.ByteArray
import Data.ByteString (ByteString)

import Network.TLS.ECH.HPKE

type Salt = ByteString
type IKM = ByteString -- Input Keying Material
type Key = ByteString

class KDF h where
    labeledExtract :: ByteString -> Salt -> ByteString -> IKM -> PRK h
    labeledExpand :: ByteString -> PRK h -> ByteString -> ByteString -> Int -> Key

instance KDF SHA256 where
    labeledExtract = labeledExtract_
    labeledExpand = labeledExpand_

instance KDF SHA384 where
    labeledExtract = labeledExtract_
    labeledExpand = labeledExpand_

instance KDF SHA512 where
    labeledExtract = labeledExtract_
    labeledExpand = labeledExpand_

suite1 :: KEM_ID -> ByteString
suite1 kem_id = "KEM" <> i
  where
    i = i2ospOf_ 2 $ fromIntegral $ fromKEM_ID kem_id

labeledExtract_
    :: HashAlgorithm a => ByteString -> Salt -> ByteString -> IKM -> PRK a
labeledExtract_ suite salt label ikm = HKDF.extract salt labeled_ikm
  where
    labeled_ikm = "HPKE-v1" <> suite <> label <> ikm

labeledExpand_
    :: HashAlgorithm a => ByteString -> PRK a -> ByteString -> ByteString -> Int -> Key
labeledExpand_ suite prk label info len = HKDF.expand prk labeled_info len
  where
    labeled_info =
        i2ospOf_ 2 (fromIntegral len) <> "HPKE-v1" <> suite <> label <> info

extractAndExpand
    :: forall h bin
     . (ByteArrayAccess bin, HashAlgorithm h, KDF h)
    => h -> ByteString -> bin -> ByteString -> Key
extractAndExpand h suite dh kem_context = shared_secret
  where
    eae_prk :: PRK h
    eae_prk = labeledExtract suite "" "eae_prk" $ convert dh
    siz = hashDigestSize h
    shared_secret =
        labeledExpand suite eae_prk "shared_secret" kem_context siz
