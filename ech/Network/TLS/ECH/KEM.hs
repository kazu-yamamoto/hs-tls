{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.ECH.KEM where

import Crypto.Cipher.Types (AEAD (..))
import Crypto.Error
import Crypto.Hash.Algorithms (SHA256, SHA384, SHA512)
import qualified Crypto.PubKey.Curve25519 as X25519
import Data.ByteArray
import Data.ByteString
import qualified Data.ByteString.Base16 as B16
import Data.Proxy

import Network.TLS.ECH.HPKE
import Network.TLS.ECH.KDF

extractAndExpand
    :: ByteArrayAccess ba => KEM_ID -> ba -> ByteString -> ByteString
extractAndExpand kem_id dh kem_context = shared_secret
  where
    eae_prk :: PRK SHA256
    eae_prk =
        labeledExtract kem_id "" "eae_prk" $ convert dh
    shared_secret =
        labeledExpand
            kem_id
            eae_prk
            "shared_secret"
            kem_context
            32 -- from Table 2
