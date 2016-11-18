{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Network.TLS.Record.Engage
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Engage a record into the Record layer.
-- The record is compressed, added some integrity field, then encrypted.
--
{-# LANGUAGE BangPatterns #-}
module Network.TLS.Record.Engage2
        ( engageRecord
        ) where

import Control.Monad.State
import Crypto.Cipher.Types (AuthTag(..))

import Data.Bits (xor)
import Network.TLS.Record.State
import Network.TLS.Record.Types2
import Network.TLS.Cipher
import Network.TLS.Wire
import Network.TLS.Struct (valOfType, Bytes)
import Network.TLS.Struct2
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert)

engageRecord :: Record2 -> RecordM Record2
engageRecord record@(Record2 ct bytes) = do
    st <- get
    case stCipher st of
        Nothing -> return record
        _       -> do
            ebytes <- encryptContent $ innerPlaintext ct bytes
            return $ Record2 ContentType_AppData ebytes

innerPlaintext :: ContentType -> Bytes -> Bytes
innerPlaintext ct bytes = runPut $ do
    putBytes bytes
    putWord8 $ valOfType ct -- non zero!
    -- fixme: zeros padding

encryptContent :: ByteString -> RecordM ByteString
encryptContent content = do
    cst  <- stCryptState <$> get
    case cstKey cst of
        BulkStateBlock _  -> error "encryptContent"
        BulkStateStream _ -> error "encryptContent"
        BulkStateUninitialized -> return content
        BulkStateAEAD encryptF -> do
            encodedSeq <- encodeWord64 <$> getMacSequence
            let iv = cstIV cst
                ivlen = B.length iv
                sqnc = B.pack (replicate (ivlen - 8) 0) `B.append` encodedSeq
                nonce = B.pack $ B.zipWith xor iv sqnc
                (e, AuthTag authtag) = encryptF nonce content ""
                econtent = e `B.append` B.convert authtag
            modify incrRecordState
            return econtent
