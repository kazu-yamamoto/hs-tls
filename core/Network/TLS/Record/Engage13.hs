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
module Network.TLS.Record.Engage13
        ( engageRecord
        ) where

import Control.Monad.State
import Crypto.Cipher.Types (AuthTag(..))

import Network.TLS.Record.State
import Network.TLS.Record.Types13
import Network.TLS.Cipher
import Network.TLS.Wire
import Network.TLS.Struct (valOfType)
import Network.TLS.Struct13
import Network.TLS.Imports
import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert)

engageRecord :: Record13 -> RecordM Record13
engageRecord record@(Record13 ContentType_ChangeCipherSpec _) = return record
engageRecord record@(Record13 ct bytes) = do
    st <- get
    case stCipher st of
        Nothing -> return record
        _       -> do
            ebytes <- encryptContent $ innerPlaintext ct bytes
            return $ Record13 ContentType_AppData ebytes

innerPlaintext :: ContentType -> ByteString -> ByteString
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
