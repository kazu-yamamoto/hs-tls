{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Network.TLS.Record.Disengage
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Disengage a record from the Record layer.
-- The record is decrypted, checked for integrity and then decompressed.
--
{-# LANGUAGE FlexibleContexts #-}

module Network.TLS.Record.Disengage2
        ( disengageRecord2
        ) where

import Control.Monad.State

import Data.Bits
import Network.TLS.Imports
import Crypto.Cipher.Types (AuthTag(..))
import Network.TLS.Struct
import Network.TLS.Struct2
import Network.TLS.ErrT
import Network.TLS.Record.State
import Network.TLS.Record.Types2
import Network.TLS.Cipher
import Network.TLS.Util
import Network.TLS.Wire
import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert)

disengageRecord2 :: Record2 -> RecordM Record2
disengageRecord2 record@(Record2 ContentType_AppData e) = do
    st <- get
    case stCipher st of
        Nothing -> return record
        _       -> do
            inner <- decryptData e st
            let (dc,_pad) = B.spanEnd (== 0) inner
                Just (d,c) = B.unsnoc dc
                Just ct = valToType c
            return $ Record2 ct d
disengageRecord2 record = return record

decryptData :: Bytes -> RecordState -> RecordM Bytes
decryptData econtent tst = decryptOf (cstKey cst)
  where cipher     = fromJust "cipher" $ stCipher tst
        bulk       = cipherBulk cipher
        cst        = stCryptState tst
        econtentLen = B.length econtent

        decryptOf :: BulkState -> RecordM Bytes
        decryptOf (BulkStateAEAD decryptF) = do
            let authTagLen  = bulkAuthTagLen bulk
                cipherLen   = econtentLen - authTagLen

            (econtent', authTag) <- get2 econtent (cipherLen, authTagLen)
            let encodedSeq = encodeWord64 $ msSequence $ stMacState tst
                iv = cstIV cst
                ivlen = B.length iv
                sqnc = B.pack (replicate (ivlen - 8) 0) `B.append` encodedSeq
                nonce = B.pack $ B.zipWith xor iv sqnc
                (content, authTag2) = decryptF nonce econtent' ""

            when (AuthTag (B.convert authTag) /= authTag2) $
                throwError $ Error_Protocol ("bad record mac", True, BadRecordMac)
            modify incrRecordState
            return content

        decryptOf _ =
            throwError $ Error_Protocol ("decrypt state uninitialized", True, InternalError)

        get3 s ls = maybe (throwError $ Error_Packet "record bad format") return $ partition3 s ls
        get2 s (d1,d2) = get3 s (d1,d2,0) >>= \(r1,r2,_) -> return (r1,r2)
