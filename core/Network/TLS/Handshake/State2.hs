{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Network.TLS.Handshake.State
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.State2 where

import Network.TLS.Util
import Network.TLS.Struct
import Network.TLS.Record.State
import Network.TLS.Crypto
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Types
import Network.TLS.Handshake.State
import Network.TLS.KeySchedule (hkdfExtract, deriveSecret, hkdfExpandLabel, fromByteStringToPRKey, fromPRKeytoByteString)
import Control.Monad.State
import qualified Data.ByteString as B

-- | Set master secret and as a side effect generate the key block
-- with all the right parameters, and setup the pending tx/rx state.
setMasterSecret2 :: Role -> Bytes -> Bytes -> Bytes -> Bytes -> HandshakeM ()
setMasterSecret2 role salt ikm cLable sLabel = modify $ \hst ->
    let (pendingTx, pendingRx, secret) = computeKeyBlock2 hst salt ikm cLable sLabel role
     in hst { hstMasterSecret   = Just secret
            , hstPendingTxState = Just pendingTx
            , hstPendingRxState = Just pendingRx }

computeKeyBlock2 :: HandshakeState -> Bytes -> Bytes -> Bytes -> Bytes -> Role -> (RecordState, RecordState, Bytes)
computeKeyBlock2 hst salt ikm cLabel sLabel cc = (pendingTx, pendingRx, secret')
  where cipher       = fromJust "cipher" $ hstPendingCipher hst
        hashValue    = case hstHandshakeDigest hst of
          Right hashCtx -> hashFinal hashCtx
          Left _        -> error "un-initialized handshake digest"
        bulk         = cipherBulk cipher
        keySize      = bulkKeySize bulk
        ivSize       = max 8 (bulkIVSize bulk + bulkExplicitIV bulk)
        secret       = hkdfExtract h salt ikm
        secret'      = fromPRKeytoByteString secret
        h            = cipherHash cipher
        cSecret      = deriveSecret secret cLabel hashValue
        cPRKey       = fromByteStringToPRKey h cSecret
        sSecret      = deriveSecret secret sLabel hashValue
        sPRKey       = fromByteStringToPRKey h sSecret
        cWriteKey    = hkdfExpandLabel cPRKey "key" "" keySize
        sWriteKey    = hkdfExpandLabel sPRKey "key" "" keySize
        cWriteIV     = hkdfExpandLabel cPRKey "iv" "" ivSize
        sWriteIV     = hkdfExpandLabel sPRKey "iv"  "" ivSize
        cstClient = CryptState { cstKey        = bulkInit bulk (BulkEncrypt `orOnServer` BulkDecrypt) cWriteKey
                               , cstIV         = cWriteIV
                               , cstMacSecret  = cSecret } -- fixme: darty hack
        cstServer = CryptState { cstKey        = bulkInit bulk (BulkDecrypt `orOnServer` BulkEncrypt) sWriteKey
                               , cstIV         = sWriteIV
                               , cstMacSecret  = sSecret } -- fixme: darty hack
        msClient = MacState { msSequence = 0 }
        msServer = MacState { msSequence = 0 }

        pendingTx = RecordState
                  { stCryptState  = if cc == ClientRole then cstClient else cstServer
                  , stMacState    = if cc == ClientRole then msClient else msServer
                  , stCipher      = Just cipher
                  , stCompression = hstPendingCompression hst
                  }
        pendingRx = RecordState
                  { stCryptState  = if cc == ClientRole then cstServer else cstClient
                  , stMacState    = if cc == ClientRole then msServer else msClient
                  , stCipher      = Just cipher
                  , stCompression = hstPendingCompression hst
                  }

        orOnServer f g = if cc == ClientRole then f else g

makeEarlySecret :: Cipher -> B.ByteString -> B.ByteString
makeEarlySecret cipher ikm = fromPRKeytoByteString earlySecret
  where
    h = cipherHash cipher
    hsize = hashDigestSize h
    salt = B.replicate hsize 0
    earlySecret = hkdfExtract h salt ikm

setServerHelloParameters2 :: ServerRandom
                          -> Cipher
                          -> HandshakeM ()
setServerHelloParameters2 sran cipher = do
    modify $ \hst -> hst
                { hstServerRandom       = Just sran
                , hstPendingCipher      = Just cipher
                , hstPendingCompression = nullCompression
                , hstHandshakeDigest    = updateDigest $ hstHandshakeDigest hst
                }
  where hashAlg = cipherHash cipher
        updateDigest (Left bytes) = Right $ foldl hashUpdate (hashInit hashAlg) $ reverse bytes
        updateDigest (Right _)    = error "cannot initialize digest with another digest"
