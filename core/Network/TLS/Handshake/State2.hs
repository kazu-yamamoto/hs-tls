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
import Network.TLS.KeySchedule (hkdfExtract, deriveSecret, hkdfExpandLabel)
import Network.TLS.Context.Internal
import Control.Monad.State
import qualified Data.ByteString as B
import Control.Concurrent.MVar

-- | Set master secret and as a side effect generate the key block
-- with all the right parameters, and setup the pending tx/rx state.
setMasterSecret2 :: Context -> Role -> Cipher -> Bytes -> Bytes -> Bytes -> Bytes -> IO ()
setMasterSecret2 ctx cc cipher salt ikm cLabel sLabel = do
    hashValue <- getHandshakeContextHash ctx
    let (tx,rx,secret) = calculateKey hashValue
    modifyMVar_ (ctxTxState ctx) (\_ -> return tx)
    modifyMVar_ (ctxRxState ctx) (\_ -> return rx)
    usingHState ctx $ modify $ \hst -> hst { hstMasterSecret = Just secret }
    return ()
  where
    calculateKey hashValue = (tx,rx,secret)
      where
        bulk         = cipherBulk cipher
        keySize      = bulkKeySize bulk
        ivSize       = max 8 (bulkIVSize bulk + bulkExplicitIV bulk)
        secret       = hkdfExtract h salt ikm
        h            = cipherHash cipher
        cSecret      = deriveSecret h secret cLabel hashValue
        sSecret      = deriveSecret h secret sLabel hashValue
        cWriteKey    = hkdfExpandLabel h cSecret "key" "" keySize
        sWriteKey    = hkdfExpandLabel h sSecret "key" "" keySize
        cWriteIV     = hkdfExpandLabel h cSecret "iv"  "" ivSize
        sWriteIV     = hkdfExpandLabel h sSecret "iv"  "" ivSize
        cstClient = CryptState { cstKey        = bulkInit bulk (BulkEncrypt `orOnServer` BulkDecrypt) cWriteKey
                               , cstIV         = cWriteIV
                               , cstMacSecret  = cSecret } -- fixme: dirty hack
        cstServer = CryptState { cstKey        = bulkInit bulk (BulkDecrypt `orOnServer` BulkEncrypt) sWriteKey
                               , cstIV         = sWriteIV
                               , cstMacSecret  = sSecret } -- fixme: dirty hack
        msClient = MacState { msSequence = 0 }
        msServer = MacState { msSequence = 0 }

        tx = RecordState
          { stCryptState  = if cc == ClientRole then cstClient else cstServer
          , stMacState    = if cc == ClientRole then msClient  else msServer
          , stCipher      = Just cipher
          , stCompression = nullCompression
          }
        rx = RecordState
          { stCryptState  = if cc == ClientRole then cstServer else cstClient
          , stMacState    = if cc == ClientRole then msServer  else msClient
          , stCipher      = Just cipher
          , stCompression = nullCompression
          }

        orOnServer f g = if cc == ClientRole then f else g

makeEarlySecret :: Hash -> B.ByteString -> B.ByteString
makeEarlySecret h ikm = hkdfExtract h salt ikm
  where
    hsize = hashDigestSize h
    salt = B.replicate hsize 0

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

-- fixme: dirty hack
getBaseKey :: CryptState -> Bytes
getBaseKey = cstMacSecret

getCryptState :: Context -> Bool -> IO CryptState
getCryptState ctx isServer
 | isServer  = stCryptState <$> readMVar (ctxTxState ctx)
 | otherwise = stCryptState <$> readMVar (ctxRxState ctx)

getHandshakeContextHash :: Context -> IO B.ByteString
getHandshakeContextHash ctx = do
    Just hst <- getHState ctx -- fixme
    case hstHandshakeDigest hst of
      Right hashCtx -> return $ hashFinal hashCtx
      Left _        -> error "un-initialized handshake digest"
