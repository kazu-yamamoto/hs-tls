{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Network.TLS.Handshake.State
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.State2 where

import Network.TLS.Struct
import Network.TLS.Record.State
import Network.TLS.Crypto
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Handshake.State
import Network.TLS.KeySchedule (hkdfExpandLabel)
import Network.TLS.Context.Internal
import Control.Monad.State
import qualified Data.ByteString as B
import Control.Concurrent.MVar

setTxtate :: Context -> Hash -> Cipher -> B.ByteString -> IO ()
setTxtate = setXState ctxTxState BulkEncrypt

setRxtate :: Context -> Hash -> Cipher -> B.ByteString -> IO ()
setRxtate = setXState ctxRxState BulkDecrypt

setXState :: (Context -> MVar RecordState) -> BulkDirection
          -> Context -> Hash -> Cipher -> B.ByteString
          -> IO ()
setXState func encOrDec ctx h cipher secret =
    modifyMVar_ (func ctx) (\_ -> return rt)
  where
    bulk    = cipherBulk cipher
    keySize = bulkKeySize bulk
    ivSize  = max 8 (bulkIVSize bulk + bulkExplicitIV bulk)
    key = hkdfExpandLabel h secret "key" "" keySize
    iv  = hkdfExpandLabel h secret "iv"  "" ivSize
    cst = CryptState {
        cstKey       = bulkInit bulk encOrDec key
      , cstIV        = iv
      , cstMacSecret = "" -- not used in TLS 1.3
      }
    rt = RecordState {
        stCryptState  = cst
      , stMacState    = MacState { msSequence = 0 }
      , stCipher      = Just cipher
      , stCompression = nullCompression
      }

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

setPendingActions :: Context -> [Bytes -> IO ()] -> IO ()
setPendingActions ctx bss =
    modifyMVar_ (ctxPendingActions ctx) (\_ -> return bss)

popPendingAction :: Context -> IO (Bytes -> IO ())
popPendingAction ctx =
    modifyMVar (ctxPendingActions ctx) (\(bs:bss) -> return (bss,bs)) -- fixme
