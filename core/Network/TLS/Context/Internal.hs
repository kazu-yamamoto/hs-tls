{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- |
-- Module      : Network.TLS.Context.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
module Network.TLS.Context.Internal (
    -- * Context configuration
    ClientParams (..),
    ServerParams (..),
    defaultParamsClient,
    SessionID,
    SessionData (..),
    MaxFragmentEnum (..),
    Measurement (..),

    -- * Context object and accessor
    Context (..),
    Hooks (..),
    Established (..),
    PendingAction (..),
    RecordLayer(..),
    ctxEOF,
    ctxEstablished,
    withLog,
    ctxWithHooks,
    contextModifyHooks,
    setEOF,
    setEstablished,
    contextFlush,
    contextClose,
    contextSend,
    contextRecv,
    updateRecordLayer,
    updateMeasure,
    withMeasure,
    withReadLock,
    withWriteLock,
    withStateLock,
    withRWLock,

    -- * information
    Information (..),
    contextGetInformation,

    -- * Using context states
    throwCore,
    failOnEitherError,
    usingState,
    usingState_,
    runTxState,
    runRxState,
    usingHState,
    getHState,
    saveHState,
    restoreHState,
    getStateRNG,
    tls13orLater,
    addCertRequest13,
    getCertRequest13,
    decideRecordVersion,

    -- * Misc
    HandshakeSync (..),
) where

import Network.TLS.Backend
import Network.TLS.Cipher
import Network.TLS.Compression (Compression)
import Network.TLS.Extension
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.State
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.Parameters
import Network.TLS.Record
import Network.TLS.Record.State
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Util

import Control.Concurrent.MVar
import Control.Exception (throwIO)
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.IORef
import Data.Tuple

-- | Information related to a running context, e.g. current cipher
data Information = Information
    { infoVersion :: Version
    , infoCipher :: Cipher
    , infoCompression :: Compression
    , infoMasterSecret :: Maybe ByteString
    , infoExtendedMasterSec :: Bool
    , infoClientRandom :: Maybe ClientRandom
    , infoServerRandom :: Maybe ServerRandom
    , infoSupportedGroup :: Maybe Group
    , infoTLS12Resumption :: Bool
    , infoTLS13HandshakeMode :: Maybe HandshakeMode13
    , infoIsEarlyDataAccepted :: Bool
    }
    deriving (Show, Eq)

-- | A TLS Context keep tls specific state, parameters and backend information.
data Context = forall a.
      Monoid a =>
    Context
    { ctxConnection :: Backend
    -- ^ return the backend object associated with this context
    , ctxSupported :: Supported
    , ctxShared :: Shared
    , ctxState :: MVar TLSState
    , ctxMeasurement :: IORef Measurement
    , ctxEOF_ :: IORef Bool
    -- ^ has the handle EOFed or not.
    , ctxEstablished_ :: IORef Established
    -- ^ has the handshake been done and been successful.
    , ctxNeedEmptyPacket :: IORef Bool
    -- ^ empty packet workaround for CBC guessability.
    , ctxFragmentSize :: Maybe Int
    -- ^ maximum size of plaintext fragments
    , ctxTxState :: MVar RecordState
    -- ^ current tx state
    , ctxRxState :: MVar RecordState
    -- ^ current rx state
    , ctxHandshake :: MVar (Maybe HandshakeState)
    -- ^ optional handshake state
    , ctxDoHandshake :: Context -> IO ()
    , ctxDoHandshakeWith :: Context -> Handshake -> IO ()
    , ctxDoRequestCertificate :: Context -> IO Bool
    , ctxDoPostHandshakeAuthWith :: Context -> Handshake13 -> IO ()
    , ctxHooks :: IORef Hooks
    -- ^ hooks for this context
    , ctxLockWrite :: MVar ()
    -- ^ lock to use for writing data (including updating the state)
    , ctxLockRead :: MVar ()
    -- ^ lock to use for reading data (including updating the state)
    , ctxLockState :: MVar ()
    -- ^ lock used during read/write when receiving and sending packet.
    -- it is usually nested in a write or read lock.
    , ctxPendingActions :: IORef [PendingAction]
    , ctxCertRequests :: IORef [Handshake13]
    -- ^ pending PHA requests
    , ctxKeyLogger :: String -> IO ()
    , ctxRecordLayer :: RecordLayer a
    , ctxHandshakeSync :: HandshakeSync
    , ctxQUICMode :: Bool
    , -- For Channel Bindings for TLS, RFC5929
      ctxFinished :: IORef (Maybe VerifyData)
    , ctxPeerFinished :: IORef (Maybe VerifyData)
    }

data HandshakeSync
    = HandshakeSync
        (Context -> ClientState -> IO ())
        (Context -> ServerState -> IO ())

{- FOURMOLU_DISABLE -}
data RecordLayer a = RecordLayer
    { -- Writing.hs
      recordEncode    :: Context -> Record Plaintext -> IO (Either TLSError a)
    , recordEncode13  :: Context -> Record Plaintext -> IO (Either TLSError a)
    , recordSendBytes :: Context -> a -> IO ()
    , -- Reading.hs
      recordRecv      :: Context -> Int -> IO (Either TLSError (Record Plaintext))
    , recordRecv13    :: Context -> IO (Either TLSError (Record Plaintext))
    }
{- FOURMOLU_ENABLE -}

updateRecordLayer :: Monoid a => RecordLayer a -> Context -> Context
updateRecordLayer recordLayer Context{..} =
    Context{ctxRecordLayer = recordLayer, ..}

data Established
    = NotEstablished
    | EarlyDataAllowed Int -- remaining 0-RTT bytes allowed
    | EarlyDataNotAllowed Int -- remaining 0-RTT packets allowed to skip
    | Established
    deriving (Eq, Show)

data PendingAction
    = -- | simple pending action
      PendingAction Bool (Handshake13 -> IO ())
    | -- | pending action taking transcript hash up to preceding message
      PendingActionHash Bool (ByteString -> Handshake13 -> IO ())

updateMeasure :: Context -> (Measurement -> Measurement) -> IO ()
updateMeasure ctx = modifyIORef' (ctxMeasurement ctx)

withMeasure :: Context -> (Measurement -> IO a) -> IO a
withMeasure ctx f = readIORef (ctxMeasurement ctx) >>= f

-- | A shortcut for 'backendFlush . ctxConnection'.
contextFlush :: Context -> IO ()
contextFlush = backendFlush . ctxConnection

-- | A shortcut for 'backendClose . ctxConnection'.
contextClose :: Context -> IO ()
contextClose = backendClose . ctxConnection

-- | Information about the current context
contextGetInformation :: Context -> IO (Maybe Information)
contextGetInformation ctx = do
    ver <- usingState_ ctx $ gets stVersion
    hstate <- getHState ctx
    let (ms, ems, cr, sr, hm13, grp) =
            case hstate of
                Just st ->
                    ( hstMasterSecret st
                    , hstExtendedMasterSec st
                    , Just (hstClientRandom st)
                    , hstServerRandom st
                    , if ver == Just TLS13 then Just (hstTLS13HandshakeMode st) else Nothing
                    , hstSupportedGroup st
                    )
                Nothing -> (Nothing, False, Nothing, Nothing, Nothing, Nothing)
    (cipher, comp) <-
        readMVar (ctxRxState ctx) <&> \st -> (stCipher st, stCompression st)
    let accepted = case hstate of
            Just st -> hstTLS13RTT0Status st == RTT0Accepted
            Nothing -> False
    tls12resumption <- usingState_ ctx isSessionResuming
    case (ver, cipher) of
        (Just v, Just c) ->
            return $
                Just $
                    Information v c comp ms ems cr sr grp tls12resumption hm13 accepted
        _ -> return Nothing

contextSend :: Context -> ByteString -> IO ()
contextSend c b =
    updateMeasure c (addBytesSent $ B.length b) >> (backendSend $ ctxConnection c) b

contextRecv :: Context -> Int -> IO ByteString
contextRecv c sz = updateMeasure c (addBytesReceived sz) >> (backendRecv $ ctxConnection c) sz

ctxEOF :: Context -> IO Bool
ctxEOF ctx = readIORef $ ctxEOF_ ctx

setEOF :: Context -> IO ()
setEOF ctx = writeIORef (ctxEOF_ ctx) True

ctxEstablished :: Context -> IO Established
ctxEstablished ctx = readIORef $ ctxEstablished_ ctx

ctxWithHooks :: Context -> (Hooks -> IO a) -> IO a
ctxWithHooks ctx f = readIORef (ctxHooks ctx) >>= f

contextModifyHooks :: Context -> (Hooks -> Hooks) -> IO ()
contextModifyHooks ctx = modifyIORef (ctxHooks ctx)

setEstablished :: Context -> Established -> IO ()
setEstablished ctx = writeIORef (ctxEstablished_ ctx)

withLog :: Context -> (Logging -> IO ()) -> IO ()
withLog ctx f = ctxWithHooks ctx (f . hookLogging)

throwCore :: MonadIO m => TLSError -> m a
throwCore = liftIO . throwIO . Uncontextualized

failOnEitherError :: MonadIO m => m (Either TLSError a) -> m a
failOnEitherError f = do
    ret <- f
    case ret of
        Left err -> throwCore err
        Right r -> return r

usingState :: Context -> TLSSt a -> IO (Either TLSError a)
usingState ctx f =
    modifyMVar (ctxState ctx) $ \st ->
        let (a, newst) = runTLSState f st
         in newst `seq` return (newst, a)

usingState_ :: Context -> TLSSt a -> IO a
usingState_ ctx f = failOnEitherError $ usingState ctx f

usingHState :: MonadIO m => Context -> HandshakeM a -> m a
usingHState ctx f = liftIO $ modifyMVar (ctxHandshake ctx) $ \mst ->
    case mst of
        Nothing -> liftIO $ throwIO MissingHandshake
        Just st -> return $ swap (Just <$> runHandshake st f)

getHState :: MonadIO m => Context -> m (Maybe HandshakeState)
getHState ctx = liftIO $ readMVar (ctxHandshake ctx)

saveHState :: Context -> IO (Saved (Maybe HandshakeState))
saveHState ctx = saveMVar (ctxHandshake ctx)

restoreHState
    :: Context
    -> Saved (Maybe HandshakeState)
    -> IO (Saved (Maybe HandshakeState))
restoreHState ctx = restoreMVar (ctxHandshake ctx)

decideRecordVersion :: Context -> IO (Version, Bool)
decideRecordVersion ctx = usingState_ ctx $ do
    ver <- getVersionWithDefault (maximum $ supportedVersions $ ctxSupported ctx)
    hrr <- getTLS13HRR
    -- For TLS 1.3, ver' is only used in ClientHello.
    -- The record version of the first ClientHello SHOULD be TLS 1.0.
    -- The record version of the second ClientHello MUST be TLS 1.2.
    let ver'
            | ver >= TLS13 = if hrr then TLS12 else TLS10
            | otherwise = ver
    return (ver', ver >= TLS13)

runTxState :: Context -> RecordM a -> IO (Either TLSError a)
runTxState ctx f = do
    (ver, tls13) <- decideRecordVersion ctx
    let opt =
            RecordOptions
                { recordVersion = ver
                , recordTLS13 = tls13
                }
    modifyMVar (ctxTxState ctx) $ \st ->
        case runRecordM f opt st of
            Left err -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

runRxState :: Context -> RecordM a -> IO (Either TLSError a)
runRxState ctx f = do
    ver <-
        usingState_
            ctx
            (getVersionWithDefault $ maximum $ supportedVersions $ ctxSupported ctx)
    -- For 1.3, ver is just ignored. So, it is not necessary to convert ver.
    let opt =
            RecordOptions
                { recordVersion = ver
                , recordTLS13 = ver >= TLS13
                }
    modifyMVar (ctxRxState ctx) $ \st ->
        case runRecordM f opt st of
            Left err -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

getStateRNG :: Context -> Int -> IO ByteString
getStateRNG ctx n = usingState_ ctx $ genRandom n

withReadLock :: Context -> IO a -> IO a
withReadLock ctx f = withMVar (ctxLockRead ctx) (const f)

withWriteLock :: Context -> IO a -> IO a
withWriteLock ctx f = withMVar (ctxLockWrite ctx) (const f)

withRWLock :: Context -> IO a -> IO a
withRWLock ctx f = withReadLock ctx $ withWriteLock ctx f

withStateLock :: Context -> IO a -> IO a
withStateLock ctx f = withMVar (ctxLockState ctx) (const f)

tls13orLater :: MonadIO m => Context -> m Bool
tls13orLater ctx = do
    ev <- liftIO $ usingState ctx $ getVersionWithDefault TLS12
    return $ case ev of
        Left _ -> False
        Right v -> v >= TLS13

addCertRequest13 :: Context -> Handshake13 -> IO ()
addCertRequest13 ctx certReq = modifyIORef (ctxCertRequests ctx) (certReq :)

getCertRequest13 :: Context -> CertReqContext -> IO (Maybe Handshake13)
getCertRequest13 ctx context = do
    let ref = ctxCertRequests ctx
    l <- readIORef ref
    let (matched, others) = partition (\cr -> context == fromCertRequest13 cr) l
    case matched of
        [] -> return Nothing
        (certReq : _) -> writeIORef ref others >> return (Just certReq)
  where
    fromCertRequest13 (CertRequest13 c _) = c
    fromCertRequest13 _ = error "fromCertRequest13"
