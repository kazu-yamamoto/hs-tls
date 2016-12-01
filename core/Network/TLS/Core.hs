{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
-- |
-- Module      : Network.TLS.Core
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Core
    (
    -- * Internal packet sending and receiving
      sendPacket
    , recvPacket

    -- * Initialisation and Termination of context
    , bye
    , handshake

    -- * Next Protocol Negotiation
    , getNegotiatedProtocol

    -- * Server Name Indication
    , getClientSNI

    -- * High level API
    , sendData
    , recvData
    , recvData'
    ) where

import Network.TLS.Context
import Network.TLS.Struct
import Network.TLS.Struct2
import Network.TLS.State (getSession)
import Network.TLS.Parameters
import Network.TLS.IO
import Network.TLS.Session
import Network.TLS.Handshake
import Network.TLS.Handshake.State2
import Network.TLS.Util (catchException)
import qualified Network.TLS.State as S
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Lazy as L
import qualified Control.Exception as E

import Control.Monad.State

-- | notify the context that this side wants to close connection.
-- this is important that it is called before closing the handle, otherwise
-- the session might not be resumable (for version < TLS1.2).
--
-- this doesn't actually close the handle
bye :: MonadIO m => Context -> m ()
bye ctx = do
    tls13 <- tls13orLater ctx
    if tls13 then
        sendPacket2 ctx $ Alert2 [(AlertLevel_Warning, CloseNotify)]
      else
        sendPacket ctx $ Alert [(AlertLevel_Warning, CloseNotify)]

-- | If the Next Protocol Negotiation or ALPN extensions have been used, this will
-- return get the protocol agreed upon.
getNegotiatedProtocol :: MonadIO m => Context -> m (Maybe B.ByteString)
getNegotiatedProtocol ctx = liftIO $ usingState_ ctx S.getNegotiatedProtocol

type HostName = String

-- | If the Server Name Indication extension has been used, return the
-- hostname specified by the client.
getClientSNI :: MonadIO m => Context -> m (Maybe HostName)
getClientSNI ctx = liftIO $ usingState_ ctx S.getClientSNI

-- | sendData sends a bunch of data.
-- It will automatically chunk data to acceptable packet size
sendData :: MonadIO m => Context -> L.ByteString -> m ()
sendData ctx dataToSend = do
    tls13 <- tls13orLater ctx
    let sendP
          | tls13     = sendPacket2 ctx . AppData2
          | otherwise = sendPacket ctx . AppData
    let sendDataChunk d
            | B.length d > 16384 = do
                let (sending, remain) = B.splitAt 16384 d
                sendP sending
                sendDataChunk remain
            | otherwise = sendP d
    liftIO (checkValid ctx) >> mapM_ sendDataChunk (L.toChunks dataToSend)

-- | recvData get data out of Data packet, and automatically renegotiate if
-- a Handshake ClientHello is received
recvData :: MonadIO m => Context -> m B.ByteString
recvData ctx = do
    tls13 <- tls13orLater ctx
    if tls13 then recvData2 ctx else recvData1 ctx

recvData1 :: MonadIO m => Context -> m B.ByteString
recvData1 ctx = liftIO $ do
    checkValid ctx
    E.catchJust safeHandleError_EOF
                doRecv
                (\() -> return B.empty)
  where doRecv = do
            pkt <- withReadLock ctx $ recvPacket ctx
            either (onError terminate) process pkt

        process (Handshake [ch@(ClientHello {})]) =
            withRWLock ctx ((ctxDoHandshakeWith ctx) ctx ch) >> recvData1 ctx
        process (Handshake [hr@HelloRequest]) =
            withRWLock ctx ((ctxDoHandshakeWith ctx) ctx hr) >> recvData1 ctx

        process (Alert [(AlertLevel_Warning, CloseNotify)]) = tryBye ctx >> setEOF ctx >> return B.empty
        process (Alert [(AlertLevel_Fatal, desc)]) = do
            setEOF ctx
            E.throwIO (Terminated True ("received fatal error: " ++ show desc) (Error_Protocol ("remote side fatal error", True, desc)))

        -- when receiving empty appdata, we just retry to get some data.
        process (AppData "") = recvData1 ctx
        process (AppData x)  = return x
        process p            = let reason = "unexpected message " ++ show p in
                               terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

        terminate = terminate' ctx (\x -> sendPacket ctx $ Alert x)

recvData2 :: MonadIO m => Context -> m B.ByteString
recvData2 ctx = liftIO $ do
    checkValid ctx
    E.catchJust safeHandleError_EOF
                doRecv
                (\() -> return B.empty)
  where doRecv = do
            pkt <- withReadLock ctx $ recvPacket2 ctx
            either (onError terminate) process pkt

        process (Alert2 [(_,EndOfEarlyData)]) = do
            alertAction <- popPendingAction ctx
            alertAction "dummy"
            recvData2 ctx
        process (Alert2 [(AlertLevel_Warning, CloseNotify)]) = tryBye ctx >> setEOF ctx >> return B.empty
        process (Alert2 [(AlertLevel_Fatal, desc)]) = do
            setEOF ctx
            E.throwIO (Terminated True ("received fatal error: " ++ show desc) (Error_Protocol ("remote side fatal error", True, desc)))
        process (Handshake2 [ClientHello2 _ _ _ _]) = do
            let reason = "Client hello is not allowed"
            terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        process (Handshake2 [Finished2 verifyData']) = do
            finishedAction <- popPendingAction ctx
            finishedAction verifyData'
            recvData2 ctx
        -- when receiving empty appdata, we just retry to get some data.
        process (AppData2 "") = recvData2 ctx
        process (AppData2 x)  = return x
        process p             = let reason = "unexpected message " ++ show p in
                                terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

        terminate = terminate' ctx (\x -> sendPacket2 ctx $ Alert2 x)

safeHandleError_EOF :: TLSError -> Maybe ()
safeHandleError_EOF Error_EOF = Just ()
safeHandleError_EOF _ = Nothing

-- the other side could have close the connection already, so wrap
-- this in a try and ignore all exceptions
tryBye :: Context -> IO ()
tryBye ctx = catchException (bye ctx) (\_ -> return ())

onError :: (TLSError -> AlertLevel -> AlertDescription -> String -> a) -> TLSError -> a
onError terminate err@(Error_Protocol (reason,fatal,desc)) =
    terminate err (if fatal then AlertLevel_Fatal else AlertLevel_Warning) desc reason
onError terminate err =
    terminate err AlertLevel_Fatal InternalError (show err)

terminate' :: Context -> ([(AlertLevel, AlertDescription)] -> IO ())
           -> TLSError -> AlertLevel -> AlertDescription -> String -> IO a
terminate' ctx send err level desc reason = do
    session <- usingState_ ctx getSession
    case session of
        Session Nothing    -> return ()
        Session (Just sid) -> sessionInvalidate (sharedSessionManager $ ctxShared ctx) sid
    catchException (send [(level, desc)]) (\_ -> return ())
    setEOF ctx
    E.throwIO (Terminated False reason err)


{-# DEPRECATED recvData' "use recvData that returns strict bytestring" #-}
-- | same as recvData but returns a lazy bytestring.
recvData' :: MonadIO m => Context -> m L.ByteString
recvData' ctx = recvData ctx >>= return . L.fromChunks . (:[])
