{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Run (
    runTLS,
    runTLSSimple,
    runTLSPredicate,
    runTLSSimple13,
    runTLS0RTT,
    runTLSSimpleKeyUpdate,
    runTLSCapture13,
    runTLSSuccess,
    runTLSFailure,
) where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Default.Class
import Data.IORef
import Network.TLS
import System.Timeout
import Test.Hspec
import Test.QuickCheck

import API
import Arbitrary
import PipeChan

type ClinetWithInput = Chan ByteString -> Context -> IO ()
type ServerWithOutput = Context -> Chan [ByteString] -> IO ()

----------------------------------------------------------------

runTLS
    :: (ClientParams, ServerParams)
    -> ClinetWithInput
    -> ServerWithOutput
    -> IO ()
runTLS = runTLSN 1

runTLSN
    :: Int
    -> (ClientParams, ServerParams)
    -> ClinetWithInput
    -> ServerWithOutput
    -> IO ()
runTLSN n params tlsClient tlsServer = do
    inputChan <- newChan
    outputChan <- newChan
    -- generate some data to send
    ds <- replicateM n $ B.pack <$> generate (someWords8 256)
    forM_ ds $ writeChan inputChan
    -- run client and server
    withPairContext params $ \(cCtx, sCtx) ->
        concurrently_ (server sCtx outputChan) (client inputChan cCtx)
    -- read result
    m_dsres <- timeout 1000000 $ readChan outputChan -- 60 sec
    case m_dsres of
        Nothing -> expectationFailure "timed out"
        Just dsres -> dsres `shouldBe` ds
  where
    server sCtx outputChan =
        E.catch
            (tlsServer sCtx outputChan)
            (printAndRaise "server" (serverSupported $ snd params))
    client inputChan cCtx =
        E.catch
            (tlsClient inputChan cCtx)
            (printAndRaise "client" (clientSupported $ fst params))
    printAndRaise :: String -> Supported -> E.SomeException -> IO ()
    printAndRaise s supported e = do
        putStrLn $
            s
                ++ " exception: "
                ++ show e
                ++ ", supported: "
                ++ show supported
        E.throwIO e

----------------------------------------------------------------

runTLSSimple :: (ClientParams, ServerParams) -> IO ()
runTLSSimple params = runTLSPredicate params (const True)

runTLSPredicate
    :: (ClientParams, ServerParams) -> (Maybe Information -> Bool) -> IO ()
runTLSPredicate params p = runTLSSuccess params hsClient hsServer
  where
    hsClient ctx = do
        handshake ctx
        checkInfoPredicate ctx
    hsServer ctx = do
        handshake ctx
        checkInfoPredicate ctx
    checkInfoPredicate ctx = do
        minfo <- contextGetInformation ctx
        unless (p minfo) $
            fail ("unexpected information: " ++ show minfo)

----------------------------------------------------------------

runTLSSimple13
    :: (ClientParams, ServerParams)
    -> HandshakeMode13
    -> IO ()
runTLSSimple13 params mode =
    runTLSSuccess params hsClient hsServer
  where
    hsClient ctx = do
        handshake ctx
        minfo <- contextGetInformation ctx
        case minfo >>= infoTLS13HandshakeMode of
            Nothing -> expectationFailure "C: mode should be Just"
            Just m -> m `shouldBe` mode
    hsServer ctx = do
        handshake ctx
        minfo <- contextGetInformation ctx
        case minfo >>= infoTLS13HandshakeMode of
            Nothing -> expectationFailure "S: mode should be Just"
            Just m -> m `shouldBe` mode

runTLS0RTT
    :: (ClientParams, ServerParams)
    -> HandshakeMode13
    -> ByteString
    -> IO ()
runTLS0RTT params mode earlyData =
    withPairContext params $ \(cCtx, sCtx) ->
        concurrently_ (tlsServer sCtx) (tlsClient cCtx)
  where
    tlsClient ctx = do
        handshake ctx
        sendData ctx $ L.fromStrict earlyData
        _ <- recvData ctx
        bye ctx
        minfo <- contextGetInformation ctx
        case minfo >>= infoTLS13HandshakeMode of
            Nothing -> expectationFailure "C: mode should be Just"
            Just m -> m `shouldBe` mode
    tlsServer ctx = do
        handshake ctx
        let ls = chunkLengths $ B.length earlyData
        chunks <- replicateM (length ls) $ recvData ctx
        (map B.length chunks, B.concat chunks) `shouldBe` (ls, earlyData)
        sendData ctx $ L.fromStrict earlyData
        bye ctx
        minfo <- contextGetInformation ctx
        case minfo >>= infoTLS13HandshakeMode of
            Nothing -> expectationFailure "S: mode should be Just"
            Just m -> m `shouldBe` mode
    chunkLengths :: Int -> [Int]
    chunkLengths len
        | len > 16384 = 16384 : chunkLengths (len - 16384)
        | len > 0 = [len]
        | otherwise = []

runTLSCapture13
    :: (ClientParams, ServerParams) -> IO ([Handshake13], [Handshake13])
runTLSCapture13 params = do
    sRef <- newIORef []
    cRef <- newIORef []
    runTLSSuccess params (hsClient cRef) (hsServer sRef)
    sReceived <- readIORef sRef
    cReceived <- readIORef cRef
    return (reverse sReceived, reverse cReceived)
  where
    hsClient ref ctx = do
        installHook ctx ref
        handshake ctx
    hsServer ref ctx = do
        installHook ctx ref
        handshake ctx
    installHook ctx ref =
        let recv hss = modifyIORef ref (hss :) >> return hss
         in contextHookSetHandshake13Recv ctx recv

runTLSSimpleKeyUpdate :: (ClientParams, ServerParams) -> IO ()
runTLSSimpleKeyUpdate params = runTLSN 3 params tlsClient tlsServer
  where
    tlsClient queue ctx = do
        handshake ctx
        d0 <- readChan queue
        sendData ctx (L.fromChunks [d0])
        d1 <- readChan queue
        sendData ctx (L.fromChunks [d1])
        req <- generate $ elements [OneWay, TwoWay]
        _ <- updateKey ctx req
        d2 <- readChan queue
        sendData ctx (L.fromChunks [d2])
        checkCtxFinished ctx
        bye ctx
    tlsServer ctx queue = do
        handshake ctx
        d0 <- recvData ctx
        req <- generate $ elements [OneWay, TwoWay]
        _ <- updateKey ctx req
        d1 <- recvData ctx
        d2 <- recvData ctx
        writeChan queue [d0, d1, d2]
        checkCtxFinished ctx
        bye ctx

----------------------------------------------------------------

runTLSSuccess
    :: (ClientParams, ServerParams)
    -> (Context -> IO ())
    -> (Context -> IO ())
    -> IO ()
runTLSSuccess params hsClient hsServer = runTLS params tlsClient tlsServer
  where
    tlsClient queue ctx = do
        hsClient ctx
        d <- readChan queue
        sendData ctx (L.fromChunks [d])
        checkCtxFinished ctx
        bye ctx
    tlsServer ctx queue = do
        hsServer ctx
        d <- recvData ctx
        writeChan queue [d]
        checkCtxFinished ctx
        bye ctx

runTLSFailure
    :: (ClientParams, ServerParams)
    -> (Context -> IO c)
    -> (Context -> IO s)
    -> IO ()
runTLSFailure params hsClient hsServer =
    withPairContext params $ \(cCtx, sCtx) ->
        concurrently_ (tlsServer sCtx) (tlsClient cCtx)
  where
    tlsClient ctx = hsClient ctx `shouldThrow` anyTLSException
    tlsServer ctx = hsServer ctx `shouldThrow` anyTLSException

anyTLSException :: Selector TLSException
anyTLSException = const True

----------------------------------------------------------------

debug :: Bool
debug = False

withPairContext
    :: (ClientParams, ServerParams) -> ((Context, Context) -> IO ()) -> IO ()
withPairContext params body =
    E.bracket
        (newPairContext params)
        (\((t1, t2), _) -> killThread t1 >> killThread t2)
        (\(_, ctxs) -> body ctxs)

newPairContext
    :: (ClientParams, ServerParams)
    -> IO ((ThreadId, ThreadId), (Context, Context))
newPairContext (cParams, sParams) = do
    pipe <- newPipe
    tids <- runPipe pipe
    let noFlush = return ()
    let noClose = return ()

    let cBackend = Backend noFlush noClose (writePipeC pipe) (readPipeC pipe)
    let sBackend = Backend noFlush noClose (writePipeS pipe) (readPipeS pipe)
    cCtx' <- contextNew cBackend cParams
    sCtx' <- contextNew sBackend sParams

    contextHookSetLogging cCtx' (logging "client: ")
    contextHookSetLogging sCtx' (logging "server: ")

    return (tids, (cCtx', sCtx'))
  where
    logging pre =
        if debug
            then
                def
                    { loggingPacketSent = putStrLn . ((pre ++ ">> ") ++)
                    , loggingPacketRecv = putStrLn . ((pre ++ "<< ") ++)
                    }
            else def
