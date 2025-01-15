{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Crypto.PubKey.DH
import Data.IORef
import qualified Data.Map.Strict as M
import Data.X509.CertificateStore
import Network.Run.TCP
import Network.TLS
import Network.TLS.ECH.Config
import Network.TLS.Internal
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit
import System.IO
import System.X509

import Common
import Imports
import Server

data Options = Options
    { optDebugLog :: Bool
    , optClientAuth :: Bool
    , optShow :: Bool
    , optKeyLogFile :: Maybe FilePath
    , optTrustedAnchor :: Maybe FilePath
    , optGroups :: [Group]
    , optCertFile :: FilePath
    , optKeyFile :: FilePath
    , optECHConfigFile :: Maybe FilePath
    , optECHKeyFile :: Maybe FilePath
    , optTraceKey :: Bool
    }
    deriving (Show)

defaultOptions :: Options
defaultOptions =
    Options
        { optDebugLog = False
        , optClientAuth = False
        , optShow = False
        , optKeyLogFile = Nothing
        , optTrustedAnchor = Nothing
        , -- excluding FFDHE8192 for retry
          optGroups = FFDHE8192 `delete` supportedGroups defaultSupported
        , optCertFile = "servercert.pem"
        , optKeyFile = "serverkey.pem"
        , optECHConfigFile = Nothing
        , optECHKeyFile = Nothing
        , optTraceKey = False
        }

options :: [OptDescr (Options -> Options)]
options =
    [ Option
        ['a']
        ["client-auth"]
        (NoArg (\o -> o{optClientAuth = True}))
        "require client authentication"
    , Option
        ['d']
        ["debug"]
        (NoArg (\o -> o{optDebugLog = True}))
        "print debug info"
    , Option
        ['v']
        ["show-content"]
        (NoArg (\o -> o{optShow = True}))
        "print downloaded content"
    , Option
        ['l']
        ["key-log-file"]
        (ReqArg (\file o -> o{optKeyLogFile = Just file}) "<file>")
        "a file to store negotiated secrets"
    , Option
        ['g']
        ["groups"]
        (ReqArg (\gs o -> o{optGroups = readGroups gs}) "<groups>")
        "groups for key exchange"
    , Option
        ['c']
        ["cert"]
        (ReqArg (\fl o -> o{optCertFile = fl}) "<file>")
        "certificate file"
    , Option
        ['k']
        ["key"]
        (ReqArg (\fl o -> o{optKeyFile = fl}) "<file>")
        "key file"
    , Option
        ['t']
        ["trusted-anchor"]
        (ReqArg (\fl o -> o{optTrustedAnchor = Just fl}) "<file>")
        "trusted anchor file"
    , Option
        []
        ["ech-config"]
        (ReqArg (\fl o -> o{optECHConfigFile = Just fl}) "<file>")
        "ECH config file"
    , Option
        []
        ["ech-key"]
        (ReqArg (\fl o -> o{optECHKeyFile = Just fl}) "<file>")
        "ECH key file"
    , Option
        []
        ["trace-key"]
        (NoArg (\o -> o{optTraceKey = True}))
        "Trace transcript hash"
    ]

usage :: String
usage = "Usage: tls-server [OPTION] addr port"

showUsageAndExit :: String -> IO a
showUsageAndExit msg = do
    putStrLn msg
    putStrLn $ usageInfo usage options
    exitFailure

serverOpts :: [String] -> IO (Options, [String])
serverOpts argv =
    case getOpt Permute options argv of
        (o, n, []) -> return (foldl (flip id) defaultOptions o, n)
        (_, _, errs) -> showUsageAndExit $ concat errs

main :: IO ()
main = do
    hSetBuffering stdout NoBuffering
    args <- getArgs
    (Options{..}, ips) <- serverOpts args
    (host, port) <- case ips of
        [h, p] -> return (h, p)
        _ -> showUsageAndExit "cannot recognize <addr> and <port>\n"
    when (null optGroups) $ do
        putStrLn "Error: unsupported groups"
        exitFailure
    smgr <- newSessionManager
    Right cred@(!_cc, !_priv) <- credentialLoadX509 optCertFile optKeyFile
    mstore <- do
        mstore' <- case optTrustedAnchor of
            Nothing -> Just <$> getSystemCertificateStore
            Just file -> readCertificateStore file
        when (isNothing mstore') $ showUsageAndExit "cannot set trusted anchor"
        return mstore'
    ech <- case optECHKeyFile of
        Nothing -> case optECHConfigFile of
            Nothing -> return ([], [])
            Just _ -> showUsageAndExit "must specify ECH key file, too"
        Just ekeyf -> case optECHConfigFile of
            Nothing -> showUsageAndExit "must specify ECH config file, too"
            Just ecnff -> do
                ekey <- loadECHSecretKeys [ekeyf]
                ecnf <- loadECHConfigList ecnff
                return (ekey, ecnf)
    let keyLog = getLogger optKeyLogFile
        printError
            | optDebugLog = putStrLn
            | otherwise = \_ -> return ()
        traceKey
            | optTraceKey = putStrLn
            | otherwise = \_ -> return ()
        creds = Credentials [cred]
    makeCipherShowPretty
    runTCPServer (Just host) port $ \sock -> do
        let sparams =
                getServerParams
                    creds
                    optGroups
                    smgr
                    keyLog
                    optClientAuth
                    mstore
                    ech
                    printError
                    traceKey
        ctx <- contextNew sock sparams
        when optDebugLog $
            contextHookSetLogging
                ctx
                defaultLogging
                    { loggingPacketSent = putStrLn . ("<< " ++)
                    , loggingPacketRecv = putStrLn . (">> " ++)
                    --                    , loggingIOSent = \bs -> putStrLn $ "{{ " ++ showBytesHex bs
                    --                    , loggingIORecv = \hd bs -> putStrLn $ "}} " ++ show hd ++ " " ++ showBytesHex bs
                    }
        when (optDebugLog || optShow) $ putStrLn "------------------------"
        handshake ctx
        when optDebugLog $
            getInfo ctx >>= printHandshakeInfo
        server ctx optShow
        bye ctx

getServerParams
    :: Credentials
    -> [Group]
    -> SessionManager
    -> (String -> IO ())
    -> Bool
    -> Maybe CertificateStore
    -> ([(Word8, ByteString)], ECHConfigList)
    -> (String -> IO ())
    -> (String -> IO ())
    -> ServerParams
getServerParams creds groups sm keyLog clientAuth mstore (ekey, ecnf) printError traceKey =
    defaultParamsServer
        { serverSupported = supported
        , serverShared = shared
        , serverHooks = hooks
        , serverDebug = debug
        , serverEarlyDataSize = 2048
        , serverWantClientCert = clientAuth
        , serverECHKey = ekey
        , serverDHEParams -- ffdhe2048
          =
            Just $
                Params
                    { params_p =
                        0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF
                    , params_g = 2
                    , params_bits = 2048
                    }
        }
  where
    shared =
        defaultShared
            { sharedCredentials = creds
            , sharedSessionManager = sm
            , sharedCAStore = case mstore of
                Just store -> store
                Nothing -> sharedCAStore defaultShared
            , sharedECHConfigList = ecnf
            , sharedLimit =
                defaultLimit
                    { limitRecordSize = Just 16384
                    }
            }
    supported =
        defaultSupported
            { supportedGroups = groups
            , supportedExtendedMainSecret = AllowEMS
            , supportedClientInitiatedRenegotiation = True
            }
    hooks =
        defaultServerHooks
            { onALPNClientSuggest = Just chooseALPN
            , onClientCertificate = case mstore of
                Nothing -> onClientCertificate defaultServerHooks
                Just _ -> checkCertificate
            }
    debug =
        defaultDebugParams
            { debugKeyLogger = keyLog
            , debugError = printError
            , debugTraceKey = traceKey
            }
    checkCertificate cc
        | isNullCertificateChain cc = return CertificateUsageAccept
        | otherwise =
            validateClientCertificate
                (sharedCAStore shared)
                (sharedValidationCache shared)
                cc

chooseALPN :: [ByteString] -> IO ByteString
chooseALPN protos
    | "http/1.1" `elem` protos = return "http/1.1"
    | otherwise = return ""

newSessionManager :: IO SessionManager
newSessionManager = do
    ref <- newIORef M.empty
    return $
        noSessionManager
            { sessionResume = \key -> do
                M.lookup key <$> readIORef ref
            , sessionResumeOnlyOnce = \key -> do
                M.lookup key <$> readIORef ref
            , sessionEstablish = \key val -> do
                atomicModifyIORef' ref $ \m -> (M.insert key val m, Nothing)
            , sessionInvalidate = \key -> do
                atomicModifyIORef' ref $ \m -> (M.delete key m, ())
            , sessionUseTicket = False
            }
