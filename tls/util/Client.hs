{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Client (
    Aux (..),
    Cli,
    clientHTTP11,
    clientDNS,
) where

import qualified Data.ByteString.Lazy.Char8 as CL8
import Network.Socket
import Network.TLS

import Imports

data Aux = Aux
    { auxAuthority :: HostName
    , auxPort :: ServiceName
    , auxDebug :: String -> IO ()
    , auxShow :: ByteString -> IO ()
    , auxReadResumptionData :: IO [(SessionID, SessionData)]
    }

type Cli = Aux -> [ByteString] -> Context -> IO ()

clientHTTP11 :: Cli
clientHTTP11 aux@Aux{..} paths ctx = do
    sendData ctx $
        "GET "
            <> CL8.fromStrict (head paths)
            <> " HTTP/1.1\r\n"
            <> "Host: "
            <> CL8.pack auxAuthority
            <> "\r\n"
            <> "Connection: close\r\n"
            <> "\r\n"
    consume ctx aux

clientDNS aux paths ctx = do
    sendData
        ctx
        "\x00\x2c\xdc\xe3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x03\x77\x77\x77\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"
    consume ctx aux

consume :: Context -> Aux -> IO ()
consume ctx Aux{..} = loop
  where
    loop = do
        bs <- recvData ctx
        if bs == ""
            then auxShow "\n"
            else auxShow bs >> loop
