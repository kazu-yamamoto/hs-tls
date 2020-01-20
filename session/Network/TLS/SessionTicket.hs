{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.SessionTicket (
    Config(..)
  , defaultConfig
  , newSessionTickerManager
  ) where

import Crypto.Token
import Foreign.Storable


import Network.TLS

instance Storable SessionData where
    sizeOf _ = undefined
    alignment _ = 4
    peek = undefined
    poke = undefined

newSessionTickerManager :: Config -> IO SessionManager
newSessionTickerManager conf = do
    mgr <- spawnTokenManager conf
    return $ SessionManager {
        sessionResume         = \sid -> decryptToken mgr sid
      , sessionResumeOnlyOnce = \_ -> return Nothing
      , sessionEstablish      = \_ _ -> return ()
      , sessionInvalidate     = \_ -> return ()
      }
