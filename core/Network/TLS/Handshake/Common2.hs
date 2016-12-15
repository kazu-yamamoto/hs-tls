{-# LANGUAGE OverloadedStrings #-}
module Network.TLS.Handshake.Common2 where

import Data.ByteString (ByteString)
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake.State2
import Network.TLS.KeySchedule
import Network.TLS.MAC
import Network.TLS.Struct2

makeFinished :: Context -> Hash -> ByteString -> IO Handshake2
makeFinished ctx usedHash baseKey = do
    transcript <- getHandshakeContextHash ctx
    return $ Finished2 $ makeVerifyData usedHash baseKey transcript

makeVerifyData :: Hash -> ByteString -> ByteString -> ByteString
makeVerifyData usedHash baseKey hashValue = hmac usedHash finishedKey hashValue
  where
    hashSize = hashDigestSize usedHash
    finishedKey = hkdfExpandLabel usedHash baseKey "finished" "" hashSize

