-- |
-- Module      : Network.TLS.Record.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--

module Network.TLS.Record.Types2 where

import Network.TLS.Struct (Bytes)
import Network.TLS.Struct2
import Network.TLS.Record.Types (Header(..))

-- | Represent a TLS record.
data Record2 = Record2 !ContentType Bytes deriving (Show,Eq)

-- | turn a header and a fragment into a record
rawToRecord2 :: Header -> Bytes -> Record2
rawToRecord2 (Header pt _ _) fragment = Record2 (protoToContent pt) fragment
