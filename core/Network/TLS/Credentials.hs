-- |
-- Module      : Network.TLS.Credentials
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Credentials
    ( Credential
    , Credentials(..)
    , credentialLoadX509
    , credentialLoadX509FromMemory
    , credentialLoadX509Chain
    , credentialLoadX509ChainFromMemory
    , credentialsFindForSigning
    , credentialsFindForDecrypting
    , credentialsListSigningAlgorithms
    , credentialsFindForTLS13
    ) where

import Data.Function (on)
import Data.Maybe (catMaybes)
import Data.List (find, groupBy)
import Network.TLS.Struct as S
import Network.TLS.X509
import Data.X509.File
import Data.X509.Memory
import Data.X509
import Network.TLS.Extension (SignatureScheme(..))

type Credential = (CertificateChain, PrivKey)

newtype Credentials = Credentials [Credential]

instance Monoid Credentials where
    mempty = Credentials []
    mappend (Credentials l1) (Credentials l2) = Credentials (l1 ++ l2)

-- | try to create a new credential object from a public certificate
-- and the associated private key that are stored on the filesystem
-- in PEM format.
credentialLoadX509 :: FilePath -- ^ public certificate (X.509 format)
                   -> FilePath -- ^ private key associated
                   -> IO (Either String Credential)
credentialLoadX509 certFile = credentialLoadX509Chain certFile []

-- | similar to 'credentialLoadX509' but take the certificate
-- and private key from memory instead of from the filesystem.
credentialLoadX509FromMemory :: Bytes
                  -> Bytes
                  -> Either String Credential
credentialLoadX509FromMemory certData =
  credentialLoadX509ChainFromMemory certData []

-- | similar to 'credentialLoadX509' but also allow specifying chain
-- certificates.
credentialLoadX509Chain ::
                      FilePath   -- ^ public certificate (X.509 format)
                   -> [FilePath] -- ^ chain certificates (X.509 format)
                   -> FilePath   -- ^ private key associated
                   -> IO (Either String Credential)
credentialLoadX509Chain certFile chainFiles privateFile = do
    x509 <- readSignedObject certFile
    chains <- mapM readSignedObject chainFiles
    keys <- readKeyFile privateFile
    case keys of
        []    -> return $ Left "no keys found"
        (k:_) -> return $ Right (CertificateChain . concat $ x509 : chains, k)

-- | similar to 'credentialLoadX509FromMemory' but also allow
-- specifying chain certificates.
credentialLoadX509ChainFromMemory :: Bytes
                  -> [Bytes]
                  -> Bytes
                  -> Either String Credential
credentialLoadX509ChainFromMemory certData chainData privateData = do
    let x509   = readSignedObjectFromMemory certData
        chains = map readSignedObjectFromMemory chainData
        keys   = readKeyFileFromMemory privateData
     in case keys of
            []    -> Left "no keys found"
            (k:_) -> Right (CertificateChain . concat $ x509 : chains, k)

credentialsListSigningAlgorithms :: Credentials -> [SignatureAlgorithm]
credentialsListSigningAlgorithms (Credentials l) = catMaybes $ map credentialCanSign l

credentialsFindForSigning :: SignatureAlgorithm -> Credentials -> Maybe (CertificateChain, PrivKey)
credentialsFindForSigning sigAlg (Credentials l) = find forSigning l
  where forSigning cred = Just sigAlg == credentialCanSign cred

credentialsFindForDecrypting :: Credentials -> Maybe (CertificateChain, PrivKey)
credentialsFindForDecrypting (Credentials l) = find forEncrypting l
  where forEncrypting cred = Just () == credentialCanDecrypt cred

-- here we assume that only RSA is supported for key encipherment (encryption/decryption)
-- we keep the same construction as 'credentialCanSign', returning a Maybe of () in case
-- this change in future.
credentialCanDecrypt :: Credential -> Maybe ()
credentialCanDecrypt (chain, priv) =
    case extensionGet (certExtensions cert) of
        Nothing    -> Just ()
        Just (ExtKeyUsage flags)
            | KeyUsage_keyEncipherment `elem` flags ->
                case (pub, priv) of
                    (PubKeyRSA _, PrivKeyRSA _) -> Just ()
                    _                           -> Nothing
            | otherwise                         -> Nothing
    where cert   = signedObject $ getSigned signed
          pub    = certPubKey cert
          signed = getCertificateChainLeaf chain

credentialCanSign :: Credential -> Maybe SignatureAlgorithm
credentialCanSign (chain, priv) =
    case extensionGet (certExtensions cert) of
        Nothing    -> getSignatureAlg pub priv
        Just (ExtKeyUsage flags)
            | KeyUsage_digitalSignature `elem` flags -> getSignatureAlg pub priv
            | otherwise                              -> Nothing
    where cert   = signedObject $ getSigned signed
          pub    = certPubKey cert
          signed = getCertificateChainLeaf chain

getSignatureAlg :: PubKey -> PrivKey -> Maybe SignatureAlgorithm
getSignatureAlg pub priv =
    case (pub, priv) of
        (PubKeyRSA _, PrivKeyRSA _)     -> Just SignatureRSA
        (PubKeyDSA _, PrivKeyDSA _)     -> Just SignatureDSS
        --(PubKeyECDSA _, PrivKeyECDSA _) -> Just SignatureECDSA
        _                               -> Nothing


data SigAlg = SigAlg_RSApss
            | SigAlg_ECDSA
            | SigAlg_Ed25519
            | SigAlg_Ed448
            deriving (Eq,Show)

splitSignatureScheme :: SignatureScheme -> (SigAlg,HashAlgorithm)
splitSignatureScheme SigScheme_RSApkcs1SHA1    = (SigAlg_RSApss, S.HashSHA1)
splitSignatureScheme SigScheme_RSApkcs1SHA256  = (SigAlg_RSApss, S.HashSHA256)
splitSignatureScheme SigScheme_RSApkcs1SHA384  = (SigAlg_RSApss, S.HashSHA384)
splitSignatureScheme SigScheme_RSApkcs1SHA512  = (SigAlg_RSApss, S.HashSHA512)
splitSignatureScheme SigScheme_ECDSAp256SHA256 = (SigAlg_ECDSA,  S.HashSHA256)
splitSignatureScheme SigScheme_ECDSAp384SHA384 = (SigAlg_ECDSA,  S.HashSHA384)
splitSignatureScheme SigScheme_ECDSAp512SHA512 = (SigAlg_ECDSA,  S.HashSHA512)
splitSignatureScheme SigScheme_RSApssSHA256    = (SigAlg_RSApss, S.HashSHA256)
splitSignatureScheme SigScheme_RSApssSHA384    = (SigAlg_RSApss, S.HashSHA384)
splitSignatureScheme SigScheme_RSApssSHA512    = (SigAlg_RSApss, S.HashSHA512)
splitSignatureScheme SigScheme_Ed25519         = (SigAlg_Ed25519,S.HashNone)
splitSignatureScheme SigScheme_Ed448           = (SigAlg_Ed448,  S.HashNone)

catToSignatureScheme :: (SigAlg,HashAlgorithm) -> SignatureScheme
catToSignatureScheme (SigAlg_RSApss, S.HashSHA1)   = SigScheme_RSApkcs1SHA1 -- fixme
catToSignatureScheme (SigAlg_RSApss, S.HashSHA256) = SigScheme_RSApssSHA256
catToSignatureScheme (SigAlg_RSApss, S.HashSHA384) = SigScheme_RSApssSHA384
catToSignatureScheme (SigAlg_RSApss, S.HashSHA512) = SigScheme_RSApssSHA512
catToSignatureScheme (SigAlg_ECDSA,  S.HashSHA256) = SigScheme_ECDSAp256SHA256
catToSignatureScheme (SigAlg_ECDSA,  S.HashSHA384) = SigScheme_ECDSAp384SHA384
catToSignatureScheme (SigAlg_ECDSA,  S.HashSHA512) = SigScheme_ECDSAp512SHA512
catToSignatureScheme (SigAlg_Ed25519,S.HashNone)   = SigScheme_Ed25519
catToSignatureScheme (SigAlg_Ed448,  S.HashNone)   = SigScheme_Ed448
catToSignatureScheme _                             = error "catToSignatureScheme"

credentialsFindForTLS13 :: [SignatureScheme]
                        -> Credentials
                        -> Maybe (Credential,SignatureScheme)
credentialsFindForTLS13 sss (Credentials creds) = go shs
  where
    shs = map head $ groupBy ((==) `on` fst) $ map splitSignatureScheme sss
    go []     = Nothing
    go (sh@(s,_):shs') = case find (match s) creds of
      Nothing   -> go shs'
      Just cred -> Just (cred, catToSignatureScheme sh)
    -- fixme: this is incomplete due to EC
    match SigAlg_RSApss (_, PrivKeyRSA _) = True
    match _             _                 = False
