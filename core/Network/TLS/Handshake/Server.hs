{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Handshake.Server
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Server
    ( handshakeServer
    , handshakeServerWith
    ) where

import Network.TLS.Parameters
import Network.TLS.Imports
import Network.TLS.Context.Internal
import Network.TLS.Session
import Network.TLS.Struct
import Network.TLS.Struct2
import Network.TLS.Packet2
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Crypto.Types
import Network.TLS.Extension
import Network.TLS.Util (catchException, fromJust)
import Network.TLS.IO
import Network.TLS.Types
import Network.TLS.State hiding (getNegotiatedProtocol)
import Network.TLS.Handshake.State
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Key
import Network.TLS.Measurement
import Data.Maybe (isJust, listToMaybe, mapMaybe)
import Data.List (intersect, sortOn, find, (\\))
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()
import Data.Ord (Down(..))

import Control.Monad.State

import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Certificate
import Network.TLS.X509

import qualified Data.ByteArray as BA

import Network.TLS.Handshake.State2
import Network.TLS.Wire
import Network.TLS.MAC
import Network.TLS.KeySchedule

import qualified Crypto.Hash.Algorithms as C
import qualified Crypto.PubKey.RSA.PSS as C
import qualified Crypto.PubKey.RSA.PKCS15 as R

import qualified Data.X509 as X

-- Put the server context in handshake mode.
--
-- Expect to receive as first packet a client hello handshake message
--
-- This is just a helper to pop the next message from the recv layer,
-- and call handshakeServerWith.
handshakeServer :: MonadIO m => ServerParams -> Context -> m ()
handshakeServer sparams ctx = liftIO $ do
    hss <- recvPacketHandshake ctx
    case hss of
        [ch] -> handshakeServerWith sparams ctx ch
        _    -> fail ("unexpected handshake received, excepting client hello and received " ++ show hss)

-- | Put the server context in handshake mode.
--
-- Expect a client hello message as parameter.
-- This is useful when the client hello has been already poped from the recv layer to inspect the packet.
--
-- When the function returns, a new handshake has been succesfully negociated.
-- On any error, a HandshakeFailed exception is raised.
--
-- handshake protocol (<- receiving, -> sending, [] optional):
--    (no session)           (session resumption)
--      <- client hello       <- client hello
--      -> server hello       -> server hello
--      -> [certificate]
--      -> [server key xchg]
--      -> [cert request]
--      -> hello done
--      <- [certificate]
--      <- client key xchg
--      <- [cert verify]
--      <- change cipher      -> change cipher
--      <- [NPN]
--      <- finish             -> finish
--      -> change cipher      <- change cipher
--      -> finish             <- finish
--
handshakeServerWith :: ServerParams -> Context -> Handshake -> IO ()
handshakeServerWith sparams ctx clientHello@(ClientHello clientVersion _ clientSession ciphers compressions exts _) = do
    -- rejecting client initiated renegotiation to prevent DOS.
    unless (supportedClientInitiatedRenegotiation (ctxSupported ctx)) $ do
        established <- ctxEstablished ctx
        eof <- ctxEOF ctx
        when (established == Established && not eof) $
            throwCore $ Error_Protocol ("renegotiation is not allowed", False, NoRenegotiation)
    -- check if policy allow this new handshake to happens
    handshakeAuthorized <- withMeasure ctx (onNewHandshake $ serverHooks sparams)
    unless handshakeAuthorized (throwCore $ Error_HandshakePolicy "server: handshake denied")
    updateMeasure ctx incrementNbHandshakes

    -- Handle Client hello
    processHandshake ctx clientHello

    -- rejecting SSL2. RFC 6176
    when (clientVersion == SSL2) $ throwCore $ Error_Protocol ("SSL 2.0 is not supported", True, ProtocolVersion)
    -- rejecting SSL3. RFC 7568
    -- when (clientVersion == SSL3) $ throwCore $ Error_Protocol ("SSL 3.0 is not supported", True, ProtocolVersion)

    -- Fallback SCSV: RFC7507
    -- TLS_FALLBACK_SCSV: {0x56, 0x00}
    when (supportedFallbackScsv (ctxSupported ctx) &&
          (0x5600 `elem` ciphers) &&
          clientVersion /= maxBound) $
        throwCore $ Error_Protocol ("fallback is not allowed", True, InappropriateFallback)

    -- choosing TLS version
    let clientVersions = case extensionLookup extensionID_SupportedVersions exts >>= extensionDecode MsgTClinetHello of
            Just (SupportedVersions vers) -> vers
            _                             -> []
        serverVersions = supportedVersions $ ctxSupported ctx
        mver
          | clientVersion == TLS12 && clientVersions /= [] =
                findHighestVersionFrom13 clientVersions serverVersions
          | otherwise = findHighestVersionFrom clientVersion serverVersions

    chosenVersion <- case mver of
                        Nothing -> throwCore $ Error_Protocol ("client version " ++ show clientVersion ++ " is not supported", True, ProtocolVersion)
                        Just v  -> return v

    -- If compression is null, commonCompressions should be [0].
    when (null commonCompressions) $ throwCore $
        Error_Protocol ("no compression in common with the client", True, HandshakeFailure)

    -- SNI (Server Name Indication)
    let serverName = case extensionLookup extensionID_ServerName exts >>= extensionDecode MsgTClinetHello of
            Just (ServerName ns) -> listToMaybe (mapMaybe toHostName ns)
                where toHostName (ServerNameHostName hostName) = Just hostName
                      toHostName (ServerNameOther _)           = Nothing
            _                           -> Nothing
    maybe (return ()) (usingState_ ctx . setClientSNI) serverName

    -- ALPN (Application Layer Protocol Negotiation)
    case extensionLookup extensionID_ApplicationLayerProtocolNegotiation exts >>= extensionDecode MsgTClinetHello of
        Just (ApplicationLayerProtocolNegotiation protos) -> usingState_ ctx $ setClientALPNSuggest protos
        _ -> return ()

    -- choosing cipher suite
    extraCreds <- (onServerNameIndication $ serverHooks sparams) serverName

    let ciphersFilteredVersion = filter (cipherAllowedForVersion chosenVersion) (commonCiphers extraCreds)
        usedCipher = (onCipherChoosing $ serverHooks sparams) chosenVersion ciphersFilteredVersion
        creds = extraCreds `mappend` sharedCredentials (ctxShared ctx)

    when (null $ commonCipherIDs extraCreds) $ throwCore $
        Error_Protocol ("no cipher in common with the client", True, HandshakeFailure)

    -- TLS version dependent
    if chosenVersion <= TLS12 then do
        -- TLS 1.0, 1.1 and 1.2
        cred <- case cipherKeyExchange usedCipher of
                    CipherKeyExchange_RSA     -> return $ credentialsFindForDecrypting creds
                    CipherKeyExchange_DH_Anon -> return Nothing
                    CipherKeyExchange_DHE_RSA -> return $ credentialsFindForSigning SignatureRSA creds
                    CipherKeyExchange_DHE_DSS -> return $ credentialsFindForSigning SignatureDSS creds
                    CipherKeyExchange_ECDHE_RSA -> return $ credentialsFindForSigning SignatureRSA creds
                    _                         -> throwCore $ Error_Protocol ("key exchange algorithm not implemented", True, HandshakeFailure)

        resumeSessionData <- case clientSession of
                (Session (Just clientSessionId)) -> liftIO $ sessionResume (sharedSessionManager $ ctxShared ctx) clientSessionId
                (Session Nothing)                -> return Nothing

        case extensionLookup extensionID_Groups exts >>= extensionDecode MsgTClinetHello of
            Just (SupportedGroups es) -> usingState_ ctx $ setClientGroupSuggest es
            _ -> return ()

        -- Currently, we don't send back EcPointFormats. In this case,
        -- the client chooses EcPointFormat_Uncompressed.
        case extensionLookup extensionID_EcPointFormats exts >>= extensionDecode MsgTClinetHello of
            Just (EcPointFormatsSupported fs) -> usingState_ ctx $ setClientEcPointFormatSuggest fs
            _ -> return ()

        doHandshake sparams cred ctx chosenVersion usedCipher usedCompression clientSession resumeSessionData exts

      else do
        -- TLS 1.3 or later
        -- Deciding key exchange from key shares
        keyShares <- case extensionLookup extensionID_KeyShare exts >>= extensionDecode MsgTClinetHello of
              Just (KeyShareClientHello kses) -> return kses
              _                               -> throwCore $ Error_Protocol ("key exchange not implemented", True, HandshakeFailure)
        let serverGroups = supportedGroups $ ctxSupported ctx
        case findKeyShare keyShares (supportedGroups $ ctxSupported ctx) of
          Nothing -> helloRetryRequest sparams ctx chosenVersion keyShares serverGroups
          Just keyShare -> do
            -- Deciding signature algorithm
            let sigAlgos = case extensionLookup extensionID_SignatureAlgorithms exts >>= extensionDecode MsgTClinetHello of
                  Just (SignatureSchemes hss) -> hss
                  _                           -> []
            (cred, sigAlgo) <- case credentialsFindForTLS13 sigAlgos creds of
              Nothing -> throwCore $ Error_Protocol ("signature algorithm not implemented", True, HandshakeFailure)
              Just c  -> return c
            let usedHash = cipherHash usedCipher
            doHandshake2 sparams cred ctx chosenVersion usedCipher usedHash keyShare sigAlgo exts
  where
        commonCipherIDs extra = ciphers `intersect` map cipherID (ctxCiphers ctx extra)
        commonCiphers   extra = filter (flip elem (commonCipherIDs extra) . cipherID) (ctxCiphers ctx extra)
        commonCompressions    = compressionIntersectID (supportedCompressions $ ctxSupported ctx) compressions
        usedCompression       = head commonCompressions
        findKeyShare _      [] = Nothing
        findKeyShare ks (n:ns) = case find (\(KeyShareEntry n' _) -> n == n') ks of
          Just k  -> Just k
          Nothing -> findKeyShare ks ns


handshakeServerWith _ _ _ = throwCore $ Error_Protocol ("unexpected handshake message received in handshakeServerWith", True, HandshakeFailure)

doHandshake :: ServerParams -> Maybe Credential -> Context -> Version -> Cipher
            -> Compression -> Session -> Maybe SessionData
            -> [ExtensionRaw] -> IO ()
doHandshake sparams mcred ctx chosenVersion usedCipher usedCompression clientSession resumeSessionData exts = do
    case resumeSessionData of
        Nothing -> do
            handshakeSendServerData
            liftIO $ contextFlush ctx
            -- Receive client info until client Finished.
            recvClientData sparams ctx
            sendChangeCipherAndFinish (return ()) ctx ServerRole
        Just sessionData -> do
            usingState_ ctx (setSession clientSession True)
            serverhello <- makeServerHello clientSession
            sendPacket ctx $ Handshake [serverhello]
            usingHState ctx $ setMasterSecret chosenVersion ServerRole $ sessionSecret sessionData
            sendChangeCipherAndFinish (return ()) ctx ServerRole
            recvChangeCipherAndFinish ctx
    handshakeTerminate ctx
  where
        ---
        -- When the client sends a certificate, check whether
        -- it is acceptable for the application.
        --
        ---
        makeServerHello session = do
            srand <- ServerRandom <$> getStateRNG ctx 32
            case mcred of
                Just (_, privkey) -> usingHState ctx $ setPrivateKey privkey
                _                 -> return () -- return a sensible error

            -- in TLS12, we need to check as well the certificates we are sending if they have in the extension
            -- the necessary bits set.
            secReneg   <- usingState_ ctx getSecureRenegotiation
            secRengExt <- if secReneg
                    then do
                            vf <- usingState_ ctx $ do
                                    cvf <- getVerifiedData ClientRole
                                    svf <- getVerifiedData ServerRole
                                    return $ extensionEncode (SecureRenegotiation cvf $ Just svf)
                            return [ ExtensionRaw 0xff01 vf ]
                    else return []
            protoExt <- applicationProtocol ctx exts sparams
            let extensions = secRengExt ++ protoExt
            usingState_ ctx (setVersion chosenVersion)
            usingHState ctx $ setServerHelloParameters chosenVersion srand usedCipher usedCompression
            return $ ServerHello chosenVersion srand session (cipherID usedCipher)
                                               (compressionID usedCompression) extensions

        handshakeSendServerData = do
            serverSession <- newSession ctx
            usingState_ ctx (setSession serverSession False)
            serverhello   <- makeServerHello serverSession
            -- send ServerHello & Certificate & ServerKeyXchg & CertReq
            let certMsg = case mcred of
                            Just (srvCerts, _) -> Certificates srvCerts
                            _                  -> Certificates $ CertificateChain []
            sendPacket ctx $ Handshake [ serverhello, certMsg ]

            -- send server key exchange if needed
            skx <- case cipherKeyExchange usedCipher of
                        CipherKeyExchange_DH_Anon -> Just <$> generateSKX_DH_Anon
                        CipherKeyExchange_DHE_RSA -> Just <$> generateSKX_DHE SignatureRSA
                        CipherKeyExchange_DHE_DSS -> Just <$> generateSKX_DHE SignatureDSS
                        CipherKeyExchange_ECDHE_RSA -> Just <$> generateSKX_ECDHE SignatureRSA
                        _                         -> return Nothing
            maybe (return ()) (sendPacket ctx . Handshake . (:[]) . ServerKeyXchg) skx

            -- FIXME we don't do this on a Anonymous server

            -- When configured, send a certificate request
            -- with the DNs of all confgure CA
            -- certificates.
            --
            when (serverWantClientCert sparams) $ do
                usedVersion <- usingState_ ctx getVersion
                let certTypes = [ CertificateType_RSA_Sign ]
                    hashSigs = if usedVersion < TLS12
                                   then Nothing
                                   else Just (supportedHashSignatures $ ctxSupported ctx)
                    creq = CertRequest certTypes hashSigs
                               (map extractCAname $ serverCACertificates sparams)
                usingHState ctx $ setCertReqSent True
                sendPacket ctx (Handshake [creq])

            -- Send HelloDone
            sendPacket ctx (Handshake [ServerHelloDone])

        extractCAname :: SignedCertificate -> DistinguishedName
        extractCAname cert = certSubjectDN $ getCertificate cert

        setup_DHE = do
            let dhparams = fromJust "server DHE Params" $ serverDHEParams sparams
            (priv, pub) <- generateDHE ctx dhparams

            let serverParams = serverDHParamsFrom dhparams pub

            usingHState ctx $ setServerDHParams serverParams
            usingHState ctx $ setDHPrivate priv
            return serverParams

        generateSKX_DHE sigAlg = do
            serverParams  <- setup_DHE
            signed <- digitallySignDHParams ctx serverParams sigAlg
            case sigAlg of
                SignatureRSA -> return $ SKX_DHE_RSA serverParams signed
                SignatureDSS -> return $ SKX_DHE_DSS serverParams signed
                _            -> throwCore $ Error_Protocol ("unknown signature scheme", True, HandshakeFailure)

        generateSKX_DH_Anon = SKX_DH_Anon <$> setup_DHE

        setup_ECDHE grp = do
            (priv, pub) <- ecdhGenerateKeyPair grp
            let serverParams = ServerECDHParams pub
            usingHState ctx $ setServerECDHParams serverParams
            usingHState ctx $ setECDHPrivate priv
            return serverParams

        generateSKX_ECDHE sigAlg = do
            grps <- usingState_ ctx getClientGroupSuggest
            let common = supportedGroups (ctxSupported ctx) `intersect` availableEllipticGroups `intersect` fromJust "ClientEllipticCurveSuggest" grps
            grp <- case common of
                []  -> throwCore $ Error_Protocol ("no common elliptic curves", True, HandshakeFailure)
                x:_ -> return x
            serverParams <- setup_ECDHE grp
            signed       <- digitallySignECDHParams ctx serverParams sigAlg
            case sigAlg of
                SignatureRSA -> return $ SKX_ECDHE_RSA serverParams signed
                _            -> throwCore $ Error_Protocol ("unknown signature scheme", True, HandshakeFailure)

        -- create a DigitallySigned objects for DHParams or ECDHParams.

-- | receive Client data in handshake until the Finished handshake.
--
--      <- [certificate]
--      <- client key xchg
--      <- [cert verify]
--      <- change cipher
--      <- [NPN]
--      <- finish
--
recvClientData :: ServerParams -> Context -> IO ()
recvClientData sparams ctx = runRecvState ctx (RecvStateHandshake processClientCertificate)
  where processClientCertificate (Certificates certs) = do
            -- run certificate recv hook
            ctxWithHooks ctx (\hooks -> hookRecvCertificates hooks certs)
            -- Call application callback to see whether the
            -- certificate chain is acceptable.
            --
            usage <- liftIO $ catchException (onClientCertificate (serverHooks sparams) certs) rejectOnException
            case usage of
                CertificateUsageAccept        -> return ()
                CertificateUsageReject reason -> certificateRejected reason

            -- Remember cert chain for later use.
            --
            usingHState ctx $ setClientCertChain certs

            -- FIXME: We should check whether the certificate
            -- matches our request and that we support
            -- verifying with that certificate.

            return $ RecvStateHandshake processClientKeyExchange

        processClientCertificate p = processClientKeyExchange p

        -- cannot use RecvStateHandshake, as the next message could be a ChangeCipher,
        -- so we must process any packet, and in case of handshake call processHandshake manually.
        processClientKeyExchange (ClientKeyXchg _) = return $ RecvStateNext processCertificateVerify
        processClientKeyExchange p                 = unexpected (show p) (Just "client key exchange")

        -- Check whether the client correctly signed the handshake.
        -- If not, ask the application on how to proceed.
        --
        processCertificateVerify (Handshake [hs@(CertVerify dsig@(DigitallySigned mbHashSig _))]) = do
            processHandshake ctx hs

            checkValidClientCertChain "change cipher message expected"

            usedVersion <- usingState_ ctx getVersion
            -- Fetch all handshake messages up to now.
            msgs  <- usingHState ctx $ B.concat <$> getHandshakeMessages
            verif <- certificateVerifyCheck ctx usedVersion mbHashSig msgs dsig

            case verif of
                True -> do
                    -- When verification succeeds, commit the
                    -- client certificate chain to the context.
                    --
                    Just certs <- usingHState ctx getClientCertChain
                    usingState_ ctx $ setClientCertificateChain certs
                    return ()

                False -> do
                    -- Either verification failed because of an
                    -- invalid format (with an error message), or
                    -- the signature is wrong.  In either case,
                    -- ask the application if it wants to
                    -- proceed, we will do that.
                    res <- liftIO $ onUnverifiedClientCert (serverHooks sparams)
                    if res
                        then do
                            -- When verification fails, but the
                            -- application callbacks accepts, we
                            -- also commit the client certificate
                            -- chain to the context.
                            Just certs <- usingHState ctx getClientCertChain
                            usingState_ ctx $ setClientCertificateChain certs
                        else throwCore $ Error_Protocol ("verification failed", True, BadCertificate)
            return $ RecvStateNext expectChangeCipher

        processCertificateVerify p = do
            chain <- usingHState ctx getClientCertChain
            case chain of
                Just cc | isNullCertificateChain cc -> return ()
                        | otherwise                 -> throwCore $ Error_Protocol ("cert verify message missing", True, UnexpectedMessage)
                Nothing -> return ()
            expectChangeCipher p

        expectChangeCipher ChangeCipherSpec = do
            npn <- usingState_ ctx getExtensionNPN
            return $ RecvStateHandshake $ if npn then expectNPN else expectFinish
        expectChangeCipher p                = unexpected (show p) (Just "change cipher")

        expectNPN (HsNextProtocolNegotiation _) = return $ RecvStateHandshake expectFinish
        expectNPN p                             = unexpected (show p) (Just "Handshake NextProtocolNegotiation")

        expectFinish (Finished _) = return RecvStateDone
        expectFinish p            = unexpected (show p) (Just "Handshake Finished")

        checkValidClientCertChain msg = do
            chain <- usingHState ctx getClientCertChain
            let throwerror = Error_Protocol (msg , True, UnexpectedMessage)
            case chain of
                Nothing -> throwCore throwerror
                Just cc | isNullCertificateChain cc -> throwCore throwerror
                        | otherwise                 -> return ()

doHandshake2 :: ServerParams -> Credential -> Context -> Version
             -> Cipher -> Hash -> KeyShareEntry -> SignatureScheme
             -> [ExtensionRaw] -> IO ()
doHandshake2 sparams (certChain, privKey) ctx chosenVersion usedCipher usedHash (KeyShareEntry grp bytes) sigAlgo exts = do
    when (isNullCertificateChain certChain) $
        throwCore $ Error_Protocol ("no certification found", True, HandshakeFailure)
    newSession ctx >>= \ss -> usingState_ ctx (setSession ss False)
    srand <- setServerParameter
    (psk, binderInfo) <- choosePSK
    hCh <- getHandshakeContextHash ctx
    let earlySecret = hkdfExtract usedHash zero psk
        clientEarlyTrafficSecret = deriveSecret usedHash earlySecret "client early traffic secret" hCh
    (extensions, authenticated) <- checkBinder earlySecret binderInfo
    ----------------------------------------------------------------
    (ecdhe,keyShare) <- makeShare
    let handshakeSecret = hkdfExtract usedHash earlySecret ecdhe
    helo <- makeServerHello keyShare srand extensions >>= writeHandshakePacket2 ctx
    ----------------------------------------------------------------
    hChSh <- getHandshakeContextHash ctx
    let clientHandshakeTrafficSecret = deriveSecret usedHash handshakeSecret "client handshake traffic secret" hChSh
        serverHandshakeTrafficSecret = deriveSecret usedHash handshakeSecret "server handshake traffic secret" hChSh
    setRxtate ctx usedHash usedCipher $ if rtt0 then clientEarlyTrafficSecret else clientHandshakeTrafficSecret
    setTxtate ctx usedHash usedCipher serverHandshakeTrafficSecret
    ----------------------------------------------------------------
    serverHandshake <- makeServerHandshake authenticated serverHandshakeTrafficSecret
    contextSend ctx $ B.concat (helo : serverHandshake)
    ----------------------------------------------------------------
    let masterSecret = hkdfExtract usedHash handshakeSecret zero
    hChSf <- getHandshakeContextHash ctx
    let clientTrafficSecret0 = deriveSecret usedHash masterSecret "client application traffic secret" hChSf
        serverTrafficSecret0 = deriveSecret usedHash masterSecret "server application traffic secret" hChSf
        verifyData = makeVerifyData clientHandshakeTrafficSecret hChSf
        clientFinished = encodeHandshake2 $ Finished2 verifyData
    ----------------------------------------------------------------
    setTxtate ctx usedHash usedCipher serverTrafficSecret0
    sendNewSessionTicket masterSecret clientFinished
    ----------------------------------------------------------------
    let established = if authenticated && rtt0 then EarlyDataAllowed
                                               else EarlyDataNotAllowed
    setEstablished ctx established
    let finishedAction verifyData'
          | verifyData == verifyData' = do
              setEstablished ctx Established
              setRxtate ctx usedHash usedCipher clientTrafficSecret0
          | otherwise = throwCore $ Error_Protocol ("cannot verify finished", True, HandshakeFailure)
    if rtt0 then do
        let alertAction = \_ -> do
                setRxtate ctx usedHash usedCipher clientHandshakeTrafficSecret
        setPendingActions ctx [alertAction, finishedAction]
      else do
        setPendingActions ctx [finishedAction]
  where
    setServerParameter = do
        srand <- ServerRandom <$> getStateRNG ctx 32
        usingHState ctx $ setPrivateKey privKey
        usingState_ ctx $ setVersion chosenVersion
        usingHState ctx $ setServerHelloParameters2 srand usedCipher
        return srand

    choosePSK = case extensionLookup extensionID_PreSharedKey exts >>= extensionDecode MsgTClinetHello of
      Just (PreSharedKeyClientHello (PskIdentity ticket _:_) bnds@(bnd:_)) -> do
          let len = sum (map (\x -> B.length x + 1) bnds) + 2
              PrivKeyRSA rsaPriv = privKey -- fixme
          Right psk <- R.decryptSafer rsaPriv ticket
          return (psk, Just (bnd,0::Int,len))
      _ -> return (zero, Nothing)

    rtt0 = case extensionLookup extensionID_EarlyData exts >>= extensionDecode MsgTClinetHello of
             Just EarlyDataIndication -> True
             Nothing                  -> False

    checkBinder _ Nothing = return ([], False)
    checkBinder earlySecret (Just (binder,n,tlen)) = do
        hss <- usingHState ctx $ getHandshakeMessages
        let hss' = truncateHss hss
            hChTruncated = hash usedHash $ B.concat hss' -- fixme: inefficient
            binderKey = deriveSecret usedHash earlySecret "resumption psk binder key" (hash usedHash "")
            binder' = makeVerifyData binderKey hChTruncated
        if binder == binder' then do
            let spsk = extensionEncode $ PreSharedKeyServerHello $ fromIntegral n
                extensions = [ExtensionRaw extensionID_PreSharedKey spsk]
            -- fixme: check age
            return (extensions, True)
          else
            return ([], False)
      where
        truncateHss []   = [] -- not reached
        truncateHss [hs] = let totalLen = B.length hs
                               takeLen = totalLen - tlen
                           in [B.take takeLen hs]
        truncateHss (h:hs) = h : truncateHss hs

    makeShare = case grp of
        P256   -> setup_ECDHE
        P384   -> setup_ECDHE
        P521   -> setup_ECDHE
        X25519 -> setup_ECDHE
        _      -> throwCore $ Error_Protocol ("no common group", True, HandshakeFailure)

    setup_ECDHE = do
        let eyourpub = decodeECDHPublic grp bytes
        yourpub <- case eyourpub of
                     Right pub -> return pub
                     Left  e   -> throwCore $ Error_Protocol (show e, True, HandshakeFailure)
        (mypub, share) <- ecdhGetPubShared yourpub
        let (_, bytes') = encodeECDHPublic mypub
            keyShare = KeyShareEntry grp bytes'
        return (BA.convert share, keyShare)

    makeServerHello keyShare srand extensions = do
        let serverKeyShare = extensionEncode $ KeyShareServerHello keyShare
            extensions' = ExtensionRaw extensionID_KeyShare serverKeyShare
                        : extensions
        return $ ServerHello2 chosenVersion srand (cipherID usedCipher) extensions'

    makeServerHandshake False serverHandshakeTrafficSecret = do
        eext <- makeExtensions >>= writeHandshakePacket2 ctx
        cert <- writeHandshakePacket2 ctx $ Certificate2 "" certChain
        vrfy <- makeCertVerify >>= writeHandshakePacket2 ctx
        fish <- makeFinished serverHandshakeTrafficSecret >>= writeHandshakePacket2 ctx
        return $ [eext, cert, vrfy, fish]
    makeServerHandshake True serverHandshakeTrafficSecret = do
        eext <- makeExtensions >>= writeHandshakePacket2 ctx
        fish <- makeFinished serverHandshakeTrafficSecret >>= writeHandshakePacket2 ctx
        return $ [eext, fish]

    makeExtensions = do
        extensions' <- applicationProtocol ctx exts sparams
        let extensions
              | rtt0 = ExtensionRaw extensionID_EarlyData (extensionEncode EarlyDataIndication) : extensions'
              | otherwise = extensions'
        return $ EncryptedExtensions2 extensions

    makeCertVerify = do
        hChCe <- getHandshakeContextHash ctx
        let toBeSinged = runPut $ do
                putBytes $ B.pack $ replicate 64 32
                putBytes "TLS 1.3, server CertificateVerify"
                putWord8 0
                putBytes hChCe
        CertVerify2 sigAlgo <$> sign toBeSinged

    makeFinished serverHandshakeTrafficSecret = do
        hChEe <- getHandshakeContextHash ctx
        return $ Finished2 $ makeVerifyData serverHandshakeTrafficSecret hChEe

    makeVerifyData baseKey hashValue = hmac usedHash finishedKey hashValue
      where
        finishedKey = hkdfExpandLabel usedHash baseKey "finished" "" hashSize

    sendNewSessionTicket masterSecret clientFinished = when sendNST $ do
        usingHState ctx $ do
            updateHandshakeDigest clientFinished
            addHandshakeMessage clientFinished
        hChCf <- getHandshakeContextHash ctx
        let resumption_secret = deriveSecret usedHash masterSecret "resumption master secret" hChCf
        let PubKeyRSA rsaPub = X.certPubKey $ X.signedObject $ X.getSigned $ getCertificateChainLeaf certChain -- fixme
        Right ticket <- R.encrypt rsaPub resumption_secret -- fixme
        let tedi = extensionEncode $ TicketEarlyDataInfo 1000 -- fixme
            extensions = [ExtensionRaw extensionID_TicketEarlyDataInfo tedi]
        let nst = NewSessionTicket2 100000 ticket extensions
        writeHandshakePacket2 ctx nst >>= contextSend ctx
      where
        sendNST = null dhModes || (PSK_DHE_KE `elem` dhModes)
        dhModes = case extensionLookup extensionID_PskKeyExchangeModes exts >>= extensionDecode MsgTClinetHello of
          Just (PskKeyExchangeModes ms) -> ms
          Nothing                       -> []

    sign toBeSinged = case sigAlgo of
      SigScheme_RSApssSHA256 -> signRSApss C.SHA256 toBeSinged
      SigScheme_RSApssSHA384 -> signRSApss C.SHA384 toBeSinged
      SigScheme_RSApssSHA512 -> signRSApss C.SHA512 toBeSinged
      _ -> throwCore $ Error_Protocol ("unsupported signature scheme", True, HandshakeFailure)

    signRSApss h toBeSinged = do
      let PrivKeyRSA rsaPriv = privKey
      Right signed <- C.sign Nothing (C.defaultPSSParams h) rsaPriv toBeSinged
      return signed

    hashSize = hashDigestSize usedHash
    zero = B.replicate hashSize 0

helloRetryRequest :: MonadIO m => ServerParams -> Context -> Version -> [KeyShareEntry] -> [Group] -> m ()
helloRetryRequest sparams ctx chosenVersion keyShares serverGroups = liftIO $ do
    ecount <- usingState ctx getHRRCount
    case ecount of
      Left _ -> err
      Right count
        | count >= 3 -> err -- fixme: hard-corded
        | otherwise -> do
            usingState_ ctx incrementHRRCount
            case possibleGroups of
              [] -> err
              g:_ -> do
                  let ext = ExtensionRaw extensionID_KeyShare $ extensionEncode $ KeyShareHRR g
                  sendPacket2 ctx $ Handshake2 [HelloRetryRequest2 chosenVersion [ext]]
                  handshakeServer sparams ctx
  where
    clientGroups = map (\(KeyShareEntry g _) -> g) keyShares
    possibleGroups = serverGroups \\ clientGroups
    err = throwCore $ Error_Protocol ("key exchange not implemented", True, HandshakeFailure)

findHighestVersionFrom :: Version -> [Version] -> Maybe Version
findHighestVersionFrom clientVersion allowedVersions =
    case filter (clientVersion >=) $ sortOn Down allowedVersions of
        []  -> Nothing
        v:_ -> Just v

findHighestVersionFrom13 :: [Version] -> [Version] -> Maybe Version
findHighestVersionFrom13 clientVersions serverVersions = case svs `intersect` cvs of
        []  -> Nothing
        v:_ -> Just v
  where
    svs = sortOn Down serverVersions
    cvs = sortOn Down clientVersions

applicationProtocol :: Context -> [ExtensionRaw] -> ServerParams -> IO [ExtensionRaw]
applicationProtocol ctx exts sparams = do
    protos <- alpn
    if null protos then npn else return protos
  where
    clientRequestedNPN = isJust $ extensionLookup extensionID_NextProtocolNegotiation exts
    clientALPNSuggest = isJust $ extensionLookup extensionID_ApplicationLayerProtocolNegotiation exts

    alpn | clientALPNSuggest = do
        suggest <- usingState_ ctx getClientALPNSuggest
        case (onALPNClientSuggest $ serverHooks sparams, suggest) of
            (Just io, Just protos) -> do
                proto <- liftIO $ io protos
                usingState_ ctx $ do
                    setExtensionALPN True
                    setNegotiatedProtocol proto
                return [ ExtensionRaw extensionID_ApplicationLayerProtocolNegotiation
                                        (extensionEncode $ ApplicationLayerProtocolNegotiation [proto]) ]
            (_, _)                  -> return []
         | otherwise = return []
    npn = do
        nextProtocols <-
            if clientRequestedNPN
                then liftIO $ onSuggestNextProtocols $ serverHooks sparams
                else return Nothing
        case nextProtocols of
            Just protos -> do
                usingState_ ctx $ do
                    setExtensionNPN True
                    setServerNextProtocolSuggest protos
                return [ ExtensionRaw extensionID_NextProtocolNegotiation
                         (extensionEncode $ NextProtocolNegotiation protos) ]
            Nothing -> return []
