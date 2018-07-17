{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Monadic

import PipeChan
import Connection
import Marshalling
import Ciphers

import Data.Maybe
import Data.List (intersect)

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as L
import Network.TLS
import Network.TLS.Extra
import Control.Applicative
import Control.Concurrent
import Control.Monad

import Data.IORef
import Data.X509 (ExtKeyUsageFlag(..))

import System.Timeout

prop_pipe_work :: PropertyM IO ()
prop_pipe_work = do
    pipe <- run newPipe
    _ <- run (runPipe pipe)

    let bSize = 16
    n <- pick (choose (1, 32))

    let d1 = B.replicate (bSize * n) 40
    let d2 = B.replicate (bSize * n) 45

    d1' <- run (writePipeA pipe d1 >> readPipeB pipe (B.length d1))
    d1 `assertEq` d1'

    d2' <- run (writePipeB pipe d2 >> readPipeA pipe (B.length d2))
    d2 `assertEq` d2'

    return ()

recvDataNonNull :: Context IO -> IO C8.ByteString
recvDataNonNull ctx = recvData ctx >>= \l -> if B.null l then recvDataNonNull ctx else return l

runTLSPipe :: (ClientParams IO, ServerParams IO) -> (Context IO -> Chan C8.ByteString -> IO ()) -> (Chan C8.ByteString -> Context IO -> IO ()) -> PropertyM IO ()
runTLSPipe params tlsServer tlsClient = do
    (startQueue, resultQueue) <- run (establishDataPipe params tlsServer tlsClient)
    -- send some data
    d <- B.pack <$> pick (someWords8 256)
    run $ writeChan startQueue d
    -- receive it
    dres <- run $ timeout 10000000 $ readChan resultQueue
    -- check if it equal
    Just d `assertEq` dres
    return ()

runTLSPipeSimple :: (ClientParams IO, ServerParams IO) -> PropertyM IO ()
runTLSPipeSimple params = runTLSPipe params tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            handshake ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            bye ctx
            return ()

runTLSInitFailure :: (ClientParams IO, ServerParams IO) -> PropertyM IO ()
runTLSInitFailure params = do
    (cRes, sRes) <- run (initiateDataPipe params tlsServer tlsClient)
    assertIsLeft cRes
    assertIsLeft sRes
  where tlsServer ctx = handshake ctx >> bye ctx >> return ("server success" :: String)
        tlsClient ctx = handshake ctx >> bye ctx >> return ("client success" :: String)

prop_handshake_initiate :: PropertyM IO ()
prop_handshake_initiate = do
    params  <- pick arbitraryPairParams
    runTLSPipeSimple params

prop_handshake_ciphersuites :: PropertyM IO ()
prop_handshake_ciphersuites = do
    let clientVersions = [TLS12]
        serverVersions = [TLS12]
    clientCiphers <- pick arbitraryCiphers
    serverCiphers <- pick arbitraryCiphers
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (clientVersions, serverVersions)
                                            (clientCiphers, serverCiphers)
    let shouldFail = null (clientCiphers `intersect` serverCiphers)
    if shouldFail
        then runTLSInitFailure (clientParam,serverParam)
        else runTLSPipeSimple  (clientParam,serverParam)

prop_handshake_hashsignatures :: PropertyM IO ()
prop_handshake_hashsignatures = do
    let clientVersions = [TLS12]
        serverVersions = [TLS12]
        ciphers = [ cipher_ECDHE_RSA_AES256GCM_SHA384
                  , cipher_ECDHE_RSA_AES128CBC_SHA
                  , cipher_DHE_RSA_AES128_SHA1
                  , cipher_DHE_DSS_AES128_SHA1
                  ]
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (clientVersions, serverVersions)
                                            (ciphers, ciphers)
    clientHashSigs <- pick arbitraryHashSignatures
    serverHashSigs <- pick arbitraryHashSignatures
    let clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                       { supportedHashSignatures = clientHashSigs }
                                   }
        serverParam' = serverParam { serverSupported = (serverSupported serverParam)
                                       { supportedHashSignatures = serverHashSigs }
                                   }
        shouldFail = null (clientHashSigs `intersect` serverHashSigs)
    if shouldFail
        then runTLSInitFailure (clientParam',serverParam')
        else runTLSPipeSimple  (clientParam',serverParam')

-- Tests ability to use or ignore client "signature_algorithms" extension when
-- choosing a server certificate.  Here peers allow DHE_RSA_AES128_SHA1 but
-- the server RSA certificate has a SHA-1 signature that the client does not
-- support.  Server may choose the DSA certificate only when cipher
-- DHE_DSS_AES128_SHA1 is allowed.  Otherwise it must fallback to the RSA
-- certificate.
prop_handshake_cert_fallback :: PropertyM IO ()
prop_handshake_cert_fallback = do
    let clientVersions = [TLS12]
        serverVersions = [TLS12]
        commonCiphers  = [ cipher_DHE_RSA_AES128_SHA1 ]
        otherCiphers   = [ cipher_ECDHE_RSA_AES256GCM_SHA384
                         , cipher_ECDHE_RSA_AES128CBC_SHA
                         , cipher_DHE_DSS_AES128_SHA1
                         ]
        hashSignatures = [ (HashSHA256, SignatureRSA), (HashSHA1, SignatureDSS) ]
    chainRef <- run $ newIORef Nothing
    clientCiphers <- pick $ sublistOf otherCiphers
    serverCiphers <- pick $ sublistOf otherCiphers
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (clientVersions, serverVersions)
                                            (clientCiphers ++ commonCiphers, serverCiphers ++ commonCiphers)
    let clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                       { supportedHashSignatures = hashSignatures }
                                   , clientHooks = (clientHooks clientParam)
                                       { onServerCertificate = \_ _ _ chain ->
                                             writeIORef chainRef (Just chain) >> return [] }
                                   }
        dssDisallowed = cipher_DHE_DSS_AES128_SHA1 `notElem` clientCiphers
                            || cipher_DHE_DSS_AES128_SHA1 `notElem` serverCiphers
    runTLSPipeSimple (clientParam',serverParam)
    serverChain <- run $ readIORef chainRef
    dssDisallowed `assertEq` isLeafRSA serverChain
  where
    isLeafRSA chain = case chain >>= leafPublicKey of
                          Just (PubKeyRSA _) -> True
                          _                  -> False

prop_handshake_groups :: PropertyM IO ()
prop_handshake_groups = do
    let clientVersions = [TLS12]
        serverVersions = [TLS12]
        ciphers = [ cipher_ECDHE_RSA_AES256GCM_SHA384
                  , cipher_ECDHE_RSA_AES128CBC_SHA
                  , cipher_DHE_RSA_AES256GCM_SHA384
                  , cipher_DHE_RSA_AES128_SHA1
                  ]
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (clientVersions, serverVersions)
                                            (ciphers, ciphers)
    clientGroups <- pick arbitraryGroups
    serverGroups <- pick arbitraryGroups
    denyCustom   <- pick arbitrary
    let groupUsage = if denyCustom then GroupUsageUnsupported "custom group denied" else GroupUsageValid
        clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                       { supportedGroups = clientGroups }
                                   , clientHooks = (clientHooks clientParam)
                                       { onCustomFFDHEGroup = \_ _ -> return groupUsage }
                                   }
        serverParam' = serverParam { serverSupported = (serverSupported serverParam)
                                       { supportedGroups = serverGroups }
                                   }
        isCustom = maybe True isCustomDHParams (serverDHEParams serverParam')
        shouldFail = null (clientGroups `intersect` serverGroups) && isCustom && denyCustom
    if shouldFail
        then runTLSInitFailure (clientParam',serverParam')
        else runTLSPipeSimple  (clientParam',serverParam')

prop_handshake_srv_key_usage :: PropertyM IO ()
prop_handshake_srv_key_usage = do
    let versions = [SSL3,TLS10,TLS11,TLS12]
        ciphers = [ cipher_ECDHE_RSA_AES128CBC_SHA
                  , cipher_DHE_RSA_AES128_SHA1
                  , cipher_AES256_SHA256
                  ]
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (versions, versions)
                                            (ciphers, ciphers)
    usageFlags <- pick arbitraryKeyUsage
    cred <- pick $ arbitraryRSACredentialWithUsage usageFlags
    let serverParam' = serverParam
            { serverShared = (serverShared serverParam)
                  { sharedCredentials = Credentials [cred]
                  }
            }
        shouldSucceed = KeyUsage_digitalSignature `elem` usageFlags
                            || KeyUsage_keyEncipherment `elem` usageFlags
    if shouldSucceed
        then runTLSPipeSimple  (clientParam,serverParam')
        else runTLSInitFailure (clientParam,serverParam')

prop_handshake_client_auth :: PropertyM IO ()
prop_handshake_client_auth = do
    (clientParam,serverParam) <- pick arbitraryPairParams
    cred <- pick arbitraryClientCredential
    let clientParam' = clientParam { clientHooks = (clientHooks clientParam)
                                       { onCertificateRequest = \_ -> return $ Just cred }
                                   }
        serverParam' = serverParam { serverWantClientCert = True
                                   , serverHooks = (serverHooks serverParam)
                                        { onClientCertificate = validateChain cred }
                                   }
    runTLSPipeSimple (clientParam',serverParam')
  where validateChain cred chain
            | chain == fst cred = return CertificateUsageAccept
            | otherwise         = return (CertificateUsageReject CertificateRejectUnknownCA)

prop_handshake_clt_key_usage :: PropertyM IO ()
prop_handshake_clt_key_usage = do
    (clientParam,serverParam) <- pick arbitraryPairParams
    usageFlags <- pick arbitraryKeyUsage
    cred <- pick $ arbitraryRSACredentialWithUsage usageFlags
    let clientParam' = clientParam { clientHooks = (clientHooks clientParam)
                                       { onCertificateRequest = \_ -> return $ Just cred }
                                   }
        serverParam' = serverParam { serverWantClientCert = True
                                   , serverHooks = (serverHooks serverParam)
                                        { onClientCertificate = \_ -> return CertificateUsageAccept }
                                   }
        shouldSucceed = KeyUsage_digitalSignature `elem` usageFlags
    if shouldSucceed
        then runTLSPipeSimple  (clientParam',serverParam')
        else runTLSInitFailure (clientParam',serverParam')

prop_handshake_alpn :: PropertyM IO ()
prop_handshake_alpn = do
    (clientParam,serverParam) <- pick arbitraryPairParams
    let clientParam' = clientParam { clientHooks = (clientHooks clientParam)
                                       { onSuggestALPN = return $ Just ["h2", "http/1.1"] }
                                    }
        serverParam' = serverParam { serverHooks = (serverHooks serverParam)
                                        { onALPNClientSuggest = Just alpn }
                                   }
        params' = (clientParam',serverParam')
    runTLSPipe params' tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            proto <- getNegotiatedProtocol ctx
            Just "h2" `assertEq` proto
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            handshake ctx
            proto <- getNegotiatedProtocol ctx
            Just "h2" `assertEq` proto
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            bye ctx
            return ()
        alpn xs
          | "h2"    `elem` xs = return "h2"
          | otherwise         = return "http/1.1"

prop_handshake_sni :: PropertyM IO ()
prop_handshake_sni = do
    (clientParam,serverParam) <- pick arbitraryPairParams
    let clientParam' = clientParam { clientServerIdentification = (serverName, "")
                                   , clientUseServerNameIndication = True
                                    }
        params' = (clientParam',serverParam)
    runTLSPipe params' tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            sni <- getClientSNI ctx
            Just serverName `assertEq` sni
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            handshake ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            bye ctx
            return ()
        serverName = "haskell.org"

prop_handshake_renegotiation :: PropertyM IO ()
prop_handshake_renegotiation = do
    (cparams, sparams) <- pick arbitraryPairParams
    let sparams' = sparams {
            serverSupported = (serverSupported sparams) {
                 supportedClientInitiatedRenegotiation = True
               }
          }
    runTLSPipe (cparams, sparams') tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            handshake ctx
            handshake ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            bye ctx
            return ()

prop_handshake_session_resumption :: PropertyM IO ()
prop_handshake_session_resumption = do
    sessionRef <- run $ newIORef Nothing
    let sessionManager = oneSessionManager sessionRef

    plainParams <- pick arbitraryPairParams
    let params = setPairParamsSessionManager sessionManager plainParams

    runTLSPipeSimple params

    -- and resume
    sessionParams <- run $ readIORef sessionRef
    assert (isJust sessionParams)
    let params2 = setPairParamsSessionResuming (fromJust sessionParams) params

    runTLSPipeSimple params2

assertEq :: (Show a, Monad m, Eq a) => a -> a -> m ()
assertEq expected got = unless (expected == got) $ error ("got " ++ show got ++ " but was expecting " ++ show expected)

assertIsLeft :: (Show b, Monad m) => Either a b -> m ()
assertIsLeft (Left  _) = return()
assertIsLeft (Right b) = error ("got " ++ show b ++ " but was expecting a failure")

main :: IO ()
main = defaultMain $ testGroup "tls"
    [ tests_marshalling
    , tests_ciphers
    , tests_handshake
    ]
  where -- lowlevel tests to check the packet marshalling.
        tests_marshalling = testGroup "Marshalling"
            [ testProperty "Header" prop_header_marshalling_id
            , testProperty "Handshake" prop_handshake_marshalling_id
            ]
        tests_ciphers = testGroup "Ciphers"
            [ testProperty "Bulk" propertyBulkFunctional ]

        -- high level tests between a client and server with fake ciphers.
        tests_handshake = testGroup "Handshakes"
            [ testProperty "Setup" (monadicIO prop_pipe_work)
            , testProperty "Initiation" (monadicIO prop_handshake_initiate)
            , testProperty "Hash and signatures" (monadicIO prop_handshake_hashsignatures)
            , testProperty "Cipher suites" (monadicIO prop_handshake_ciphersuites)
            , testProperty "Groups" (monadicIO prop_handshake_groups)
            , testProperty "Certificate fallback" (monadicIO prop_handshake_cert_fallback)
            , testProperty "Server key usage" (monadicIO prop_handshake_srv_key_usage)
            , testProperty "Client authentication" (monadicIO prop_handshake_client_auth)
            , testProperty "Client key usage" (monadicIO prop_handshake_clt_key_usage)
            , testProperty "ALPN" (monadicIO prop_handshake_alpn)
            , testProperty "SNI" (monadicIO prop_handshake_sni)
            , testProperty "Renegotiation" (monadicIO prop_handshake_renegotiation)
            , testProperty "Resumption" (monadicIO prop_handshake_session_resumption)
            ]
