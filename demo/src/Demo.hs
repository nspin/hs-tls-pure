{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE UndecidableInstances #-}
-- |
-- Module      : Network.TLS.Pure
-- License     : BSD-style
-- Maintainer  : Nick Spinale <nick@nickspinale.com>
-- Stability   : experimental
-- Portability : unknown
--

import Network.TLS hiding (SHA256, HashSHA256)
import Network.TLS.Extra
import Network.TLS.Pure
import Network.TLS.Internal (HandshakeState(..), getHState, ClientRandom(..))

import Prelude hiding (null, splitAt, log)

import Control.Concurrent
import Control.Lens (makeLenses, use, assign, (<%=))
import Control.Monad.Catch
import Control.Monad.Catch.Pure
import Control.Monad.Reader
import Control.Monad.State.Strict
import Control.Monad.Writer
import Crypto.Hash (SHA256(SHA256))
import Crypto.PubKey.RSA (PrivateKey(..), generate)
import Crypto.PubKey.RSA.PKCS15 (sign)
import Crypto.Random (seedFromInteger, withDRG, drgNewSeed)
import Data.ASN1.Types (getObjectID, ASN1StringEncoding(UTF8))
import Data.ByteString.Builder (Builder, byteString, toLazyByteString)
import Data.ByteString.Lazy (ByteString, toStrict, splitAt, null)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as Hex
import qualified Data.ByteString.Char8 as C
import Data.Default
import Data.Streaming.Network
import Data.X509
import Network.Socket (Socket)
import Network.Socket.ByteString (recv)
import Pipes
import Pipes.Core
import Time.Types


newtype EndpointT m a = EndpointT { runEndpointT :: ReaderT (ByteString -> m ByteString) (StateT EndpointBufferState m) a }
    deriving (Functor, Applicative, Monad, MonadReader (ByteString -> m ByteString), MonadState EndpointBufferState)

instance MonadCatch m => MonadCatch (EndpointT m) where
    catch (EndpointT m) f = EndpointT $ catch m (runEndpointT . f)

instance MonadThrow m => MonadThrow (EndpointT m) where
    throwM = lift . throwM

instance MonadWriter w m => MonadWriter w (EndpointT m) where
    tell = lift . tell
    listen = EndpointT . listen . runEndpointT
    pass = EndpointT . pass . runEndpointT

instance MonadTrans EndpointT where
    lift = EndpointT . lift . lift

data EndpointBufferState = EndpointBufferState
    { _sendBuffer :: Builder
    , _recvBuffer :: ByteString
    }

makeLenses ''EndpointBufferState

session :: [(Direction, B.ByteString)]
secrets :: [(ClientRandom, B.ByteString)]
debug :: [String]
result :: Either SomeException ()
(result, log) = runWriter (runCatchT (communicate doClient doServer))
(debug, secrets, session) = partitionLog log

doClient :: (MonadThrow m, MonadCatch m) => Context m -> m ()
doClient ctx = do
    handshake ctx
    sendData ctx "im client"
    recvData ctx
    sendData ctx "nice"
    recvData ctx
    return ()

doServer :: (MonadThrow m, MonadCatch m) => Context m -> m ()
doServer ctx = do
    handshake ctx
    recvData ctx
    sendData ctx "im server"
    recvData ctx
    sendData ctx "cool"
    bye ctx

communicate :: forall m. (MonadThrow m, MonadCatch m, MonadWriter Log m)
            => (forall n. (MonadThrow n, MonadCatch n, MonadWriter Log n) => Context n -> n ())
            -> (forall n. (MonadThrow n, MonadCatch n, MonadWriter Log n) => Context n -> n ())
            -> m ()
communicate client server = runEffect $
    evalStateT
        (runReaderT
            (runEndpointT
                (evalStateT (client clientCtx) clientSt))
            respond)
        (EndpointBufferState mempty mempty)
    >>~ \bs ->
        evalStateT
            (runReaderT
                (runEndpointT
                    (evalStateT (server serverCtx) serverSt))
                request)
            (EndpointBufferState mempty bs)
  where
    hooks :: forall n. MonadWriter Log n => Context (StateT TLSMutState n) -> Hooks (StateT TLSMutState n)
    hooks ctx = def
        { hookRecvHandshake = \hs -> do
            mhsts <- getHState ctx
            tell . maybe [] (:[]) $ do
                hsts <- mhsts
                msec <- hstMasterSecret hsts
                return $ LogEntrySecret (hstClientRandom hsts, msec)
            return hs
        }
    (clientSt, clientCtx) = contextNewPure (seedFromInteger 37) (endpointBackend FromClient) clientParams hooks
    (serverSt, serverCtx) = contextNewPure (seedFromInteger 13) (endpointBackend FromServer) serverParams hooks

serverParams :: Monad m => ServerParams m
serverParams = def
    { serverSupported = def
        { supportedCiphers = ciphersuite_default
        }
    , serverShared = def
        { sharedCredentials = Credentials [(CertificateChain [serverCert], PrivKeyRSA serverPriv)]
        }
    }

clientParams :: Monad m => ClientParams m
clientParams = (defaultParamsClient "" mempty)
    { clientSupported = def
        { supportedCiphers = ciphersuite_default
        }
    , clientUseServerNameIndication = False
    }

endpointBackend :: MonadWriter Log m => Direction -> Backend (StateT TLSMutState (EndpointT m))
endpointBackend direction = Backend
    { backendFlush = return ()
    , backendClose = return ()
    , backendSend = \b -> do
        tell [LogEntryTraffic (direction, b)]
        lift $ void (sendBuffer <%= (<> byteString b))
    , backendRecv = \n -> lift $
        let f buf =
                if null buf
                then return mempty
                else
                    let (l, r) = splitAt (toEnum n) buf
                    in do
                        assign recvBuffer r
                        return (toStrict l)
        in do
            recvQ <- use recvBuffer
            if null recvQ
              then do
                sendBuf <- use sendBuffer
                assign sendBuffer mempty
                send <- ask
                lift (send (toLazyByteString sendBuf)) >>= f
              else f recvQ
    }

-- Logging

type Log = [LogEntry]

data LogEntry = LogEntryDebug String
              | LogEntrySecret (ClientRandom, B.ByteString)
              | LogEntryTraffic (Direction, B.ByteString)

data Direction = FromClient | FromServer deriving (Eq, Show)

partitionLog :: Log -> ([String], [(ClientRandom, B.ByteString)], [(Direction, B.ByteString)])
partitionLog = foldMap $ \case
    LogEntryDebug x -> ([x], [], [])
    LogEntrySecret x -> ([], [x], [])
    LogEntryTraffic x -> ([], [], [x])

showsSecret :: (ClientRandom, B.ByteString) -> String -> String
showsSecret (ClientRandom clientRandom, masterSecret)
    = showString "CLIENT_RANDOM "
    . showString (C.unpack (Hex.encode clientRandom))
    . showChar ' '
    . showString (C.unpack (Hex.encode masterSecret))
    . showChar '\n'

showSecrets :: [(ClientRandom, B.ByteString)] -> String
showSecrets secrets = appEndo (foldMap (Endo . showsSecret) secrets) ""

-- Credentials

serverCert :: SignedExact Certificate
serverCert = makeRootCert serverPriv

serverPriv :: PrivateKey
serverPriv = privateKeyFromSeed 1337

privateKeyFromSeed :: Integer -> PrivateKey
privateKeyFromSeed i = priv
  where
    ((_, priv), _) = withDRG (drgNewSeed (seedFromInteger i)) (generate 256 3)

makeRootCert :: PrivateKey -> SignedCertificate
makeRootCert priv = signed
  where
    Right signed = objectToSignedExactF f cert
    f bs = (, sigAlg) <$> sign Nothing (Just SHA256) priv bs
    sigAlg = SignatureALG HashSHA256 PubKeyALG_RSA
    dn = DistinguishedName [(getObjectID DnCommonName, ASN1CharacterString UTF8 "me")]
    start = DateTime (Date 1970 January 1) (TimeOfDay 0 0 0 0)
    end = DateTime (Date 2070 January 1) (TimeOfDay 0 0 0 0)
    cert = Certificate
        { certVersion = 3
        , certSerial = 0x133333333333333337
        , certSignatureAlg = sigAlg
        , certIssuerDN = dn
        , certValidity = (start, end)
        , certSubjectDN = dn
        , certPubKey = PubKeyRSA $ private_pub priv
        , certExtensions = Extensions Nothing
        }

-- IO

main :: IO ()
main = do
    putStr (showSecrets secrets)
    case result of
        Left ex -> throwM ex
        _ -> return ()
    forkIO $ runTCPServer (serverSettingsTCP 13337 "127.0.0.1") $ \conn ->
        let Just sock = appRawSocket conn
        in forM_ session $ \case
            (FromServer, chunk) -> appWrite conn chunk
            (FromClient, chunk) -> recvExact (B.length chunk) sock >>= \c -> unless (c == chunk) (error "mismatched chunk")
    threadDelay 2000
    runTCPClient (clientSettingsTCP 13337 "127.0.0.1") $ \conn ->
        let Just sock = appRawSocket conn
        in forM_ session $ \case
            (FromClient, chunk) -> appWrite conn chunk
            (FromServer, chunk) -> recvExact (B.length chunk) sock >>= \c -> unless (c == chunk) (error "mismatched chunk")

recvExact :: Int -> Socket -> IO B.ByteString
recvExact 0 _ = mempty
recvExact n sock = do
    b <- recv sock n
    mappend b <$> recvExact (n - B.length b) sock
