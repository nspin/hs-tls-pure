{-# LANGUAGE RankNTypes #-}
-- |
-- Module      : Network.TLS.Context.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Context.Internal
    (
    -- * Context configuration
      ClientParams(..)
    , ServerParams(..)
    , defaultParamsClient
    , SessionID
    , SessionData(..)
    , MaxFragmentEnum(..)
    , Measurement(..)

    -- * Context object and accessor
    , Context(..)
    , Hooks(..)
    , ctxEOF
    , ctxHasSSLv2ClientHello
    , ctxDisableSSLv2ClientHello
    , ctxEstablished
    , ctxNeedEmptyPacket
    , withLog
    , setEOF
    , setEstablished
    , setNeedEmptyPacket
    , contextFlush
    , contextClose
    , contextSend
    , contextRecv
    , updateMeasure
    , withMeasure
    , withReadLock
    , withWriteLock
    , withRWLock

    -- * information
    , Information(..)
    , contextGetInformation

    -- * Using context states
    , throwCore
    , usingState
    , usingState_
    , runTxState
    , runRxState
    , usingHState
    , getHState
    , getStateRNG
    ) where

import Network.TLS.Backend
import Network.TLS.Extension
import Network.TLS.Cipher
import Network.TLS.Struct
import Network.TLS.Compression (Compression)
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Hooks
import Network.TLS.Record.State
import Network.TLS.Parameters
import Network.TLS.Measurement
import Network.TLS.Imports
import qualified Data.ByteString as B

import Control.Monad.Catch (throwM, Exception(), MonadThrow)
import Control.Monad.Except


-- | Information related to a running context, e.g. current cipher
data Information = Information
    { infoVersion      :: Version
    , infoCipher       :: Cipher
    , infoCompression  :: Compression
    , infoMasterSecret :: Maybe ByteString
    , infoClientRandom :: Maybe ClientRandom
    , infoServerRandom :: Maybe ServerRandom
    } deriving (Show,Eq)

-- | A TLS Context keep tls specific state, parameters and backend information.
data Context m = Context
    { ctxConnection       :: Backend m -- ^ return the backend object associated with this context
    , ctxSupported        :: Supported
    , ctxShared           :: Shared m
    , ctxState            :: forall a. TLSSt a -> ExceptT TLSError m a
    , ctxMeasurement      :: forall a. State Measurement a -> m a
    , ctxEOF_             :: forall a. State Bool a -> m a -- ^ has the handle EOFed or not.
    , ctxEstablished_     :: forall a. State Bool a -> m a -- ^ has the handshake been done and been successful.
    , ctxNeedEmptyPacket_ :: forall a. State Bool a -> m a -- ^ empty packet workaround for CBC guessability.
    , ctxSSLv2ClientHello :: forall a. State Bool a -> m a -- ^ enable the reception of compatibility SSLv2 client hello.
                                                    -- the flag will be set to false regardless of its initial value
                                                    -- after the first packet received.
    , ctxTxState          :: forall a. State RecordState a -> m a -- ^ current tx state
    , ctxRxState          :: forall a. State RecordState a -> m a -- ^ current rx state
    , ctxHandshake        :: forall a. State (Maybe HandshakeState) a -> m a -- ^ optional handshake state
    , ctxDoHandshake      :: m ()
    , ctxDoHandshakeWith  :: Handshake -> m ()
    , ctxHooks            :: Hooks m                        -- ^ hooks for this context
    , withWriteLock       :: forall a. m a -> m a           -- ^ lock to use for writing data (including updating the state)
    , withReadLock        :: forall a. m a -> m a           -- ^ lock to use for reading data (including updating the state)
    }

-- NOTE: Hooks must live in the top-level monad, because they should have
-- access to actions like 'contextGetInformation'. More complicated changes
-- would be necessary to properly isolate hooks from the top-level monad.

updateMeasure :: Monad m => Context m -> (Measurement -> Measurement) -> m ()
updateMeasure ctx = ctxMeasurement ctx . modify

withMeasure :: Monad m => Context m -> (Measurement -> m a) -> m a
withMeasure ctx f = ctxMeasurement ctx get >>= f

contextFlush :: Context m -> m ()
contextFlush = backendFlush . ctxConnection

contextClose :: Context m -> m ()
contextClose = backendClose . ctxConnection

-- | Information about the current context
contextGetInformation :: MonadThrow m => Context m -> m (Maybe Information)
contextGetInformation ctx = do
    ver    <- usingState_ ctx $ gets stVersion
    hstate <- getHState ctx
    let (ms, cr, sr) = case hstate of
                           Just st -> (hstMasterSecret st,
                                       Just (hstClientRandom st),
                                       hstServerRandom st)
                           Nothing -> (Nothing, Nothing, Nothing)
    (cipher,comp) <- failOnEitherError $ runRxState ctx $ gets $ \st -> (stCipher st, stCompression st)
    case (ver, cipher) of
        (Just v, Just c) -> return $ Just $ Information v c comp ms cr sr
        _                -> return Nothing

contextSend :: Monad m => Context m -> ByteString -> m ()
contextSend c b = updateMeasure c (addBytesSent $ B.length b) >> (backendSend $ ctxConnection c) b

contextRecv :: Monad m => Context m -> Int -> m ByteString
contextRecv c sz = updateMeasure c (addBytesReceived sz) >> (backendRecv $ ctxConnection c) sz

ctxEOF :: Context m -> m Bool
ctxEOF ctx = ctxEOF_ ctx get

ctxHasSSLv2ClientHello :: Context m -> m Bool
ctxHasSSLv2ClientHello ctx = ctxSSLv2ClientHello ctx get

ctxDisableSSLv2ClientHello :: Context m -> m ()
ctxDisableSSLv2ClientHello ctx = ctxSSLv2ClientHello ctx (put False)

setEOF :: Context m -> m ()
setEOF ctx = ctxEOF_ ctx (put True)

ctxEstablished :: Context m -> m Bool
ctxEstablished ctx = ctxEstablished_ ctx get

ctxNeedEmptyPacket :: Context m -> m Bool
ctxNeedEmptyPacket ctx = ctxNeedEmptyPacket_ ctx get

setEstablished :: Context m -> Bool -> m ()
setEstablished ctx = ctxEstablished_ ctx . put

setNeedEmptyPacket :: Context m -> Bool -> m ()
setNeedEmptyPacket ctx = ctxNeedEmptyPacket_ ctx . put

withLog :: Monad m => Context m -> (Logging m -> m ()) -> m ()
withLog ctx f =  f . hookLogging $ ctxHooks ctx

throwCore :: (MonadThrow m, Exception e) => e -> m a
throwCore = throwM

failOnEitherError :: MonadThrow m => m (Either TLSError a) -> m a
failOnEitherError f = do
    ret <- f
    case ret of
        Left err -> throwCore err
        Right r  -> return r

usingState :: Monad m => Context m -> TLSSt a -> m (Either TLSError a)
usingState ctx = runExceptT . ctxState ctx

usingState_ :: MonadThrow m => Context m -> TLSSt a -> m a
usingState_ ctx f = failOnEitherError $ usingState ctx f

usingHState :: MonadThrow m => Context m -> HandshakeM a -> m a
usingHState ctx f = join . ctxHandshake ctx $ do
    mst <- get
    case mst of
        Nothing -> return $ throwCore (Error_Misc "missing handshake")
        Just st -> do
            let (a, st') = runHandshake st f
            put (Just st')
            return (return a)

getHState :: Monad m => Context m -> m (Maybe HandshakeState)
getHState ctx = ctxHandshake ctx get

runTxState :: MonadThrow m => Context m -> RecordM a -> m (Either TLSError a)
runTxState ctx f = do
    ver <- usingState_ ctx (getVersionWithDefault $ maximum $ supportedVersions $ ctxSupported ctx)
    ctxTxState ctx . state $ \st ->
        case runRecordM f ver st of
            Left err         -> (Left err, st)
            Right (a, newSt) -> (Right a, newSt)

runRxState :: MonadThrow m => Context m -> RecordM a -> m (Either TLSError a)
runRxState ctx f = do
    ver <- usingState_ ctx getVersion
    ctxRxState ctx . state $ \st ->
        case runRecordM f ver st of
            Left err         -> (Left err, st)
            Right (a, newSt) -> (Right a, newSt)

getStateRNG :: MonadThrow m => Context m -> Int -> m ByteString
getStateRNG ctx n = usingState_ ctx $ genRandom n

withRWLock :: Context m -> m a -> m a           -- ^ lock to use for reading data (including updating the state)
withRWLock = fmap <$> withReadLock <*> withWriteLock
