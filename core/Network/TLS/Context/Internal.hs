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
    , ctxWithHooks
    , contextModifyHooks
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
    , withStateLock
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

    , readMMVar
    , swapMMVar
    , withMMVar
    ) where

import Network.TLS.Backend
import Network.TLS.Extension
import Network.TLS.Cipher
import Network.TLS.Struct
import Network.TLS.Compression (Compression)
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Hooks
import Network.TLS.Record
import Network.TLS.Parameters
import Network.TLS.Measurement
import Network.TLS.Imports

import Control.Monad.Catch (throwM, Exception(), MonadThrow)
import Control.Monad.State.Strict (gets)


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
    , ctxState            :: forall a. (TLSState -> m (a, TLSState)) -> m a
    , ctxMeasurement      :: (m Measurement, Measurement -> m ())
    , ctxEOF_             :: (m Bool, Bool -> m ()) -- ^ has the handle EOFed or not.
    , ctxEstablished_     :: (m Bool, Bool -> m ()) -- ^ has the handshake been done and been successful.
    , ctxNeedEmptyPacket_ :: (m Bool, Bool -> m ()) -- ^ empty packet workaround for CBC guessability.
    , ctxSSLv2ClientHello :: (m Bool, Bool -> m ()) -- ^ enable the reception of compatibility SSLv2 client hello.
                                                    -- the flag will be set to false regardless of its initial value
                                                    -- after the first packet received.
    , ctxTxState          :: forall a. (RecordState -> m (a, RecordState)) -> m a -- ^ current tx state
    , ctxRxState          :: forall a. (RecordState -> m (a, RecordState)) -> m a -- ^ current rx state
    , ctxHandshake        :: forall a. (Maybe HandshakeState -> m (a, Maybe HandshakeState)) -> m a -- ^ optional handshake state
    , ctxDoHandshake      :: Context m -> m ()
    , ctxDoHandshakeWith  :: Context m -> Handshake -> m ()
    , ctxHooks            :: (m (Hooks m), Hooks m -> m ()) -- ^ hooks for this context
    , ctxLockWrite        :: forall a. m a -> m a           -- ^ lock to use for writing data (including updating the state)
    , ctxLockRead         :: forall a. m a -> m a           -- ^ lock to use for reading data (including updating the state)
    , ctxLockState        :: forall a. m a -> m a           -- ^ lock used during read/write when receiving and sending packet.
                                                            -- it is usually nested in a write or read lock.
    }

-- NOTE: Hooks must live in the top-level monad, because they should have
-- access to actions like 'contextGetInformation'. More complicated changes
-- would be necessary to properly isolate hooks from the top-level monad.

readMRef :: (m a, a -> m ()) -> m a
readMRef = fst

writeMRef :: (m a, a -> m ()) -> a -> m ()
writeMRef = snd

modifyMRef :: Monad m => (m a, a -> m ()) -> (a -> a) -> m ()
modifyMRef (r, w) f = r >>= w . f

readMMVar :: Monad m => (forall r. (a -> m (r, a)) -> m r) -> m a
readMMVar f = f $ \a -> return (a, a)

swapMMVar :: Monad m => (forall r. (a -> m (r, a)) -> m r) -> a -> m a
swapMMVar f a = f $ \a' -> return (a', a)

withMMVar :: Monad m => ((a -> m (r, a)) -> m r) -> (a -> m r) -> m r
withMMVar f g = f $ \a -> flip (,) a <$> g a

updateMeasure :: Monad m => Context m -> (Measurement -> Measurement) -> m ()
updateMeasure ctx f = do
    x <- readMRef (ctxMeasurement ctx)
    writeMRef (ctxMeasurement ctx) $! f x

withMeasure :: Monad m => Context m -> (Measurement -> m a) -> m a
withMeasure ctx f = readMRef (ctxMeasurement ctx) >>= f

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

contextSend :: Monad m => Context m -> Record Ciphertext -> m ()
contextSend c rec = do
    updateMeasure c . addBytesSent $ recordLength rec
    backendSend (ctxConnection c) rec

contextRecv :: Monad m => Context m -> m (Record Ciphertext)
contextRecv c = do
    rec <- backendRecv $ ctxConnection c
    updateMeasure c . addBytesReceived $ recordLength rec
    return rec

ctxEOF :: Context m -> m Bool
ctxEOF = readMRef . ctxEOF_

ctxHasSSLv2ClientHello :: Context m -> m Bool
ctxHasSSLv2ClientHello ctx = readMRef $ ctxSSLv2ClientHello ctx

ctxDisableSSLv2ClientHello :: Context m -> m ()
ctxDisableSSLv2ClientHello ctx = writeMRef (ctxSSLv2ClientHello ctx) False

setEOF :: Context m -> m ()
setEOF ctx = writeMRef (ctxEOF_ ctx) True

ctxEstablished :: Context m -> m Bool
ctxEstablished ctx = readMRef $ ctxEstablished_ ctx

ctxNeedEmptyPacket :: Context m -> m Bool
ctxNeedEmptyPacket = readMRef . ctxNeedEmptyPacket_

ctxWithHooks :: Monad m => Context m -> (Hooks m -> m a) -> m a
ctxWithHooks ctx f = readMRef (ctxHooks ctx) >>= f

contextModifyHooks :: Monad m => Context m -> (Hooks m -> Hooks m) -> m ()
contextModifyHooks ctx f = modifyMRef (ctxHooks ctx) f

setEstablished :: Context m -> Bool -> m ()
setEstablished ctx v = writeMRef (ctxEstablished_ ctx) v

setNeedEmptyPacket :: Context m -> Bool -> m ()
setNeedEmptyPacket = writeMRef . ctxNeedEmptyPacket_

withLog :: Monad m => Context m -> (Logging m -> m ()) -> m ()
withLog ctx f = ctxWithHooks ctx (f . hookLogging)

throwCore :: (MonadThrow m, Exception e) => e -> m a
throwCore = throwM

failOnEitherError :: MonadThrow m => m (Either TLSError a) -> m a
failOnEitherError f = do
    ret <- f
    case ret of
        Left err -> throwCore err
        Right r  -> return r

usingState :: Monad m => Context m -> TLSSt a -> m (Either TLSError a)
usingState ctx f =
    ctxState ctx $ \st ->
            let (a, newst) = runTLSState f st
             in newst `seq` return (a, newst)

usingState_ :: MonadThrow m => Context m -> TLSSt a -> m a
usingState_ ctx f = failOnEitherError $ usingState ctx f

usingHState :: MonadThrow m => Context m -> HandshakeM a -> m a
usingHState ctx f = ctxHandshake ctx $ \mst ->
    case mst of
        Nothing -> throwCore $ Error_Misc "missing handshake"
        Just st -> return (Just <$> runHandshake st f)

getHState :: Monad m => Context m -> m (Maybe HandshakeState)
getHState ctx = readMMVar (ctxHandshake ctx)

runTxState :: MonadThrow m => Context m -> RecordM a -> m (Either TLSError a)
runTxState ctx f = do
    ver <- usingState_ ctx (getVersionWithDefault $ maximum $ supportedVersions $ ctxSupported ctx)
    ctxTxState ctx $ \st ->
        case runRecordM f ver st of
            Left err         -> return (Left err, st)
            Right (a, newSt) -> return (Right a, newSt)

runRxState :: MonadThrow m => Context m -> RecordM a -> m (Either TLSError a)
runRxState ctx f = do
    ver <- usingState_ ctx getVersion
    ctxRxState ctx $ \st ->
        case runRecordM f ver st of
            Left err         -> return (Left err, st)
            Right (a, newSt) -> return (Right a, newSt)

getStateRNG :: MonadThrow m => Context m -> Int -> m ByteString
getStateRNG ctx n = usingState_ ctx $ genRandom n

withReadLock :: Context m -> m a -> m a
withReadLock = ctxLockRead

withWriteLock :: Context m -> m a -> m a
withWriteLock = ctxLockWrite

withRWLock :: Context m -> m a -> m a
withRWLock ctx f = withReadLock ctx $ withWriteLock ctx f

withStateLock :: Context m -> m a -> m a
withStateLock = ctxLockState
