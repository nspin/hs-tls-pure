{-# LANGUAGE CPP #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
-- |
-- Module      : Network.TLS.Context
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Context
    (
    -- * Context configuration
      TLSParams(..)

    -- * Context object and accessor
    , Context(..)
    , Hooks(..)
    , ctxEOF
    , ctxHasSSLv2ClientHello
    , ctxDisableSSLv2ClientHello
    , ctxEstablished
    , withLog
    , ctxWithHooks
    , contextModifyHooks
    , setEOF
    , setEstablished
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

    -- * New contexts
    , contextNew
    -- * Deprecated new contexts methods
    , contextNewOnHandle
#ifdef INCLUDE_NETWORK
    , contextNewOnSocket
#endif

    -- * Context hooks
    , contextHookSetHandshakeRecv
    , contextHookSetCertificateRecv
    , contextHookSetLogging

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
import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.State
import Network.TLS.Hooks
import Network.TLS.Record.State
import Network.TLS.Parameters
import Network.TLS.Measurement
import Network.TLS.Types (Role(..))
import Network.TLS.Handshake (handshakeClient, handshakeClientWith, handshakeServer, handshakeServerWith)
import Network.TLS.X509
import Network.TLS.RNG

import Control.Concurrent.MVar
import Control.Monad.Catch (MonadCatch)
import Data.IORef
import Data.Tuple

-- deprecated imports
#ifdef INCLUDE_NETWORK
import Network.Socket (Socket)
#endif
import System.IO (Handle)

class TLSParams m a | a -> m where
    getTLSCommonParams :: a -> CommonParams m
    getTLSRole         :: a -> Role
    doHandshake        :: a -> Context m -> m ()
    doHandshakeWith    :: a -> Context m -> Handshake -> m ()

instance MonadCatch m => TLSParams m (ClientParams m) where
    getTLSCommonParams cparams = ( clientSupported cparams
                                 , clientShared cparams
                                 , clientDebug cparams
                                 )
    getTLSRole _ = ClientRole
    doHandshake = handshakeClient
    doHandshakeWith = handshakeClientWith

instance MonadCatch m => TLSParams m (ServerParams m) where
    getTLSCommonParams sparams = ( serverSupported sparams
                                 , serverShared sparams
                                 , serverDebug sparams
                                 )
    getTLSRole _ = ServerRole
    doHandshake = handshakeServer
    doHandshakeWith = handshakeServerWith

-- | create a new context using the backend and parameters specified.
contextNew :: (HasBackend IO backend, TLSParams IO params)
           => backend   -- ^ Backend abstraction with specific method to interact with the connection type.
           -> params    -- ^ Parameters of the context.
           -> IO (Context IO)
contextNew backend params = do
    initializeBackend backend

    let (supported, shared, debug) = getTLSCommonParams params

    seed <- case debugSeed debug of
                Nothing     -> do seed <- seedNew
                                  debugPrintSeed debug seed
                                  return seed
                Just determ -> return determ
    let rng = newStateRNG seed

    let role = getTLSRole params
        st   = newTLSState rng role

    stvar <- newMVar st
    eof   <- newIORef False
    established <- newIORef False
    stats <- newIORef newMeasurement
    -- we enable the reception of SSLv2 ClientHello message only in the
    -- server context, where we might be dealing with an old/compat client.
    sslv2Compat <- newIORef (role == ServerRole)
    needEmptyPacket <- newIORef False
    hooks <- newIORef defaultHooks
    tx    <- newMVar newRecordState
    rx    <- newMVar newRecordState
    hs    <- newMVar Nothing
    lockWrite <- newMVar ()
    lockRead  <- newMVar ()
    lockState <- newMVar ()

    let fromMVar v f = modifyMVar v $ fmap swap . f

    return Context
            { ctxConnection   = getBackend backend
            , ctxShared       = shared
            , ctxSupported    = supported
            , ctxState        = fromMVar stvar
            , ctxTxState      = fromMVar tx
            , ctxRxState      = fromMVar rx
            , ctxHandshake    = fromMVar hs
            , ctxDoHandshake  = doHandshake params
            , ctxDoHandshakeWith  = doHandshakeWith params
            , ctxMeasurement  = (readIORef stats, writeIORef stats)
            , ctxEOF_         = (readIORef eof, writeIORef eof)
            , ctxEstablished_ = (readIORef established, writeIORef established)
            , ctxSSLv2ClientHello = (readIORef sslv2Compat, writeIORef sslv2Compat)
            , ctxNeedEmptyPacket_ = (readIORef needEmptyPacket, writeIORef needEmptyPacket)
            , ctxHooks            = (readIORef hooks, writeIORef hooks)
            , ctxLockWrite        = withMVar lockWrite . const
            , ctxLockRead         = withMVar lockRead . const
            , ctxLockState        = withMVar lockState . const
            }

-- | create a new context on an handle.
contextNewOnHandle :: TLSParams IO params
                   => Handle -- ^ Handle of the connection.
                   -> params -- ^ Parameters of the context.
                   -> IO (Context IO)
contextNewOnHandle handle params = contextNew handle params
{-# DEPRECATED contextNewOnHandle "use contextNew" #-}

#ifdef INCLUDE_NETWORK
-- | create a new context on a socket.
contextNewOnSocket :: TLSParams IO params
                   => Socket -- ^ Socket of the connection.
                   -> params -- ^ Parameters of the context.
                   -> IO (Context IO)
contextNewOnSocket sock params = contextNew sock params
{-# DEPRECATED contextNewOnSocket "use contextNew" #-}
#endif

contextHookSetHandshakeRecv :: Monad m => Context m -> (Handshake -> m Handshake) -> m ()
contextHookSetHandshakeRecv context f =
    contextModifyHooks context (\hooks -> hooks { hookRecvHandshake = f })

contextHookSetCertificateRecv :: Monad m => Context m -> (CertificateChain -> m ()) -> m ()
contextHookSetCertificateRecv context f =
    contextModifyHooks context (\hooks -> hooks { hookRecvCertificates = f })

contextHookSetLogging :: Monad m => Context m -> Logging m -> m ()
contextHookSetLogging context loggingCallbacks =
    contextModifyHooks context (\hooks -> hooks { hookLogging = loggingCallbacks })
