{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
-- |
-- Module      : Network.TLS.Pure
-- License     : BSD-style
-- Maintainer  : Nick Spinale <nick@nickspinale.com>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Pure
    ( TLSPureT(..)
    , TLSMutState
    , contextNewPure
    ) where

import Network.TLS.Backend
import Network.TLS.Context (TLSParams(..))
import Network.TLS.Context.Internal
import Network.TLS.Handshake.State (HandshakeState)
import Network.TLS.Hooks
import Network.TLS.Measurement
import Network.TLS.Record.State
import Network.TLS.RNG
import Network.TLS.State
import Network.TLS.Types (Role(..))

import Control.Lens (Lens', use, assign, makeLenses)
import Control.Monad.State.Strict

data TLSMutState m = TLSMutState
    { _tlsMutState            :: TLSState
    , _tlsMutMeasurement      :: Measurement
    , _tlsMutEOF_             :: Bool
    , _tlsMutEstablished_     :: Bool
    , _tlsMutNeedEmptyPacket_ :: Bool
    , _tlsMutSSLv2ClientHello :: Bool
    , _tlsMutTxState          :: RecordState
    , _tlsMutRxState          :: RecordState
    , _tlsMutHandshake        :: Maybe HandshakeState
    , _tlsMutHooks            :: Hooks m
    }

makeLenses ''TLSMutState

newtype TLSPureT m a = TLSPureT { runTLSPureT :: StateT (TLSMutState (TLSPureT m)) m a }
    deriving (Functor, Applicative, Monad)

instance MonadTrans TLSPureT where
    lift = TLSPureT . lift

-- | Ignores 'DebugParams', because a seed is specified anyways.
contextNewPure :: forall m params. (Monad m, TLSParams (TLSPureT m) params)
               => Seed
               -> Backend (TLSPureT m)
               -> params
               -> (TLSMutState (TLSPureT m), Context (TLSPureT m))
contextNewPure seed backend params = (st, ctx)
  where
    (supported, shared, _) = getTLSCommonParams params
    rng = newStateRNG seed
    role = getTLSRole params

    st = TLSMutState
        { _tlsMutState            = newTLSState rng role
        , _tlsMutMeasurement      = newMeasurement
        , _tlsMutEOF_             = False
        , _tlsMutEstablished_     = False
        , _tlsMutNeedEmptyPacket_ = False
        , _tlsMutSSLv2ClientHello = role == ServerRole
        , _tlsMutTxState          = newRecordState
        , _tlsMutRxState          = newRecordState
        , _tlsMutHandshake        = Nothing
        , _tlsMutHooks            = defaultHooks
        }

    mkRef :: Lens' (TLSMutState (TLSPureT m)) c -> (TLSPureT m c, c -> TLSPureT m ())
    mkRef l = (TLSPureT (use l), TLSPureT . assign l)

    mkVar :: Lens' (TLSMutState (TLSPureT m)) c -> (forall a. (c -> TLSPureT m (a, c)) -> TLSPureT m a)
    mkVar l f = TLSPureT $ fst <$> (use l >>= runTLSPureT . f)

    ctx = Context
        { ctxConnection       = backend
        , ctxShared           = shared
        , ctxSupported        = supported
        , ctxState            = mkVar tlsMutState
        , ctxTxState          = mkVar tlsMutTxState
        , ctxRxState          = mkVar tlsMutRxState
        , ctxHandshake        = mkVar tlsMutHandshake
        , ctxDoHandshake      = doHandshake params
        , ctxDoHandshakeWith  = doHandshakeWith params
        , ctxMeasurement      = mkRef tlsMutMeasurement
        , ctxEOF_             = mkRef tlsMutEOF_
        , ctxEstablished_     = mkRef tlsMutEstablished_
        , ctxSSLv2ClientHello = mkRef tlsMutSSLv2ClientHello
        , ctxNeedEmptyPacket_ = mkRef tlsMutNeedEmptyPacket_
        , ctxHooks            = mkRef tlsMutHooks
        , ctxLockWrite        = id
        , ctxLockRead         = id
        , ctxLockState        = id
        }
