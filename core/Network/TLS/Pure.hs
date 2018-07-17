{-# LANGUAGE FlexibleContexts #-}
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
    ( TLSMutState
    , contextNewPure
    ) where

import Network.TLS.Backend
import Network.TLS.Context (TLSParams(..))
import Network.TLS.Context.Internal
import Network.TLS.Handshake.State (HandshakeState)
import Network.TLS.Measurement
import Network.TLS.Record.State
import Network.TLS.RNG
import Network.TLS.State
import Network.TLS.Types (Role(..))

import Control.Lens (Lens', use, assign, makeLenses)
import Control.Monad.State.Strict

data TLSMutState = TLSMutState
    { _tlsMutState            :: TLSState
    , _tlsMutMeasurement      :: Measurement
    , _tlsMutEOF_             :: Bool
    , _tlsMutEstablished_     :: Bool
    , _tlsMutNeedEmptyPacket_ :: Bool
    , _tlsMutSSLv2ClientHello :: Bool
    , _tlsMutTxState          :: RecordState
    , _tlsMutRxState          :: RecordState
    , _tlsMutHandshake        :: Maybe HandshakeState
    }

makeLenses ''TLSMutState

-- | Ignores 'DebugParams', because a seed is specified anyways.
contextNewPure :: forall m params. (Monad m, TLSParams (StateT TLSMutState m) params)
               => Seed
               -> Backend (StateT TLSMutState m)
               -> params
               -> Hooks (StateT TLSMutState m)
               -> (TLSMutState, Context (StateT TLSMutState m))
contextNewPure seed backend params hooks = (st, ctx)
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
        }

    mkRef :: Lens' TLSMutState c -> (StateT TLSMutState m c, c -> StateT TLSMutState m ())
    mkRef l = (use l, assign l)

    mkVar :: Lens' TLSMutState c -> (forall a. (c -> StateT TLSMutState m (a, c)) -> StateT TLSMutState m a)
    mkVar l f = use l >>= f >>= \(a, c) -> a <$ assign l c

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
        , ctxHooks            = (return hooks, error "hooks immutable") -- TODO
        , ctxLockWrite        = id
        , ctxLockRead         = id
        , ctxLockState        = id
        }
