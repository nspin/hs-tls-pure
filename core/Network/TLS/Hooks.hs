-- |
-- Module      : Network.TLS.Context
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Hooks
    ( Logging(..)
    , Hooks(..)
    , defaultHooks
    ) where

import qualified Data.ByteString as B
import Network.TLS.Struct (Header, Handshake(..))
import Network.TLS.X509 (CertificateChain)
import Data.Default.Class

-- | Hooks for logging
--
-- This is called when sending and receiving packets and IO
data Logging m = Logging
    { loggingPacketSent :: String -> m ()
    , loggingPacketRecv :: String -> m ()
    , loggingMSent      :: B.ByteString -> m ()
    , loggingMRecv      :: Header -> B.ByteString -> m ()
    }

defaultLogging :: Monad m => Logging m
defaultLogging = Logging
    { loggingPacketSent = \_ -> return ()
    , loggingPacketRecv = \_ -> return ()
    , loggingMSent      = \_ -> return ()
    , loggingMRecv      = \_ _ -> return ()
    }

instance Monad m => Default (Logging m) where
    def = defaultLogging

-- | A collection of hooks actions.
data Hooks m = Hooks
    { -- | called at each handshake message received
      hookRecvHandshake    :: Handshake -> m Handshake
      -- | called at each certificate chain message received
    , hookRecvCertificates :: CertificateChain -> m ()
      -- | hooks on IO and packets, receiving and sending.
    , hookLogging          :: Logging m
    }

defaultHooks :: Monad m => Hooks m
defaultHooks = Hooks
    { hookRecvHandshake    = return
    , hookRecvCertificates = return . const ()
    , hookLogging          = def
    }

instance Monad m => Default (Hooks m) where
    def = defaultHooks
