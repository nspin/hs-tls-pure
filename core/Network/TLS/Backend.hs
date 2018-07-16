{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
-- |
-- Module      : Network.TLS.Backend
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A Backend represents a unified way to do IO on different
-- types without burdening our calling API with multiple
-- ways to initialize a new context.
--
-- Typically, a backend provides:
-- * a way to read data
-- * a way to write data
-- * a way to close the stream
-- * a way to flush the stream
--
module Network.TLS.Backend
    ( HasBackend(..)
    , Backend(..)
    ) where

import Network.TLS.Imports
import qualified Data.ByteString as B
import System.IO (Handle, hSetBuffering, BufferMode(..), hFlush, hClose)

#ifdef INCLUDE_NETWORK
import qualified Network.Socket as Network (Socket, close)
import qualified Network.Socket.ByteString as Network
#endif

#ifdef INCLUDE_HANS
import qualified Data.ByteString.Lazy as L
import qualified Hans.NetworkStack as Hans
#endif

-- | Connection IO backend
data Backend m = Backend
    { backendFlush :: m ()                -- ^ Flush the connection sending buffer, if any.
    , backendClose :: m ()                -- ^ Close the connection.
    , backendSend  :: ByteString -> m ()  -- ^ Send a bytestring through the connection.
    , backendRecv  :: Int -> m ByteString -- ^ Receive specified number of bytes from the connection.
    }

class HasBackend m a | a -> m where
    initializeBackend :: a -> m ()
    getBackend :: a -> Backend m

instance Monad m => HasBackend m (Backend m) where
    initializeBackend _ = return ()
    getBackend = id

#if defined(__GLASGOW_HASKELL__) && WINDOWS
-- Socket recv and accept calls on Windows platform cannot be interrupted when compiled with -threaded.
-- See https://ghc.haskell.org/trac/ghc/ticket/5797 for details.
-- The following enables simple workaround
#define SOCKET_ACCEPT_RECV_WORKAROUND
#endif

safeRecv :: Network.Socket -> Int -> IO ByteString
#ifndef SOCKET_ACCEPT_RECV_WORKAROUND
safeRecv = Network.recv
#else
safeRecv s buf = do
    var <- newEmptyMVar
    forkIO $ Network.recv s buf `E.catch` (\(_::IOException) -> return S8.empty) >>= putMVar var
    takeMVar var
#endif

#ifdef INCLUDE_NETWORK
instance HasBackend IO Network.Socket where
    initializeBackend _ = return ()
    getBackend sock = Backend (return ()) (Network.close sock) (Network.sendAll sock) recvAll
      where recvAll n = B.concat <$> loop n
              where loop 0    = return []
                    loop left = do
                        r <- safeRecv sock left
                        if B.null r
                            then return []
                            else liftM (r:) (loop (left - B.length r))
#endif

#ifdef INCLUDE_HANS
instance HasBackend IO Hans.Socket where
    initializeBackend _ = return ()
    getBackend sock = Backend (return ()) (Hans.close sock) sendAll recvAll
      where sendAll x = do
              amt <- fromIntegral <$> Hans.sendBytes sock (L.fromStrict x)
              if (amt == 0) || (amt == B.length x)
                 then return ()
                 else sendAll (B.drop amt x)
            recvAll n = loop (fromIntegral n) L.empty
            loop    0 acc = return (L.toStrict acc)
            loop left acc = do
                r <- Hans.recvBytes sock left
                if L.null r
                   then loop 0 acc
                   else loop (left - L.length r) (acc `L.append` r)
#endif

instance HasBackend IO Handle where
    initializeBackend handle = hSetBuffering handle NoBuffering
    getBackend handle = Backend (hFlush handle) (hClose handle) (B.hPut handle) (B.hGet handle)
