-- |
-- Module      : Network.TLS.Session
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Session
    ( SessionManager(..)
    , noSessionManager
    ) where

import Network.TLS.Types

-- | A session manager
data SessionManager m = SessionManager
    { -- | used on server side to decide whether to resume a client session.
      sessionResume     :: SessionID -> m (Maybe SessionData)
      -- | used when a session is established.
    , sessionEstablish  :: SessionID -> SessionData -> m ()
      -- | used when a session is invalidated.
    , sessionInvalidate :: SessionID -> m ()
    }

noSessionManager :: Monad m => SessionManager m
noSessionManager = SessionManager
    { sessionResume     = \_   -> return Nothing
    , sessionEstablish  = \_ _ -> return ()
    , sessionInvalidate = \_   -> return ()
    }
