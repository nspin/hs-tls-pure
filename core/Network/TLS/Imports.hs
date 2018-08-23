{-# LANGUAGE CPP #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-dodgy-exports #-} -- Char8

-- |
-- Module      : Network.TLS.Imports
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Imports
    (
    -- generic exports
      ByteString
    , module Data.ByteString.Char8 -- instance
    , module Control.Applicative
    , module Control.Monad
    , module Data.Bits
    , module Data.List
    , module Data.Maybe
#if MIN_VERSION_base(4,9,0)
    , module Data.Semigroup
#else
    , module Data.Monoid
#endif
    , module Data.Ord
    , module Data.Word
#if !MIN_VERSION_base(4,8,0)
    , sortOn
#endif
    , module Data.Functor
    , module Control.Monad.State.Strict
    -- project definition
    , showBytesHex
    ) where

import Data.ByteString (ByteString)
import Data.ByteString.Char8 ()

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.List
import Data.Maybe hiding (fromJust)
#if MIN_VERSION_base(4,9,0)
import Data.Semigroup
#else
import Data.Monoid
#endif
import Data.Ord
import Data.Word

import Data.ByteArray.Encoding as B
import qualified Prelude as P

import Data.Functor
import Control.Monad.State.Strict (State, state, modify, put, get, gets)

#if !MIN_VERSION_base(4,8,0)
import Prelude ((.))

sortOn :: Ord b => (a -> b) -> [a] -> [a]
sortOn f =
  map P.snd . sortBy (comparing P.fst) . map (\x -> let y = f x in y `P.seq` (y, x))
#endif

showBytesHex :: ByteString -> P.String
showBytesHex bs = P.show (B.convertToBase B.Base16 bs :: ByteString)

