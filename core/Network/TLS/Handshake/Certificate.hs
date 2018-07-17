-- |
-- Module      : Network.TLS.Handshake.Certificate
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Certificate
    ( certificateRejected
    , badCertificate
    , rejectOnException
    , verifyLeafKeyUsage
    ) where

import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.X509
import Control.Monad.Catch (MonadThrow, SomeException)
import Control.Monad.State.Strict
import Data.X509 (ExtKeyUsage(..), ExtKeyUsageFlag, extensionGet, getSigned, signedObject)

-- on certificate reject, throw an exception with the proper protocol alert error.
certificateRejected :: MonadThrow m => CertificateRejectReason -> m a
certificateRejected CertificateRejectRevoked =
    throwCore $ Error_Protocol ("certificate is revoked", True, CertificateRevoked)
certificateRejected CertificateRejectExpired =
    throwCore $ Error_Protocol ("certificate has expired", True, CertificateExpired)
certificateRejected CertificateRejectUnknownCA =
    throwCore $ Error_Protocol ("certificate has unknown CA", True, UnknownCa)
certificateRejected (CertificateRejectOther s) =
    throwCore $ Error_Protocol ("certificate rejected: " ++ s, True, CertificateUnknown)

badCertificate :: MonadThrow m => String -> m a
badCertificate msg = throwCore $ Error_Protocol (msg, True, BadCertificate)

rejectOnException :: Monad m => SomeException -> m CertificateUsage
rejectOnException e = return $ CertificateUsageReject $ CertificateRejectOther $ show e

verifyLeafKeyUsage :: MonadThrow m => ExtKeyUsageFlag -> CertificateChain -> m ()
verifyLeafKeyUsage _    (CertificateChain [])         = return ()
verifyLeafKeyUsage flag (CertificateChain (signed:_)) =
    unless verified $
        badCertificate $ "certificate is not allowed for " ++ show flag
  where
    cert     = signedObject $ getSigned signed
    verified =
        case extensionGet (certExtensions cert) of
            Nothing                          -> True -- unrestricted cert
            Just (ExtKeyUsage flags)         -> flag `elem` flags
