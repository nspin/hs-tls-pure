{-# LANGUAGE OverloadedStrings #-}
module Network.TLS.Handshake.Common
    ( handshakeFailed
    , errorToAlert
    , unexpected
    , newSession
    , handshakeTerminate
    -- * sending packets
    , sendChangeCipherAndFinish
    -- * receiving packets
    , recvChangeCipherAndFinish
    , RecvState(..)
    , runRecvState
    , recvPacketHandshake
    , onRecvStateHandshake
    , extensionLookup
    ) where

import Network.TLS.Parameters
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Session
import Network.TLS.Struct
import Network.TLS.IO
import Network.TLS.State hiding (getNegotiatedProtocol)
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.State
import Network.TLS.Record.State
import Network.TLS.Measurement
import Network.TLS.Types
import Network.TLS.Cipher
import Network.TLS.Util
import Network.TLS.Imports

import Control.Monad.Catch (MonadThrow, throwM)
import Control.Monad.State.Strict

handshakeFailed :: MonadThrow m => TLSError -> m ()
handshakeFailed err = throwM $ HandshakeFailed err

errorToAlert :: TLSError -> Packet
errorToAlert (Error_Protocol (_, _, ad)) = Alert [(AlertLevel_Fatal, ad)]
errorToAlert _                           = Alert [(AlertLevel_Fatal, InternalError)]

unexpected :: MonadThrow m => String -> Maybe String -> m a
unexpected msg expected = throwCore $ Error_Packet_unexpected msg (maybe "" (" expected: " ++) expected)

newSession :: MonadThrow m => Context m -> m Session
newSession ctx
    | supportedSession $ ctxSupported ctx = Session . Just <$> getStateRNG ctx 32
    | otherwise                           = return $ Session Nothing

-- | when a new handshake is done, wrap up & clean up.
handshakeTerminate :: MonadThrow m => Context m -> m ()
handshakeTerminate ctx = do
    session <- usingState_ ctx getSession
    -- only callback the session established if we have a session
    case session of
        Session (Just sessionId) -> do
            sessionData <- getSessionData ctx
            sessionEstablish (sharedSessionManager $ ctxShared ctx) sessionId (fromJust "session-data" sessionData)
        _ -> return ()
    -- forget most handshake data and reset bytes counters.
    let f hshake = (newEmptyHandshake (hstClientVersion hshake) (hstClientRandom hshake))
            { hstServerRandom = hstServerRandom hshake
            , hstMasterSecret = hstMasterSecret hshake
            }
    usingHState ctx (modify f)
    updateMeasure ctx resetBytesCounters
    -- mark the secure connection up and running.
    setEstablished ctx True

sendChangeCipherAndFinish :: MonadThrow m
                          => Context m
                          -> Role
                          -> m ()
sendChangeCipherAndFinish ctx role = do
    sendPacket ctx ChangeCipherSpec
    contextFlush ctx
    cf <- usingState_ ctx getVersion >>= \ver -> usingHState ctx $ getHandshakeDigest ver role
    sendPacket ctx (Handshake [Finished cf])
    contextFlush ctx

recvChangeCipherAndFinish :: MonadThrow m => Context m -> m ()
recvChangeCipherAndFinish ctx = runRecvState ctx (RecvStateNext expectChangeCipher)
  where expectChangeCipher ChangeCipherSpec = return $ RecvStateHandshake expectFinish
        expectChangeCipher p                = unexpected (show p) (Just "change cipher")
        expectFinish (Finished _) = return RecvStateDone
        expectFinish p            = unexpected (show p) (Just "Handshake Finished")

data RecvState m =
      RecvStateNext (Packet -> m (RecvState m))
    | RecvStateHandshake (Handshake -> m (RecvState m))
    | RecvStateDone

recvPacketHandshake :: MonadThrow m => Context m -> m [Handshake]
recvPacketHandshake ctx = do
    pkts <- recvPacket ctx
    case pkts of
        Right (Handshake l) -> return l
        Right x             -> fail ("unexpected type received. expecting handshake and got: " ++ show x)
        Left err            -> throwCore err

-- | process a list of handshakes message in the recv state machine.
onRecvStateHandshake :: MonadThrow m => Context m -> RecvState m -> [Handshake] -> m (RecvState m)
onRecvStateHandshake _   recvState [] = return recvState
onRecvStateHandshake ctx (RecvStateHandshake f) (x:xs) = do
    nstate <- f x
    processHandshake ctx x
    onRecvStateHandshake ctx nstate xs
onRecvStateHandshake _ _ _   = unexpected "spurious handshake" Nothing

runRecvState :: MonadThrow m => Context m -> RecvState m -> m ()
runRecvState _    RecvStateDone    = return ()
runRecvState ctx (RecvStateNext f) = recvPacket ctx >>= either throwCore f >>= runRecvState ctx
runRecvState ctx iniState          = recvPacketHandshake ctx >>= onRecvStateHandshake ctx iniState >>= runRecvState ctx

getSessionData :: MonadThrow m => Context m -> m (Maybe SessionData)
getSessionData ctx = do
    ver <- usingState_ ctx getVersion
    sni <- usingState_ ctx getClientSNI
    mms <- usingHState ctx (gets hstMasterSecret)
    tx  <- ctxTxState ctx get
    case mms of
        Nothing -> return Nothing
        Just ms -> return $ Just SessionData
                        { sessionVersion     = ver
                        , sessionCipher      = cipherID $ fromJust "cipher" $ stCipher tx
                        , sessionCompression = compressionID $ stCompression tx
                        , sessionClientSNI   = sni
                        , sessionSecret      = ms
                        }

extensionLookup :: ExtensionID -> [ExtensionRaw] -> Maybe ByteString
extensionLookup toFind = fmap (\(ExtensionRaw _ content) -> content)
                       . find (\(ExtensionRaw eid _) -> eid == toFind)
