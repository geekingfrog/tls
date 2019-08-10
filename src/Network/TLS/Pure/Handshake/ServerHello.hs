{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StrictData          #-}

module Network.TLS.Pure.Handshake.ServerHello where

import           Control.Monad
import qualified Data.Serialize.Put                     as Put

import qualified Network.TLS.Pure.Cipher                as Cipher
import qualified Network.TLS.Pure.Extension             as Extension
import qualified Network.TLS.Pure.Handshake.Common      as H.C
import qualified Network.TLS.Pure.Handshake.MessageType as H.MT
import qualified Network.TLS.Pure.Serialization         as S
import qualified Network.TLS.Pure.Version               as Version


data ServerHello13Data = ServerHello13Data
  { shlo13dRandom :: H.C.Random
  , shlo13dLegacySessionId :: S.Opaque8
  , shlo13dCipherSuite :: Cipher.Cipher
  , shlo13dExtensions :: Extension.Extensions 'H.MT.ServerHello
  }
  deriving (Eq, Show)

instance S.FromWire ServerHello13Data where
  decode = do
    -- ignore legacy version
    (_ :: Version.ProtocolVersion) <- S.decode
    shlo13dRandom <- S.decode
    shlo13dLegacySessionId <- S.decode
    shlo13dCipherSuite <- S.decode
    void S.getWord8 -- compression method
    shlo13dExtensions <- S.decode

    -- TODO perhaps validate the serverHello there, some extensions *must*
    -- be present (like supported versions &co)
    -- TODO check that there is no duplicate in the extensions

    pure $ ServerHello13Data{..}

instance S.ToWire ServerHello13Data where
  encode shlo = do
    S.encode Version.TLS12 -- legacy version
    S.encode (shlo13dRandom shlo)
    S.encode (shlo13dLegacySessionId shlo)
    S.encode (shlo13dCipherSuite shlo)
    Put.putWord8 0 -- compression method
    S.encode (shlo13dExtensions shlo)
