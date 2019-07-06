{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Pure.Handshake.ServerHello where

import qualified Network.TLS.Pure.Cipher           as Cipher
import qualified Network.TLS.Pure.Handshake.Common as H.C
import qualified Network.TLS.Pure.Serialization    as S
import qualified Network.TLS.Pure.Version          as Version
import qualified Network.TLS.Pure.Handshake.MessageType as H.MT
import qualified Network.TLS.Pure.Extension as Extension


data ServerHello13Data = ServerHello13Data
  { shlo13dRandom :: H.C.Random
  , shlo13dLegacySessionId :: S.Opaque8
  , shlo13dCipherSuite :: Cipher.Cipher
  , shlo13dExtensions :: Extension.Extensions 'H.MT.ServerHello
  }

instance S.FromWire ServerHello13Data where
  decode = do
    -- ignore legacy version
    (_ :: Version.ProtocolVersion) <- S.decode
    shlo13dRandom <- S.decode
    shlo13dLegacySessionId <- S.decode
    shlo13dCipherSuite <- S.decode
    S.getWord8 -- compression method
    shlo13dExtensions <- S.decode

    pure $ ServerHello13Data{..}
    -- error "wip decode server hello data"
