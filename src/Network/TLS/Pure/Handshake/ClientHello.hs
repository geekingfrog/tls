{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE StrictData #-}

module Network.TLS.Pure.Handshake.ClientHello where

import           Control.Monad
import qualified Data.ByteString                        as BS
import qualified Data.Serialize.Put                     as Put

import qualified Network.TLS.Pure.Cipher                as Cipher
import qualified Network.TLS.Pure.Error                 as Err
import qualified Network.TLS.Pure.Extension             as Extension
import qualified Network.TLS.Pure.Handshake.Common      as H.C
import qualified Network.TLS.Pure.Handshake.MessageType as H.MT
import qualified Network.TLS.Pure.Serialization         as S
import qualified Network.TLS.Pure.Version               as Version

data ClientHello13Data = ClientHello13Data
  { chlo13dRandom :: H.C.Random -- 32 bytes
  , chlo13dLegacySessionId :: S.Opaque8 -- should be random garbage
  , chlo13dCipherSuites :: Cipher.CipherSuites
  , chlo13dExtensions :: Extension.Extensions 'H.MT.ClientHello
  }
  deriving (Eq, Show)

instance S.ToWire ClientHello13Data where
  encode chlo = do
    S.encode Version.TLS12 -- legacy version
    S.encode (chlo13dRandom chlo)
    S.encode (chlo13dLegacySessionId chlo)
    S.encode (chlo13dCipherSuites chlo)
    Put.putWord8 1 *> Put.putWord8 0 -- legacy compression method
    S.encode (chlo13dExtensions chlo)

instance S.FromWire ClientHello13Data where
  decode = do
    (_legacyVersion :: Version.ProtocolVersion) <- S.decode
    chlo13dRandom <- S.decode
    chlo13dLegacySessionId <- S.decode
    chlo13dCipherSuites <- S.decode
    compressionMethodLen <- S.getWord8
    compressionMethod <- S.getWord8
    when (compressionMethodLen /= 1 || compressionMethod /= 0) $
      S.throwError $ Err.InvalidCompressionMethod compressionMethodLen compressionMethod

    chlo13dExtensions <- S.decode

    pure $ ClientHello13Data{..}
