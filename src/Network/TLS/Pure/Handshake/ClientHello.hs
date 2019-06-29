{-# LANGUAGE DataKinds #-}
{-# LANGUAGE StrictData #-}

module Network.TLS.Pure.Handshake.ClientHello where

import qualified Data.ByteString as BS
import qualified Data.Serialize.Put as S

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Network.TLS.Pure.Cipher as Cipher
import qualified Network.TLS.Pure.Extension as Extension
import qualified Network.TLS.Pure.Version as Version
import qualified Network.TLS.Pure.Handshake.MessageType as H.MT

newtype Random = Random { getRandom :: BS.ByteString }

instance Serialization.ToWire Random where
  encode (Random bytes) = S.putByteString bytes

data ClientHello13Data = ClientHello13Data
  { chlo13dCipherSuites :: Cipher.CipherSuites
  , chlo13dExtensions :: Extension.Extensions 'H.MT.ClientHello
  , chlo13dRandom :: Random -- 32 bytes
  , chlo13dLegacySessionId :: Serialization.Opaque8 -- should be random garbage
  }

instance Serialization.ToWire ClientHello13Data where
  encode chlo = do
    Serialization.encode Version.TLS12 -- legacy version
    Serialization.encode (chlo13dRandom chlo)
    Serialization.encode (chlo13dLegacySessionId chlo)
    Serialization.encode (chlo13dCipherSuites chlo)
    S.putWord8 1 *> S.putWord8 0 -- legacy compression method
    Serialization.encode (chlo13dExtensions chlo)
