module Network.TLS.Pure.Handshake.Common where

import qualified Data.Serialize.Put             as Put
import qualified Data.ByteString                as BS

import qualified Network.TLS.Pure.Serialization as S

-- TODO Random32? or make sure it's only 32 bytes
newtype Random = Random { getRandom :: BS.ByteString }

instance S.ToWire Random where
  encode (Random bytes) = Put.putByteString bytes

instance S.FromWire Random where
  decode = Random <$> S.getByteString 32
