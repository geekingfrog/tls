module Network.TLS.Pure.Packet where

import qualified Data.Vector as V
import           Data.Foldable
import qualified Control.Monad.Loops as Loops
import qualified Data.Serialize as S

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Network.TLS.Pure.Record as Record

newtype TLSPacket = TLSPacket { getTlsPacket :: V.Vector Record.TLSRecord }

instance Serialization.ToWire TLSPacket where
  encode (TLSPacket records) = traverse_ Serialization.encode records

instance Serialization.FromWire TLSPacket where
  decode = TLSPacket . V.singleton <$> Serialization.decode
  -- decode = TLSPacket . V.fromList <$> Loops.untilM Serialization.decode S.isEmpty
