module Network.TLS.Pure.Packet where

import qualified Data.Vector as V
import           Data.Foldable

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Network.TLS.Pure.Record as Record

newtype TLSPacket = TLSPacket { getTlsPacket :: V.Vector Record.TLSRecord }

instance Serialization.ToWire TLSPacket where
  encode (TLSPacket records) = traverse_ Serialization.encode records
