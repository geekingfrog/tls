module Network.TLS.Pure.Packet where

import qualified Data.Vector as V
import           Data.Foldable
import qualified Control.Monad.Loops as Loops

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Network.TLS.Pure.Record as Record

newtype TLSPacket = TLSPacket { getTlsPacket :: V.Vector Record.TLSRecord }
  deriving (Show)

instance Serialization.ToWire TLSPacket where
  encode (TLSPacket records) = traverse_ Serialization.encode records

instance Serialization.FromWire TLSPacket where
  -- TODO fix that, there are multiple packets
  decode = TLSPacket . V.singleton <$> Serialization.decode
  -- decode = TLSPacket . V.fromList <$> Loops.untilM Serialization.decode S.isEmpty
