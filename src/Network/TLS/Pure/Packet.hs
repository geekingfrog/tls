module Network.TLS.Pure.Packet where

import           Data.Foldable
import qualified Data.Vector                    as V

import qualified Network.TLS.Pure.Record        as Record
import qualified Network.TLS.Pure.Serialization as S

newtype TLSPacket = TLSPacket { getTlsPacket :: V.Vector Record.TLSRecord }
  deriving (Show)

instance S.ToWire TLSPacket where
  encode (TLSPacket records) = traverse_ S.encode records

instance S.FromWire TLSPacket where
  -- TODO fix that, there are multiple packets
  -- decode = TLSPacket . V.singleton <$> S.decode
  decode = do
    len <- S.remaining
    TLSPacket <$> S.decodeVectorVariable "TLSPacket" len Record.decodeRecord
