module Network.TLS.Pure.Extension.ServerNameIndication where

import qualified Data.Serialize.Put as S
import qualified Data.ByteString as BS

import qualified Network.TLS.Pure.Serialization as Serialization

-- See RFC 6066 for definition and RFC 5890 for hostname comparison
newtype ServerName = ServerName BS.ByteString deriving (Show)

instance Serialization.ToWire ServerName where
  encode (ServerName hostname) = do
    let bytes = S.runPut $ do
          S.putWord8 0 -- type: host_name
          Serialization.encode $ Serialization.Opaque16 hostname
    Serialization.encode $ Serialization.Opaque16 bytes
