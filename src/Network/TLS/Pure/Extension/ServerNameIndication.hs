module Network.TLS.Pure.Extension.ServerNameIndication where

import Control.Monad
import qualified Data.Serialize.Put as Put
import qualified Data.ByteString as BS

import qualified Network.TLS.Pure.Serialization as S
import qualified Network.TLS.Pure.Error as Err

-- See RFC 6066 for definition and RFC 5890 for hostname comparison
newtype ServerName = ServerName BS.ByteString
  deriving (Show, Eq)

instance S.ToWire ServerName where
  encode (ServerName hostname) = do
    let bytes = S.runTLSEncoder $ do
          Put.putWord8 0 -- type: host_name
          S.encode $ S.Opaque16 hostname
    S.encode $ S.Opaque16 bytes

instance S.FromWire ServerName where
  decode = do
    -- TODO list of servername ??? Check the rfc and handle that (or just throw)
    _len <- S.getWord16be
    typ <- S.getWord8
    when (typ /= 0) $ S.throwError $ Err.InvalidServerNameType typ
    nameLength <- fromIntegral <$> S.getWord16be
    ServerName <$> S.getByteString nameLength
