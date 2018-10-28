module Network.TLS.Pure.Cipher.Serialize where

import qualified Data.Serialize.Put            as Put

-- import           Network.TLS.Pure.Cipher        ( Cipher(..) )
--
-- putCipher :: Cipher -> Put.Put
-- putCipher AES128_GCM    = Put.putWord16be 0x1301
-- putCipher AES256_GCM    = Put.putWord16be 0x1302
-- putCipher CHACHA20_POLY = Put.putWord16be 0x1303
-- putCipher AES128_CCM    = Put.putWord16be 0x1304
-- putCipher AES128_CCM_8  = Put.putWord16be 0x1305
