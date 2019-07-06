module Network.TLS.Pure.Debug where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BS.B
import Text.Printf (printf)
import GHC.Word
import Data.Bits ((.&.))
import qualified Data.Bits as Bits

class ShowHex a where
  showHex :: a -> String

instance ShowHex BS.ByteString where
  showHex bs = unwords $ map (printf "%02x") (BS.unpack bs)

instance ShowHex Word8 where
  showHex w = showHex (BS.singleton w)

instance ShowHex Word16 where
  showHex w = showHex $ BS.pack $ map fromIntegral
    [ w .&. 0xFF
    , (w .&. 0xFF00) `Bits.shiftR` 8
    ]
