module Network.TLS.Pure.Debug where

import qualified Data.ByteString as BS
import Text.Printf (printf)

bsToHex :: BS.ByteString -> String
bsToHex bs = unwords $ map (printf "%02x") (BS.unpack bs)
