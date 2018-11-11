module Util
    ( bsToHex
    , hexToBs
    )
where

import GHC.Word
import Text.Printf
import Data.Char
import qualified Data.ByteString as B

bsToHex :: B.ByteString -> String
bsToHex bs = unwords $ map (printf "%02x") (B.unpack bs)

hexToBs :: [Word8] -> B.ByteString
hexToBs = B.pack
