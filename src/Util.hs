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
bsToHex bs
    = let
        bytes = B.unpack bs
    in concatMap (printf "%02x ") bytes

hexToBs :: [Word8] -> B.ByteString
hexToBs = B.pack
