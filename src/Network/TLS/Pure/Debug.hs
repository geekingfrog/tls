{-# LANGUAGE TemplateHaskell #-}

module Network.TLS.Pure.Debug where

import           Data.Bits               ((.&.))
import qualified Data.Bits               as Bits
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Builder as BS.B
import qualified Data.Char               as C
import           GHC.Word
import           Instances.TH.Lift       ()
import           Text.Printf             (printf)
import qualified Data.ByteArray                         as BA

import qualified Language.Haskell.TH       as TH
import qualified Language.Haskell.TH.Quote as TH.Q

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

-- | quasiquoter to include bytestrings as hex stream in the code:
-- [hexStream|011d1a009557|]
-- [hexStream|01 1d 1a 00 95 57|]
hexStream :: TH.Q.QuasiQuoter
hexStream = TH.Q.QuasiQuoter
  { TH.Q.quoteExp = quoteExprExp
  , TH.Q.quotePat = error "hexStream quasiquoter not supported for pattern"
  , TH.Q.quoteType = error "hexStream quasiquoter not supported for types"
  , TH.Q.quoteDec = error "hexStream quasiquoter not supported for declaration"
  }

quoteExprExp :: String -> TH.Q TH.Exp
quoteExprExp input = case parseBytes input of
  Left err -> fail err
  Right bs -> [| bs |]

parseBytes :: String -> Either String BS.ByteString
parseBytes input =
  let splitted = splitEvery2 $ filter (not . C.isSpace) input
      showByte (x, y) = [x,y]
      bytes = traverse (\x -> maybe (Left ("Invalid byte: " <> showByte x)) Right (readByte x)) splitted
  in BS.pack <$> bytes

splitEvery2 :: String -> [(Char, Char)]
splitEvery2 = go Nothing
  where
    go Nothing [] = []
    go (Just _) [] = error "Not an even number of characters"
    go Nothing (x:xs) = go (Just x) xs
    go (Just a) (x:xs) = (a, x) : go Nothing xs

readByte :: (Char, Char) -> Maybe Word8
readByte (a, b) =
  if C.isHexDigit a && C.isHexDigit b
    then Just $ fromIntegral $ toHex a * 16 + toHex b
    else Nothing

  where
    toHex c = if C.isLetter c
      then C.ord (C.toLower c) - C.ord 'a' + 10
      else C.ord c - C.ord '0'


toHexStream :: BA.ByteArrayAccess ba => ba -> String
toHexStream = concatMap (printf "%02x") . BS.unpack . BA.convert
