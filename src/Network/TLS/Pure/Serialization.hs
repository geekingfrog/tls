{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE StrictData #-}

module Network.TLS.Pure.Serialization where

import           Data.Bits (shiftR, shiftL, (.&.))
import qualified Data.Serialize.Put as S
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           GHC.Word
import qualified Data.Vector as V
import           Data.Foldable

class ToWire a where
  encode :: a -> S.Put

newtype Opaque8
  = Opaque8 { getOpaque8 :: ByteString }

instance ToWire Opaque8 where
  encode (Opaque8 bytes)
    = S.putWord8 (fromIntegral $ BS.length bytes) *> S.putByteString bytes


newtype Opaque16
  = Opaque16 { getOpaque16 :: ByteString }

instance ToWire Opaque16 where
  encode (Opaque16 bytes)
    = S.putWord16be (fromIntegral $ BS.length bytes) *> S.putByteString bytes


newtype Opaque24
  = Opaque24 { getOpaque24 :: ByteString }

instance ToWire Opaque24 where
  encode (Opaque24 bytes)
    = putWord24be (fromIntegral $ BS.length bytes) *> S.putByteString bytes

putWord24be :: Int -> S.Put
putWord24be i = do
    let !a = fromIntegral ((i `shiftR` 16) .&. 0xff)
    let !b = fromIntegral ((i `shiftR` 8) .&. 0xff)
    let !c = fromIntegral (i .&. 0xff)
    traverse_ S.putWord8 [a,b,c]



newtype Opaque32
  = Opaque32 { getOpaque32 :: ByteString }

instance ToWire Opaque32 where
  encode (Opaque32 bytes)
    = S.putWord32be (fromIntegral $ BS.length bytes) *> S.putByteString bytes



-- | encode a list of items, where each item has the same encoded length
encodeVector
  :: ToWire a
  => Int
  -- ^ the size in byte of each item
  -> V.Vector a
  -> S.Put
encodeVector itemSize items
  = do
    S.putWord16be (fromIntegral $ V.length items * itemSize)
    traverse_ encode items
