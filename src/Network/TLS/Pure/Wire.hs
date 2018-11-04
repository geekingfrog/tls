{-# LANGUAGE BangPatterns #-}

module Network.TLS.Pure.Wire where

import GHC.Word
import Data.Bits (shiftR, shiftL, (.&.))
import qualified Data.Serialize.Put            as Put
import qualified Data.Serialize.Get            as Get
import qualified Data.ByteString               as B
import qualified Data.Vector                   as V

import qualified Data.Serialize                as Serial

class ToWire a where
    put :: a -> Serial.Put

class FromWire a where
    get :: Serial.Get a

newtype Opaque8 = Opaque8 B.ByteString deriving (Show)

instance ToWire Opaque8 where
    put (Opaque8 o)
        = Serial.putWord8 (fromIntegral $ B.length o) *> Serial.putByteString o

instance FromWire Opaque8 where
    get = do
        len <- fromIntegral <$> Serial.getWord8
        Opaque8 <$> Serial.getByteString len

newtype Opaque16 = Opaque16 B.ByteString deriving (Show)

instance ToWire Opaque16 where
    put (Opaque16 o)
        = Serial.putWord16be (fromIntegral $ B.length o) *> Serial.putByteString o

instance FromWire Opaque16 where
    get = do
        len <- fromIntegral <$> Serial.getWord16be
        Opaque16 <$> Serial.getByteString len

opaque16Length :: Opaque16 -> Int
opaque16Length (Opaque16 bytes) = B.length bytes

putOpaque8 :: B.ByteString -> Put.Put
putOpaque8 !b = Put.putWord8 (fromIntegral $ B.length b) *> Put.putByteString b

putOpaque16 :: B.ByteString -> Put.Put
putOpaque16 !b = Put.putWord16be (fromIntegral $ B.length b) *> Put.putByteString b

putOpaque32 :: B.ByteString -> Put.Put
putOpaque32 !b = Put.putWord32be (fromIntegral $ B.length b) *> Put.putByteString b

putWord24 :: Int -> Put.Put
putWord24 i = do
    let !a = fromIntegral ((i `shiftR` 16) .&. 0xff)
    let !b = fromIntegral ((i `shiftR` 8) .&. 0xff)
    let !c = fromIntegral (i .&. 0xff)
    mapM_ Serial.putWord8 [a,b,c]

getWord24be :: Get.Get Word32
getWord24be = do
    a <- fromIntegral <$> Get.getWord8
    b <- fromIntegral <$> Get.getWord16be
    pure $ a `shiftL` 16 + b

parseArray :: FromWire a => Int -> Serial.Get (V.Vector a)
parseArray elemSize = do
    len <- fromIntegral <$> Serial.getWord16be
    V.replicateM (len `div` elemSize) get
