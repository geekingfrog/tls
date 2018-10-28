{-# LANGUAGE BangPatterns #-}

module Network.TLS.Pure.Wire where

import Data.Bits (shiftR, (.&.))
import qualified Data.Serialize.Put            as Put
import qualified Data.ByteString               as B

import qualified Data.Serialize                as Serial

class ToWire a where
    put :: a -> Serial.Put

class FromWire a where
    get :: Serial.Get a

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
