{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE StrictData #-}

module Network.TLS.Pure.Serialization where

import qualified Control.Monad.Except as Ex
import qualified Control.Monad.Morph  as Morph
import           Data.Bits            (shiftL, shiftR, (.&.))
import qualified Data.Bytes.Get       as S
import           Data.ByteString      (ByteString)
import qualified Data.ByteString      as BS
import           Data.Foldable
import qualified Data.Serialize.Get   as Get
import qualified Data.Serialize.Put   as Put
import qualified Data.Vector          as V
import           GHC.Word

import qualified Network.TLS.Pure.Error as Err

class (Monad m) => MonadTLSParser m where
  getWord8 :: m Word8
  getWord16be :: m Word16
  getWord24be :: m Word32
  getWord32be :: m Word32
  getByteString :: Int -> m BS.ByteString
  isEmpty :: m Bool

  isolate :: Int -> m a -> m a
  getNested :: m Int -> m a -> m a


newtype TLSParser a = TLSParser { unTLSParser :: Ex.ExceptT Err.ParseError Get.Get a }
  deriving
    ( Functor, Applicative, Monad
    , S.MonadGet
    , Ex.MonadError Err.ParseError
    )

runTLSParser :: TLSParser a -> BS.ByteString -> Either Err.ParseError a
runTLSParser action input =
  let raw = S.runGetS (Ex.runExceptT $ unTLSParser action) input
   in case raw of
        Left str -> Left (Err.UnHandled str)
        Right x -> x

instance MonadTLSParser TLSParser where
  getWord8 = S.getWord8
  getWord16be = S.getWord16be
  getWord32be = S.getWord32be
  getByteString = S.getByteString

  getWord24be = do
      a <- fromIntegral <$> S.getWord8
      b <- fromIntegral <$> S.getWord16be
      pure $ a `shiftL` 16 + b

  isEmpty = S.isEmpty

  -- this is a bit shitty because if the inner action throws an error and thus, doesn't
  -- consume all bytes, then isolate will fail and override the thrown error
  isolate l (TLSParser action) = TLSParser $ Morph.hoist (Get.isolate l) action

  getNested getLen getVal = do
    l <- getLen
    isolate l getVal

class ToWire a where
  encode :: a -> Put.Put

class FromWire a where
  decode :: MonadTLSParser m => m a

newtype Opaque8
  = Opaque8 { getOpaque8 :: ByteString }
  deriving (Show)

instance ToWire Opaque8 where
  encode (Opaque8 bytes)
    = Put.putWord8 (fromIntegral $ BS.length bytes) *> Put.putByteString bytes

instance FromWire Opaque8 where
  decode = do
    l <- fromIntegral <$> getWord8
    Opaque8 <$> getByteString l

newtype Opaque16
  = Opaque16 { getOpaque16 :: ByteString }
  deriving (Show)

instance ToWire Opaque16 where
  encode (Opaque16 bytes)
    = Put.putWord16be (fromIntegral $ BS.length bytes) *> Put.putByteString bytes

instance FromWire Opaque16 where
  decode = do
    l <- fromIntegral <$> getWord16be
    Opaque16 <$> getByteString l

newtype Opaque24
  = Opaque24 { getOpaque24 :: ByteString }
  deriving (Show)

instance ToWire Opaque24 where
  encode (Opaque24 bytes)
    = putWord24be (fromIntegral $ BS.length bytes) *> Put.putByteString bytes

instance FromWire Opaque24 where
  decode = do
    l <- fromIntegral <$> getWord24be
    Opaque24 <$> getByteString l

putWord24be :: Int -> Put.Put
putWord24be i = do
    let !a = fromIntegral ((i `shiftR` 16) .&. 0xff)
    let !b = fromIntegral ((i `shiftR` 8) .&. 0xff)
    let !c = fromIntegral (i .&. 0xff)
    traverse_ Put.putWord8 [a,b,c]


newtype Opaque32
  = Opaque32 { getOpaque32 :: ByteString }
  deriving (Show)

instance ToWire Opaque32 where
  encode (Opaque32 bytes)
    = Put.putWord32be (fromIntegral $ BS.length bytes) *> Put.putByteString bytes

instance FromWire Opaque32 where
  decode = do
    l <- fromIntegral <$> getWord32be
    Opaque32 <$> getByteString l


-- | encode a list of items, where each item has the same encoded length
encodeVector
  :: ToWire a
  => Int
  -- ^ the size in byte of each item
  -> V.Vector a
  -> Put.Put
encodeVector itemSize items
  = do
    Put.putWord16be (fromIntegral $ V.length items * itemSize)
    traverse_ encode items
