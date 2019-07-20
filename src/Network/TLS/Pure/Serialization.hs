{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE StrictData #-}

module Network.TLS.Pure.Serialization where

import           Control.Monad
import qualified Control.Monad.Except   as Ex
import qualified Control.Monad.Morph    as Morph
import           Data.Bits              (shiftL, shiftR, (.&.))
import qualified Data.Bytes.Get         as S
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import           Data.Foldable
import qualified Data.Serialize.Get     as Get
import qualified Data.Serialize.Put     as Put
import qualified Data.Vector            as V
import           GHC.Word
import Data.Kind (Type)
import GHC.TypeNats
import qualified GHC.Natural as N
import Data.Proxy

import qualified Network.TLS.Pure.Error as Err

class (Monad m) => MonadTLSParser m where
  getWord8 :: m Word8
  getWord16be :: m Word16
  getWord24be :: m Word32
  getWord32be :: m Word32
  getByteString :: Int -> m BS.ByteString
  isEmpty :: m Bool
  remaining :: m Int

  isolate :: Int -> m a -> m a
  getNested :: m Int -> m a -> m a

  throwError :: Err.ParseError -> m a


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
  remaining = S.remaining

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

  throwError = Ex.throwError

runTLSEncoder :: Put.Put -> BS.ByteString
runTLSEncoder = Put.runPut

class ToWire a where
  encode :: a -> Put.Put

class FromWire a where
  decode :: MonadTLSParser m => m a

newtype Opaque8
  = Opaque8 { getOpaque8 :: ByteString }
  deriving (Eq, Show)

instance ToWire Opaque8 where
  encode (Opaque8 bytes)
    = Put.putWord8 (fromIntegral $ BS.length bytes) *> Put.putByteString bytes

instance FromWire Opaque8 where
  decode = do
    l <- fromIntegral <$> getWord8
    Opaque8 <$> getByteString l

newtype Opaque16
  = Opaque16 { getOpaque16 :: ByteString }
  deriving (Eq, Show)

instance ToWire Opaque16 where
  encode (Opaque16 bytes)
    = Put.putWord16be (fromIntegral $ BS.length bytes) *> Put.putByteString bytes

instance FromWire Opaque16 where
  decode = do
    l <- fromIntegral <$> getWord16be
    Opaque16 <$> getByteString l

newtype Opaque24
  = Opaque24 { getOpaque24 :: ByteString }
  deriving (Eq, Show)

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
  deriving (Eq, Show)

instance ToWire Opaque32 where
  encode (Opaque32 bytes)
    = Put.putWord32be (fromIntegral $ BS.length bytes) *> Put.putByteString bytes

instance FromWire Opaque32 where
  decode = do
    l <- fromIntegral <$> getWord32be
    Opaque32 <$> getByteString l

-- | A typeclass for values which have a fixed size in byte on the wire
class FixedSize a where
  type ByteSize a :: Nat

encodeVector' :: forall a. (ToWire a, FixedSize a, KnownNat (ByteSize a)) => V.Vector a -> Put.Put
encodeVector' items =
  let itemSize = N.naturalToInt $ natVal (Proxy @(ByteSize a))
   in do
        Put.putWord16be (fromIntegral $ V.length items * itemSize)
        traverse_ encode items


-- | encode a list of items, where each item has the same encoded length
encodeVector
  :: forall a. (ToWire a, FixedSize a, KnownNat (ByteSize a))
  => V.Vector a
  -> Put.Put
encodeVector items
  = do
    let itemSize = N.naturalToInt $ natVal (Proxy @(ByteSize a))
    Put.putWord16be (fromIntegral $ V.length items * itemSize)
    traverse_ encode items

decodeVector
  :: (FromWire a, MonadTLSParser m)
  => m Int
  -- ^ how to get the size
  -> Int
  -- ^ the size in byte of each item
  -> m (V.Vector a)
decodeVector getLen itemLength = do
  len <- getLen
  let (numberItems, remainder) = len `quotRem` itemLength
  when (remainder /= 0) $ throwError
    ( Err.InvalidLength
    $ "Given number of bytes (" <> show len <> ") not a multiple of "
    <> show itemLength
    )
  isolate len $ V.replicateM numberItems decode

decodeVector16, decodeVector8
  :: (FromWire a, MonadTLSParser m)
  => Int
  -- ^ the size in byte of each item
  -> m (V.Vector a)
decodeVector16 = decodeVector (fromIntegral <$> getWord16be)
decodeVector8  = decodeVector (fromIntegral <$> getWord8)

-- TODO this may be slow, benchmark and improve
decodeVectorVariable
  :: (MonadTLSParser m)
  => String
  -> Int
  -> m (Int, a)
  -> m (V.Vector a)

decodeVectorVariable desc len getVal = go len []
  where
    go !n acc
      | n < 0 = throwError $ Err.InvalidLength $ "Not enough bytes to decode key " <> desc
      | n == 0 = pure $ V.fromList $ reverse acc
      | otherwise = do
          (l, a) <- getVal
          go (n-l) (a : acc)


    -- l <- fromIntegral <$> S.getWord16be
    -- Extensions . V.fromList <$> S.isolate l (Loops.untilM S.decode S.isEmpty)
