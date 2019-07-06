{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE UndecidableInstances #-}

module Class where

import Control.Monad.Identity
import qualified Data.ByteString as BS
import qualified Data.Serialize.Get as SG
import qualified Data.Bytes.Get as S
import qualified Control.Monad.Except as Ex
import GHC.Word
import Control.Applicative

-- import qualified Data.Binary as Bin
-- import qualified Data.Binary.Get as BG

-- test :: IO ()
-- test = do
--   let input = BS.pack [0x91, 0x92]
--   let result = SG.runGet action input
--   print result
--
-- action :: SG.Get (Word8, Word16)
-- action = (,) <$> SG.getWord8 <*> (SG.getWord16be <|> pure 0)

class (Ex.MonadError e m) => MyMonadGet e m where
  getWord8 :: m Word8


data MyError
  = MyError
  | Handled String
  | Unhandled String
  deriving (Show, Eq)

newtype FooM a = FooM { runFooM :: Ex.ExceptT [MyError] SG.Get a }
  deriving (Functor, Applicative, Alternative, Monad, S.MonadGet, Ex.MonadError [MyError])

instance MyMonadGet [MyError] FooM where
  getWord8 = S.getWord8

runFoo :: FooM a -> BS.ByteString -> Either [MyError] a
runFoo action input =
  let raw = SG.runGet (Ex.runExceptT $ runFooM action) input
   in case raw of
        Left str -> Left [Unhandled str]
        Right x -> x

data Var = Var
  { var1 :: Word8
  , var2 :: Word8
  }
  deriving (Show, Eq)

class (MyMonadGet e m) => FromWire e m a where
  decode :: m a

class HardcodedGet a where
  hdecode :: FooM a

instance (MyMonadGet [MyError] m) => FromWire [MyError] m Var where
  decode = do
    a <- getWord8
    b <- getWord8
    when (a > b) $ Ex.throwError [Handled "var1 must be less than or equal to var2"]
    pure $ Var a b

instance HardcodedGet Var where
  hdecode = decode


test :: IO ()
test = do
  let input = BS.pack [0x61, 0x62]
  let (res :: Either [MyError] Var) = runFoo decode input
  print res

action :: FooM (Word8, Word16)
action = do
  a <- S.getWord8
  b <- S.getWord16be <|> Ex.throwError [Handled "NOPE"]
  pure (a, b)
  -- (,) <$> S.getWord8 <*> (S.getWord16be <|> Ex.throwError [Handled "NOPE"])

action2 :: SG.Get (Word8, Word16)
action2 = do
  a <- S.getWord8
  b <- S.getWord16be <|> fail "NOOOPE"
  pure (a, b)
