{-# LANGUAGE LambdaCase #-}
module TestUtil where

unsafeFromRight :: Either e a -> a
unsafeFromRight = \case
  Left _ -> error "unsafeFromRight called on Left"
  Right x -> x
