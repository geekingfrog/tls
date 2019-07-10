{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Prelude where

import GHC.Generics
import Data.Function (on)

hush :: Either e a -> Maybe a
hush = \case
  Right x -> Just x
  Left _ -> Nothing

note :: err -> Maybe a -> Either err a
note err = \case
  Just x -> Right x
  Nothing -> Left err


-- | typeclass to check if two values have the same constructor
-- taken from: https://stackoverflow.com/a/45444300
class EqC a where
  eqConstr :: a -> a -> Bool
  default eqConstr :: (Generic a, GEqC (Rep a)) => a -> a -> Bool
  eqConstr = geqConstr `on` from

class GEqC f where
  geqConstr :: f p -> f p -> Bool
  {-# INLINE geqConstr #-}
  geqConstr _ _ = True

instance GEqC f => GEqC (M1 i c f) where
  {-# INLINE geqConstr #-}
  geqConstr (M1 x) (M1 y) = geqConstr x y

instance GEqC (K1 i c)
instance GEqC (f :*: g)
instance GEqC U1
instance GEqC V1

-- the interesting case
instance (GEqC f, GEqC g) => GEqC (f :+: g) where
  {-# INLINE geqConstr #-}
  geqConstr (L1 x) (L1 y) = geqConstr x y
  geqConstr (R1 x) (R1 y) = geqConstr x y
  geqConstr _ _ = False
