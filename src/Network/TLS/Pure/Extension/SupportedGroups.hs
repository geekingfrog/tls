{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Extension.SupportedGroups where

import qualified Data.Vector as V
import qualified Data.Serialize.Put as S

import qualified Network.TLS.Pure.Serialization as Serialization

data Group
  = X25519
  | X448
  deriving (Show)

instance Serialization.ToWire Group where
  encode = \case
    X25519 -> S.putWord16be 29
    X448 -> S.putWord16be 30

newtype SupportedGroups
  = SupportedGroups { getSupportedGroups :: V.Vector Group }

instance Serialization.ToWire SupportedGroups where
  encode (SupportedGroups groups) = Serialization.encodeVector 2 groups
