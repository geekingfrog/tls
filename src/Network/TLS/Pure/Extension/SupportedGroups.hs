{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Extension.SupportedGroups where

import qualified Data.Serialize.Put             as Put
import qualified Data.Vector                    as V

import qualified Network.TLS.Pure.Serialization as S

data Group
  = X25519
  -- | X448
  deriving (Show, Eq)

instance S.ToWire Group where
  encode = \case
    X25519 -> Put.putWord16be 29
    -- X448   -> Put.putWord16be 30

instance S.FromWire Group where
  decode = S.getWord16be >>= \case
    29 -> pure X25519
    -- 30 -> pure X448
    w -> fail $ "Unknown group: " <> show w

newtype SupportedGroups
  = SupportedGroups { getSupportedGroups :: V.Vector Group }
  deriving (Show, Eq)

instance S.ToWire SupportedGroups where
  encode (SupportedGroups groups) = S.encodeVector 2 groups

instance S.FromWire SupportedGroups where
  decode = SupportedGroups <$> S.decodeVector 2
