{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Version where

import qualified Data.Serialize.Put            as Serial
import qualified Data.Serialize.Get            as Serial

import qualified Network.TLS.Pure.Wire             as Wire

data Version = TLS10 | TLS12 | TLS13 deriving (Show, Eq)

instance Wire.ToWire Version where
    put TLS10 = Serial.putWord16be 0x301
    put TLS12 = Serial.putWord16be 0x303
    put TLS13 = Serial.putWord16be 0x304

instance Wire.FromWire Version where
    get = Serial.getWord16be >>= \case
        0x301 -> pure TLS10
        0x303 -> pure TLS12
        0x304 -> pure TLS13
        v -> fail $ "Unknown version " <> show v
