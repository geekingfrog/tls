{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Version where

import qualified Data.Serialize.Put             as Put
import           GHC.Word

import qualified Network.TLS.Pure.Serialization as S

data ProtocolVersion
  = TLS10
  | TLS12
  | TLS13
  | Unknown Word16
  deriving (Show, Eq)

instance S.ToWire ProtocolVersion where
  encode = \case
    TLS10     -> Put.putWord16be 0x0301
    TLS12     -> Put.putWord16be 0x0303
    TLS13     -> Put.putWord16be 0x0304
    Unknown v -> Put.putWord16be v

instance S.FromWire ProtocolVersion where
  decode = S.getWord16be >>= \case
    0x0301 -> pure TLS10
    0x0303 -> pure TLS12
    0x0304 -> pure TLS13
    code   -> pure (Unknown code)
