{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Version where

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Data.Serialize.Put as S
import GHC.Word

data ProtocolVersion
  = TLS10
  | TLS12
  | TLS13
  | Unknown Word16
  deriving (Show)

instance Serialization.ToWire ProtocolVersion where
  encode = \case
    TLS10 -> S.putWord16be 0x0301
    TLS12 -> S.putWord16be 0x0303
    TLS13 -> S.putWord16be 0x0304
    Unknown v -> S.putWord16be v
