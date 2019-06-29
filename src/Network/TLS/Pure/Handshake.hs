{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE StrictData #-}

module Network.TLS.Pure.Handshake where

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Data.Serialize.Put as S

import Network.TLS.Pure.Handshake.ClientHello
import qualified Network.TLS.Pure.Handshake.MessageType as MT

data Handshake
  = ClientHello13 ClientHello13Data
  | FooHandshake

instance Serialization.ToWire Handshake where
  encode = \case
    ClientHello13 chloData-> do
      Serialization.encode MT.ClientHello
      let bytes = S.runPut (Serialization.encode chloData)
      Serialization.encode (Serialization.Opaque24 bytes)

    FooHandshake -> error "wip"
