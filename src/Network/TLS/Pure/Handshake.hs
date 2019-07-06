{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE StrictData #-}

module Network.TLS.Pure.Handshake where

import qualified Data.Serialize.Put as Put

import qualified Network.TLS.Pure.Serialization as S
import qualified Network.TLS.Pure.Handshake.ClientHello as CH
import qualified Network.TLS.Pure.Handshake.ServerHello as SH
import qualified Network.TLS.Pure.Handshake.MessageType as MT

data Handshake
  = ClientHello13 CH.ClientHello13Data
  | ServerHello13 SH.ServerHello13Data

instance S.ToWire Handshake where
  encode = \case
    ClientHello13 chloData -> do
      S.encode MT.ClientHello
      let bytes = Put.runPut (S.encode chloData)
      S.encode (S.Opaque24 bytes)

    ServerHello13{} -> error "wip encode serverHello13"


instance S.FromWire Handshake where
  decode = S.decode >>= \case
    MT.ClientHello -> error "wip decode handshake client hello"
    MT.ServerHello -> S.getNested (fmap fromIntegral S.getWord24be) (ServerHello13 <$> S.decode)
    MT.Unknown w -> fail $ "Unknown message type: " <> show w
