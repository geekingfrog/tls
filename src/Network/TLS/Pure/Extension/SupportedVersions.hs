{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}

module Network.TLS.Pure.Extension.SupportedVersions where

import           Data.Foldable
import qualified Data.Serialize.Put as S
import qualified Data.Vector as V

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Network.TLS.Pure.Version as Version
import qualified Network.TLS.Pure.Handshake.MessageType as H.MT

data SupportedVersions (msgType :: H.MT.MessageType) where
  -- TODO make it so that it is not empty?
  SupportedVersionsCH :: V.Vector Version.ProtocolVersion -> SupportedVersions 'H.MT.ClientHello
  SupportedVersionsSH :: Version.ProtocolVersion -> SupportedVersions 'H.MT.ServerHello
  -- TODO should also be there for HelloRetryRequest (HRR)

instance Serialization.ToWire (SupportedVersions a) where
  encode ver = case ver of
    SupportedVersionsCH versions -> do
      let bytes = S.runPut $ traverse_ Serialization.encode versions
      Serialization.encode $ Serialization.Opaque8 bytes

    SupportedVersionsSH version -> Serialization.encode version
