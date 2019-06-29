{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Extension where

import qualified Data.Vector as V
import qualified Data.ByteString as BS
import           GHC.Word
import qualified Data.Serialize.Put as S
import           Data.Foldable

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Network.TLS.Pure.Handshake.MessageType as H.MT
import qualified Network.TLS.Pure.Extension.SupportedVersions as SV
import qualified Network.TLS.Pure.Extension.KeyShare as KS
import qualified Network.TLS.Pure.Extension.SignatureAlgorithms as SA
import qualified Network.TLS.Pure.Extension.ServerNameIndication as SNI
import qualified Network.TLS.Pure.Extension.SupportedGroups as SG

data Extension (a :: H.MT.MessageType)
  = SupportedVersions (SV.SupportedVersions a)
  | KeyShare (KS.KeyShare a)
  | SignatureAlgorithms SA.SignatureAlgorithms
  | ServerNameIndication SNI.ServerName
  | SupportedGroups SG.SupportedGroups
  | Unknown Word16 BS.ByteString

instance Serialization.ToWire (Extension a) where
  encode = \case
    SupportedVersions sv -> encodeWithCode 43 sv
    KeyShare ks -> encodeWithCode 51 ks
    SignatureAlgorithms algs -> encodeWithCode 13 algs
    ServerNameIndication sn -> encodeWithCode 0 sn
    SupportedGroups groups -> encodeWithCode 10 groups
    Unknown code content -> do
      S.putWord16be code
      Serialization.encode (Serialization.Opaque16 content)

    where
      encodeWithCode code ext = do
        S.putWord16be code
        let content = S.runPut (Serialization.encode ext)
        Serialization.encode (Serialization.Opaque16 content)

newtype Extensions a = Extensions { getExtensions :: V.Vector (Extension a) }

instance Serialization.ToWire (Extensions a) where
  encode (Extensions exts) = do
    let bytes = S.runPut (traverse_ Serialization.encode exts)
    Serialization.encode (Serialization.Opaque16 bytes)
