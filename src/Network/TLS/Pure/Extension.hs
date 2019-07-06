{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Extension where

import qualified Control.Monad.Loops as Loops
import qualified Data.ByteString     as BS
import           Data.Foldable
import qualified Data.Serialize.Put  as Put
import qualified Data.Vector         as V
import           GHC.Word

import qualified Network.TLS.Pure.Serialization as S
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

instance S.ToWire (Extension a) where
  encode = \case
    SupportedVersions sv -> encodeWithCode 43 sv
    KeyShare ks -> encodeWithCode 51 ks
    SignatureAlgorithms algs -> encodeWithCode 13 algs
    ServerNameIndication sn -> encodeWithCode 0 sn
    SupportedGroups groups -> encodeWithCode 10 groups
    Unknown code content -> do
      Put.putWord16be code
      S.encode (S.Opaque16 content)

    where
      encodeWithCode code ext = do
        Put.putWord16be code
        let content = Put.runPut (S.encode ext)
        S.encode (S.Opaque16 content)

instance S.FromWire (Extension 'H.MT.ServerHello) where
  decode = S.getWord16be >>= \case
    43 -> SupportedVersions <$> S.decode
    51 -> KeyShare <$> S.decode
    13 -> error "wip decode SignatureAlgorithms"
    0 -> error "wip decode SNI"
    10 -> error "wip decode SupportedGroups"
    c -> do
      l <- fromIntegral <$> S.getWord16be
      content <- S.isolate l $ S.getByteString l
      pure $ Unknown c content


newtype Extensions a = Extensions { getExtensions :: V.Vector (Extension a) }

instance S.ToWire (Extensions a) where
  encode (Extensions exts) = do
    let bytes = Put.runPut (traverse_ S.encode exts)
    S.encode (S.Opaque16 bytes)

instance S.FromWire (Extensions 'H.MT.ServerHello) where
  decode = do
    l <- fromIntegral <$> S.getWord16be
    Extensions . V.fromList <$> S.isolate l (Loops.untilM S.decode S.isEmpty)
