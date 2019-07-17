{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Extension where

import qualified Control.Monad.Loops                             as Loops
import qualified Data.ByteString                                 as BS
import           Data.Foldable
import qualified Data.Serialize.Put                              as Put
import qualified Data.Vector                                     as V
import           GHC.Generics
import           GHC.Word

import qualified Network.TLS.Pure.Extension.KeyShare             as KS
import qualified Network.TLS.Pure.Extension.ServerNameIndication as SNI
import qualified Network.TLS.Pure.Extension.SignatureAlgorithms  as SA
import qualified Network.TLS.Pure.Extension.SupportedGroups      as SG
import qualified Network.TLS.Pure.Extension.SupportedVersions    as SV
import qualified Network.TLS.Pure.Handshake.MessageType          as H.MT
import qualified Network.TLS.Pure.Serialization                  as S

data Extension (a :: H.MT.MessageType)
  = SupportedVersions (SV.SupportedVersions a)
  | KeyShare (KS.KeyShare a)
  | SignatureAlgorithms SA.SignatureAlgorithms
  | ServerNameIndication SNI.ServerName
  | SupportedGroups SG.SupportedGroups
  | Unknown Word16 S.Opaque16
  deriving (Show, Eq, Generic)

instance S.ToWire (Extension a) where
  encode = \case
    SupportedVersions sv -> encodeWithCode 43 sv
    KeyShare ks -> encodeWithCode 51 ks
    SignatureAlgorithms algs -> encodeWithCode 13 algs
    ServerNameIndication sn -> encodeWithCode 0 sn
    SupportedGroups groups -> encodeWithCode 10 groups
    Unknown code content -> do
      Put.putWord16be code
      S.encode content

    where
      encodeWithCode code ext = do
        Put.putWord16be code
        let content = Put.runPut (S.encode ext)
        S.encode (S.Opaque16 content)

instance
  ( S.FromWire (SV.SupportedVersions a)
  , S.FromWire (KS.KeyShare a)
  ) => S.FromWire (Extension a) where
  decode = fmap snd decodeExtension

decodeExtension
  :: ( S.MonadTLSParser m
     , S.FromWire (SV.SupportedVersions a)
     , S.FromWire (KS.KeyShare a)
     )
  => m (Int, Extension a)
decodeExtension = S.getWord16be >>= \case
  43 -> getExt (SupportedVersions <$> S.decode)
  51 -> getExt (KeyShare <$> S.decode)
  13 -> getExt (SignatureAlgorithms <$> S.decode)
  0  -> getExt (ServerNameIndication <$> S.decode)
  10 -> getExt (SupportedGroups <$> S.decode)
  c -> do
    l <- fromIntegral <$> S.getWord16be
    content <- S.isolate l $ S.getByteString l
    pure (l+4, Unknown c (S.Opaque16 content))

  where
    getExt act = do
      len <- fromIntegral <$> S.getWord16be
      ext <- S.isolate len act
      pure (len+4, ext)


newtype Extensions a = Extensions { getExtensions :: V.Vector (Extension a) }
  deriving (Eq, Show)

instance S.ToWire (Extensions a) where
  encode (Extensions exts) = do
    let bytes = S.runTLSEncoder (traverse_ S.encode exts)
    S.encode (S.Opaque16 bytes)

instance S.FromWire (Extensions 'H.MT.ClientHello) where
  decode = do
    l <- fromIntegral <$> S.getWord16be
    Extensions <$> S.decodeVectorVariable "extensions" l decodeExtension
    -- Extensions . V.fromList <$> S.isolate l (Loops.untilM S.decode S.isEmpty)

instance S.FromWire (Extensions 'H.MT.ServerHello) where
  decode = do
    l <- fromIntegral <$> S.getWord16be
    Extensions <$> S.decodeVectorVariable "extensions" l decodeExtension
    -- Extensions . V.fromList <$> S.isolate l (Loops.untilM S.decode S.isEmpty)

findKeyShare :: Extensions a -> Maybe (KS.KeyShare a)
findKeyShare (Extensions exts) = V.find isKeyShare exts >>= getKs
  where
    isKeyShare = \case
      KeyShare _ -> True
      _ -> False
    getKs = \case
      (KeyShare ks) -> Just ks
      _ -> Nothing -- unreachable though
