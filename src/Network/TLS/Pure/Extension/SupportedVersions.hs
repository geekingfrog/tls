{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}

module Network.TLS.Pure.Extension.SupportedVersions where

import           Control.Monad
import           Data.Foldable
import qualified Data.Vector                            as V

import qualified Network.TLS.Pure.Error                 as Err
import qualified Network.TLS.Pure.Handshake.MessageType as H.MT
import qualified Network.TLS.Pure.Serialization         as S
import qualified Network.TLS.Pure.Version               as Version

data SupportedVersions (msgType :: H.MT.MessageType) where
  -- TODO make it so that it is not empty?
  SupportedVersionsCH :: V.Vector Version.ProtocolVersion -> SupportedVersions 'H.MT.ClientHello
  SupportedVersionsSH :: Version.ProtocolVersion -> SupportedVersions 'H.MT.ServerHello
  -- TODO should also be there for HelloRetryRequest (HRR)

deriving instance Eq (SupportedVersions a)
deriving instance Show (SupportedVersions a)

instance S.ToWire (SupportedVersions a) where
  encode ver = case ver of
    SupportedVersionsCH versions -> do
      let bytes = S.runTLSEncoder $ traverse_ S.encode versions
      S.encode $ S.Opaque8 bytes

    SupportedVersionsSH version -> S.encode version

instance S.FromWire (SupportedVersions 'H.MT.ClientHello) where
  decode = do
    versions <- S.decodeVector8
    -- TODO check which TLS error that should generate
    when (V.null versions) $ S.throwError (Err.InvalidLength "empty versions for SupportedVersions")
    pure $ SupportedVersionsCH versions

instance S.FromWire (SupportedVersions 'H.MT.ServerHello) where
  decode = SupportedVersionsSH <$> S.decode
