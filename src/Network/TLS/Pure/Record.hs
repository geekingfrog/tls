{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Pure.Record where

import Data.Functor
import GHC.Word
import qualified Data.ByteString as BS
import Control.Monad (when, void)
import qualified Data.Serialize.Put as Put

import qualified Network.TLS.Pure.Serialization as S
import qualified Network.TLS.Pure.Version as Version
import qualified Network.TLS.Pure.Handshake as Handshake

newtype RecordContent
  -- = Invalid
  -- | ChangeCipherSpec
  -- | Alert
  = Handshake Handshake.Handshake
  -- | ChangeCipherSpec -- TODO
  -- | ApplicationData BS.ByteString
  deriving (Eq, Show)

instance S.ToWire RecordContent where
  encode = \case
    Handshake h -> S.encode h
    -- ChangeCipherSpec -> error "wip encode change cipher spec"
    -- ApplicationData{} -> error "wip encode application data"

data TLSRecord = TLSRecord
  { rVersion :: Version.ProtocolVersion
  , rContent :: RecordContent
  }
  deriving (Eq, Show)

encodeRecordContentType :: RecordContent -> Put.Put
encodeRecordContentType = \case
  Handshake{}       -> Put.putWord8 0x16
  -- ChangeCipherSpec  -> Put.putWord8 0x20
  -- ApplicationData{} -> Put.putWord8 0x23

instance S.ToWire TLSRecord where
  encode r = do
    encodeRecordContentType (rContent r)
    S.encode (rVersion r)
    let bytes = S.runTLSEncoder (S.encode $ rContent r)
    -- when (BS.length bytes > 16384 {- 2¹⁴ -}) $ fail "record overflow"
    -- -- ^ TODO this should throw a "record_overflow" alert
    S.encode (S.Opaque16 bytes)

instance S.FromWire TLSRecord where
  decode = S.getWord8 >>= \case
    0x16 -> do
      version <- S.decode
      content <- S.getNested
        (fromIntegral <$> S.getWord16be)
        (Handshake <$> S.decode)
      pure $ TLSRecord version content

    -- 0x20 -> do -- TODO do that properly
    --   rVersion <- S.decode
    --   l <- fromIntegral <$> S.getWord16be
    --   rContent <- S.isolate l (S.getByteString l $> ChangeCipherSpec)
    --   pure $ TLSRecord{..}
    --
    -- 0x23 -> do -- TODO do that properly as well
    --   rVersion <- S.decode
    --   l <- fromIntegral <$> S.getWord16be
    --   rContent <- S.isolate l (ApplicationData <$> S.getByteString l)
    --   pure $ TLSRecord{..}

    _code -> error "throw the proper error with code"
