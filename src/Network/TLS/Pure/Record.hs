{-# LANGUAGE StrictData #-}
{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Record where

import GHC.Word
import qualified Data.ByteString as BS
import qualified Data.Serialize.Put as S
import Control.Monad (when)

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Network.TLS.Pure.Version as Version
import qualified Network.TLS.Pure.Handshake as Handshake

data RecordContent
  -- = Invalid
  -- | ChangeCipherSpec
  -- | Alert
  = Handshake Handshake.Handshake
  | ApplicationData

instance Serialization.ToWire RecordContent where
  encode = \case
    Handshake h -> Serialization.encode h
    ApplicationData -> error "wip encode application data"

data TLSRecord = TLSRecord
  { rVersion :: Version.ProtocolVersion
  , rContent :: RecordContent
  }

encodeRecordContentType :: RecordContent -> S.Put
encodeRecordContentType = \case
  Handshake{}       -> S.putWord8 0x16
  ApplicationData{} -> S.putWord8 0x23

instance Serialization.ToWire TLSRecord where
  encode r = do
    encodeRecordContentType (rContent r)
    Serialization.encode (rVersion r)
    let bytes = S.runPut (Serialization.encode $ rContent r)
    -- when (BS.length bytes > 16384 {- 2¹⁴ -}) $ fail "record overflow"
    -- -- ^ TODO this should throw a "record_overflow" alert
    Serialization.encode (Serialization.Opaque16 bytes)
