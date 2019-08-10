{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Record where

import Data.Functor
import GHC.Word
import qualified Data.ByteString as BS
import Control.Monad (when, void)
import qualified Data.Serialize.Put as Put

import qualified Network.TLS.Pure.Serialization as S
import qualified Network.TLS.Pure.Version as Version
import qualified Network.TLS.Pure.Handshake as Handshake

data RecordContent
  -- = Invalid
  = ChangeCipherSpec
  -- | Alert
  | Handshake Handshake.Handshake
  | ApplicationData S.Opaque16
  deriving (Eq, Show)

instance S.ToWire RecordContent where
  encode = \case
    Handshake h -> S.encode h
    ChangeCipherSpec -> S.encode (S.Opaque16 $ BS.singleton 0x01)
    ApplicationData content -> Put.putByteString (S.getOpaque16 content)

data TLSRecord = TLSRecord
  { rVersion :: Version.ProtocolVersion
  , rContent :: RecordContent
  }
  deriving (Eq, Show)

contentLength :: TLSRecord -> Int
contentLength record = case rContent record of
  Handshake c -> BS.length $ S.runTLSEncoder (S.encode c)
  ChangeCipherSpec -> 1
  ApplicationData c -> BS.length (S.getOpaque16 c)

headerBytes :: TLSRecord -> BS.ByteString
headerBytes record = S.runTLSEncoder $ do
  encodeRecordContentType (rContent record)
  S.encode (rVersion record)
  Put.putWord16be (fromIntegral $ contentLength record)

encodeRecordContentType :: RecordContent -> Put.Put
encodeRecordContentType = \case
  Handshake{}       -> Put.putWord8 0x16
  ChangeCipherSpec  -> Put.putWord8 0x14
  ApplicationData{} -> Put.putWord8 0x17

instance S.ToWire TLSRecord where
  encode r = do
    encodeRecordContentType (rContent r)
    S.encode (rVersion r)
    let bytes = S.runTLSEncoder (S.encode $ rContent r)
    -- when (BS.length bytes > 16384 {- 2¹⁴ -}) $ fail "record overflow"
    -- -- ^ TODO this should throw a "record_overflow" alert
    S.encode (S.Opaque16 bytes)

instance S.FromWire TLSRecord where
  decode = fmap snd decodeRecord

-- TODO the manuall tracking of the length is *very* tedious and error prone
decodeRecord :: (S.MonadTLSParser m) => m (Int, TLSRecord)
decodeRecord = S.getWord8 >>= \case
  -- handshake
  0x16 -> do
    version <- S.decode
    len <- fromIntegral <$> S.getWord16be
    content <- S.isolate len (Handshake <$> S.decode)
    pure (len+5, TLSRecord version content)

  -- change cipher spec
  0x14 -> do
    -- TODO check that the version is TLS12 and the content should only be
    -- one byte long
    version <- S.decode
    (_content :: S.Opaque16) <- S.decode
    pure (6, TLSRecord version ChangeCipherSpec)

  -- application data
  0x17 -> do
    version <- S.decode
    content <- S.decode
    let len = BS.length (S.getOpaque16 content) + 5
    pure (len, TLSRecord version (ApplicationData content))

  code -> error $ "can't decrypt record with code: " <> show code
