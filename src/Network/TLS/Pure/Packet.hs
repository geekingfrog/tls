{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE BangPatterns #-}

module Network.TLS.Pure.Packet where

import Debug.Trace as D

import Data.Functor
import Data.Foldable
import Control.Monad

import qualified Numeric                    as N
import qualified Data.List.Split            as Split
import qualified Util

import qualified Data.Bits                          as Bits
import qualified Data.ByteString                    as B
import qualified Data.Vector                        as V
import qualified Data.Serialize                     as Serial
import qualified Network.TLS.Pure.Wire              as Wire

import qualified Network.TLS.Pure.Handshake.Header  as Handshake
import qualified Network.TLS.Pure.Cipher            as Cipher
import qualified Network.TLS.Pure.Extension         as Ext
import qualified Network.TLS.Pure.Version           as Version


newtype TLSPacket
    = TLSPacket (V.Vector TLSRecord)
    deriving (Show)

instance Wire.ToWire TLSPacket where
    put (TLSPacket records) = traverse_ Wire.put records

instance Wire.FromWire TLSPacket where
    get = TLSPacket . V.fromList <$> parsePacket []
      where
        parsePacket (!acc) = do
            r <- Serial.remaining
            if r == 0
                then pure (reverse acc)
                else do
                    !record <- Wire.get
                    parsePacket (record : acc)


data TLSRecordType
    = TLSRecordTypeChangeCipherSpec
    | TLSRecordTypeAlert
    | TLSRecordTypeHandshake
    | TLSRecordTypeApplicationData
    deriving (Show)

instance Wire.ToWire TLSRecordType where
    put TLSRecordTypeChangeCipherSpec = Serial.putWord8 20
    put TLSRecordTypeAlert            = Serial.putWord8 21
    put TLSRecordTypeHandshake        = Serial.putWord8 22
    put TLSRecordTypeApplicationData  = Serial.putWord8 23

instance Wire.FromWire TLSRecordType where
    get = Serial.getWord8 >>= \case
        20 -> pure TLSRecordTypeChangeCipherSpec
        21 -> pure TLSRecordTypeAlert
        22 -> pure TLSRecordTypeHandshake
        23 -> pure TLSRecordTypeApplicationData
        c  -> fail $ "Unknown tls packet code: " <> show c


data TLSRecord
    = HandshakeRecord !Handshake
    | EncryptedRecord !TLSRecordType !B.ByteString

instance Show TLSRecord where
    show (HandshakeRecord h)
        = "HandshakeRecord " <> show h
    show (EncryptedRecord typ bytes)
        = "EncryptedRecord "
        <> show typ
        <> " ("
        <> show (B.length bytes)
        <> " bytes)"


instance Wire.ToWire TLSRecord where
    put (HandshakeRecord h) = do
        Wire.put TLSRecordTypeHandshake
        putLegacyVersion
        let bytes = Serial.runPut (Wire.put h)
        Wire.putOpaque16 bytes

    put (EncryptedRecord typ bytes) = do
        Wire.put typ
        putLegacyVersion
        Wire.putOpaque16 bytes


instance Wire.FromWire TLSRecord where
    get = do
        recordType <- Wire.get
        (_legacyVersion :: Version.Version) <- Wire.get
        recordLength <- fromIntegral <$> Serial.getWord16be
        case recordType of
            TLSRecordTypeHandshake -> HandshakeRecord <$> Serial.isolate recordLength Wire.get
            _ -> EncryptedRecord recordType <$> Serial.getByteString recordLength

putLegacyVersion :: Serial.Put
putLegacyVersion = Wire.put Version.TLS12


data Handshake
    = ClientHello !ClientHelloData
    | ServerHello !ServerHelloData
    deriving (Show)

instance Wire.ToWire Handshake where
    put handshake = do
        let dataBytes = Serial.runPut (Wire.put Version.TLS12 *> putHandshakeBytes handshake)
        Wire.put Handshake.ClientHello
        Wire.putWord24 (B.length dataBytes)
        Serial.putByteString dataBytes

putHandshakeBytes :: Handshake -> Serial.Put
putHandshakeBytes (ClientHello c) = Wire.put c
putHandshakeBytes (ServerHello s) = Wire.put s

instance Wire.FromWire Handshake where
    get = do
        handshakeType <- Wire.get
        len <- fromIntegral <$> Wire.getWord24be
        version <- Wire.get
        when (version /= Version.TLS12) $
            fail ("Legacy version must be TLS12 but got " <> show version)
        case handshakeType of
            Handshake.ClientHello -> ClientHello <$> Wire.get
            Handshake.ServerHello -> ServerHello <$> Wire.get
            _ -> error "wip FromWire Handshake"


data ClientHelloData
    = ClientHelloData
    { chlodRandom     :: !B.ByteString -- TODO
    , chlodSessionId  :: !Wire.Opaque8 -- TODO
    , chlodCiphers    :: !Cipher.CipherSuites
    , chlodExtensions :: !Ext.Extensions
    }
    deriving (Show)


instance Wire.ToWire ClientHelloData where
    put chlod = do
        Serial.putByteString (chlodRandom chlod) -- Random

        Wire.put (chlodSessionId chlod)

        Wire.put $ chlodCiphers chlod

        -- compression method for TLS13
        Serial.putWord8 1
        Serial.putWord8 0

        Wire.put $ chlodExtensions chlod

instance Wire.FromWire ClientHelloData where
    get = do
        rnd <- Serial.getByteString 32
        sess <- Wire.get
        ciphers <- Wire.get
        exts <- Ext.parseExtensions Handshake.ClientHello
        pure $ ClientHelloData
            { chlodRandom     = rnd
            , chlodSessionId  = sess
            , chlodCiphers    = ciphers
            , chlodExtensions = exts
            }


data ServerHelloData = ServerHelloData
    { shlodRandom     :: !B.ByteString
    , shlodSessionId  :: !Wire.Opaque8
    , shlodCipher     :: !Cipher.Cipher
    , shlodExtensions :: !Ext.Extensions
    }
    deriving Show

instance Wire.ToWire ServerHelloData where
    put shlod = do
        -- TODO generic to the rescue ?
        Serial.putByteString (shlodRandom shlod)
        Wire.put (shlodSessionId shlod)
        Wire.put (shlodCipher shlod)
        Wire.put (shlodExtensions shlod)

instance Wire.FromWire ServerHelloData where
    get = do
        rnd <- Serial.getByteString 32
        sess <- Wire.get
        cipher <- Wire.get
        Serial.skip 1 -- skip compression method
        exts <- Ext.parseExtensions Handshake.ServerHello
        -- rawExts <- Util.bsToHex <$> Serial.getByteString 46
        -- D.traceShow rawExts (pure ())
        pure $ ServerHelloData
            { shlodRandom = rnd
            , shlodSessionId = sess
            , shlodCipher = cipher
            , shlodExtensions = exts
            }

-- hardcoded = hexToBs
--     $ map (fst . head . N.readHex)
--     $ Split.chunksOf 2
--     "008f0000000e000c0000096c6f63616c686f7374000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d002035d7341289ba8b30af3b1c967446b0190caf4da23f55f44aee1b06b1c8aec179"
