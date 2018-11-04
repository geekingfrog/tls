{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.TLS.Pure.Packet where

import Debug.Trace as D

import Control.Monad

import qualified Numeric                    as N
import qualified Data.List.Split            as Split
import qualified Util

import qualified Data.Bits                          as Bits
import qualified Data.ByteString                    as B
import qualified Data.Serialize                     as Serial
import qualified Network.TLS.Pure.Wire              as Wire

import qualified Network.TLS.Pure.Handshake.Header  as Handshake
import qualified Network.TLS.Pure.Cipher            as Cipher
import qualified Network.TLS.Pure.Extension         as Ext
import qualified Network.TLS.Pure.Version           as Version


newtype TLSPacket
    = Handshake HandshakePacket
    deriving (Show)

instance Wire.ToWire TLSPacketType where
    put TLSPacketTypeHandshake = Serial.putWord8 22

instance Wire.FromWire TLSPacketType where
    get = Serial.getWord8 >>= \case
        22 -> pure TLSPacketTypeHandshake
        c  -> fail $ "Unknown tls packet code: " <> show c


data TLSPacketType
    = TLSPacketTypeHandshake
    deriving (Show)

instance Wire.ToWire TLSPacket where
    put (Handshake p) = do
        Wire.put TLSPacketTypeHandshake
        Wire.put Version.TLS10
        let packetBytes = Serial.runPut (Wire.put p)
        Wire.putOpaque16 packetBytes

instance Wire.FromWire TLSPacket where
    get = do
        pktType <- Wire.get
        (version :: Version.Version) <- Wire.get
        -- TODO check the version there (not always TLS10)
        -- when (version /= Version.TLS10) $
        --     fail ("Legacy version must be TLS10 but got " <> show version)
        pktLength <- fromIntegral <$> Serial.getWord16be
        case pktType of
            TLSPacketTypeHandshake -> Handshake <$> Wire.get


data HandshakePacket
    = ClientHello ClientHelloData
    | ServerHello ServerHelloData
    deriving (Show)

instance Wire.ToWire HandshakePacket where
    put (ClientHello chloData) = do
        let dataBytes = Serial.runPut (Wire.put Version.TLS12 *> Wire.put chloData)
        Wire.put Handshake.ClientHello
        Wire.putWord24 (B.length dataBytes)
        Serial.putByteString dataBytes

    put (ServerHello shloData) = error "put ServerHello not implemented"


instance Wire.FromWire HandshakePacket where
    get = do
        handshakeType <- Wire.get
        len <- fromIntegral <$> Wire.getWord24be
        version <- Wire.get
        when (version /= Version.TLS12) $
            fail ("Legacy version must be TLS12 but got " <> show version)
        case handshakeType of
            Handshake.ClientHello -> ClientHello <$> Wire.get
            Handshake.ServerHello -> ServerHello <$> Wire.get
            _ -> error "wip FromWire HandshakePacket"


data ClientHelloData
    = ClientHelloData
    { chlodRandom     :: !B.ByteString -- TODO
    , chlodSessionId  :: !Wire.Opaque8 -- TODO
    , chlodCiphers    :: !Cipher.CipherSuites
    , chlodExtensions :: !Ext.Extensions
    }
    deriving (Show)


instance Wire.ToWire ClientHelloData where
    -- TODO instead of hardcoding a bunch of things there, do the actual thing
    -- regarding versions and co
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
