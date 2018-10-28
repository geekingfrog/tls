module Network.TLS.Pure.Packet where

import qualified Numeric                    as N
import qualified Data.List.Split            as Split
import Util

import qualified Data.Bits                          as Bits
import qualified Data.ByteString                    as B
import qualified Data.Serialize                     as Serial
import qualified Network.TLS.Pure.Wire              as Wire

import qualified Network.TLS.Pure.Packet.Handshake  as Handshake
import qualified Network.TLS.Pure.Cipher            as Cipher
import qualified Network.TLS.Pure.Extension         as Ext

newtype TLSPacket
    = Handshake HandshakePacket
    deriving (Show, Eq)

instance Wire.ToWire TLSPacket where
    put (Handshake p) = do
        Serial.putWord8 22
        Wire.put Ext.TLS10
        let packetBytes = Serial.runPut (Wire.put p)
        Serial.putWord16be $ fromIntegral (B.length packetBytes)
        Serial.putByteString packetBytes

newtype HandshakePacket
    = ClientHello ClientHelloData
    deriving (Show, Eq)

instance Wire.ToWire HandshakePacket where
    put (ClientHello chloData) = do
        let dataBytes = Serial.runPut (Wire.put chloData)
        Serial.putWord8 1 -- chlo handshake code
        Wire.putWord24 (B.length dataBytes + 2) -- length of TLS version
        Wire.put Ext.TLS12
        Serial.putByteString dataBytes


data ClientHelloData
    = ClientHelloData
    { chlodCiphers    :: !Cipher.CipherSuites
    , chlodRandom     :: !B.ByteString -- TODO
    , chlodExtensions :: !Ext.Extensions
    }
    deriving (Show, Eq)


instance Wire.ToWire ClientHelloData where
    -- TODO instead of hardcoding a bunch of things there, do the actual thing
    -- regarding versions and co
    put chlod = do
        Serial.putByteString (chlodRandom chlod) -- Random

        -- TODO session ID
        Serial.putWord8 32
        Serial.putByteString $ B.replicate 32 0x01

        Wire.put $ chlodCiphers chlod

        -- compression method for TLS13
        Serial.putWord8 1
        Serial.putWord8 0

        Wire.put $ chlodExtensions chlod
        -- Serial.putByteString hardcoded

hardcoded = hexToBs
    $ map (fst . head . N.readHex)
    $ Split.chunksOf 2
    "008f0000000e000c0000096c6f63616c686f7374000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d002035d7341289ba8b30af3b1c967446b0190caf4da23f55f44aee1b06b1c8aec179"
