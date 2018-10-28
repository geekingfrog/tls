{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Cipher where

import qualified Data.Vector                   as V
import qualified Data.Serialize.Put            as Serial
import qualified Data.Serialize.Get            as Serial
import qualified Network.TLS.Pure.Wire         as Wire

newtype CipherSuites = CipherSuites (V.Vector Cipher)
    deriving (Show, Eq)

instance Wire.ToWire CipherSuites where
    put (CipherSuites suites) = do
        Serial.putWord16be (fromIntegral $ V.length suites * 2)
        mapM_ Wire.put suites

data Cipher
    = AES128_GCM
    | AES256_GCM
    | CHACHA20_POLY
    | AES128_CCM
    | AES128_CCM_8
    -- TODO add empty renegotiation info ?
    deriving (Show, Eq)

instance Wire.ToWire Cipher where
    put AES128_GCM    = Serial.putWord16be 0x1301
    put AES256_GCM    = Serial.putWord16be 0x1302
    put CHACHA20_POLY = Serial.putWord16be 0x1303
    put AES128_CCM    = Serial.putWord16be 0x1304
    put AES128_CCM_8  = Serial.putWord16be 0x1305

instance Wire.FromWire Cipher where
    get = Serial.getWord16be >>= \case
        0x1301 -> pure AES128_GCM
        0x1302 -> pure AES256_GCM
        0x1303 -> pure CHACHA20_POLY
        0x1304 -> pure AES128_CCM
        0x1305 -> pure AES128_CCM_8
        c      -> fail $ "Unknown cipher for code " <> show c

tls13Ciphers :: CipherSuites
tls13Ciphers = CipherSuites $ V.fromList
    [ AES128_GCM
    , AES256_GCM
    , CHACHA20_POLY
    , AES128_CCM
    -- , AES128_CCM_8
    ]
