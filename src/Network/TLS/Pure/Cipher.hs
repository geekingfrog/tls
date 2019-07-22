{-# LANGUAGE DataKinds    #-}
{-# LANGUAGE LambdaCase   #-}
{-# LANGUAGE StrictData   #-}
{-# LANGUAGE TypeFamilies #-}

module Network.TLS.Pure.Cipher where

import qualified Data.Vector as V
import qualified Data.Serialize.Put as Put

import qualified Network.TLS.Pure.Serialization as S
import qualified Network.TLS.Pure.Debug as Dbg

data Cipher
  = AES128_GCM
  | AES256_GCM
  | CHACHA20_POLY
  | AES128_CCM
  | AES128_CCM_8
  -- TODO add empty renegotiation info ?
  deriving (Show, Eq)

instance S.ToWire Cipher where
  encode = \case
    AES128_GCM    -> Put.putWord16be 0x1301
    AES256_GCM    -> Put.putWord16be 0x1302
    CHACHA20_POLY -> Put.putWord16be 0x1303
    AES128_CCM    -> Put.putWord16be 0x1304
    AES128_CCM_8  -> Put.putWord16be 0x1305

instance S.FromWire Cipher where
  decode = S.getWord16be >>= \case
    0x1301 -> pure AES128_GCM
    0x1302 -> pure AES256_GCM
    0x1303 -> pure CHACHA20_POLY
    0x1304 -> pure AES128_CCM
    0x1305 -> pure AES128_CCM_8
    code   -> fail $ "Unknown Cipher code: " <> Dbg.showHex code

instance S.FixedSize Cipher where
  type ByteSize Cipher = 2

newtype CipherSuites
  = CipherSuites { getCipherSuites :: V.Vector Cipher }
  deriving (Show, Eq)

instance S.ToWire CipherSuites where
  encode (CipherSuites ciphers)
    = S.encodeVector ciphers

instance S.FromWire CipherSuites where
  decode = CipherSuites <$> S.decodeVector16 2
