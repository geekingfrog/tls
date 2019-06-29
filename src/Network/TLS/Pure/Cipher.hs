{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE StrictData #-}

module Network.TLS.Pure.Cipher where

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Data.Serialize.Put as S
import qualified Data.Vector as V

data Cipher
  = AES128_GCM
  | AES256_GCM
  | CHACHA20_POLY
  | AES128_CCM
  | AES128_CCM_8
  -- TODO add empty renegotiation info ?
  deriving (Show)

instance Serialization.ToWire Cipher where
  encode = \case
    AES128_GCM    -> S.putWord16be 0x1301
    AES256_GCM    -> S.putWord16be 0x1302
    CHACHA20_POLY -> S.putWord16be 0x1303
    AES128_CCM    -> S.putWord16be 0x1304
    AES128_CCM_8  -> S.putWord16be 0x1305

newtype CipherSuites
  = CipherSuites { getCipherSuites :: V.Vector Cipher }
  deriving Show

instance Serialization.ToWire CipherSuites where
  encode (CipherSuites ciphers)
    = Serialization.encodeVector 2 ciphers
