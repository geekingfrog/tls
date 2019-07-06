{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Handshake.MessageType where

import qualified Data.Serialize.Put             as Put
import           GHC.Word

import qualified Network.TLS.Pure.Serialization as S

data MessageType
  = ClientHello
  | ServerHello
  -- | NewSessionTicket
  -- | EndOfEarlyData
  -- | HelloRetryRequest
  -- | EncryptedExtensions
  -- | Certificate
  -- | CertificateRequest
  -- | CertificateVerify
  -- | Finished
  -- | KeyUpdate
  -- | MessageHash
  | Unknown Word8
  deriving (Show)

instance S.ToWire MessageType where
  encode = \case
    ClientHello -> Put.putWord8 1
    ServerHello -> Put.putWord8 2
    -- HelloRetryRequest -> S.putWord8 6
    -- TODO that's a bit dubious to serialize unknown message type
    Unknown w -> Put.putWord8 w

instance S.FromWire MessageType where
  decode = S.getWord8 >>= \case
    1 -> pure ClientHello
    2 -> pure ServerHello
    w -> pure (Unknown w)
