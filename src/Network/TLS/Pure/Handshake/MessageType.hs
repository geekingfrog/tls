{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Handshake.MessageType where

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Data.Serialize.Put as S
import GHC.Word

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

instance Serialization.ToWire MessageType where
  encode = \case
    ClientHello -> S.putWord8 1
    ServerHello -> S.putWord8 2
    -- HelloRetryRequest -> S.putWord8 6
    -- TODO that's a bit dubious to serialize unknown message type
    Unknown w -> S.putWord8 w
