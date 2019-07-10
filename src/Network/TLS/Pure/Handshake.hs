{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE StrictData #-}

module Network.TLS.Pure.Handshake where

import Data.Foldable
import Control.Applicative
import qualified Data.Serialize.Put as Put

import qualified Network.TLS.Pure.Extension             as Ext
import qualified Network.TLS.Pure.Extension.KeyShare    as KS
import qualified Network.TLS.Pure.Handshake.ClientHello as CH
import qualified Network.TLS.Pure.Handshake.MessageType as MT
import qualified Network.TLS.Pure.Handshake.ServerHello as SH
import           Network.TLS.Pure.Prelude
import qualified Network.TLS.Pure.Serialization         as S

data Handshake
  = ClientHello13 CH.ClientHello13Data
  | ServerHello13 SH.ServerHello13Data
  deriving (Show)

instance S.ToWire Handshake where
  encode = \case
    ClientHello13 chloData -> do
      S.encode MT.ClientHello
      let bytes = Put.runPut (S.encode chloData)
      S.encode (S.Opaque24 bytes)

    ServerHello13{} -> error "wip encode serverHello13"


instance S.FromWire Handshake where
  decode = S.decode >>= \case
    MT.ClientHello -> error "wip decode handshake client hello"
    MT.ServerHello -> S.getNested (fmap fromIntegral S.getWord24be) (ServerHello13 <$> S.decode)
    MT.Unknown w -> fail $ "Unknown message type: " <> show w


data SelectKeyShareError
  = NoClientKeyShare
  | NoServerKeyShare -- not sure it's required, perhaps check that beforehand?
  | NoMatchingKeyShareEntry
  | NoValidPrivateSecretPair
  deriving (Show, Eq)

selectKeyShare
  :: CH.ClientHello13Data
  -> SH.ServerHello13Data
  -> Either SelectKeyShareError KS.KeyPair

selectKeyShare chloData shloData = do
  clientKs <- note NoClientKeyShare $ Ext.findKeyShare (CH.chlo13dExtensions chloData)
  serverKs <- note NoServerKeyShare $ Ext.findKeyShare (SH.shlo13dExtensions shloData)
  let serverKse = case serverKs of KS.KeyShareSH kse -> kse
  let clientKses = case clientKs of KS.KeyShareCH kses -> kses
  note NoMatchingKeyShareEntry
    $ foldl' (\kp clientKse -> kp <|> KS.extractKeyPair serverKse clientKse) Nothing clientKses
