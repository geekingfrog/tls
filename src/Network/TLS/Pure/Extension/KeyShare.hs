{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Extension.KeyShare where

import           Data.Foldable
import qualified Crypto.Random.Types as Crypto.Rng
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Data.Serialize.Put as S
import qualified Data.Vector as V
import qualified Data.ByteArray                as BA

import qualified Network.TLS.Pure.Handshake.MessageType as H.MT
import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Network.TLS.Pure.Extension.SupportedGroups as Group

data KSE25519 = KSE25519
  { kse25519Public :: Curve25519.PublicKey
  , kse25519Private :: Maybe Curve25519.SecretKey
  }

instance Serialization.ToWire KSE25519 where
  encode kse
    = S.putByteString
    $ BA.convert
    $ kse25519Public kse

mkKSE25519 :: Crypto.Rng.MonadRandom m => m KSE25519
mkKSE25519 = do
  secret <- Curve25519.generateSecretKey
  pure $ KSE25519 (Curve25519.toPublic secret) (Just secret)

data KeyShareEntry
  = X25519 KSE25519
  | OtherKSE

instance Serialization.ToWire KeyShareEntry where
  encode = \case
    X25519 kse -> do
      Serialization.encode Group.X25519
      let content = S.runPut $ Serialization.encode kse
      Serialization.encode (Serialization.Opaque16 content)

    OtherKSE -> error "wip other KSE serialization"

-- TODO see if it's worth to add another type parameter: agent (Client | Server)
-- to enforce that the key share have the private key or not
-- example: a KeyShareCH from the client has private keys, but KeyShareCH for the
-- server doesn't
data KeyShare (msgType :: H.MT.MessageType) where
  KeyShareCH :: V.Vector KeyShareEntry -> KeyShare 'H.MT.ClientHello
  KeyShareSH :: KeyShareEntry -> KeyShare 'H.MT.ServerHello
  -- KeyShareHRR :: Group -> KeyShare 'H.MT.HelloRetryRequest


instance Serialization.ToWire (KeyShare a) where
  encode = \case
    KeyShareCH entries -> do
      let content = S.runPut $ traverse_ Serialization.encode entries
      Serialization.encode (Serialization.Opaque16 content)

    KeyShareSH entry -> Serialization.encode entry
