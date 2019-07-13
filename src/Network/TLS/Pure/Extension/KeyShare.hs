{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE FlexibleInstances #-}

module Network.TLS.Pure.Extension.KeyShare where

import           Control.Applicative
import           Control.Monad                              (when)
import qualified Crypto.Error                               as Crypto
import qualified Crypto.PubKey.Curve25519                   as Curve25519
import qualified Crypto.Random.Types                        as Crypto.Rng
import qualified Data.ByteArray                             as BA
import           Data.Foldable
import qualified Data.Serialize.Put                         as Put
import qualified Data.Vector                                as V
import           GHC.Generics


import qualified Network.TLS.Pure.Error                     as Err
import qualified Network.TLS.Pure.Extension.SupportedGroups as Group
import qualified Network.TLS.Pure.Handshake.MessageType     as H.MT
import           Network.TLS.Pure.Prelude
import qualified Network.TLS.Pure.Serialization             as S

data KSE25519 = KSE25519
  { kse25519Public :: Curve25519.PublicKey
  , kse25519Private :: Maybe Curve25519.SecretKey
  }
  deriving (Show, Eq)

instance S.ToWire KSE25519 where
  encode kse
    = Put.putByteString
    $ BA.convert
    $ kse25519Public kse

mkKSE25519 :: Crypto.Rng.MonadRandom m => m KSE25519
mkKSE25519 = do
  secret <- Curve25519.generateSecretKey
  pure $ KSE25519 (Curve25519.toPublic secret) (Just secret)

newtype KeyShareEntry
  = X25519 KSE25519
  -- | OtherKSE
  deriving (Show, Eq, Generic, EqC)

instance S.ToWire KeyShareEntry where
  encode = \case
    X25519 kse -> do
      S.encode Group.X25519
      let content = Put.runPut $ S.encode kse
      S.encode (S.Opaque16 content)

    -- OtherKSE -> error "wip other KSE serialization"

instance S.FromWire KeyShareEntry where
  decode = fmap snd decodeKeyShareEntry

decodeKeyShareEntry :: S.MonadTLSParser m => m (Int, KeyShareEntry)
decodeKeyShareEntry = S.decode >>= \case
  Group.X25519 -> do
    l <- fromIntegral <$> S.getWord16be
    raw <- S.getByteString l
    case Crypto.eitherCryptoError (Curve25519.publicKey raw) of
      Left cryptoError -> S.throwError $ Err.CryptoFailed cryptoError
      -- l + 2 (word16 for the length of l) + 2 (length of the encoded group)
      Right publicKey -> pure (l+4, X25519 $ KSE25519 publicKey Nothing)

  -- Group.X448 -> error "wip decode kse X448"

-- TODO see if it's worth to add another type parameter: agent (Client | Server)
-- to enforce that the key share have the private key or not
-- example: a KeyShareCH from the client has private keys, but KeyShareCH for the
-- server doesn't
data KeyShare (msgType :: H.MT.MessageType) where
  KeyShareCH :: V.Vector KeyShareEntry -> KeyShare 'H.MT.ClientHello
  KeyShareSH :: KeyShareEntry -> KeyShare 'H.MT.ServerHello
  -- KeyShareHRR :: Group -> KeyShare 'H.MT.HelloRetryRequest

deriving instance Eq (KeyShare a)
deriving instance Show (KeyShare a)

instance S.ToWire (KeyShare a) where
  encode = \case
    KeyShareCH entries -> do
      let content = Put.runPut $ traverse_ S.encode entries
      S.encode (S.Opaque16 content)

    KeyShareSH entry -> S.encode entry

instance S.FromWire (KeyShare 'H.MT.ClientHello) where
  decode = do
    len <- fromIntegral <$> S.getWord16be
    go len []

    where
      -- TODO this is likely not very good performance wise
      go !n acc
        | n < 0 = S.throwError $ Err.InvalidLength "Not enough bytes to decode key share entry"
        | n == 0 = pure $ KeyShareCH (V.fromList $ reverse acc)
        | otherwise = do
            (l, kse) <- decodeKeyShareEntry
            go (n-l) (kse : acc)

instance S.FromWire (KeyShare 'H.MT.ServerHello) where
  decode = KeyShareSH <$> S.decode

data KeyPair = KPX25519
  { kpxPublic :: Curve25519.PublicKey
  , kpxSecret :: Curve25519.SecretKey
  , kpxDh     :: Curve25519.DhSecret
  }
  deriving (Show, Eq)

extractKeyPair
  :: KeyShareEntry
  -> KeyShareEntry
  -> Maybe KeyPair
extractKeyPair a b = case (a, b) of
  (X25519 kseA, X25519 kseB) -> do
    (pub, sec) <-
      ((kse25519Public kseA, ) <$> kse25519Private kseB)
      <|>
      ((kse25519Public kseB, ) <$> kse25519Private kseA)
    -- TODO check for all zero result and throw an error if that's the case
    let dh = Curve25519.dh pub sec
    pure $ KPX25519 pub sec dh
  -- _ -> Nothing
