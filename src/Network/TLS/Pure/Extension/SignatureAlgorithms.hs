{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Extension.SignatureAlgorithms where

import qualified Data.Vector as V
import qualified Data.Serialize.Put as Put

import qualified Network.TLS.Pure.Serialization as S
import qualified Network.TLS.Pure.Error as Err

data SignatureAlgorithm
    = RsaPkcs1Sha256
    | RsaPkcs1Sha384
    | RsaPkcs1Sha512
    | EcdsaSecp256r1Sha256
    | EcdsaSecp384r1Sha384
    | EcdsaSecp521r1Sha512
    | RsaPssRsaeSha256
    | RsaPssRsaeSha384
    | RsaPssRsaeSha512
    | Ed25519
    | Ed448
    | RsaPssPssSha256
    | RsaPssPssSha384
    | RsaPssPssSha512
    | RsaPkcs1Sha1
    | EcdsaSha1
    -- | PrivateUse
    deriving (Show, Eq)

instance S.ToWire SignatureAlgorithm where
  encode = \case
    RsaPkcs1Sha256       -> Put.putWord16be 0x0401
    RsaPkcs1Sha384       -> Put.putWord16be 0x0501
    RsaPkcs1Sha512       -> Put.putWord16be 0x0601
    EcdsaSecp256r1Sha256 -> Put.putWord16be 0x0403
    EcdsaSecp384r1Sha384 -> Put.putWord16be 0x0503
    EcdsaSecp521r1Sha512 -> Put.putWord16be 0x0603
    RsaPssRsaeSha256     -> Put.putWord16be 0x0804
    RsaPssRsaeSha384     -> Put.putWord16be 0x0805
    RsaPssRsaeSha512     -> Put.putWord16be 0x0806
    Ed25519              -> Put.putWord16be 0x0807
    Ed448                -> Put.putWord16be 0x0808
    RsaPssPssSha256      -> Put.putWord16be 0x0809
    RsaPssPssSha384      -> Put.putWord16be 0x080a
    RsaPssPssSha512      -> Put.putWord16be 0x080b
    RsaPkcs1Sha1         -> Put.putWord16be 0x0201
    EcdsaSha1            -> Put.putWord16be 0x0203

instance S.FromWire SignatureAlgorithm where
  decode = S.getWord16be >>= \case
    0x0401 -> pure RsaPkcs1Sha256
    0x0501 -> pure RsaPkcs1Sha384
    0x0601 -> pure RsaPkcs1Sha512
    0x0403 -> pure EcdsaSecp256r1Sha256
    0x0503 -> pure EcdsaSecp384r1Sha384
    0x0603 -> pure EcdsaSecp521r1Sha512
    0x0804 -> pure RsaPssRsaeSha256
    0x0805 -> pure RsaPssRsaeSha384
    0x0806 -> pure RsaPssRsaeSha512
    0x0807 -> pure Ed25519
    0x0808 -> pure Ed448
    0x0809 -> pure RsaPssPssSha256
    0x080a -> pure RsaPssPssSha384
    0x080b -> pure RsaPssPssSha512
    0x0201 -> pure RsaPkcs1Sha1
    0x0203 -> pure EcdsaSha1
    w -> S.throwError (Err.InvalidSignatureAlgorithm w)

newtype SignatureAlgorithms
    = SignatureAlgorithms (V.Vector SignatureAlgorithm)
    deriving (Show, Eq)

instance S.ToWire SignatureAlgorithms where
  encode (SignatureAlgorithms algs)
    = S.encodeVector 2 algs

instance S.FromWire SignatureAlgorithms where
  decode = SignatureAlgorithms <$> S.decodeVector 2
