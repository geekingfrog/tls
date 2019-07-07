{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Extension.SignatureAlgorithms where

import qualified Data.Serialize.Put as S
import qualified Data.Vector as V

import qualified Network.TLS.Pure.Serialization as Serialization

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

instance Serialization.ToWire SignatureAlgorithm where
  encode = \case
    RsaPkcs1Sha256       -> S.putWord16be 0x0401
    RsaPkcs1Sha384       -> S.putWord16be 0x0501
    RsaPkcs1Sha512       -> S.putWord16be 0x0601
    EcdsaSecp256r1Sha256 -> S.putWord16be 0x0403
    EcdsaSecp384r1Sha384 -> S.putWord16be 0x0503
    EcdsaSecp521r1Sha512 -> S.putWord16be 0x0603
    RsaPssRsaeSha256     -> S.putWord16be 0x0804
    RsaPssRsaeSha384     -> S.putWord16be 0x0805
    RsaPssRsaeSha512     -> S.putWord16be 0x0806
    Ed25519              -> S.putWord16be 0x0807
    Ed448                -> S.putWord16be 0x0808
    RsaPssPssSha256      -> S.putWord16be 0x0809
    RsaPssPssSha384      -> S.putWord16be 0x080a
    RsaPssPssSha512      -> S.putWord16be 0x080b
    RsaPkcs1Sha1         -> S.putWord16be 0x0201
    EcdsaSha1            -> S.putWord16be 0x0203


newtype SignatureAlgorithms
    = SignatureAlgorithms (V.Vector SignatureAlgorithm)
    deriving (Show, Eq)

instance Serialization.ToWire SignatureAlgorithms where
  encode (SignatureAlgorithms algs)
    = Serialization.encodeVector 2 algs
