{-# LANGUAGE DataKinds #-}

module Network.TLS.Pure.RoundtripSpec where

import qualified Data.ByteString                        as BS
import qualified Data.Vector                            as V
import qualified Hedgehog                               as H
import qualified Hedgehog.Gen                           as Gen
import qualified Hedgehog.Range                         as Range
import qualified Test.Tasty                             as T
import           Test.Tasty.Hedgehog                    (testProperty)
import           Test.Tasty.HUnit                       ((@?=))
import qualified Test.Tasty.HUnit                       as T.H
import GHC.Word
import  Crypto.Random.Types                   (MonadRandom(..))
import qualified Crypto.PubKey.Curve25519                   as Curve25519
import qualified Data.ByteArray                             as BA

import Control.Monad.Trans

import qualified Network.TLS.Pure.Cipher                as Cipher
import qualified Network.TLS.Pure.Error                 as Err
import qualified Network.TLS.Pure.Handshake.ClientHello as CH
import qualified Network.TLS.Pure.Handshake.Common      as H.C
import qualified Network.TLS.Pure.Serialization         as S
import qualified Network.TLS.Pure.Version               as Version
import qualified Network.TLS.Pure.Extension as Ext
import qualified Network.TLS.Pure.Extension.SupportedVersions               as SV
import qualified Network.TLS.Pure.Extension.KeyShare               as KS
import qualified Network.TLS.Pure.Handshake.MessageType as H.MT
import qualified Network.TLS.Pure.Extension.SignatureAlgorithms  as SA
import qualified Network.TLS.Pure.Extension.ServerNameIndication as SNI
import qualified Network.TLS.Pure.Extension.SupportedGroups      as SG


tests :: T.TestTree
tests = T.testGroup "Roundtrip"
  [ testProperty "Version" (roundtrip genProtocolVersion)
  , testProperty "Random" (roundtrip genRandom)
  , testProperty "CipherSuites" (roundtrip genCipherSuites)
  , T.testGroup "Extensions"
    [ testProperty "Supported Versions ClientHello" (roundtrip genSupportedVersionCH)
    , testProperty "Supported Versions ServerHello" (roundtrip genSupportedVersionSH)
    , testProperty "KeyShare ClientHello" (roundtrip genKeyShareCH)
    , testProperty "KeyShare ServerHello" (roundtrip genKeyShareSH)
    , testProperty "Signature Algorithms" (roundtrip genSignatureAlgorithms)
    , testProperty "Server Name Indication" (roundtrip genSNI)
    , testProperty "Supported Groups" (roundtrip genSupportedGroups)
    , testProperty "All Extensions ClientHello" (roundtrip genExtensionCH)
    , testProperty "All Extensions ServerHello" (roundtrip genExtensionSH)
    ]
  ]

genProtocolVersion :: H.Gen Version.ProtocolVersion
genProtocolVersion = Gen.choice
  [ pure Version.TLS10
  , pure Version.TLS12
  , pure Version.TLS13
  , Version.Unknown <$> Gen.filter
      (\x -> x /= 0x0301 && x /= 0x0303 && x /= 0x0304)
      (Gen.word16 Range.linearBounded)
  ]


genRandom :: H.MonadGen m => m H.C.Random
genRandom = H.C.Random <$> Gen.bytes (Range.singleton 32)


genCipherSuites :: H.MonadGen m => m Cipher.CipherSuites
genCipherSuites = fmap (Cipher.CipherSuites . V.fromList) $ Gen.list (Range.linear 1 5) $ Gen.element
    [ Cipher.AES128_GCM
    , Cipher.AES256_GCM
    , Cipher.CHACHA20_POLY
    , Cipher.AES128_CCM
    , Cipher.AES128_CCM_8
    ]


genSupportedVersionCH :: H.Gen (SV.SupportedVersions 'H.MT.ClientHello)
genSupportedVersionCH = do
  versions <- Gen.list (Range.linear 1 3) genProtocolVersion
  pure $ SV.SupportedVersionsCH (V.fromList versions)

genSupportedVersionSH :: H.Gen (SV.SupportedVersions 'H.MT.ServerHello)
genSupportedVersionSH = SV.SupportedVersionsSH <$> genProtocolVersion

-- TODO get rid of this orphan instance
instance Monad m => MonadRandom (H.GenT m) where
  getRandomBytes size = do
    bytes <- Gen.bytes (Range.singleton size)
    pure $ BA.convert bytes

genKeyShareCH :: H.Gen (KS.KeyShare 'H.MT.ClientHello)
genKeyShareCH = KS.KeyShareCH . V.fromList
  <$> Gen.list (Range.singleton 1) genKSE


genKeyShareSH :: H.Gen (KS.KeyShare 'H.MT.ServerHello)
genKeyShareSH = KS.KeyShareSH <$> genKSE


genKSE :: (H.MonadGen m, MonadRandom m) => m KS.KeyShareEntry
genKSE = do
  secret <- Curve25519.generateSecretKey
  let pub = Curve25519.toPublic secret
  -- the secret key isn't serialized, so omit it for roundtrip checks
  pure $ KS.X25519 $ KS.KSE25519 pub Nothing

genSignatureAlgorithms :: H.Gen SA.SignatureAlgorithms
genSignatureAlgorithms = SA.SignatureAlgorithms . V.fromList
  <$> Gen.list (Range.linear 1 16)
    (Gen.element
      [ SA.RsaPkcs1Sha256
      , SA.RsaPkcs1Sha384
      , SA.RsaPkcs1Sha512
      , SA.EcdsaSecp256r1Sha256
      , SA.EcdsaSecp384r1Sha384
      , SA.EcdsaSecp521r1Sha512
      , SA.RsaPssRsaeSha256
      , SA.RsaPssRsaeSha384
      , SA.RsaPssRsaeSha512
      , SA.Ed25519
      , SA.Ed448
      , SA.RsaPssPssSha256
      , SA.RsaPssPssSha384
      , SA.RsaPssPssSha512
      , SA.RsaPkcs1Sha1
      , SA.EcdsaSha1
      ]
    )


genSNI :: H.MonadGen m => m SNI.ServerName
genSNI = SNI.ServerName <$> Gen.bytes (fromIntegral <$> (Range.linearBounded :: Range.Range Word8))


genSupportedGroups :: H.MonadGen m => m SG.SupportedGroups
genSupportedGroups = SG.SupportedGroups . V.fromList
  <$> Gen.list (Range.singleton 1) (pure SG.X25519)


genExtensionCH :: H.Gen (Ext.Extension 'H.MT.ClientHello)
genExtensionCH = Gen.choice
  [ Ext.SupportedVersions <$> genSupportedVersionCH
  , Ext.KeyShare <$> genKeyShareCH
  , Ext.SignatureAlgorithms <$> genSignatureAlgorithms
  , Ext.ServerNameIndication <$> genSNI
  , Ext.SupportedGroups <$> genSupportedGroups
  , genUnknownExtension >>= \(l, bytes) -> pure $ Ext.Unknown l bytes
  ]

genExtensionSH :: H.Gen (Ext.Extension 'H.MT.ServerHello)
genExtensionSH = Gen.choice
  [ Ext.SupportedVersions <$> genSupportedVersionSH
  , Ext.KeyShare <$> genKeyShareSH
  , Ext.SignatureAlgorithms <$> genSignatureAlgorithms
  , Ext.ServerNameIndication <$> genSNI
  , Ext.SupportedGroups <$> genSupportedGroups
  , genUnknownExtension >>= \(l, bytes) -> pure $ Ext.Unknown l bytes
  ]

genUnknownExtension :: H.Gen (Word16, BS.ByteString)
genUnknownExtension = do
  let knownCodes = [0, 10, 13, 43, 51]
  code <- Gen.filter (`notElem` knownCodes) $ Gen.word16 (Range.linearBounded :: Range.Range Word16)
  bs <- Gen.bytes (fromIntegral <$> (Range.linearBounded :: Range.Range Word16))
  pure (code, bs)

genOpaque8 :: H.MonadGen m => m S.Opaque8
genOpaque8 = S.Opaque8 <$> Gen.bytes (fromIntegral <$> (Range.linearBounded :: Range.Range Word8))


roundtrip
  :: (S.ToWire a, S.FromWire a, Show a, Eq a)
  => H.Gen a
  -> H.Property
roundtrip gen = H.property $ do
  val <- H.forAll gen
  let x = S.runTLSParser S.decode (S.runTLSEncoder $ S.encode val)
  x H.=== Right val


-- Use '--hedgehog-replay "Size 0 Seed 14283716626356546830 2126914509161056859"' to reproduce.
