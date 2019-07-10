module Network.TLS.Pure.RoundtripSpec where

import qualified Hedgehog            as H
import qualified Hedgehog.Gen        as Gen
import qualified Hedgehog.Range      as Range
import qualified Test.Tasty          as T
import           Test.Tasty.Hedgehog (testProperty)
import           Test.Tasty.HUnit    ((@?=))
import qualified Test.Tasty.HUnit    as T.H
import qualified Data.ByteString as BS
import qualified Data.Vector as V


import qualified Network.TLS.Pure.Version as Version
import qualified Network.TLS.Pure.Serialization as S
import qualified Network.TLS.Pure.Handshake.Common as H.C
import qualified Network.TLS.Pure.Error as Err
import qualified Network.TLS.Pure.Cipher as Cipher

tests :: T.TestTree
tests = T.testGroup "Roundtrip"
  [ testProperty "Version" roundtripVersion
  , testProperty "Random" roundtripRandom
  , testProperty "CipherSuites" roundtripCipherSuites
  ]

roundtripVersion :: H.Property
roundtripVersion = H.property $ do
  v <- H.forAll $ Gen.choice
    [ pure Version.TLS10
    , pure Version.TLS12
    , pure Version.TLS13
    , fmap Version.Unknown (Gen.word16 Range.linearBounded)
    ]
  roundtrip v H.=== Right v

roundtripRandom :: H.Property
roundtripRandom = H.property $ do
  bs <- H.forAll $ H.C.Random <$> Gen.bytes (Range.constant 32 32)
  roundtrip bs H.=== Right bs


roundtripCipherSuites :: H.Property
roundtripCipherSuites = H.property $ do
  suites <- H.forAll $ fmap (Cipher.CipherSuites . V.fromList) $ Gen.list (Range.linear 1 5) $ Gen.element
    [ Cipher.AES128_GCM
    , Cipher.AES256_GCM
    , Cipher.CHACHA20_POLY
    , Cipher.AES128_CCM
    , Cipher.AES128_CCM_8
    ]
  roundtrip suites H.=== Right suites

roundtrip :: (S.ToWire a, S.FromWire a) => a -> Either Err.ParseError a
roundtrip x = S.runTLSParser S.decode (S.runTLSEncoder $ S.encode x)
