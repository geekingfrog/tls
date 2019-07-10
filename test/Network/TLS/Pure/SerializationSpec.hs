{-# LANGUAGE QuasiQuotes #-}

module Network.TLS.Pure.SerializationSpec where

import qualified Test.Tasty as T
import           Test.Tasty.HUnit ((@?=))
import qualified Test.Tasty.HUnit as T.H
import qualified Data.ByteString as BS
import qualified Data.Serialize.Put as Put
import GHC.Stack (HasCallStack)

import qualified Network.TLS.Pure.Extension.SupportedVersions as SV
import qualified Network.TLS.Pure.Serialization as S
import qualified Network.TLS.Pure.Version as Version
import qualified Network.TLS.Pure.Handshake.MessageType as H.MT
import qualified Network.TLS.Pure.Extension as Ext
import qualified Network.TLS.Pure.Debug as Dbg
import qualified Network.TLS.Pure.Packet as Pkt

import qualified Network.TLS.Pure.Extension.KeyShareSpec as KSS


tests :: T.TestTree
tests = T.testGroup "Serialization"
  [ testVersions
  , KSS.tests
  , testSupportedVersions
  -- , testRoundTrip
  ]

testVersions :: T.TestTree
testVersions = T.testGroup "Versions"
  [ T.H.testCase "1.3" $
      S.runTLSParser S.decode (BS.pack [0x03, 0x04]) @?= Right Version.TLS13
  , T.H.testCase "1.2" $
      S.runTLSParser S.decode (BS.pack [0x03, 0x03]) @?= Right Version.TLS12
  , T.H.testCase "Unknown" $
      S.runTLSParser S.decode (BS.pack [0x03, 0x05]) @?= Right (Version.Unknown 773)
  ]


testSupportedVersions :: T.TestTree
testSupportedVersions = T.testGroup "SupportedVersions"
  [ T.H.testCase "ServerHello" $
      T.H.assertEqual
        "Decode"
        (S.runTLSParser S.decode (BS.pack [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]))
        (Right (Ext.SupportedVersions $ SV.SupportedVersionsSH Version.TLS13))

  ]

testRoundTrip :: T.TestTree
testRoundTrip = T.testGroup "Roundtrip"
  [ T.H.testCase "ClientHello" $ do
      let raw =  [Dbg.hexStream|16030100ca010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304
|]
      T.H.assertEqual
        "Chlo"
        (fmap (S.runTLSEncoder . encodePacket) (S.runTLSParser S.decode raw))
        (Right raw)
  ]

encodePacket :: Pkt.TLSPacket -> Put.Put
encodePacket = S.encode

-- testKeyShare :: T.TestTree
-- testKeyShare = T.testGroup "KeyShare"
--   [ T.H.testCase "ServerHello" $
--       T.H.assertEqual
--         "Decode"
--         (S.runTLSParser S.decode (BS.pack [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]))
--   ]
