module Network.TLS.Pure.SerializationSpec where

import qualified Test.Tasty as T
import           Test.Tasty.HUnit ((@?=))
import qualified Test.Tasty.HUnit as T.H
import qualified Data.ByteString as BS
import GHC.Stack (HasCallStack)

import qualified Network.TLS.Pure.Extension.SupportedVersions as SV
import qualified Network.TLS.Pure.Serialization as S
import qualified Network.TLS.Pure.Version as Version
import qualified Network.TLS.Pure.Handshake.MessageType as H.MT
import qualified Network.TLS.Pure.Extension as Ext

import qualified Network.TLS.Pure.Extension.KeyShareSpec as KSS


tests :: T.TestTree
tests = T.testGroup "Serialization"
  [ testVersions
  , KSS.tests
  , testSupportedVersions
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

-- testKeyShare :: T.TestTree
-- testKeyShare = T.testGroup "KeyShare"
--   [ T.H.testCase "ServerHello" $
--       T.H.assertEqual
--         "Decode"
--         (S.runTLSParser S.decode (BS.pack [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]))
--   ]
