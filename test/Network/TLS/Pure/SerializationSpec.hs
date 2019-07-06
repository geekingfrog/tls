module Network.TLS.Pure.SerializationSpec where

import qualified Test.Tasty as T
import           Test.Tasty.HUnit ((@?=))
import qualified Test.Tasty.HUnit as T.H

import qualified Network.TLS.Pure.Extension.SupportedVersions as SV
-- import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Network.TLS.Pure.Version as Version
import qualified Network.TLS.Pure.Handshake.MessageType as H.MT


tests :: T.TestTree
tests = T.testGroup "Serialization" []

testSupportedVersions :: T.TestTree
testSupportedVersions = T.testGroup "SupportedVersions" []
  -- [ T.H.testCase "ServerHello"
  --     ()
  -- ]
