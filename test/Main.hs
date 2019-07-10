module Main where

import qualified Test.Tasty as T
import           Test.Tasty.HUnit ((@?=))
import qualified Test.Tasty.HUnit as T.H

import qualified Network.TLS.Pure.SerializationSpec as Serialization
import qualified Network.TLS.Pure.DebugSpec as Dbg
import qualified Network.TLS.Pure.RoundtripSpec as Roundtrip

main :: IO ()
main = T.defaultMain tests

tests :: T.TestTree
tests = T.testGroup "Tests"
  [ Serialization.tests
  , Dbg.tests
  , Roundtrip.tests
  ]
