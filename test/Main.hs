module Main where

import qualified Test.Tasty as T
import           Test.Tasty.HUnit ((@?=))
import qualified Test.Tasty.HUnit as T.H

import qualified Network.TLS.Pure.SerializationSpec as Serialization
import qualified Network.TLS.Pure.DebugSpec as Dbg

main :: IO ()
main = T.defaultMain tests

tests :: T.TestTree
tests = T.testGroup "Tests"
  [ Serialization.tests
  , Dbg.tests
  ]
