module Main where

import qualified Test.Tasty as T
import           Test.Tasty.HUnit ((@?=))
import qualified Test.Tasty.HUnit as T.H

import qualified Network.TLS.Pure.SerializationSpec as Serialization

main :: IO ()
main = T.defaultMain tests

tests :: T.TestTree
tests = T.testGroup "Tests"
  [ tmpTest
  , Serialization.tests
  ]

tmpTest :: T.TestTree
tmpTest = T.testGroup "tmpTest"
  [ T.H.testCase "yay" $
      2 @?= (1+1)
  ]
