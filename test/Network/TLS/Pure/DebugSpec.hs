{-# LANGUAGE QuasiQuotes #-}

module Network.TLS.Pure.DebugSpec where

import qualified Data.ByteString  as BS
import qualified Test.Tasty       as T
import           Test.Tasty.HUnit ((@?=))
import qualified Test.Tasty.HUnit as T.H

import qualified Network.TLS.Pure.Debug as Dbg

tests :: T.TestTree
tests = T.testGroup "Debug"
  [ T.H.testCase "split" $
      Dbg.splitEvery2 "1234" @?= [('1','2'), ('3','4')]

  , T.H.testCase "readByte" $
      Dbg.readByte ('1', 'a') @?= Just (16 + 10)

  , T.H.testCase "hex stream" $
      BS.pack [0x01, 0x1d] @?=
      [Dbg.hexStream|011d|]

  , T.H.testCase "hex stream line break" $
      BS.pack [0x01, 0x02] @?=
      [Dbg.hexStream|0
      102|]

  , T.H.testCase "hex stream with space between bytes" $
      BS.pack [0x01, 0x02] @?=
      [Dbg.hexStream|01 02|]
  ]
