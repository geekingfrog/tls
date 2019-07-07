{-# LANGUAGE QuasiQuotes #-}
module Network.TLS.Pure.Extension.KeyShareSpec where

import qualified Test.Tasty as T
import           Test.Tasty.HUnit ((@?=))
import qualified Test.Tasty.HUnit as T.H
import qualified Data.ByteString as BS
import qualified Crypto.Error                               as Crypto
import qualified Crypto.PubKey.Curve25519                   as Curve25519


import qualified TestUtil
import qualified Network.TLS.Pure.Serialization as S
import qualified Network.TLS.Pure.Debug as Dbg
import qualified Network.TLS.Pure.Extension.KeyShare as KS

tests :: T.TestTree
tests = T.testGroup "KeyShareEntry"
  [ T.testGroup "X25519"
    [ T.H.testCase "Decode" $
        (Right $ KS.X25519 $ KS.KSE25519
          (TestUtil.unsafeFromRight $ Crypto.eitherCryptoError $ Curve25519.publicKey
            [Dbg.hexStream|0eebafdcf8a002f91be0d13859c63270f7352c6db8c175bfd052914fdb73375a|])
          Nothing
        )
        @?=
        S.runTLSParser S.decode
        [Dbg.hexStream|
          001d00200eebafdcf8a002f91be0d13859c63270f7352c6db8c175bfd052914fdb73375a
        |]
    ]
  ]

