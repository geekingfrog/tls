{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeFamilies #-}

module TestTypes where

import qualified Data.ByteString               as B
import           Data.Serialize                as S
import           Type.Reflection

import           Data.ByteArray                as BA
import qualified Crypto.PubKey.Curve25519      as C25519
import           Crypto.Error                  as CryptoErr

import qualified Network.TLS.Pure.Wire         as Wire

import GHC.Types


data RecordType
    = RT1
    | RT2
    | RT3
    deriving (Show)

showByteArray :: BA.ByteArrayAccess a => a -> String
showByteArray = Wire.bsToHex . B.pack . BA.unpack

testDH :: IO ()
testDH = do
-- clientPrivate :: B.ByteString
    (clientPrivate, clientPublic) <- CryptoErr.throwCryptoErrorIO $ do
        -- clientPrivate <- C25519.secretKey $ B.pack [0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a]
        -- clientPrivate <- C25519.secretKey $ B.replicate 32 0x61
        clientPrivate <- C25519.secretKey $ B.pack [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]
        -- clientPrivate <- C25519.secretKey $ B.pack [0..31]
        let clientPublic = C25519.toPublic clientPrivate
        pure (clientPrivate, clientPublic)
    putStrLn $ showByteArray clientPrivate
    putStrLn $ showByteArray clientPublic

    (serverPrivate, serverPublic) <- CryptoErr.throwCryptoErrorIO $ do
        -- private <- C25519.secretKey $ B.pack [0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb]
        private <- C25519.secretKey $ B.pack [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf]
        let public = C25519.toPublic private
        pure (private, public)
    putStrLn $ showByteArray serverPrivate
    putStrLn $ showByteArray serverPublic

    let shared = C25519.dh serverPublic clientPrivate
    putStrLn $ showByteArray shared

    putStrLn $ showByteArray $ C25519.dh clientPublic serverPrivate

    print $ BA.convert shared == (BA.zero 32 :: B.ByteString)
    print $ BA.constEq shared (B.replicate 32 0)


    pure ()
