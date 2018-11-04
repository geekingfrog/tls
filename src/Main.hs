{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.Vector                as V
import qualified Data.ByteString            as B
import qualified Data.Serialize             as Serial
import qualified Network.Simple.TCP         as TCP

import qualified Network.TLS.Pure.Packet    as Packet
import qualified Network.TLS.Pure.Cipher    as Cipher
import qualified Network.TLS.Pure.Extension as Ext
import qualified Network.TLS.Pure.Wire      as Wire
import qualified Network.TLS.Pure.Version   as Version

import Util

import qualified TestTypes

main :: IO ()
main = do
    let chlo = Packet.Handshake (Packet.ClientHello chloData)
    TCP.connect "localhost" "4433" $ \(connectionSocket, remoteAddr) -> do
        putStrLn $ "Connection established to " ++ show remoteAddr
        let chloBytes = Serial.runPut $ Wire.put chlo
        TCP.send connectionSocket chloBytes
        fromSrv <- TCP.recv connectionSocket 16000
        case fromSrv of
            Just bytes -> do
                putStrLn $ "got " <> show (fmap B.length fromSrv) <> " bytes from server"
                B.writeFile "./debug/ShHlo.bin" bytes
                print $ Serial.runGet (Wire.get :: Serial.Get Packet.TLSPacket) bytes
            Nothing -> putStrLn "got nothing from server :/"

readShlo :: IO ()
readShlo = do
    bytes <- B.readFile "debug/ShHlo.bin"
    print $ Serial.runGet (Wire.get :: Serial.Get Packet.TLSPacket) bytes

chloData :: Packet.ClientHelloData
chloData =
    let extensions = Ext.Extensions $ V.fromList
            [ Ext.ServerNameIndication (Ext.ServerName "localhost")
            , Ext.SupportedGroups $ Ext.SupportedGroupsExtension $ V.fromList
        -- Serial.isolate extLength Wire.get
                [ Ext.X25519
                , Ext.Secp256r1
                , Ext.X448
                , Ext.Secp521r1
                , Ext.Secp384r1
                ]
            , Ext.SignatureAlgs $ Ext.SignatureAlgorithms $ V.fromList
                [ Ext.EcdsaSecp256r1Sha256
                , Ext.EcdsaSecp384r1Sha384
                , Ext.EcdsaSecp521r1Sha512
                , Ext.Ed25519
                , Ext.Ed448
                , Ext.RsaPssRsaeSha256
                , Ext.RsaPssRsaeSha384
                , Ext.RsaPssRsaeSha512
                , Ext.RsaPssPssSha256
                , Ext.RsaPssPssSha384
                , Ext.RsaPssPssSha512
                , Ext.RsaPkcs1Sha1
                , Ext.RsaPkcs1Sha256
                , Ext.RsaPkcs1Sha384
                , Ext.RsaPkcs1Sha512
                ]
            , Ext.SupportedVersions $ Ext.SupportedVersionsClient $ V.fromList [Version.TLS13]
            , Ext.KeyShare $ Ext.KeyShareChlo $ V.fromList
                [ Ext.KeyShareEntry (Ext.X25519, Wire.Opaque16 $ B.replicate 32 0x01) -- TODO random there
                ]
            ]

        chloData = Packet.ClientHelloData
            { Packet.chlodCiphers = Cipher.tls13Ciphers
            , Packet.chlodSessionId = Wire.Opaque8 (B.replicate 32 0x01)
            , Packet.chlodRandom = B.replicate 32 0x01
            , Packet.chlodExtensions = extensions
            }
    in  chloData
