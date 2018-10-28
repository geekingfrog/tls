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

import Util

main :: IO ()
main = do
    let chlo = Packet.Handshake (Packet.ClientHello chloData)
    TCP.connect "localhost" "4433" $ \(connectionSocket, remoteAddr) -> do
        putStrLn $ "Connection established to " ++ show remoteAddr
        let chloBytes = Serial.runPut $ Wire.put chlo
        TCP.send connectionSocket chloBytes
    pure ()


chloData :: Packet.ClientHelloData
chloData =
    let extensions = Ext.Extensions $ V.fromList
            [ Ext.ServerNameIndication (Ext.ServerName "localhost")
            , Ext.SupportedGroups $ V.fromList
                [ Ext.X25519
                , Ext.Secp256r1
                , Ext.X448
                , Ext.Secp521r1
                , Ext.Secp384r1
                ]
            , Ext.SignatureAlgs $ V.fromList
                [ Ext.EcdsaSecp256r1Sha256
                , Ext.EcdsaSecp384r1Sha384
                , Ext.EcdsaSecp521r1Sha512
                , Ext.Ed25519
                , Ext.Ed448
                ]
            , Ext.SupportedVersions $ Ext.SupportedVersionsClient $ V.fromList [Ext.TLS13]
            , Ext.KeyShare $ Ext.KeyShareChlo $ V.fromList
                [ Ext.KeyShareEntry (Ext.X25519, Ext.Opaque16 $ B.replicate 32 0x01) -- TODO random there
                ]
            ]

        chloData = Packet.ClientHelloData
            { Packet.chlodCiphers = Cipher.tls13Ciphers
            , Packet.chlodRandom = B.replicate 32 0x01
            , Packet.chlodExtensions = extensions
            }
    in  chloData
