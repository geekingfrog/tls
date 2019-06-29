{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.Serialize.Put as S
import qualified Data.Vector as V
import qualified Data.ByteString as BS
import qualified Crypto.Error as Crypto
import qualified Crypto.PubKey.Curve25519 as C25519
import qualified Network.Simple.TCP as TCP

import qualified Network.TLS.Pure.Serialization as Serialization
import qualified Network.TLS.Pure.Cipher as Cipher
import qualified Network.TLS.Pure.Extension as Extension
import qualified Network.TLS.Pure.Version as Version
import qualified Network.TLS.Pure.Handshake.ClientHello as Chlo
import qualified Network.TLS.Pure.Extension.SupportedVersions as SV
import qualified Network.TLS.Pure.Extension.SupportedGroups as SG
import qualified Network.TLS.Pure.Extension.ServerNameIndication as SNI
import qualified Network.TLS.Pure.Extension.SignatureAlgorithms as SA
import qualified Network.TLS.Pure.Extension.KeyShare as KS

import qualified Network.TLS.Pure.Handshake as Handshake
import qualified Network.TLS.Pure.Record as Record
import qualified Network.TLS.Pure.Packet as Pkt

import qualified Network.TLS.Pure.Debug as Dbg

main :: IO ()
main = sendChlo *> putStrLn "done"


sendChlo :: IO ()
sendChlo = do
  chloData <- mkTestChlo
  let record = Record.TLSRecord
        { Record.rVersion = Version.TLS10
        , Record.rContent = Record.Handshake (Handshake.ClientHello13 chloData)
        }
  let packet = Pkt.TLSPacket $ V.singleton record
  TCP.connect "localhost" "4433" $ \(socket, remoteAddr) -> do
    putStrLn $ "Connected to: " <> show remoteAddr
    TCP.send socket (S.runPut $ Serialization.encode packet)
  pure ()


mkTestChlo :: IO Chlo.ClientHello13Data
mkTestChlo = do
  secret <- Crypto.throwCryptoErrorIO $ C25519.secretKey $ BS.pack [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]
  let public = C25519.toPublic secret
  let kse = KS.KSE25519 public (Just secret)
  pure $ testChlo $ KS.X25519 kse


testChlo :: KS.KeyShareEntry -> Chlo.ClientHello13Data
testChlo kse = Chlo.ClientHello13Data
  { Chlo.chlo13dCipherSuites = Cipher.CipherSuites $ V.fromList
      [ Cipher.AES128_GCM
      , Cipher.AES256_GCM
      , Cipher.CHACHA20_POLY
      , Cipher.AES128_CCM
      , Cipher.AES128_CCM_8
      ]
  , Chlo.chlo13dRandom = Chlo.Random (BS.replicate 32 0) -- TODO should be random
  , Chlo.chlo13dLegacySessionId = Serialization.Opaque8 (BS.replicate 32 0) -- TODO should be random
  , Chlo.chlo13dExtensions = Extension.Extensions $ V.fromList
    [ Extension.ServerNameIndication (SNI.ServerName "localhost")
    , Extension.SupportedVersions (SV.SupportedVersionsCH $ V.singleton Version.TLS13)
    , Extension.SupportedGroups $ SG.SupportedGroups $ V.fromList [ SG.X25519, SG.X448 ]
    , Extension.SignatureAlgorithms $ SA.SignatureAlgorithms $ V.fromList
      [ SA.RsaPkcs1Sha256
      , SA.RsaPkcs1Sha384
      , SA.RsaPkcs1Sha512
      , SA.EcdsaSecp256r1Sha256
      , SA.EcdsaSecp384r1Sha384
      , SA.EcdsaSecp521r1Sha512
      , SA.RsaPssRsaeSha256
      , SA.RsaPssRsaeSha384
      , SA.RsaPssRsaeSha512
      , SA.Ed25519
      , SA.Ed448
      , SA.RsaPssPssSha256
      , SA.RsaPssPssSha384
      , SA.RsaPssPssSha512
      , SA.RsaPkcs1Sha1
      , SA.EcdsaSha1
      ]
    , Extension.KeyShare $ KS.KeyShareCH $ V.singleton kse
    ]
  }

-- testRepl :: IO _
testRepl = do
  putStr ""
  let sni = Extension.ServerNameIndication (SNI.ServerName "localhost")
  let versions = Extension.SupportedVersions (SV.SupportedVersionsCH $ V.singleton Version.TLS13)
  let ext = versions

  secret <- Crypto.throwCryptoErrorIO $ C25519.secretKey $ BS.pack [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]
  let public = C25519.toPublic secret
  let kse = KS.KSE25519 public (Just secret)

  let bytes = S.runPut $ Serialization.encode kse
  print $ BS.length bytes
  putStrLn $ Dbg.bsToHex bytes
