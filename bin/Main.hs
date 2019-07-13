{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import qualified Crypto.Error                                    as Crypto
import qualified Crypto.PubKey.Curve25519                        as C25519
import qualified Data.ByteArray                                  as BA
import qualified Data.ByteString                                 as BS
import qualified Data.ByteString.Base64                          as B64
import qualified Data.Serialize.Put                              as Put
import qualified Data.Vector                                     as V
import qualified Network.Simple.TCP                              as TCP
import           Text.Printf                                     (printf)
import qualified Data.PEM as PEM

import qualified Network.TLS.Pure.Cipher                         as Cipher
import qualified Network.TLS.Pure.Extension                      as Extension
import qualified Network.TLS.Pure.Extension.KeyShare             as KS
import qualified Network.TLS.Pure.Extension.ServerNameIndication as SNI
import qualified Network.TLS.Pure.Extension.SignatureAlgorithms  as SA
import qualified Network.TLS.Pure.Extension.SupportedGroups      as SG
import qualified Network.TLS.Pure.Extension.SupportedVersions    as SV
import qualified Network.TLS.Pure.Handshake.ClientHello          as Chlo
import qualified Network.TLS.Pure.Handshake.Common               as H.C
import qualified Network.TLS.Pure.Serialization                  as S
import qualified Network.TLS.Pure.Version                        as Version

import qualified Network.TLS.Pure.Handshake                      as Handshake
import qualified Network.TLS.Pure.Packet                         as Pkt
import qualified Network.TLS.Pure.Record                         as Record

import qualified Network.TLS.Pure.Debug                          as Dbg

main :: IO ()
main = testHandshake *> putStrLn "done"


testHandshake :: IO ()
testHandshake = do
  chloData <- mkTestChlo
  let record = Record.TLSRecord
        { Record.rVersion = Version.TLS10
        , Record.rContent = Record.Handshake (Handshake.ClientHello13 chloData)
        }
  let packet = Pkt.TLSPacket $ V.singleton record
  TCP.connect "localhost" "4433" $ \(socket, remoteAddr) -> do
    putStrLn $ "Connected to: " <> show remoteAddr
    TCP.send socket (Put.runPut $ S.encode packet)
    Just resp <- TCP.recv socket 16000
    case S.runTLSParser S.decode resp of
      Left err -> print err
      Right (Pkt.TLSPacket packets) -> do
        putStrLn "got a shlo"
        print $ V.head packets
        let shlo@(Record.Handshake (Handshake.ServerHello13 shloData)) = Record.rContent (V.head packets)
        print shlo
        print shloData
        putStrLn "selected keyshare:"
        let selectedKs = rightOrThrow $ Handshake.selectKeyShare chloData shloData
        print selectedKs
        -- let hexDh = concatMap (printf "%02x") (BS.unpack $ BA.convert $ KS.kpxDh selectedKs)
        let hexDh = toHexStream (KS.kpxDh selectedKs)
        putStrLn hexDh
        putStrLn $ "(" <> show (length hexDh) <> ")"
        putStrLn $ toHexStream (KS.kpxPublic selectedKs)
        putStrLn $ toHexStream (KS.kpxSecret selectedKs)
        BS.writeFile "./rawPublic.bin" (BA.convert $ KS.kpxPublic selectedKs)
        BS.putStr $ B64.encode $ BA.convert $ KS.kpxDh selectedKs
        putStr "\n"
        dumpKs selectedKs

  pure ()

toHexStream :: BA.ByteArrayAccess ba => ba -> String
toHexStream = concatMap (printf "%02x") . BS.unpack . BA.convert

dumpKs :: KS.KeyPair -> IO ()
dumpKs ks = do
  -- No idea what are the first 12 bytes of the pem content
  let pub = PEM.PEM
        { PEM.pemName = "PUBLIC KEY"
        , PEM.pemHeader = []
        , PEM.pemContent = BS.replicate 12 0 <> BA.convert (KS.kpxPublic ks)
        }
  BS.writeFile "./public.pem" (PEM.pemWriteBS pub)

  let priv = PEM.PEM
        { PEM.pemName = "PRIVATE KEY"
        , PEM.pemHeader = []
        , PEM.pemContent = BS.replicate 12 0 <> BA.convert (KS.kpxSecret ks)
        }
  BS.writeFile "./private.pem" (PEM.pemWriteBS priv)
  putStrLn $ toHexStream $ KS.kpxDh ks

  -- let rawChloSecret = [Dbg.hexStream|202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f|]
  -- let rawChloPublic = [Dbg.hexStream|358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254|]
  -- BS.writeFile "./rawChlo.pem" $ PEM.pemWriteBS $ PEM.PEM "PUBLIC KEY" [] rawChloPublic

  pure ()

-- checkDh :: IO ()
-- checkDh = do
--   let priv64 = "MC4CAQAwBQYDK2VuBCIEIJCRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6v"
--   let pub64 = "MCowBQYDK2VuAyEANYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ="
--   pure ()


rightOrThrow = \case
  Right a -> a
  Left e -> error (show e)

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
  , Chlo.chlo13dRandom = H.C.Random (BS.replicate 32 0) -- TODO should be random
  , Chlo.chlo13dLegacySessionId = S.Opaque8 (BS.replicate 32 0) -- TODO should be random
  , Chlo.chlo13dExtensions = Extension.Extensions $ V.fromList
    [ Extension.ServerNameIndication (SNI.ServerName "localhost")
    , Extension.SupportedVersions (SV.SupportedVersionsCH $ V.singleton Version.TLS13)
    , Extension.SupportedGroups $ SG.SupportedGroups $ V.fromList [ SG.X25519 ]
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

  let bytes = Put.runPut $ S.encode kse
  print $ BS.length bytes
  putStrLn $ Dbg.showHex bytes
