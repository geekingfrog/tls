{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}

module Main where

import           Crypto.Cipher.AES                               (AES128(..))
import qualified Crypto.Cipher.Types                             as CT
import qualified Crypto.Error                                    as Crypto
import           Crypto.Hash.Algorithms                          (SHA256)
import qualified Crypto.Hash.SHA256                              as SHA256
import qualified Crypto.KDF.HKDF                                 as HKDF
import qualified Crypto.PubKey.Curve25519                        as C25519
import qualified Crypto.Random                                   as Rng
import qualified Data.ByteArray                                  as BA
import qualified Data.ByteString                                 as BS
import qualified Data.ByteString.Char8                           as BS8
-- import qualified Data.ByteString.Base64                          as B64
import qualified Data.PEM                                        as PEM
import qualified Data.Serialize.Put                              as Put
import qualified Data.Vector                                     as V
import qualified Network.Simple.TCP                              as TCP
import           Text.Printf                                     (printf)

import GHC.Stack
import System.IO.Unsafe

import qualified Network.TLS.Pure.Cipher                         as Cipher
import qualified Network.TLS.Pure.Extension                      as Extension
import qualified Network.TLS.Pure.Extension.KeyShare             as KS
import qualified Network.TLS.Pure.Extension.ServerNameIndication as SNI
import qualified Network.TLS.Pure.Extension.SignatureAlgorithms  as SA
import qualified Network.TLS.Pure.Extension.SupportedGroups      as SG
import qualified Network.TLS.Pure.Extension.SupportedVersions    as SV
import qualified Network.TLS.Pure.Handshake                      as Handshake
import qualified Network.TLS.Pure.Handshake.ClientHello          as Chlo
import qualified Network.TLS.Pure.Handshake.Common               as H.C
import qualified Network.TLS.Pure.Handshake.KeyCalc              as H.Key
import qualified Network.TLS.Pure.Handshake.ServerHello          as Shlo
import qualified Network.TLS.Pure.Packet                         as Pkt
import qualified Network.TLS.Pure.Record                         as Record
import qualified Network.TLS.Pure.Serialization                  as S
import qualified Network.TLS.Pure.Version                        as Version

import qualified Network.TLS.Pure.Debug                          as Dbg

main :: IO ()
main = testHandshake *> putStrLn "done"


testHandshake :: IO ()
testHandshake = do
  chloData <- mkTestChlo
  let chloRecord = Record.TLSRecord
        { Record.rVersion = Version.TLS10
        , Record.rContent = Record.Handshake (Handshake.ClientHello13 chloData)
        }
  let packet = Pkt.TLSPacket $ V.singleton chloRecord
  TCP.connect "localhost" "4433" $ \(socket, remoteAddr) -> do
    putStrLn $ "Connected to: " <> show remoteAddr
    TCP.send socket (Put.runPut $ S.encode packet)
    Just resp <- TCP.recv socket 16000
    case S.runTLSParser S.decode resp of
      Left err -> print err
      Right (Pkt.TLSPacket packets) -> do
        putStrLn $ "got some TLS records: " <> show (V.length packets)
        let shloRecord = V.head packets
        print shloRecord
        let shlo@(Record.Handshake (Handshake.ServerHello13 shloData)) = Record.rContent shloRecord
        print shlo
        print shloData
        putStrLn "selected keyshare:"
        let selectedKs = rightOrThrow $ Handshake.selectKeyShare chloData shloData
        print selectedKs
        -- let hexDh = concatMap (printf "%02x") (BS.unpack $ BA.convert $ KS.kpxDh selectedKs)
        let hexDh = Dbg.toHexStream (KS.kpxDh selectedKs)
        putStrLn hexDh
        putStrLn $ "(" <> show (length hexDh) <> ")"
        putStrLn $ Dbg.toHexStream (KS.kpxPublic selectedKs)
        putStrLn $ Dbg.toHexStream (KS.kpxSecret selectedKs)
        BS.writeFile "./rawPublic.bin" (BA.convert $ KS.kpxPublic selectedKs)
        putStrLn "shared secret:"
        putStrLn $ Dbg.toHexStream $ KS.kpxDh selectedKs
        putStr "\n"
        -- dumpKs selectedKs

        putStrLn "chlo bytes:"
        putStrLn $ Dbg.toHexStream $ S.runTLSEncoder (S.encode $ Record.rContent chloRecord)
        putStrLn "shlo bytes"
        putStrLn $ Dbg.toHexStream $ S.runTLSEncoder (S.encode $ Record.rContent shloRecord)

        let chloBytes = S.runTLSEncoder (S.encode $ Record.rContent chloRecord)
        let shloBytes = S.runTLSEncoder (S.encode $ Record.rContent shloRecord)
        let helloHash = SHA256.finalize (SHA256.updates SHA256.init [chloBytes, shloBytes])

        let hsKeys = rightOrThrow $ H.Key.computeHandshakeKeys chloData shloData
        dumpHandshakeKeys (Chlo.chlo13dRandom chloData) hsKeys


        (serverCipher :: AES128) <- Crypto.throwCryptoErrorIO $ CT.cipherInit (H.Key.hkServerKey hsKeys)
        aeadServer <- Crypto.throwCryptoErrorIO $ CT.aeadInit CT.AEAD_GCM serverCipher (H.Key.hkServerIV hsKeys)

        let (Right encryptedStuff) = do
              encryptedExts <- note "failed decrypt encrypted ext"
                (decryptServer hsKeys (H.Key.SequenceNumber 0) (packets V.! 2))

              serverCert <- note "failed decrypt server cert"
                (decryptServer hsKeys (H.Key.SequenceNumber 1) (packets V.! 3))

              serverVerify <- note "failed decrypt server verify"
                (decryptServer hsKeys (H.Key.SequenceNumber 2) (packets V.! 4))

              handshakeFinished <- note "failed decrypt handshake finished"
                (decryptServer hsKeys (H.Key.SequenceNumber 3) (packets V.! 5))

              pure [encryptedExts, serverCert, serverVerify, handshakeFinished]


        putStrLn "last bytes of encrypted records:"
        V.forM_ (V.fromList encryptedStuff) (putStrLn . Dbg.toHexStream . BS.take 8)
        putStrLn $ "encrypted exts: " <> Dbg.toHexStream (head encryptedStuff)
        let handshakeHash = SHA256.finalize $ SHA256.updates SHA256.init $
              [chloBytes, shloBytes] <> fmap BS.init encryptedStuff
        let apKeys = H.Key.computeApplicationKeys hsKeys handshakeHash

        -- dumpNSS (Chlo.chlo13dRandom chloData) hsKeys apKeys

        let clientChangeCipherSpec = Record.TLSRecord Version.TLS12 Record.ChangeCipherSpec
        TCP.send socket (S.runTLSEncoder $ S.encode clientChangeCipherSpec)

        pure ()

  pure ()

dumpKeylog :: KS.KeyPair -> IO ()
dumpKeylog ks = do
  let keylog = BS.concat
        [ "CLIENT_HANDSHAKE_TRAFFIC_SECRET "
        , BS8.pack (Dbg.toHexStream $ KS.kpxPublic ks)
        , " "
        , BS8.pack (Dbg.toHexStream $ KS.kpxSecret ks)
        , "\n"
        ]
  BS.writeFile "debug/mykeylog.txt" keylog
  pure ()

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
  putStrLn $ Dbg.toHexStream $ KS.kpxDh ks

  -- let rawChloSecret = [Dbg.hexStream|202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f|]
  -- let rawChloPublic = [Dbg.hexStream|358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254|]
  -- BS.writeFile "./rawChlo.pem" $ PEM.pemWriteBS $ PEM.PEM "PUBLIC KEY" [] rawChloPublic

  pure ()



decryptServer
  :: H.Key.HandshakeKeys
  -> H.Key.SequenceNumber
  -> Record.TLSRecord
  -> Maybe BS.ByteString

decryptServer keys sequenceNumber packet =
  let bytes = S.runTLSEncoder (S.encode packet)
      (headerTag, rest) = BS.splitAt 5 bytes
      tagLength = 16
      (encrypted, tag) = BS.splitAt (BS.length rest - tagLength) rest
      (Right (serverCipher :: AES128)) = Crypto.eitherCryptoError $ CT.cipherInit (H.Key.hkServerKey keys)
      iv = H.Key.xorIv (BA.convert $ H.Key.hkServerIV keys) sequenceNumber
      (Right aead) = Crypto.eitherCryptoError $ CT.aeadInit CT.AEAD_GCM serverCipher iv
      decrypted = CT.aeadSimpleDecrypt aead headerTag encrypted (CT.AuthTag $ BA.convert tag)
   in decrypted



rightOrThrow :: (HasCallStack, Show e) => Either e a -> a
rightOrThrow = \case
  Right a -> a
  Left e -> error (show e)

note :: e -> Maybe a -> Either e a
note e = \case
  Nothing -> Left e
  Just x -> Right x

mkTestChlo :: IO Chlo.ClientHello13Data
mkTestChlo = do
  secret <- Crypto.throwCryptoErrorIO $ C25519.secretKey
    [Dbg.hexStream|202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f|]

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
  , Chlo.chlo13dRandom = H.C.Random (unsafePerformIO $ Rng.getRandomBytes 32) -- TODO should be random
  , Chlo.chlo13dLegacySessionId = S.Opaque8 (unsafePerformIO $ Rng.getRandomBytes 32) -- TODO should be random
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

dumpHandshakeKeys :: H.C.Random -> H.Key.HandshakeKeys -> IO ()
dumpHandshakeKeys (H.C.Random clientRandomBytes) hsKeys = do
  let clientRandomHex = Dbg.toHexStream clientRandomBytes

  let nss = "CLIENT_HANDSHAKE_TRAFFIC_SECRET "
        <> clientRandomHex <> " " <> Dbg.toHexStream (H.Key.hkClientSecret hsKeys)
        <> "\n"
        <> "SERVER_HANDSHAKE_TRAFFIC_SECRET "
        <> clientRandomHex <> " " <> Dbg.toHexStream (H.Key.hkServerSecret hsKeys)
        <> "\n"
  appendFile "debug/mykeylog.txt" nss

-- dumpNSS :: H.C.Random -> H.Key.HandshakeKeys -> H.Key.ApplicationKeys -> IO ()
-- dumpNSS (H.C.Random clientRandomBytes) hsKeys apKeys = do
--
--   let clientRandomHex = Dbg.toHexStream clientRandomBytes
--
--   let nss = "CLIENT_HANDSHAKE_TRAFFIC_SECRET "
--         <> clientRandomHex <> " " <> Dbg.toHexStream (H.Key.hkClientSecret hsKeys)
--         <> "\n"
--         <> "SERVER_HANDSHAKE_TRAFFIC_SECRET "
--         <> clientRandomHex <> " " <> Dbg.toHexStream (H.Key.hkServerSecret hsKeys)
--         <> "\n"
--         <> "CLIENT_TRAFFIC_SECRET_0 "
--         <> clientRandomHex <> " " <> Dbg.toHexStream (H.Key.akClientSecret apKeys)
--         <> "\n"
--         <> "SERVER_TRAFFIC_SECRET_0 "
--         <> clientRandomHex <> " " <> Dbg.toHexStream (H.Key.akServerSecret apKeys)
--         <> "\n"
--   putStrLn nss
--   appendFile "debug/mykeylog.txt" nss

hkdfExpandLabel
  :: HKDF.PRK SHA256
  -> BS.ByteString
  -> BS.ByteString
  -> Int
  -> BS.ByteString -- out

hkdfExpandLabel secret label context outLen
  = let label' = S.runTLSEncoder $ do
          Put.putWord16be (fromIntegral outLen)
          S.encode $ S.Opaque8 $ "tls13 " <> BA.convert label
          S.encode $ S.Opaque8 $ BA.convert context
    in HKDF.expand secret label' outLen

testRepl :: (HasCallStack) => IO ()
testRepl = do
  let rawChlo = [Dbg.hexStream|16030100ca010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304|]
  let rawShlo = [Dbg.hexStream|160303007a020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615002b00020304|]
  let (Record.TLSRecord _ (Record.Handshake chlo)) = rightOrThrow $ S.runTLSParser S.decode rawChlo
  let (Handshake.ClientHello13 chloData) = chlo

  let (Record.TLSRecord _ (Record.Handshake shlo)) = rightOrThrow $ S.runTLSParser S.decode rawShlo
  let (Handshake.ServerHello13 shloData) = shlo

  print $ Extension.findKeyShare (Chlo.chlo13dExtensions chloData)
  print $ Extension.findKeyShare (Shlo.shlo13dExtensions shloData)
  let keys = rightOrThrow $ H.Key.computeHandshakeKeys chloData shloData

  putStrLn $ H.Key.hexHandshakeKeys keys

  let header = [Dbg.hexStream|17 03 03 04 75|]
  let encryptedData = [Dbg.hexStream|da1ec2d7bda8ebf73edd5010fba8089fd426b0ea1ea4d88d074ffea8a9873af5f502261e34b1563343e9beb6132e7e836d65db6dcf00bc401935ae369c440d67af719ec03b984c4521b905d58ba2197c45c4f773bd9dd121b4d2d4e6adfffa27c2a81a99a8efe856c35ee08b71b3e441bbecaa65fe720815cab58db3efa8d1e5b71c58e8d1fdb6b21bfc66a9865f852c1b4b640e94bd908469e7151f9bbca3ce53224a27062ceb240a105bd3132dc18544477794c373bc0fb5a267885c857d4ccb4d31742b7a29624029fd05940de3f9f9b6e0a9a237672bc624ba2893a21709833c5276d413631bdde6ae7008c697a8ef428a79dbf6e8bbeb47c4e408ef656d9dc19b8b5d49bc091e2177357594c8acd41c101c7750cb11b5be6a194b8f877088c9828e3507dada17bb14bb2c738903c7aab40c545c46aa53823b120181a16ce92876288c4acd815b233d96bb572b162ec1b9d712f2c3966caac9cf174f3aedfec4d19ff9a87f8e21e8e1a9789b490ba05f1debd21732fb2e15a017c475c4fd00be042186dc29e68bb7ece192438f3b0c5ef8e4a53583a01943cf84bba5842173a6b3a7289566687c3018f764ab18103169919328713c3bd463d3398a1feb8e68e44cfe482f72847f46c80e6cc7f6ccf179f482c888594e76276653b48398a26c7c9e420cb6c1d3bc7646f33bb832bfba98489cadfbd55dd8b2c57687a47acba4ab390152d8fbb3f20327d824b284d288fb0152e49fc44678aed4d3f085b7c55de77bd45af812fc37944ad2454f99fbb34a583bf16b67659e6f216d34b1d79b1b4decc098a44207e1c5feeb6ce30acc2cf7e2b134490b442744772d184e59038aa517a97154181e4dfd94fe72a5a4ca2e7e22bce733d03e7d9319710befbc30d7826b728519ba74690e4f906587a0382895b90d82ed3e357faf8e59aca85fd2063ab592d83d245a919ea53c501b9accd2a1ed951f43c049ab9d25c7f1b70ae4f942edb1f311f7417833062245b429d4f013ae9019ff52044c97c73b8882cf03955c739f874a029637c0f0607100e3070f408d082aa7a2abf13e73bd1e252c228aba7a9c1f075bc439571b35932f5c912cb0b38da1c95e64fcf9bfec0b9b0dd8f042fdf05e5058299e96e4185074919d90b7b3b0a97e2242ca08cd99c9ecb12fc49adb2b257240cc387802f00e0e49952663ea278408709bce5b363c036093d7a05d440c9e7a7abb3d71ebb4d10bfc7781bcd66f79322c18262dfc2dccf3e5f1ea98bea3caae8a83706312764423a692ae0c1e2e23b016865ffb125b223857547ac7e2468433b5269843abbabbe9f6f438d7e387e3617a219f62540e7343e1bbf49355fb5a1938048439cba5cee819199b2b5c39fd351aa274536aadb682b578943f0ccf48e4ec7ddc938e2fd01acfaa1e7217f7b389285c0dfd31a1545ed3a85fac8eb9dab6ee826af90f9e1ee5d555dd1c05aec077f7c803cbc2f1cf98393f0f37838ffea372ff708886b05934e1a64512de144608864a88a5c3a173fdcfdf5725da916ed507e4caec8787befb91e3ec9b222fa09f374bd96881ac2ddd1f885d42ea584c|]
  let tag = [Dbg.hexStream|e0 8b 0e 45 5a 35 0a e5 4d 76 34 9a a6 8c 71 ae|]

  putStrLn $ Dbg.toHexStream $ H.Key.hkClientKey keys
  putStrLn $ Dbg.toHexStream $ H.Key.hkClientIV keys
  putStrLn "----"
  putStrLn $ Dbg.toHexStream $ H.Key.hkServerKey keys
  putStrLn $ Dbg.toHexStream $ H.Key.hkServerIV keys

  (serverCipher :: AES128) <- Crypto.throwCryptoErrorIO $ CT.cipherInit (H.Key.hkServerKey keys)
  -- let (Just (clientIv :: CT.IV AES128)) = CT.makeIV (H.Key.hkClientIV keys)
  aeadServer <- Crypto.throwCryptoErrorIO $ CT.aeadInit CT.AEAD_GCM serverCipher (H.Key.hkServerIV keys)

  -- (serverCipher :: AES128) <- Crypto.throwCryptoErrorIO $ CT.cipherInit [Dbg.hexStream|844780a7acad9f980fa25c114e43402a|]
  -- aeadServer <- Crypto.throwCryptoErrorIO $ CT.aeadInit CT.AEAD_GCM serverCipher [Dbg.hexStream|4c042ddc120a38d1417fc815|]

  let res = CT.aeadSimpleDecrypt aeadServer header encryptedData (CT.AuthTag $ BA.convert tag)
  case res of
    Nothing -> print "fail to decrypt"
    Just x -> print $ Dbg.toHexStream x

  pure ()



testHash :: IO ()
testHash =
  let chloBytes = [Dbg.hexStream|16 03 01 00 ca 01 00 00 c6 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 06 13 01 13 02 13 03 01 00 00 77 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04|]
      shloBytes = [Dbg.hexStream|16 03 03 00 7a 02 00 00 76 03 03 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 01 00 00 2e 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15 00 2b 00 02 03 04|]
      encryptedExtsBytes = [Dbg.hexStream|08 00 00 02 00 00|]
      serverCertBytes = [Dbg.hexStream|0b 00 03 2e 00 00 03 2a 00 03 25 30 82 03 21 30 82 02 09 a0 03 02 01 02 02 08 15 5a 92 ad c2 04 8f 90 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 22 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 13 30 11 06 03 55 04 0a 13 0a 45 78 61 6d 70 6c 65 20 43 41 30 1e 17 0d 31 38 31 30 30 35 30 31 33 38 31 37 5a 17 0d 31 39 31 30 30 35 30 31 33 38 31 37 5a 30 2b 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 1c 30 1a 06 03 55 04 03 13 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 c4 80 36 06 ba e7 47 6b 08 94 04 ec a7 b6 91 04 3f f7 92 bc 19 ee fb 7d 74 d7 a8 0d 00 1e 7b 4b 3a 4a e6 0f e8 c0 71 fc 73 e7 02 4c 0d bc f4 bd d1 1d 39 6b ba 70 46 4a 13 e9 4a f8 3d f3 e1 09 59 54 7b c9 55 fb 41 2d a3 76 52 11 e1 f3 dc 77 6c aa 53 37 6e ca 3a ec be c3 aa b7 3b 31 d5 6c b6 52 9c 80 98 bc c9 e0 28 18 e2 0b f7 f8 a0 3a fd 17 04 50 9e ce 79 bd 9f 39 f1 ea 69 ec 47 97 2e 83 0f b5 ca 95 de 95 a1 e6 04 22 d5 ee be 52 79 54 a1 e7 bf 8a 86 f6 46 6d 0d 9f 16 95 1a 4c f7 a0 46 92 59 5c 13 52 f2 54 9e 5a fb 4e bf d7 7a 37 95 01 44 e4 c0 26 87 4c 65 3e 40 7d 7d 23 07 44 01 f4 84 ff d0 8f 7a 1f a0 52 10 d1 f4 f0 d5 ce 79 70 29 32 e2 ca be 70 1f df ad 6b 4b b7 11 01 f4 4b ad 66 6a 11 13 0f e2 ee 82 9e 4d 02 9d c9 1c dd 67 16 db b9 06 18 86 ed c1 ba 94 21 02 03 01 00 01 a3 52 30 50 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 05 a0 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 03 01 30 1f 06 03 55 1d 23 04 18 30 16 80 14 89 4f de 5b cc 69 e2 52 cf 3e a3 00 df b1 97 b8 1d e1 c1 46 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 59 16 45 a6 9a 2e 37 79 e4 f6 dd 27 1a ba 1c 0b fd 6c d7 55 99 b5 e7 c3 6e 53 3e ff 36 59 08 43 24 c9 e7 a5 04 07 9d 39 e0 d4 29 87 ff e3 eb dd 09 c1 cf 1d 91 44 55 87 0b 57 1d d1 9b df 1d 24 f8 bb 9a 11 fe 80 fd 59 2b a0 39 8c de 11 e2 65 1e 61 8c e5 98 fa 96 e5 37 2e ef 3d 24 8a fd e1 74 63 eb bf ab b8 e4 d1 ab 50 2a 54 ec 00 64 e9 2f 78 19 66 0d 3f 27 cf 20 9e 66 7f ce 5a e2 e4 ac 99 c7 c9 38 18 f8 b2 51 07 22 df ed 97 f3 2e 3e 93 49 d4 c6 6c 9e a6 39 6d 74 44 62 a0 6b 42 c6 d5 ba 68 8e ac 3a 01 7b dd fc 8e 2c fc ad 27 cb 69 d3 cc dc a2 80 41 44 65 d3 ae 34 8c e0 f3 4a b2 fb 9c 61 83 71 31 2b 19 10 41 64 1c 23 7f 11 a5 d6 5c 84 4f 04 04 84 99 38 71 2b 95 9e d6 85 bc 5c 5d d6 45 ed 19 90 94 73 40 29 26 dc b4 0e 34 69 a1 59 41 e8 e2 cc a8 4b b6 08 46 36 a0 00 00|]
      certVerifyBytes = [Dbg.hexStream|0f 00 01 04 08 04 01 00 17 fe b5 33 ca 6d 00 7d 00 58 25 79 68 42 4b bc 3a a6 90 9e 9d 49 55 75 76 a5 20 e0 4a 5e f0 5f 0e 86 d2 4f f4 3f 8e b8 61 ee f5 95 22 8d 70 32 aa 36 0f 71 4e 66 74 13 92 6e f4 f8 b5 80 3b 69 e3 55 19 e3 b2 3f 43 73 df ac 67 87 06 6d cb 47 56 b5 45 60 e0 88 6e 9b 96 2c 4a d2 8d ab 26 ba d1 ab c2 59 16 b0 9a f2 86 53 7f 68 4f 80 8a ef ee 73 04 6c b7 df 0a 84 fb b5 96 7a ca 13 1f 4b 1c f3 89 79 94 03 a3 0c 02 d2 9c bd ad b7 25 12 db 9c ec 2e 5e 1d 00 e5 0c af cf 6f 21 09 1e bc 4f 25 3c 5e ab 01 a6 79 ba ea be ed b9 c9 61 8f 66 00 6b 82 44 d6 62 2a aa 56 88 7c cf c6 6a 0f 38 51 df a1 3a 78 cf f7 99 1e 03 cb 2c 3a 0e d8 7d 73 67 36 2e b7 80 5b 00 b2 52 4f f2 98 a4 da 48 7c ac de af 8a 23 36 c5 63 1b 3e fa 93 5b b4 11 e7 53 ca 13 b0 15 fe c7 e4 a7 30 f1 36 9f 9e|]
      handshakeFinishedBytes = [Dbg.hexStream|14 00 00 20 ea 6e e1 76 dc cc 4a f1 85 9e 9e 4e 93 f7 97 ea c9 a7 8c e4 39 30 1e 35 27 5a d4 3f 3c dd bd e3|]
      expectedHash = "22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b"
      hsHash = SHA256.finalize $ SHA256.updates SHA256.init
        [ BS.drop 5 chloBytes
        , BS.drop 5 shloBytes
        , encryptedExtsBytes
        , serverCertBytes
        , certVerifyBytes
        , handshakeFinishedBytes
        ]
      (Right parsedChlo) = S.runTLSParser (fmap snd Record.decodeRecord) chloBytes
      (Right parsedShlo) = S.runTLSParser (fmap snd Record.decodeRecord) shloBytes
      (Record.Handshake (Handshake.ClientHello13 chloData)) = Record.rContent parsedChlo
      (Record.Handshake (Handshake.ServerHello13 shloData)) = Record.rContent parsedShlo
      (Right hsKeys) = H.Key.computeHandshakeKeys chloData shloData
   in do
     putStrLn $ "client handshake traffic secret: " <> Dbg.toHexStream (H.Key.hkClientSecret hsKeys)
     putStrLn $ "expected                       : " <> "ff0e5b965291c608c1e8cd267eefc0afcc5e98a2786373f0db47b04786d72aea"

     putStrLn $ "client handshake key: " <> Dbg.toHexStream (H.Key.hkClientKey hsKeys)
     putStrLn $ "expected            : " <> "7154f314e6be7dc008df2c832baa1d39"

     putStrLn expectedHash
     putStrLn $ Dbg.toHexStream hsHash
        -- let helloHash = SHA256.finalize (SHA256.updates SHA256.init [chloBytes, shloBytes])
