{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DerivingVia       #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Pure.Handshake.KeyCalc where

import           Crypto.Hash.Algorithms                 (SHA256)
import qualified Crypto.Hash.SHA256                     as SHA256
import qualified Crypto.KDF.HKDF                        as HKDF
import qualified Data.ByteArray                         as BA
import qualified Data.ByteString                        as BS
import qualified Data.ByteString.Builder                as B
import qualified Data.ByteString.Lazy                   as LBS
import qualified Data.Serialize.Put                     as Put
import           GHC.Word
import qualified Data.Bits as Bits

import qualified Network.TLS.Pure.Extension.KeyShare    as KS
import qualified Network.TLS.Pure.Handshake             as Handshake
import qualified Network.TLS.Pure.Handshake.ClientHello as Chlo
import qualified Network.TLS.Pure.Handshake.Common      as H.C
import qualified Network.TLS.Pure.Handshake.ServerHello as Shlo
import qualified Network.TLS.Pure.Serialization         as S

import qualified Network.TLS.Pure.Debug                 as Dbg

newtype HandshakeClientSecret = HandshakeClientSecret { getHandshakeClientSecret :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype HandshakeServerSecret = HandshakeServerSecret { getHandshakeServerSecret :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype HandshakeClientKey = HandshakeClientKey { getHandshakeClientKey :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype HandshakeServerKey = HandshakeServerKey { getHandshakeServerKey :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype HandshakeClientIV = HandshakeClientIV { getHandshakeClientIV :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype HandshakeServerIV = HandshakeServerIV { getHandshakeServerIV :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype MasterSecret = MasterSecret { getMasterSecret :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype ApplicationClientSecret = ApplicationClientSecret { getApplicationClientSecret :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype ApplicationServerSecret = ApplicationServerSecret { getApplicationServerSecret :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype ApplicationClientKey = ApplicationClientKey { getApplicationClientKey :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype ApplicationServerKey = ApplicationServerKey { getApplicationServerKey :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype ApplicationClientIV = ApplicationClientIV { getApplicationClientIV :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype ApplicationServerIV = ApplicationServerIV { getApplicationServerIV :: BS.ByteString }
  deriving (Eq, Ord, Monoid, Semigroup, BA.ByteArray, BA.ByteArrayAccess) via BS.ByteString

newtype SequenceNumber = SequenceNumber { getSequenceNumber :: Word64 }

data HandshakeKeys = HandshakeKeys
  { hkSecret :: HKDF.PRK SHA256
  , hkClientSecret :: HandshakeClientSecret
  -- ^ not directly required but handy for debugging
  , hkServerSecret :: HandshakeServerSecret
  -- ^ not directly required but handy for debugging
  , hkClientKey :: HandshakeClientKey
  , hkServerKey :: HandshakeServerKey
  , hkClientIV :: HandshakeClientIV
  , hkServerIV :: HandshakeServerIV
  }

data ApplicationKeys = ApplicationKeys
  { akMasterSecret :: MasterSecret
  , akClientSecret :: ApplicationClientSecret
  , akServerSecret :: ApplicationServerSecret
  , akClientKey    :: ApplicationClientKey
  , akServerKey    :: ApplicationServerKey
  , akClientIV     :: ApplicationClientIV
  , akServerIV     :: ApplicationServerIV
  }

hexHandshakeKeys :: HandshakeKeys -> String
hexHandshakeKeys HandshakeKeys{..} = "HandshakeKeys { "
  <> "hkSecret = <secret> "
  <> "hkClientSecret = " <> Dbg.toHexStream hkClientSecret <> " "
  <> "hkServerSecret = " <> Dbg.toHexStream hkServerSecret <> " "
  <> "hkClientKey = " <> Dbg.toHexStream hkClientKey <> " "
  <> "hkServerKey = " <> Dbg.toHexStream hkServerKey <> " "
  <> "hkClientIV = " <> Dbg.toHexStream hkClientIV <> " "
  <> "hkServerIV = " <> Dbg.toHexStream hkServerIV <> "}"

computeHandshakeKeys
  :: Chlo.ClientHello13Data
  -> Shlo.ServerHello13Data
  -> Either Handshake.SelectKeyShareError HandshakeKeys

computeHandshakeKeys chloData shloData = do
  let chloBytes = S.runTLSEncoder $ S.encode (Handshake.ClientHello13 chloData)
  let shloBytes = S.runTLSEncoder $ S.encode (Handshake.ServerHello13 shloData)
  let helloHash = SHA256.finalize $ SHA256.update (SHA256.update SHA256.init chloBytes) shloBytes
  let clientRandomBytes = H.C.getRandom (Chlo.chlo13dRandom chloData)
  selectedKs <- Handshake.selectKeyShare chloData shloData
  let (sharedSecretBytes :: BS.ByteString) = BA.convert (KS.kpxDh selectedKs)

  let earlySecret = HKDF.extract @SHA256 BS.empty (BS.replicate 32 0)
  let emptyHash = SHA256.hash mempty
  let derivedSecret = hkdfExpandLabel earlySecret "derived" emptyHash 32
  let handshakeSecret = HKDF.extract @SHA256 derivedSecret sharedSecretBytes
  let clientHandshakeSecret = HKDF.extractSkip $ hkdfExpandLabel handshakeSecret "c hs traffic" helloHash 32
  let serverHandshakeSecret = HKDF.extractSkip $ hkdfExpandLabel handshakeSecret "s hs traffic" helloHash 32
  let clientHandshakeKey = hkdfExpandLabel clientHandshakeSecret "key" BS.empty 16
  let serverHandshakeKey = hkdfExpandLabel serverHandshakeSecret "key" BS.empty 16
  let clientHandshakeIV = hkdfExpandLabel clientHandshakeSecret "iv" BS.empty 12
  let serverHandshakeIV = hkdfExpandLabel serverHandshakeSecret "iv" BS.empty 12

  pure $ HandshakeKeys
    handshakeSecret
    (HandshakeClientSecret $ BA.convert clientHandshakeSecret)
    (HandshakeServerSecret $ BA.convert serverHandshakeSecret)
    (HandshakeClientKey clientHandshakeKey)
    (HandshakeServerKey serverHandshakeKey)
    (HandshakeClientIV clientHandshakeIV)
    (HandshakeServerIV serverHandshakeIV)

computeApplicationKeys
  :: HandshakeKeys
  -> BS.ByteString
  -> ApplicationKeys

computeApplicationKeys hsKeys handshakeHash =
  let emptyHash = SHA256.hash mempty
      derivedSecret = hkdfExpandLabel (hkSecret hsKeys) "derived" emptyHash 32
      masterSecret = HKDF.extract @SHA256 derivedSecret BS.empty
      clientSecret = HKDF.extractSkip $ hkdfExpandLabel masterSecret "c ap traffic" handshakeHash 32
      serverSecret = HKDF.extractSkip $ hkdfExpandLabel masterSecret "s ap traffic" handshakeHash 32
      clientKey = hkdfExpandLabel clientSecret "key" BS.empty 16
      serverKey = hkdfExpandLabel serverSecret "key" BS.empty 16
      clientIV = hkdfExpandLabel clientSecret "iv" BS.empty 12
      serverIV = hkdfExpandLabel serverSecret "iv" BS.empty 12
  in ApplicationKeys
      (MasterSecret $ BA.convert masterSecret)
      (ApplicationClientSecret $ BA.convert clientSecret)
      (ApplicationServerSecret $ BA.convert serverSecret)
      (ApplicationClientKey clientKey)
      (ApplicationServerKey serverKey)
      (ApplicationClientIV clientIV)
      (ApplicationServerIV serverIV)


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

-- | Convenience function to xor a bytestring with a sequence number
-- to produce cipher nonces
xorIv :: BS.ByteString -> SequenceNumber -> BS.ByteString
xorIv iv (SequenceNumber seqNum) =
  let n = BS.length iv
      builderSeq = B.byteString (BS.replicate (n - 8) 0) <> B.word64BE seqNum
      bsSeq = LBS.toStrict $ B.toLazyByteString builderSeq
  in BS.pack $ BS.zipWith Bits.xor bsSeq iv
