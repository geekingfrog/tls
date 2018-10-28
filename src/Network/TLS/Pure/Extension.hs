{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}

module Network.TLS.Pure.Extension where

import Control.Monad
import Data.Functor

import qualified Data.ByteString               as B
import qualified Data.Serialize.Put            as Serial
import qualified Data.Serialize.Get            as Serial
import qualified Data.Vector                   as V
import           GHC.Word

import qualified Network.TLS.Pure.Packet.Handshake as Handshake
import qualified Network.TLS.Pure.Wire             as Wire

newtype Opaque16 = Opaque16 B.ByteString deriving (Show, Eq)

instance Wire.ToWire Opaque16 where
    put (Opaque16 o) = do
        Serial.putWord16be (fromIntegral $ B.length o)
        Serial.putByteString o

instance Wire.FromWire Opaque16 where
    get = do
        len <- fromIntegral <$> Serial.getWord16be
        Opaque16 <$> Serial.getByteString len

-- | number of bytes required to encode an Opaque16
opaque16Len :: Opaque16 -> Int
opaque16Len (Opaque16 o) = 2 + B.length o

newtype Extensions = Extensions (V.Vector Extension)
    deriving (Show, Eq)

instance Wire.ToWire Extensions where
    put (Extensions exts)
        | V.null exts = pure ()
        | otherwise = do
            let extensionBytes = Serial.runPut (mapM_ Wire.put exts)
            Serial.putWord16be $ fromIntegral (B.length extensionBytes)
            Serial.putByteString extensionBytes

data ExtensionType
    = ETServerNameIndication
    | ETSupportedGroups
    | ETSignatureAlgs
    | ETSupportedVersions
    | ETSignatureCookie
    | ETSignatureAlgsCert
    | ETKeyShare
    | ETUnknown Word16
    deriving (Show, Eq)

instance Wire.FromWire ExtensionType where
    get = Serial.getWord16be >>= \case
        0   -> pure ETServerNameIndication
        10  -> pure ETSupportedGroups
        13  -> pure ETSignatureAlgs
        43  -> pure ETSupportedVersions
        44  -> pure ETSignatureCookie
        50  -> pure ETSignatureAlgsCert
        51  -> pure ETKeyShare
        t   -> pure $ ETUnknown t

instance Wire.ToWire ExtensionType where
    put ETServerNameIndication = Serial.putWord16be 0
    put ETSupportedGroups      = Serial.putWord16be 10
    put ETSignatureAlgs        = Serial.putWord16be 13
    put ETSupportedVersions    = Serial.putWord16be 43
    put ETSignatureCookie      = Serial.putWord16be 44
    put ETSignatureAlgsCert    = Serial.putWord16be 50
    put ETKeyShare             = Serial.putWord16be 51
    put (ETUnknown w)          = Serial.putWord16be w

data Extension
    = ServerNameIndication ServerName
    -- -- | MaxFragmentLength
    -- -- | StatusRequest RFC 6066
    | SupportedGroups (V.Vector Group)
    | SignatureAlgs (V.Vector SignatureAlgorithm)
    -- -- | UseSRTP
    -- -- | Heartbeat
    -- -- | ALPN
    -- -- | SignedCertTimestamp
    -- -- | ClientCertType
    -- -- | ServerCertType
    -- -- | Padding
    -- -- | PSK PSKExtension -- TODO lots of psk stuff (B.3.1)
    | SupportedVersions SupportedVersionsExtension
    | Cookie Opaque16
    -- -- | PSKKeyExchangeModes TODO (4.2.9)
    -- -- | CertificateAuthorities TODO certificates
    -- -- | OIDFilters TODO certificates
    -- -- | PostHandshakeAuth
    | SignatureAlgsCert (V.Vector SignatureAlgorithm) -- (4.2.4)
    | KeyShare KeyShareExtension
    -- -- | KeyShareClientHello [KeyShare]
    -- -- | KeyShareHelloRetryRequest Group
    -- -- | Custom
    | Unknown
    deriving (Show, Eq)

instance Wire.ToWire Extension where
    put (ServerNameIndication name) = do
        Wire.put ETServerNameIndication
        let bytes = Serial.runPut $ Wire.put name
        Serial.putWord16be $ fromIntegral (B.length bytes)
        Serial.putByteString bytes

    put (SupportedGroups groups) = do
        Wire.put ETSupportedGroups
        let len = V.length groups
        Serial.putWord16be (fromIntegral $ len * 2 + 2)
        Serial.putWord16be (fromIntegral $ len * 2)
        mapM_ Wire.put groups

    put (SignatureAlgs algs) = do
        Wire.put ETSignatureAlgs
        putSignatureAlgorithms algs
        -- let len = V.length algs
        -- Serial.putWord16be (fromIntegral $ len * 2 + 2)
        -- Serial.putWord16be (fromIntegral $ len * 2)
        -- mapM_ Wire.put algs

    put (Cookie c) = do
        Wire.put ETSignatureCookie
        Wire.put c

    put (SupportedVersions versions) = do
        Wire.put ETSupportedVersions
        case versions of
          SupportedVersionsClient vs -> do
              let versionBytes = Serial.runPut (mapM_ Wire.put vs)
              Serial.putWord16be $ fromIntegral $ B.length versionBytes + 1
              Serial.putWord8 $ fromIntegral $ B.length versionBytes
              Serial.putByteString versionBytes
          SupportedVersionsServer v -> do
              Serial.putWord8 2
              Wire.put v

    put (SignatureAlgsCert algs) = do
        Wire.put ETSignatureAlgsCert
        putSignatureAlgorithms algs

    put (KeyShare ks) = do
        Wire.put ETKeyShare
        case ks of
          KeyShareChlo keys -> do
              let keyShareBytes = Serial.runPut (mapM_ Wire.put keys)
              Wire.putOpaque16 keyShareBytes
          KeyShareHelloRetryRequest group -> Wire.put group
          KeyShareShlo keyShare -> Wire.put keyShare

    put Unknown = fail "Cannot serialize unknown extension"


putSignatureAlgorithms :: V.Vector SignatureAlgorithm -> Serial.Put
putSignatureAlgorithms algs = do
    let len = V.length algs
    Serial.putWord16be (fromIntegral $ len * 2 + 2)
    Serial.putWord16be (fromIntegral $ len * 2)
    mapM_ Wire.put algs

-- See RFC 6066 for definition and RFC 5890 for hostname comparison
newtype ServerName = ServerName B.ByteString deriving (Show, Eq)

instance Wire.ToWire ServerName where
    put (ServerName hostname) = do
        let bytes = Serial.runPut $ do
                Serial.putWord8 0 -- type: host_name
                Serial.putWord16be $ fromIntegral (B.length hostname)
                Serial.putByteString hostname
        Serial.putWord16be $ fromIntegral (B.length bytes)
        Serial.putByteString bytes
        -- let len = B.length hostname
        -- Serial.putWord16be (fromIntegral $ len + 3 + 2)
        -- Serial.putWord16be (fromIntegral $ len + 3)
        -- Serial.putWord8 0 -- type: host_name
        -- Serial.putWord16be (fromIntegral len)
        -- Serial.putByteString hostname

parseExtensionForType
    :: Int
    -> ExtensionType
    -> Handshake.HandshakeType
    -> Serial.Get Extension

parseExtensionForType _ ETServerNameIndication = parseSNI
parseExtensionForType _ ETSupportedGroups      = parseSupportedGroups
parseExtensionForType _ ETSignatureAlgs        = parseSignatureAlgs
parseExtensionForType _ ETSupportedVersions    = parseSupportedVersions
parseExtensionForType _ ETSignatureCookie      = parseSignatureCookie
parseExtensionForType _ ETSignatureAlgsCert    = parseSignatureAlgsCert
parseExtensionForType _ ETKeyShare             = parseKeyShare
parseExtensionForType l (ETUnknown _)          = const $ Serial.skip l $> Unknown


parseSNI :: Handshake.HandshakeType -> Serial.Get Extension
parseSNI Handshake.ClientHello = parseSNIValid
parseSNI Handshake.EncryptedExtensions = parseSNIValid
parseSNI ht = fail $ "Server name extension cannot be sent in " <> show ht

parseSNIValid :: Serial.Get Extension
parseSNIValid = do
    Serial.skip 2
    nameType <- Serial.getWord8
    when (nameType /= 0) $ fail ("Unsupported name type: " <> show nameType)
    nameLen <- fromIntegral <$> Serial.getWord16be
    name <- Serial.getByteString nameLen
    pure $ ServerNameIndication (ServerName name)


parseSupportedGroups :: Handshake.HandshakeType -> Serial.Get Extension
parseSupportedGroups Handshake.ClientHello = parseSupportedGroupsValid
parseSupportedGroups Handshake.EncryptedExtensions = parseSupportedGroupsValid
parseSupportedGroups ht = fail $ "Server name extension cannot be sent in " <> show ht

parseSupportedGroupsValid :: Serial.Get Extension
parseSupportedGroupsValid = SupportedGroups <$> parseArray 2


parseSignatureAlgs :: Handshake.HandshakeType -> Serial.Get Extension
parseSignatureAlgs Handshake.ClientHello        = parseSignatureAlgsValid
parseSignatureAlgs Handshake.CertificateRequest = parseSignatureAlgsValid
parseSignatureAlgs ht                           = invalidExtensionFor "Signature Algorithms" ht

parseSignatureAlgsValid :: Serial.Get Extension
parseSignatureAlgsValid = SignatureAlgs <$> parseArray 2


parseSignatureAlgsCert :: Handshake.HandshakeType -> Serial.Get Extension
parseSignatureAlgsCert Handshake.ClientHello        = parseSignatureAlgsCertValid
parseSignatureAlgsCert Handshake.CertificateRequest = parseSignatureAlgsCertValid
parseSignatureAlgsCert ht                           = invalidExtensionFor "Signature Algorithms" ht

parseSignatureAlgsCertValid :: Serial.Get Extension
parseSignatureAlgsCertValid = SignatureAlgsCert <$> parseArray 2


parseSupportedVersions :: Handshake.HandshakeType -> Serial.Get Extension
parseSupportedVersions Handshake.ClientHello       = parseSupportedVersionsClient
parseSupportedVersions Handshake.ServerHello       = parseSupportedVersionsServer
parseSupportedVersions Handshake.HelloRetryRequest = parseSupportedVersionsServer
parseSupportedVersions ht                          = invalidExtensionFor "Supported versions" ht

parseSupportedVersionsClient :: Serial.Get Extension
parseSupportedVersionsClient = SupportedVersions . SupportedVersionsClient <$> parseArray 2

parseSupportedVersionsServer :: Serial.Get Extension
parseSupportedVersionsServer = SupportedVersions . SupportedVersionsServer <$> Wire.get


parseSignatureCookie :: Handshake.HandshakeType -> Serial.Get Extension
parseSignatureCookie Handshake.ClientHello       = parseSignatureCookieValid
parseSignatureCookie Handshake.HelloRetryRequest = parseSignatureCookieValid
parseSignatureCookie ht                          = invalidExtensionFor "Signature cookie" ht

parseSignatureCookieValid :: Serial.Get Extension
parseSignatureCookieValid = Cookie <$> Wire.get


parseKeyShare :: Handshake.HandshakeType -> Serial.Get Extension
parseKeyShare Handshake.ClientHello       = do
    len <- fromIntegral <$> Serial.getWord16be
    Serial.isolate len $ KeyShare . KeyShareChlo . V.fromList <$> parseKeySharesForLength len
  where
      parseKeySharesForLength :: Int -> Serial.Get [KeyShareEntry]
      parseKeySharesForLength l
        | l > 0 = do
                    keyShare <- Wire.get
                    (:) <$> pure keyShare <*> parseKeySharesForLength (l - keyShareEntryLength keyShare)
        | otherwise = pure []
parseKeyShare Handshake.ServerHello       = KeyShare . KeyShareShlo <$> Wire.get
parseKeyShare Handshake.HelloRetryRequest = KeyShare . KeyShareHelloRetryRequest <$> Wire.get
parseKeyShare ht                          = invalidExtensionFor "Key share" ht


invalidExtensionFor :: String -> Handshake.HandshakeType -> Serial.Get Extension
invalidExtensionFor extName ht = fail $ extName <> " extension cannot be sent in " <> show ht

-- parseArray :: Serial.Serialize a => Int -> Serial.Get (V.Vector a)
parseArray :: Wire.FromWire a => Int -> Serial.Get (V.Vector a)
parseArray elemSize = do
    len <- fromIntegral <$> Serial.getWord16be
    V.replicateM (len `div` elemSize) Wire.get


data SignatureAlgorithm
    = RsaPkcs1Sha256
    | RsaPkcs1Sha384
    | RsaPkcs1Sha512
    | EcdsaSecp256r1Sha256
    | EcdsaSecp384r1Sha384
    | EcdsaSecp521r1Sha512
    | RsaPssRsaeSha256
    | RsaPssRsaeSha384
    | RsaPssRsaeSha512
    | Ed25519
    | Ed448
    | RsaPssPssSha256
    | RsaPssPssSha384
    | RsaPssPssSha512
    | RsaPkcs1Sha1
    | EcdsaSha1
    -- | PrivateUse
    deriving (Show, Eq)

instance Wire.ToWire SignatureAlgorithm where
    put RsaPkcs1Sha256       = Serial.putWord16be 0x0401
    put RsaPkcs1Sha384       = Serial.putWord16be 0x0501
    put RsaPkcs1Sha512       = Serial.putWord16be 0x0601
    put EcdsaSecp256r1Sha256 = Serial.putWord16be 0x0403
    put EcdsaSecp384r1Sha384 = Serial.putWord16be 0x0503
    put EcdsaSecp521r1Sha512 = Serial.putWord16be 0x0603
    put RsaPssRsaeSha256     = Serial.putWord16be 0x0804
    put RsaPssRsaeSha384     = Serial.putWord16be 0x0805
    put RsaPssRsaeSha512     = Serial.putWord16be 0x0806
    put Ed25519              = Serial.putWord16be 0x0807
    put Ed448                = Serial.putWord16be 0x0808
    put RsaPssPssSha256      = Serial.putWord16be 0x0809
    put RsaPssPssSha384      = Serial.putWord16be 0x080a
    put RsaPssPssSha512      = Serial.putWord16be 0x080b
    put RsaPkcs1Sha1         = Serial.putWord16be 0x0201
    put EcdsaSha1            = Serial.putWord16be 0x0203

instance Wire.FromWire SignatureAlgorithm where
    get = Serial.getWord16be >>= \case
        0x0401 -> pure RsaPkcs1Sha256
        0x0501 -> pure RsaPkcs1Sha384
        0x0601 -> pure RsaPkcs1Sha512
        0x0403 -> pure EcdsaSecp256r1Sha256
        0x0503 -> pure EcdsaSecp384r1Sha384
        0x0603 -> pure EcdsaSecp521r1Sha512
        0x0804 -> pure RsaPssRsaeSha256
        0x0805 -> pure RsaPssRsaeSha384
        0x0806 -> pure RsaPssRsaeSha512
        0x0807 -> pure Ed25519
        0x0808 -> pure Ed448
        0x0809 -> pure RsaPssPssSha256
        0x080a -> pure RsaPssPssSha384
        0x080b -> pure RsaPssPssSha512
        0x0201 -> pure RsaPkcs1Sha1
        0x0203 -> pure EcdsaSha1
        code   -> fail $ "Unrecognized algorithm code " <> show code


data SupportedVersionsExtension
    = SupportedVersionsClient (V.Vector Version)
    | SupportedVersionsServer Version
    deriving (Show, Eq)

data Version = TLS10 | TLS12 | TLS13 deriving (Show, Eq)

instance Wire.ToWire Version where
    put TLS10 = Serial.putWord16be 0x301
    put TLS12 = Serial.putWord16be 0x303
    put TLS13 = Serial.putWord16be 0x304

instance Wire.FromWire Version where
    get = do
        v <- Serial.getWord16be
        case v of
            0x301 -> pure TLS10
            0x303 -> pure TLS12
            0x304 -> pure TLS13
            _ -> fail $ "Unrecognized version " <> show v


-- -- data PSKExtension
-- --     = PSKChlo
-- --     | PSKShlo
-- --     deriving (Show, Eq)


-- should only be used for key_share extension once the handshake
-- is completed
data Group
    -- Elliptic curve groups (ECDHE)
    = Secp256r1
    | Secp384r1
    | Secp521r1
    | X25519
    | X448
    -- Finite Field Groups
    | Ffdhe2048
    | Ffdhe3072
    | Ffdhe4096
    | Ffdhe6144
    | Ffdhe8192
    -- Reserved Code Points
    -- | FfdhePrivateUse
    -- | EcdhePrivateUse
    deriving (Show, Eq)

instance Wire.ToWire Group where
    put Secp256r1 = Serial.putWord16be 23
    put Secp384r1 = Serial.putWord16be 24
    put Secp521r1 = Serial.putWord16be 25
    put X25519    = Serial.putWord16be 29
    put X448      = Serial.putWord16be 30
    put Ffdhe2048 = Serial.putWord16be 256
    put Ffdhe3072 = Serial.putWord16be 257
    put Ffdhe4096 = Serial.putWord16be 258
    put Ffdhe6144 = Serial.putWord16be 259
    put Ffdhe8192 = Serial.putWord16be 260

instance Wire.FromWire Group where
    get = do
        typ <- Serial.getWord16be
        case typ of
            23 -> pure Secp256r1
            24 -> pure Secp384r1
            25 -> pure Secp521r1
            29 -> pure X25519
            30 -> pure X448
            256 -> pure Ffdhe2048
            257 -> pure Ffdhe3072
            258 -> pure Ffdhe4096
            259 -> pure Ffdhe6144
            260 -> pure Ffdhe8192
            _ -> fail $ "Unrecognized group type: " <> show typ

data KeyShareExtension
    = KeyShareChlo (V.Vector KeyShareEntry)
    | KeyShareHelloRetryRequest Group
    | KeyShareShlo KeyShareEntry
    deriving (Show, Eq)

-- TODO the opaque value depends on the value of the Group
newtype KeyShareEntry = KeyShareEntry (Group, Opaque16) deriving (Show, Eq)

instance Wire.ToWire KeyShareEntry where
    put kse@(KeyShareEntry (group, key)) = do
        Serial.putWord16be (fromIntegral $ keyShareEntryLength kse)
        Wire.put group
        Wire.put key

instance Wire.FromWire KeyShareEntry where
    get = do
        len <- fromIntegral <$> Serial.getWord16be
        Serial.isolate len
            $ KeyShareEntry <$> Serial.getTwoOf Wire.get Wire.get

keyShareEntryLength :: KeyShareEntry -> Int
keyShareEntryLength (KeyShareEntry (group, key)) = 2 + opaque16Len key


fromWireForPacket :: Handshake.HandshakeType -> Serial.Get Extension
fromWireForPacket ht = do
    extType <- Wire.get
    len <- fromIntegral <$> Serial.getWord16be
    Serial.isolate len (parseExtensionForType len extType ht)
