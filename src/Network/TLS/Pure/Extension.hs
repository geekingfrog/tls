{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE BangPatterns #-}


module Network.TLS.Pure.Extension where

import           Control.Monad
import           Data.Functor
import           Data.Coerce

import qualified Data.ByteString               as B
import qualified Data.Serialize.Put            as Serial
import qualified Data.Serialize.Get            as Serial
import qualified Data.Vector                   as V
import           GHC.Word

import qualified Network.TLS.Pure.Handshake.Header
                                               as Handshake
import qualified Network.TLS.Pure.Wire         as Wire
import           Network.TLS.Pure.Version       ( Version(..) )


data ExtensionType
    = ETServerNameIndication
    | ETSupportedGroups
    | ETSignatureAlgs
    | ETSupportedVersions
    | ETSignatureCookie
    | ETSignatureAlgsCert
    | ETKeyShare
    | ETUnknown Word16
    deriving (Show)

instance Wire.ToWire ExtensionType where
    put ETServerNameIndication = Serial.putWord16be 0
    put ETSupportedGroups      = Serial.putWord16be 10
    put ETSignatureAlgs        = Serial.putWord16be 13
    put ETSupportedVersions    = Serial.putWord16be 43
    put ETSignatureCookie      = Serial.putWord16be 44
    put ETSignatureAlgsCert    = Serial.putWord16be 50
    put ETKeyShare             = Serial.putWord16be 51
    put (ETUnknown w)          = Serial.putWord16be w

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


newtype Extensions
    = Extensions (V.Vector Extension)
    deriving (Show)

instance Wire.ToWire Extensions where
    put (Extensions exts)
        | V.null exts = pure ()
        | otherwise = do
            let extensionBytes = Serial.runPut (mapM_ Wire.put exts)
            Serial.putWord16be $ fromIntegral (B.length extensionBytes)
            Serial.putByteString extensionBytes

parseExtensions :: Handshake.HandshakeType -> Serial.Get Extensions
parseExtensions ht = do
    len <- fromIntegral <$> Serial.getWord16be
    Extensions . V.fromList <$> Serial.isolate len (parseExtensions [])
  where
      parseExtensions :: [Extension] -> Serial.Get [Extension]
      parseExtensions acc = do
          r <- Serial.remaining
          if r == 0
             then pure $! reverse acc
             else do
                 !ext <- parseExtension ht
                 parseExtensions (ext : acc)



data Extension
    = ServerNameIndication ServerName
    -- -- | MaxFragmentLength
    -- -- | StatusRequest RFC 6066
    | SupportedGroups SupportedGroupsExtension
    | SignatureAlgs SignatureAlgorithms
    -- -- | UseSRTP
    -- -- | Heartbeat
    -- -- | ALPN
    -- -- | SignedCertTimestamp
    -- -- | ClientCertType
    -- -- | ServerCertType
    -- -- | Padding
    -- -- | PSK PSKExtension -- TODO lots of psk stuff (B.3.1)
    | SupportedVersions SupportedVersionsExtension
    | Cookie CookieExtension
    -- -- | PSKKeyExchangeModes TODO (4.2.9)
    -- -- | CertificateAuthorities TODO certificates
    -- -- | OIDFilters TODO certificates
    -- -- | PostHandshakeAuth
    | SignatureAlgsCert SignatureAlgorithms -- (4.2.4)
    | KeyShare KeyShareExtension
    -- -- | KeyShareClientHello [KeyShare]
    -- -- | KeyShareHelloRetryRequest Group
    -- -- | Custom -- TODO custom extension with a type parameter ?
    | Unknown
    deriving (Show)

instance Wire.ToWire Extension where
    put (ServerNameIndication name) = do
        Wire.put ETServerNameIndication
        let bytes = Serial.runPut $ Wire.put name
        Serial.putWord16be $ fromIntegral (B.length bytes)
        Serial.putByteString bytes

    put (SupportedGroups groups) = do
        Wire.put ETSupportedGroups
        Wire.put groups

    put (SignatureAlgs algs) = do
        Wire.put ETSignatureAlgs
        Wire.put algs

    put (Cookie c) = do
        Wire.put ETSignatureCookie
        Wire.put c

    put (SupportedVersions versions) = do
        Wire.put ETSupportedVersions
        Wire.put versions

    put (SignatureAlgsCert algs) = do
        Wire.put ETSignatureAlgsCert
        Wire.put algs

    put (KeyShare ks) = do
        Wire.put ETKeyShare
        Wire.put ks

    put Unknown = fail "Cannot serialize unknown extension"


parseExtension :: Handshake.HandshakeType -> Serial.Get Extension
parseExtension ht = do
    extType <- Wire.get
    extLength <- fromIntegral <$> Serial.getWord16be
    Serial.isolate extLength $ parseExtensionForType extType ht


newtype SupportedGroupsExtension
    = SupportedGroupsExtension (V.Vector Group)
    deriving (Show)

instance Wire.ToWire SupportedGroupsExtension where
    put (SupportedGroupsExtension groups) = do
        let len = V.length groups
        Serial.putWord16be (fromIntegral $ len * 2 + 2)
        Serial.putWord16be (fromIntegral $ len * 2)
        mapM_ Wire.put groups

parseSupportedGroupsExtension :: Serial.Get SupportedGroupsExtension
parseSupportedGroupsExtension = SupportedGroupsExtension <$> Wire.parseArray 2




putSignatureAlgorithms :: V.Vector SignatureAlgorithm -> Serial.Put
putSignatureAlgorithms algs = do
    let len = V.length algs
    Serial.putWord16be (fromIntegral $ len * 2 + 2)
    Serial.putWord16be (fromIntegral $ len * 2)
    mapM_ Wire.put algs

-- See RFC 6066 for definition and RFC 5890 for hostname comparison
newtype ServerName = ServerName B.ByteString deriving (Show)

instance Wire.ToWire ServerName where
    put (ServerName hostname) = do
        let bytes = Serial.runPut $ do
                Serial.putWord8 0 -- type: host_name
                Serial.putWord16be $ fromIntegral (B.length hostname)
                Serial.putByteString hostname
        Serial.putWord16be $ fromIntegral (B.length bytes)
        Serial.putByteString bytes

parseSNI :: Handshake.HandshakeType -> Serial.Get ServerName
parseSNI Handshake.ClientHello = parseSNIValid
parseSNI Handshake.EncryptedExtensions = parseSNIValid
parseSNI t = invalidExtensionFor "Server Name Indication" t

parseSNIValid :: Serial.Get ServerName
parseSNIValid = do
    skipExtensionLength
    nameType <- Serial.getWord8
    when (nameType /= 0) $ fail ("Unsupported name type: " <> show nameType)
    nameLen <- fromIntegral <$> Serial.getWord16be
    ServerName <$> Serial.getByteString nameLen



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
    deriving (Show)

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
        code   -> fail $ "Unknown algorithm code " <> show code

newtype SignatureAlgorithms
    = SignatureAlgorithms (V.Vector SignatureAlgorithm)
    deriving (Show)

instance Wire.ToWire SignatureAlgorithms where
    put (SignatureAlgorithms algs) = putSignatureAlgorithms algs

parseSignatureAlgs
    :: Handshake.HandshakeType
    -> Serial.Get SignatureAlgorithms
parseSignatureAlgs Handshake.ClientHello        = parseSignatureAlgsValid
parseSignatureAlgs Handshake.CertificateRequest = parseSignatureAlgsValid
parseSignatureAlgs t                            = invalidExtensionFor "Signature Algorithm" t

parseSignatureAlgsValid :: Serial.Get SignatureAlgorithms
parseSignatureAlgsValid = SignatureAlgorithms <$> Wire.parseArray 2



data SupportedVersionsExtension
    = SupportedVersionsClient (V.Vector Version)
    | SupportedVersionsServer Version
    deriving (Show)

instance Wire.ToWire SupportedVersionsExtension where
    put (SupportedVersionsClient vs) = do
          let versionBytes = Serial.runPut (mapM_ Wire.put vs)
          Serial.putWord16be $ fromIntegral $ B.length versionBytes + 1
          Serial.putWord8 $ fromIntegral $ B.length versionBytes
          Serial.putByteString versionBytes
    put (SupportedVersionsServer v) = do
          Serial.putWord8 2
          Wire.put v

parseSupportedVersions
    :: Handshake.HandshakeType
    -> Serial.Get SupportedVersionsExtension
parseSupportedVersions Handshake.ClientHello       = SupportedVersionsClient <$> Wire.parseArray 2
parseSupportedVersions Handshake.ServerHello       = SupportedVersionsServer <$> Wire.get
parseSupportedVersions Handshake.HelloRetryRequest = SupportedVersionsServer <$> Wire.get
parseSupportedVersions t                           = invalidExtensionFor "Supported Versions" t



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
            _ -> fail $ "Unknown group type: " <> show typ




skipExtensionLength :: Serial.Get ()
skipExtensionLength = Serial.skip 2

invalidExtensionFor extName typ = fail $ extName <> " extension cannot be sent in " <> show typ


parseExtensionForType
    :: ExtensionType
    -> Handshake.HandshakeType
    -> Serial.Get Extension
parseExtensionForType ETServerNameIndication = fmap ServerNameIndication . parseSNI
parseExtensionForType ETSupportedGroups = fmap SupportedGroups . parseSupportedGroups
parseExtensionForType ETSignatureAlgs = fmap SignatureAlgs . parseSignatureAlgs
parseExtensionForType ETSupportedVersions = fmap SupportedVersions . parseSupportedVersions
parseExtensionForType ETSignatureCookie = fmap Cookie . parseCookie
parseExtensionForType ETSignatureAlgsCert = const (fail "signature algs cert not implemented")
parseExtensionForType ETKeyShare = fmap KeyShare . parseKeyShare
parseExtensionForType (ETUnknown _) = undefined


parseSupportedGroups
    :: Handshake.HandshakeType
    -> Serial.Get SupportedGroupsExtension
parseSupportedGroups Handshake.ClientHello         = parseSupportedGroupsValid
parseSupportedGroups Handshake.EncryptedExtensions = parseSupportedGroupsValid
parseSupportedGroups t                             = invalidExtensionFor "Supported Groups" t

parseSupportedGroupsValid :: Serial.Get SupportedGroupsExtension
parseSupportedGroupsValid = SupportedGroupsExtension <$> Wire.parseArray 2


newtype CookieExtension
    = CookieExtension Wire.Opaque16
    deriving (Show)

instance Wire.ToWire CookieExtension where
    put (CookieExtension c) = Wire.put c

parseCookie
    :: Handshake.HandshakeType
    -> Serial.Get CookieExtension
parseCookie Handshake.ClientHello       = CookieExtension <$> Wire.get
parseCookie Handshake.HelloRetryRequest = CookieExtension <$> Wire.get
parseCookie t                           = invalidExtensionFor "Cookie" t


-- TODO would be nice to be able to statically know which extension is
-- there from the record type
data KeyShareExtension
    = KeyShareChlo (V.Vector KeyShareEntry)
    | KeyShareHelloRetryRequest Group
    | KeyShareShlo KeyShareEntry
    deriving (Show)

instance Wire.ToWire KeyShareExtension where
    put (KeyShareChlo keys) = do
        let keyShareBytes = Serial.runPut (mapM_ Wire.put keys)
        Serial.putWord16be (fromIntegral $ B.length keyShareBytes)
        Serial.putByteString keyShareBytes
    put (KeyShareHelloRetryRequest group) = Wire.put group
    put (KeyShareShlo keyShare) = Wire.put keyShare

parseKeyShare
    :: Handshake.HandshakeType
    -> Serial.Get KeyShareExtension
parseKeyShare Handshake.ClientHello = do
        len <- fromIntegral <$> Serial.getWord16be
        kses <- Serial.isolate len $ parse len []
        pure (KeyShareChlo $ V.fromList kses)
      where
        parse :: Int -> [KeyShareEntry] -> Serial.Get [KeyShareEntry]
        parse l acc | l <= 0 = pure (reverse acc)
                    | otherwise = do
                        group <- Wire.get
                        ks <- Wire.get
                        let kse = KeyShareEntry group Nothing ks
                        parse (l - Wire.opaque16Length ks) (kse : acc)

parseKeyShare Handshake.ServerHello = KeyShareShlo <$> Wire.get
parseKeyShare Handshake.HelloRetryRequest = KeyShareHelloRetryRequest <$> Wire.get
parseKeyShare t = invalidExtensionFor "Key Share" t


-- newtype KeyShareEntry = KeyShareEntry (Group, Wire.Opaque16) deriving (Show)
-- TODO typeclass to get associatedType there? Or at least different type for public and private
data KeyShareEntry = KeyShareEntry
    { kseGroup :: Group
    , ksePrivate :: Maybe Wire.Opaque16
    , ksePublic :: Wire.Opaque16
    }
    deriving (Show)

instance Wire.ToWire KeyShareEntry where
    put kse = do
        let bytes = Serial.runPut (Wire.put (kseGroup kse) *> Wire.put (ksePublic kse))
        Serial.putWord16be (fromIntegral $ B.length bytes)
        Serial.putByteString bytes

instance Wire.FromWire KeyShareEntry where
    get = do
        !group <- Wire.get
        !publicKey <- Wire.get
        let expectedLength = case group of
                X25519 -> Just 32
                X448 -> Just 56
                _ -> Nothing

        let actualLength = B.length (coerce publicKey)
        forM_ expectedLength $ \l -> when (actualLength /= l) $ fail
            $ "Incorrect publicKey length for group " <> show group
            <> " Expected " <> show l
            <> " but got " <> show actualLength

        pure $ KeyShareEntry group Nothing publicKey
