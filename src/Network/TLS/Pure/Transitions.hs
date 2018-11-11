{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.TLS.Pure.Transitions where

import qualified Network.TLS.Pure.Packet as Pkt
import qualified Network.TLS.Pure.Extension as Ext
import qualified Network.TLS.Pure.Wire as Wire
import qualified Network.TLS.Pure.Cipher as Cipher

import Control.Monad
import qualified Data.Bifunctor                as Bi
import qualified Data.Text                     as Tx
import qualified Data.Vector                   as V
import qualified Data.ByteString               as B
import qualified Data.ByteArray                as BA
import qualified Data.Serialize                as Serial

import qualified Crypto.Error                  as CErr
import qualified Crypto.PubKey.Curve25519      as C25519
import qualified Crypto.Hash                   as Hash
import qualified Crypto.Hash.Algorithms        as Hash.Algs
import qualified Crypto.KDF.HKDF               as HKDF


pickKeyShareEntry :: Pkt.ClientHelloData -> Pkt.ServerHelloData -> Maybe Ext.KeyShareEntry
pickKeyShareEntry chloData shloData = do
    let exts = Pkt.chlodExtensions chloData
    keyShares <- getKeyShares exts
    groups <- getSupportedGroups exts
    kse <- getServerKeyShare (Pkt.shlodExtensions shloData)
    let selectedGroup = Ext.kseGroup kse
    V.find (\k -> Ext.kseGroup k == selectedGroup) keyShares

getKeyShares :: Ext.Extensions -> Maybe (V.Vector Ext.KeyShareEntry)
getKeyShares (Ext.Extensions exts) = do
    (Ext.KeyShare (Ext.KeyShareChlo kses)) <- V.find isKeyShare exts
    pure kses
  where
    isKeyShare (Ext.KeyShare _) = True
    isKeyShare _ = False


getServerKeyShare :: Ext.Extensions -> Maybe Ext.KeyShareEntry
getServerKeyShare (Ext.Extensions exts) = do
    (Ext.KeyShare (Ext.KeyShareShlo kse)) <- V.find isKeyShare exts
    pure kse
  where
    isKeyShare (Ext.KeyShare _) = True
    isKeyShare _ = False

getSupportedGroups :: Ext.Extensions -> Maybe Ext.SupportedGroupsExtension
getSupportedGroups (Ext.Extensions exts) = do
    (Ext.SupportedGroups sg) <- V.find isSupportedGroups exts
    pure sg
  where
    isSupportedGroups (Ext.SupportedGroups _) = True
    isSupportedGroups _ = False


toKeyShareEntries :: Ext.Extension -> Maybe (V.Vector Ext.KeyShareEntry)
toKeyShareEntries (Ext.KeyShare (Ext.KeyShareChlo shares))
    = Just shares
toKeyShareEntries _
    = Nothing


-- TODO revisit that
data TLSError
    = CustomError Tx.Text
    | CryptoError CErr.CryptoError
    deriving (Show, Eq)

deriveHandshakeKeys
    :: Pkt.ClientHelloData
    -> Pkt.ServerHelloData
    -> Ext.KeyShareEntry
    -> Ext.KeyShareEntry
    -> Either TLSError B.ByteString

deriveHandshakeKeys chlod shlod privateKse publicKse = do
    -- TODO review error handling to get custom errors in
    (Wire.Opaque16 privateKey) <- case Ext.ksePrivate privateKse of
        Nothing -> Left $ CustomError "No private key in given keyShare"
        Just k -> pure k
    when (Ext.kseGroup privateKse /= Ext.kseGroup publicKse) $
        Left (CustomError "Different groups for given key shares")

    let (Wire.Opaque16 publicKey) = Ext.ksePublic publicKse
    (sharedSecret :: B.ByteString) <- Bi.first CryptoError
        $ CErr.eitherCryptoError
        $ case Ext.kseGroup privateKse of
            Ext.X25519 -> do
                pub <- C25519.publicKey publicKey
                priv <- C25519.secretKey privateKey
                pure $ BA.convert $ C25519.dh pub priv
            _ -> CErr.CryptoFailed CErr.CryptoError_PointFormatInvalid

    let helloHash = BA.convert $ hashHandshake chlod shlod
    let digestSize = Hash.hashDigestSize Hash.Algs.SHA256
    let earlySecret = hkdfExtract (B.replicate digestSize 0) (B.replicate digestSize 0)
    let emptyHash = BA.convert (Hash.hash B.empty :: Hash.Digest Hash.Algs.SHA256)
    let derivedSecret = hkdfExpandLabel digestSize (BA.convert earlySecret) "derived" emptyHash
    let handshakeSecret = BA.convert $ hkdfExtract derivedSecret sharedSecret

    -- TODO where does this 32 comes from? SHA256?
    let clientHandshakeTrafficSecret =
            hkdfExpandLabel 32 handshakeSecret "c hs traffic" helloHash
    let serverHandshakeTrafficSecret =
            hkdfExpandLabel 32 handshakeSecret "s hs traffic" helloHash

    let (Cipher.IvLength ivLength, Cipher.KeyLength keyLength) =
            Cipher.cipherParams (Pkt.shlodCipher shlod)
    let clientHandshakeKey = hkdfExpandLabel keyLength clientHandshakeTrafficSecret "key" ""
    let serverHandshakeKey = hkdfExpandLabel keyLength serverHandshakeTrafficSecret "key" ""
    let clientHandshakeIV = hkdfExpandLabel ivLength clientHandshakeTrafficSecret "iv" ""
    let serverHandshakeIV = hkdfExpandLabel ivLength serverHandshakeTrafficSecret "iv" ""



    pure ""

hashHandshake :: Pkt.ClientHelloData -> Pkt.ServerHelloData -> Hash.Digest Hash.Algs.SHA256
hashHandshake chlod shlod =
    let bytes = Serial.runPut (Wire.put chlod *> Wire.put shlod)
    in Hash.hash bytes


hkdfExtract :: B.ByteString -> B.ByteString -> HKDF.PRK Hash.Algs.SHA256
hkdfExtract salt key = HKDF.extract salt key

-- TODO add some newtype there!
hkdfExpandLabel
    :: Int
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
hkdfExpandLabel outLen secret label ctx
    = HKDF.expand (HKDF.extractSkip secret :: HKDF.PRK Hash.Algs.SHA256) label' outLen
  where
    label' = Serial.runPut $ do
        Serial.putWord16be $ fromIntegral outLen
        Wire.putOpaque8 $ "tls13 " <> label
        Wire.putOpaque8 ctx
