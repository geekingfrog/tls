module Network.TLS.Pure.Packet.Handshake where

-- import           GHC.Word
-- import qualified Data.Vector                          as V
-- import qualified Data.ByteString                      as B
-- import qualified Data.Serialize.Put                   as Serial
--
-- import qualified Network.TLS.Pure.Wire                as Wire
-- import qualified Data.Serialize                       as Serial
--
-- import qualified Network.TLS.Pure.Cipher            as Cipher
-- import qualified Network.TLS.Pure.Version           as Version
--
-- data HandshakeType
--     = ClientHello
--     | ServerHello
--     | NewSessionTicket
--     | EndOfEarlyData
--     | HelloRetryRequest
--     | EncryptedExtensions
--     | Certificate
--     | CertificateRequest
--     | CertificateVerify
--     | Finished
--     | KeyUpdate
--     | MessageHash
--     | Unknown Word8
--     deriving (Show, Eq)
--
--
-- instance Wire.ToWire HandshakeType where
--     put ClientHello         = Serial.putWord8 1
--     put ServerHello         = Serial.putWord8 2
--     put NewSessionTicket    = Serial.putWord8 4
--     put EndOfEarlyData      = Serial.putWord8 5
--     put HelloRetryRequest   = Serial.putWord8 6
--     put EncryptedExtensions = Serial.putWord8 8
--     put Certificate         = Serial.putWord8 11
--     put CertificateRequest  = Serial.putWord8 13
--     put CertificateVerify   = Serial.putWord8 15
--     put Finished            = Serial.putWord8 20
--     put KeyUpdate           = Serial.putWord8 24
--     put MessageHash         = Serial.putWord8 254
--     put (Unknown _)         = fail "Cannot serialize unknown handshake type"
--
-- -- instance Wire.FromWire HandshakeType where
-- --     get = Serial.getWord8 >>= \case
-- --         1 -> pure ClientHello
-- --         2 -> pure ServerHello
-- --         4 -> pure NewSessionTicket
-- --         5 -> pure EndOfEarlyData
-- --         6 -> pure HelloRetryRequest
-- --         8 -> pure EncryptedExtensions
-- --         11 -> pure Certificate
-- --         13 -> pure CertificateRequest
-- --         15 -> pure CertificateVerify
-- --         20 -> pure Finished
-- --         24 -> pure KeyUpdate
-- --         254 -> pure MessageHash
-- --         c -> pure $ Unknown c
