module Network.TLS.Pure.State where

import qualified Network.TLS.Pure.Packet as Pkt

data TLSState
    = TLSStart !StartState
    | TLSWaitSH !WaitSHState
    | TLSWaitEE !WaitEEState
    deriving (Show)

data StartState = StartState
    { ssChloData :: !Pkt.ClientHelloData
    , foo :: Int
    }
    deriving (Show)

data WaitSHState = WaitSHState
    { wshsChloData :: !Pkt.ClientHelloData
    , wsshsSecondChloData :: !(Maybe Pkt.ClientHelloData)
    }
    deriving (Show)

data WaitEEState = WaitEEState
    { weesClientHandshakeKeys :: Int
    , weesServerHandshakeKeys :: Int
    }
    deriving (Show)
