module Network.TLS.Pure.Error where

import qualified Crypto.Error as Crypto

data ParseError
  = UnHandled String
  -- ^ 'Data.Serialize.Get' calls `mzero` when things fails, which cannot
  -- be caught by any mean and always return a string. This constructor is
  -- a simple wrapper around that
  | CryptoFailed Crypto.CryptoError
  -- ^ Whenever some key comes from the wire and the format isn't correct
  -- or whatever can fail during the conversion bytes -> key

  deriving (Show, Eq)
