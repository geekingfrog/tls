{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GADTs #-}

module TestTypes where

import qualified Data.ByteString               as B
import           Data.Serialize                as S
import           Type.Reflection

import Data.Proxy

-- data Code = C1 | C2 | C3 deriving (Show)
--
-- data Ext (a :: Code)
--     = Ext1 B.ByteString
--     | Ext2 B.ByteString
--     deriving (Show)
--
-- data Enveloppe = forall a. Enveloppe (Ext a)
--
-- deriving instance Show Enveloppe

parseC1 = Ext1 <$> S.getByteString 1
parseC2 = Ext2 <$> S.getByteString 1


data Code = C1 | C2 | C3 deriving (Show)

data Ext
    = Ext1 B.ByteString
    | Ext2 B.ByteString
    deriving (Show)

class Parse a where
    parse :: S.Get a

instance Parse Ext where
    parse = parseC2


data Ext' (a :: Code) where
    ExtC1 :: Ext -> Ext' 'C1
    ExtC2 :: Ext -> Ext' 'C2
    ExtC3 :: Ext -> Ext' 'C3

deriving instance Show (Ext' a)

instance Parse (Ext' 'C1) where
    parse = ExtC1 <$> parseC1

instance Parse (Ext' 'C2) where
    parse = ExtC2 <$> parseC2

data SomeExt' = forall a. SomeExt' (Ext' a)

deriving instance Show SomeExt'

-- testInstance :: forall a. Either String Enveloppe
testInstance = flip S.runGet (B.cons 0x02 "foo") $ do
    code <- S.getWord8
    case code of
        1 -> SomeExt' <$> (parse :: Get (Ext' 'C1))
        _ -> SomeExt' <$> (parse :: Get (Ext' 'C2))
