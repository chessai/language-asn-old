{-# language BangPatterns #-}

module Language.Asn.ObjectIdentifier
  ( fromList
  , suffixSingleton
  , appendSuffix
  , isPrefixOf
  , stripPrefix
  , encodeString
  , encodeByteString
  , encodeText
  )
  where

import Control.Monad.ST (runST)
import Language.Asn.Types
import Data.Maybe (isJust)
import Data.Text (Text)
import Data.ByteString (ByteString)
import Data.Word (Word32)
import Data.Primitive (PrimArray(..))
import qualified Data.Text as Text
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as BC8
import qualified Data.Vector.Primitive as PV
import qualified Data.List as List
import qualified Data.Primitive as PM
import qualified GHC.Exts as E

fromList :: [Word] -> ObjectIdentifier
fromList = ObjectIdentifier . E.fromList

suffixSingleton :: Word -> ObjectIdentifierSuffix
suffixSingleton = ObjectIdentifierSuffix . singletonPrimArray

appendSuffix :: ObjectIdentifier -> ObjectIdentifierSuffix -> ObjectIdentifier
appendSuffix (ObjectIdentifier a) (ObjectIdentifierSuffix b) = ObjectIdentifier (mappend a b)

isPrefixOf :: ObjectIdentifier -> ObjectIdentifier -> Bool
isPrefixOf a b = isJust (stripPrefix a b)

stripPrefix :: ObjectIdentifier -> ObjectIdentifier -> Maybe ObjectIdentifierSuffix
stripPrefix (ObjectIdentifier a) (ObjectIdentifier b) =
  let lenA = PM.sizeofPrimArray a
   in if (lenA <= PM.sizeofPrimArray b) && (upgradeArray a == PV.take lenA (upgradeArray b))
        then Just (ObjectIdentifierSuffix (unsafeDropPrimArray lenA b))
        else Nothing

upgradeArray :: PM.Prim a => PrimArray a -> PV.Vector a
upgradeArray b@(PrimArray a) = PV.Vector 0 (PM.sizeofPrimArray b) (PM.ByteArray a)

singletonPrimArray :: PM.Prim a => a -> PrimArray a
singletonPrimArray a = runST $ do
  m <- PM.newPrimArray 1
  PM.writePrimArray m 0 a
  PM.unsafeFreezePrimArray m

unsafeDropPrimArray :: PM.Prim a => Int -> PrimArray a -> PrimArray a
unsafeDropPrimArray !n !xs = runST $ do
  m <- PM.newPrimArray (PM.sizeofPrimArray xs - n)
  PM.copyPrimArray m 0 xs n (PM.sizeofPrimArray xs - n)
  PM.unsafeFreezePrimArray m

encodeString :: ObjectIdentifier -> String
encodeString = List.intercalate "." . map show . E.toList . getObjectIdentifier

encodeByteString :: ObjectIdentifier -> ByteString
encodeByteString = BC8.pack . encodeString

encodeText :: ObjectIdentifier -> Text
encodeText = Text.pack . encodeString


