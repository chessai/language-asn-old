{-# LANGUAGE CPP #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE LambdaCase #-}

{-# OPTIONS_GHC -Wall #-}

module Language.Asn.Encoding
  ( -- * Run Encoding
    der
  , toDefinitionString
    -- * Build Encoding
    -- ** Constructed
  , sequence
  , sequenceOf
  , choice
  , tag
  , implicitTag
    -- ** Fields
  , required
  , optional
  , defaulted
  , option
    -- ** Primitive
  , integer
  , integerRanged
  , int32
  , int
  , word32
  , word64
  , word
  , octetString
  , octetStringWord8
  , octetStringWord32
  , utf8String
  , null
  , null'
  , objectIdentifier
  -- Remove anything exported below this 
  , int64Log256
  , encodeLength
  ) where

import Prelude hiding (sequence,null)
import Language.Asn.Types.Internal
import Data.ByteString (ByteString)
import Data.ByteString.Builder (Builder)
import Data.Text (Text)
#if !MIN_VERSION_base(4,11,0)
import Data.Monoid
#endif
import Data.Word (Word8, Word32, Word64)
import Data.Int (Int32, Int64)
import Data.Bits (Bits(..), FiniteBits(..))
import Data.Primitive (PrimArray,Prim)
import GHC.Int (Int(..))
import Data.Foldable hiding (null)
import qualified Data.Text.Encoding as TE
import qualified Text.PrettyPrint as PP
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Builder as Builder
import qualified Data.List as List
import qualified Data.Primitive as PM
import qualified Data.ByteString as ByteString

-- Note that DER encoding is a subset of BER encoding. If you
-- need to encode with BER, just use this function.
der :: AsnEncoding a -> a -> LB.ByteString
der e = encodeTaggedByteString . encodeBerInternal e

tagClassPrefix :: TagClass -> String
tagClassPrefix = \case
  Universal -> "UNIVERSAL "
  Private -> "PRIVATE "
  Application -> "APPLICATION "
  ContextSpecific -> ""

toDefinitionString :: AsnEncoding a -> String
toDefinitionString = PP.render . go where
  go :: forall b. AsnEncoding b -> PP.Doc
  go (EncUniversalValue u) = prettyPrintUniversalValue u
  go (EncRetag (TagAndExplicitness theTag expl) e) =
    PP.text (prettyPrintTag theTag ++ " " ++ ppExplicitness expl ++ " ") <> go e
  go (EncChoice (Choice _ allCtors getValAndEnc)) = (PP.$+$)
    "CHOICE"
    ( PP.nest 2 $ PP.vcat $ map (ppValEnc . getValAndEnc) allCtors)
  go (EncSequence fields) = (PP.$+$)
    "SEQUENCE"
    ( PP.nest 2 $ PP.vcat $ map ppField fields)
  go (EncSequenceOf _ e) = PP.text "SEQUENCE OF" PP.<+> go e
  ppField :: forall b. Field b -> PP.Doc
  ppField = \case
    FieldRequired (FieldName name) _ e -> PP.text (name ++ " ") <> go e
    FieldOptional (FieldName name) _ e -> PP.text (name ++ " OPTIONAL ") <> go e
    FieldDefaulted (FieldName name) _ defVal showVal _ e ->
      PP.text (name ++ " DEFAULT " ++ showVal defVal ++ " ") <> go e
  ppValEnc :: ValueAndEncoding -> PP.Doc
  ppValEnc (ValueAndEncoding _ (OptionName name) _ enc) = PP.text (name ++ " ") <> go enc
  ppExplicitness :: Explicitness -> String
  ppExplicitness = \case
    Implicit -> "IMPLICIT"
    Explicit -> "EXPLICIT"

prettyPrintTag :: Tag -> String
prettyPrintTag (Tag c n) = "[" ++ tagClassPrefix c ++ show n ++ "]"

prettyPrintUniversalValue :: UniversalValue x -> PP.Doc
prettyPrintUniversalValue = \case
  UniversalValueBoolean _ _ -> PP.text "BOOLEAN"
  UniversalValueInteger _ ss -> PP.text $ "INTEGER" ++ strSubtypes show ss
  UniversalValueNull -> PP.text "NULL"
  UniversalValueOctetString _ _ -> PP.text "OCTET STRING"
  UniversalValueObjectIdentifier _ _ -> PP.text "OBJECT IDENTIFIER"
  UniversalValueTextualString typ _ _ _ -> PP.text (strStringType typ)

strStringType :: StringType -> String
strStringType = \case
  Utf8String -> "UTF8String"
  NumericString -> "NumericString"
  PrintableString -> "PrintableString"
  TeletexString -> "TeletexString"
  VideotexString -> "VideotexString"
  IA5String -> "IA5String"
  GraphicString -> "GraphicString"
  VisibleString -> "VisibleString"
  GeneralString -> "GeneralString"
  UniversalString -> "UniversalString"
  CharacterString -> "CHARACTER STRING"
  BmpString -> "BMPString"

strSubtypes :: (a -> String) -> Subtypes a -> String
strSubtypes f (Subtypes ss)
  | length ss == 0 = ""
  | otherwise = " (" ++ List.intercalate " | " (map (strSubtype f) ss) ++ ")"

strSubtype :: (a -> String) -> Subtype a -> String
strSubtype f = \case
  SubtypeSingleValue a -> f a
  SubtypeValueRange lo hi -> f lo ++ " .. " ++ f hi

makeTag :: TagClass -> Int -> Tag
makeTag = Tag

sequence :: [Field a] -> AsnEncoding a
sequence = EncSequence

sequenceOf :: Foldable f => AsnEncoding a -> AsnEncoding (f a)
sequenceOf = EncSequenceOf toList

choice :: [a] -> (a -> ValueAndEncoding) -> AsnEncoding a
choice xs f = EncChoice (Choice id xs f)

option :: Int -> OptionName -> b -> AsnEncoding b -> ValueAndEncoding
option = ValueAndEncoding

tag :: TagClass -> Int -> Explicitness -> AsnEncoding a -> AsnEncoding a
tag c n e = EncRetag (TagAndExplicitness (Tag c n) e)

implicitTag :: Tag -> AsnEncoding a -> AsnEncoding a
implicitTag t = EncRetag (TagAndExplicitness t Implicit)

required :: FieldName -> (a -> b) -> AsnEncoding b -> Field a
required = FieldRequired

optional :: FieldName -> (a -> Maybe b) -> AsnEncoding b -> Field a
optional = FieldOptional

defaulted :: (Eq b, Show b) => FieldName -> (a -> b) -> AsnEncoding b -> b -> Field a
defaulted name getVal enc defVal = FieldDefaulted name getVal defVal show (==) enc

objectIdentifier :: AsnEncoding ObjectIdentifier
objectIdentifier = EncUniversalValue (UniversalValueObjectIdentifier id mempty)

null :: AsnEncoding ()
null = null'

-- | Anything can be encoded as @NULL@ by simply discarding it. Typically,
--   encoding a type with more than one inhabitant as @NULL@ is a mistake,
--   so the more restrictive 'null' is to be preferred.
null' :: AsnEncoding a
null' = EncUniversalValue UniversalValueNull

integer :: AsnEncoding Integer
integer = EncUniversalValue (UniversalValueInteger id mempty)

integerRanged :: Integer -> Integer -> AsnEncoding Integer
integerRanged lo hi = EncUniversalValue
  (UniversalValueInteger id (Subtypes [SubtypeValueRange lo hi]))

word32 :: AsnEncoding Word32
word32 = EncUniversalValue (UniversalValueInteger fromIntegral (Subtypes [SubtypeValueRange 0 4294967295]))

word64 :: AsnEncoding Word64
word64 = EncUniversalValue (UniversalValueInteger fromIntegral (Subtypes [SubtypeValueRange 0 18446744073709551615]))

-- TODO: add a size subtype to this
octetStringWord32 :: AsnEncoding Word32
octetStringWord32 = EncUniversalValue (UniversalValueOctetString (LB.toStrict . Builder.toLazyByteString . Builder.word32BE) mempty)

octetStringWord8 :: AsnEncoding Word8
octetStringWord8 = EncUniversalValue 
  ( UniversalValueOctetString 
    ByteString.singleton
    mempty
  )

int32 :: AsnEncoding Int32
int32 = EncUniversalValue (UniversalValueInteger fromIntegral (Subtypes [SubtypeValueRange (-2147483648) 2147483647]))

word :: AsnEncoding Word
word = EncUniversalValue (UniversalValueInteger fromIntegral (Subtypes [SubtypeValueRange 0 (fromIntegral (maxBound :: Word))]))

int :: AsnEncoding Int
int = EncUniversalValue (UniversalValueInteger fromIntegral (Subtypes [SubtypeValueRange (fromIntegral (minBound :: Int)) (fromIntegral (maxBound :: Int))]))

octetString :: AsnEncoding ByteString
octetString = EncUniversalValue (UniversalValueOctetString id mempty)

utf8String :: AsnEncoding Text
utf8String = EncUniversalValue (UniversalValueTextualString Utf8String id mempty mempty)

universalValueTag :: UniversalValue a -> Int
universalValueTag = \case
  UniversalValueOctetString _ _ -> 4
  UniversalValueBoolean _ _ -> 1
  UniversalValueInteger _ _ -> 2
  UniversalValueNull -> 5
  UniversalValueObjectIdentifier _ _ -> 6
  UniversalValueTextualString typ _ _ _ -> tagNumStringType typ

-- For DER, which is what is actually targetted by this file,
-- I think that this is always Primitive.
univsersalValueConstruction :: UniversalValue a -> Construction
univsersalValueConstruction = \case
  UniversalValueOctetString _ _ -> Primitive
  UniversalValueBoolean _ _ -> Primitive
  UniversalValueInteger _ _ -> Primitive
  UniversalValueNull -> Primitive
  UniversalValueTextualString _ _ _ _ -> Primitive
  UniversalValueObjectIdentifier _ _ -> Primitive

-- | The ByteString that accompanies the tag does not
--   include its own length.
encodeBerInternal :: AsnEncoding a -> a -> TaggedByteString
encodeBerInternal x a = case x of
  EncRetag (TagAndExplicitness outerTag explicitness) e ->
    let TaggedByteString construction innerTag lbs = encodeBerInternal e a
     in case explicitness of
          Implicit -> TaggedByteString construction outerTag lbs
          Explicit -> TaggedByteString Constructed outerTag (encodeTaggedByteString (TaggedByteString construction innerTag lbs))
  EncUniversalValue p -> TaggedByteString (univsersalValueConstruction p) (makeTag Universal (universalValueTag p)) (encodePrimitiveBer p a)
  EncChoice (Choice conv _ f) -> case f (conv a) of
    ValueAndEncoding _ _ b enc2 -> encodeBerInternal enc2 b
  EncSequence fields -> TaggedByteString Constructed sequenceTag (foldMap (encodeField a) fields)
  -- It's kind of weird that sequence and sequence-of share the same tag,
  -- but hey, that's how the committee designed it.
  EncSequenceOf listify e -> TaggedByteString Constructed sequenceTag
    (foldMap (encodeTaggedByteString . encodeBerInternal e) (listify a))

-- Factor out some of the encoding stuff here into another function
encodeField :: a -> Field a -> LB.ByteString
encodeField a = \case
  FieldRequired _ func enc -> encodeTaggedByteString (encodeBerInternal enc (func a))
  FieldDefaulted _ func defVal _ eqVal enc ->
    let val = func a
     in if eqVal defVal val
          then mempty
          else encodeTaggedByteString (encodeBerInternal enc val)
  FieldOptional _ mfunc enc -> case mfunc a of
    Nothing -> mempty
    Just v -> encodeTaggedByteString (encodeBerInternal enc v)

encodeTaggedByteString :: TaggedByteString -> LB.ByteString
encodeTaggedByteString (TaggedByteString construction theTag lbs) =
  encodeTag construction theTag <> encodeLength (LB.length lbs) <> lbs

encodeTag :: Construction -> Tag -> LB.ByteString
encodeTag c (Tag tclass tnum)
  | tnum < 31 = LB.singleton (firstThreeBits .|. intToWord8 tnum)
  | otherwise = error "tag number above 30: write this"
  where
  !firstThreeBits = constructionBit c .|. tagClassBit tclass

encodeLength :: Int64 -> LB.ByteString
encodeLength x
  | x < 128 = LB.singleton (int64ToWord8 x)
  | otherwise =
      let totalOctets = fromIntegral (int64Log256 x + 1) :: Word8
       in LB.singleton (128 .|. totalOctets)
          <> lengthBE (fromIntegral x)

int64Log256 :: Int64 -> Int
int64Log256 x = unsafeShiftR (int64Log2 x) 3

int64Log2 :: Int64 -> Int
int64Log2 x = finiteBitSize x - 1 - countLeadingZeros x

int64ToWord8 :: Int64 -> Word8
int64ToWord8 = fromIntegral
{-# INLINE int64ToWord8 #-}

intToWord8 :: Int -> Word8
intToWord8 = fromIntegral
{-# INLINE intToWord8 #-}

encodePrimitiveBer :: UniversalValue a -> a -> LB.ByteString
encodePrimitiveBer p x = case p of
  UniversalValueTextualString typ f _ _ -> LB.fromStrict (encodeText typ (f x))
  UniversalValueOctetString f _ -> LB.fromStrict (f x)
  UniversalValueObjectIdentifier f _ -> oidBE (f x)
  UniversalValueBoolean f _ -> case f x of
    True -> LB.singleton 1
    False -> LB.singleton 0
  UniversalValueInteger f _ -> integerBE (f x)
  UniversalValueNull -> LB.empty

encodeText :: StringType -> Text -> ByteString
encodeText x t = case x of
  Utf8String -> TE.encodeUtf8 t
  _ -> error "encodeText: handle more ASN.1 string types"

lengthBE :: Int64 -> LB.ByteString
lengthBE i = if i > 0
  then Builder.toLazyByteString (goPos i)
  else error "lengthBE: handle the negative case"
  where
  goPos :: Int64 -> Builder
  goPos n1 = if n1 == 0
    then mempty
    else let (!n2,!byteVal) = quotRem n1 256
          in goPos n2 <> Builder.word8 (fromIntegral byteVal)

integerBE :: Integer -> LB.ByteString
integerBE i
  | i < 128 && i > (-129) = Builder.toLazyByteString (Builder.int8 (fromIntegral i))
  | otherwise = if i > 0
      then let lb = Builder.toLazyByteString (goPos i)
            in if LB.head lb > 127 then LB.cons 0 lb else lb
      else error "integerBE: handle the negative case"
  where
  goPos :: Integer -> Builder
  goPos n1 = if n1 == 0
    then mempty
    else let (!n2,!byteVal) = quotRem n1 256
          in goPos n2 <> Builder.word8 (fromIntegral byteVal)

oidBE :: ObjectIdentifier -> LB.ByteString
oidBE (ObjectIdentifier nums1)
  | sz > 2 =
      let !n1 = PM.indexPrimArray nums1 0
          !n2 = PM.indexPrimArray nums1 1
          -- !nums2 = Vector.unsafeDrop 2 nums1
          !firstOctet = fromIntegral n1 * 40 + fromIntegral n2 :: Word8
       in Builder.toLazyByteString (Builder.word8 firstOctet <> foldMapPrimArrayFromTo 2 sz multiByteBase127Encoding nums1)
  | otherwise = error "oidBE: OID with less than 3 identifiers"
  where
  sz = PM.sizeofPrimArray nums1

foldMapPrimArrayFromTo :: forall a b. (Prim a, Monoid b) => Int -> Int -> (a -> b) -> PrimArray a -> b
foldMapPrimArrayFromTo !start !end f !arr = go start where
  go !i
    | end > i = mappend (f (PM.indexPrimArray arr i)) (go (i+1))
    | otherwise = mempty

-- This function works fine on any integral type.
multiByteBase127Encoding :: Word -> Builder
multiByteBase127Encoding i0 =
  let (!i1,!byteVal) = quotRem i0 128
   in go i1 <> Builder.word8 (fromIntegral byteVal)
  where
  go n1 = if n1 == 0
    then mempty
    else let (!n2,!byteVal) = quotRem n1 128
          in go n2 <> Builder.word8 (128 .|. fromIntegral byteVal)
