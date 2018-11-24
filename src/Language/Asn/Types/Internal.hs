{-# LANGUAGE CPP #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DeriveGeneric #-}

{-# OPTIONS_GHC -Wall #-}

module Language.Asn.Types.Internal where

import Prelude hiding (sequence,null)
import Data.String (IsString)
import Data.ByteString (ByteString)
import Data.Text (Text)
#if !MIN_VERSION_base(4,11,0)
import Data.Monoid (Monoid)
#endif
import Data.Semigroup (Semigroup)
import Data.Word
import Data.Primitive (PrimArray)
import GHC.Int (Int(..))
import Data.Hashable (Hashable(..))
import GHC.Generics (Generic)
import Data.Functor.Contravariant (Contravariant(..))
import qualified Data.ByteString.Lazy as LB
import qualified GHC.Exts as E

data AsnEncoding a
  = EncSequence [Field a]
  | forall b. EncSequenceOf (a -> [b]) (AsnEncoding b)
  | EncChoice (Choice a)
  | EncRetag TagAndExplicitness (AsnEncoding a)
  | EncUniversalValue (UniversalValue a)

instance Contravariant AsnEncoding where
  contramap f x = case x of
    EncRetag te y -> EncRetag te (contramap f y)
    EncUniversalValue u -> EncUniversalValue (contramap f u)
    EncSequence xs -> EncSequence (map (contramap f) xs)
    EncChoice c -> EncChoice (contramap f c)
    EncSequenceOf conv enc -> EncSequenceOf (conv . f) enc

data UniversalValue a
  = UniversalValueBoolean (a -> Bool) (Subtypes Bool)
  | UniversalValueInteger (a -> Integer) (Subtypes Integer)
  | UniversalValueNull
  | UniversalValueOctetString (a -> ByteString) (Subtypes ByteString)
  | UniversalValueTextualString StringType (a -> Text) (Subtypes Text) (Subtypes Char)
  | UniversalValueObjectIdentifier (a -> ObjectIdentifier) (Subtypes ObjectIdentifier)

instance Contravariant UniversalValue where
  contramap f x = case x of
    UniversalValueBoolean conv s -> UniversalValueBoolean (conv . f) s
    UniversalValueInteger conv s -> UniversalValueInteger (conv . f) s
    UniversalValueObjectIdentifier conv s -> UniversalValueObjectIdentifier (conv . f) s
    UniversalValueOctetString conv s -> UniversalValueOctetString (conv . f) s
    UniversalValueTextualString typ conv s1 s2 -> UniversalValueTextualString typ (conv . f) s1 s2
    UniversalValueNull -> UniversalValueNull

newtype Subtypes a = Subtypes { getSubtypes :: [Subtype a] }
  deriving (Semigroup,Monoid)

-- | Note: we deviate slightly from the actual definition of an object
-- identifier. Technically, each number of an OID should be allowed to
-- be an integer of unlimited size. However, we are intentionally unfaithful
-- to this specification because in practice, there are no OIDs that use
-- integers above a 32-bit word, so we just use the machine's native word
-- size.
newtype ObjectIdentifier = ObjectIdentifier
  { getObjectIdentifier :: PrimArray Word
  } deriving (Eq,Ord,Show,Generic)

instance Hashable ObjectIdentifier where
  hash (ObjectIdentifier v) = hash (E.toList v)
  hashWithSalt s (ObjectIdentifier v) = hashWithSalt s (E.toList v)

newtype ObjectIdentifierSuffix = ObjectIdentifierSuffix
  { getObjectIdentifierSuffix :: PrimArray Word
  } deriving (Eq,Ord,Show,Generic)

instance Hashable ObjectIdentifierSuffix where
  hash (ObjectIdentifierSuffix v) = hash (E.toList v)
  hashWithSalt s (ObjectIdentifierSuffix v) = hashWithSalt s (E.toList v)

data Subtype a
  = SubtypeSingleValue a -- This also acts as PermittedAlphabet
  | SubtypeValueRange a a

data StringType
  = Utf8String
  | NumericString
  | PrintableString
  | TeletexString
  | VideotexString
  | IA5String
  | GraphicString
  | VisibleString
  | GeneralString
  | UniversalString
  | CharacterString
  | BmpString

data Explicitness = Explicit | Implicit
data TagAndExplicitness = TagAndExplicitness Tag Explicitness

data Choice a = forall b. Choice (a -> b) [b] (b -> ValueAndEncoding)

instance Contravariant Choice where
  contramap f (Choice conv bs bToValEnc) =
    Choice (conv . f) bs bToValEnc

data ValueAndEncoding = forall b. ValueAndEncoding Int OptionName b (AsnEncoding b)
data Field a
  = forall b. FieldRequired FieldName (a -> b) (AsnEncoding b)
  | forall b. FieldOptional FieldName (a -> Maybe b) (AsnEncoding b)
  | forall b. FieldDefaulted FieldName (a -> b) b (b -> String) (b -> b -> Bool) (AsnEncoding b)

instance Contravariant Field where
  contramap f x = case x of
    FieldRequired name g enc -> FieldRequired name (g . f) enc
    FieldOptional name g enc -> FieldOptional name (g . f) enc
    FieldDefaulted name g b1 b2 b3 enc -> FieldDefaulted name (g . f) b1 b2 b3 enc

data TaggedByteString = TaggedByteString !Construction !Tag !LB.ByteString
data TaggedStrictByteString = TaggedStrictByteString !Construction !Tag !ByteString
data Construction = Constructed | Primitive
  deriving (Show,Eq)

newtype FieldName = FieldName { getFieldName :: String }
  deriving (IsString)
newtype OptionName = OptionName { getOptionName :: String }
  deriving (IsString)

data TagClass
  = Universal
  | Application
  | Private
  | ContextSpecific
  deriving (Show,Eq)

data Tag = Tag
  { tagClass :: TagClass
  , tagNumber :: Int
  } deriving (Show,Eq)

fromIntegerTagAndExplicitness :: Integer -> TagAndExplicitness
fromIntegerTagAndExplicitness n = TagAndExplicitness
  (Tag ContextSpecific (fromIntegral n))
  Explicit

fromIntegerTag :: Integer -> Tag
fromIntegerTag n = Tag ContextSpecific (fromIntegral n)

------------------------------
-- Stuff specific to decoding
------------------------------

data AsnDecoding a
  = AsnDecodingUniversal (UniverseDecoding a)
  | forall b. AsnDecodingSequenceOf ([b] -> a) (AsnDecoding b)
  | forall b. AsnDecodingConversion (AsnDecoding b) (b -> Either String a)
  | AsnDecodingRetag TagAndExplicitness (AsnDecoding a)
  | AsnDecodingSequence (FieldDecoding a)
  | AsnDecodingChoice [OptionDecoding a]

deriving instance Functor AsnDecoding

data Ap f a where
  Pure :: a -> Ap f a
  Ap :: f a -> Ap f (a -> b) -> Ap f b

instance Functor (Ap f) where
  fmap f (Pure a)   = Pure (f a)
  fmap f (Ap x y)   = Ap x ((f .) <$> y)

instance Applicative (Ap f) where
  pure = Pure
  Pure f <*> y = fmap f y
  Ap x y <*> z = Ap x (flip <$> y <*> z)

data OptionDecoding a = OptionDecoding OptionName (AsnDecoding a)
  deriving (Functor)

newtype FieldDecoding a = FieldDecoding (Ap FieldDecodingPart a)
  deriving (Functor,Applicative)

data FieldDecodingPart a
  = FieldDecodingRequired FieldName (AsnDecoding a)
  | FieldDecodingDefault FieldName (AsnDecoding a) a (a -> String)
  | forall b. FieldDecodingOptional FieldName (AsnDecoding b) (Maybe b -> a)

data UniverseDecoding a
  = UniverseDecodingInteger (Integer -> a) (Subtypes Integer)
  | UniverseDecodingTextualString StringType (Text -> a) (Subtypes Text) (Subtypes Char)
  | UniverseDecodingOctetString (ByteString -> a) (Subtypes ByteString)
  | UniverseDecodingObjectIdentifier (ObjectIdentifier -> a) (Subtypes ObjectIdentifier)
  | UniverseDecodingNull a
  deriving (Functor)

newtype DecodePart a = DecodePart { getDecodePart :: ByteString -> Either String (a,ByteString) }
  deriving (Functor)

instance Applicative DecodePart where
  pure a = DecodePart (\bs -> Right (a,bs))
  DecodePart f <*> DecodePart g = DecodePart $ \bs1 -> do
    (h,bs2) <- f bs1
    (a,bs3) <- g bs2
    return (h a, bs3)

runAp :: Applicative g => (forall x. f x -> g x) -> Ap f a -> g a
runAp _ (Pure x) = pure x
runAp u (Ap f x) = flip id <$> u f <*> runAp u x

liftAp :: f a -> Ap f a
liftAp x = Ap x (Pure id)
{-# INLINE liftAp #-}

--------------------------
-- Functions common to encoding and decoding
--------------------------

-- Bit six is 1 when a value is constructed.
constructionBit :: Construction -> Word8
constructionBit x = case x of
  Constructed -> 32
  Primitive -> 0

-- Controls upper two bits in the octet
tagClassBit :: TagClass -> Word8
tagClassBit x = case x of
  Universal -> 0
  Application -> 64
  ContextSpecific -> 128
  Private -> 192

sequenceTag :: Tag
sequenceTag = Tag Universal 16

tagNumStringType :: StringType -> Int
tagNumStringType x = case x of
  Utf8String -> 12
  NumericString -> 18
  PrintableString -> 19
  TeletexString -> 20
  VideotexString -> 21
  IA5String -> 22
  GraphicString -> 25
  VisibleString -> 26
  GeneralString -> 27
  UniversalString -> 28
  CharacterString -> 29
  BmpString -> 30
