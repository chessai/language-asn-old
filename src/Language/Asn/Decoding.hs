{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}

{-# OPTIONS_GHC -Wall #-}

module Language.Asn.Decoding
  ( ber
  , sequence
  , sequenceOf
  , required
  , optional
  , defaulted
  , utf8String
  , integer
  , integerRanged
  , int32
  , int
  , word32
  , word64
  , null
  , null'
  , octetString
  , octetStringWord8
  , octetStringWord32
  , objectIdentifier
  , choice
  , option
  , tag
  , mapFailable
  ) where

import Prelude hiding (sequence,null)
import Language.Asn.Types.Internal
import Data.ByteString (ByteString)
import Data.Bits (Bits(..))
import Control.Monad hiding (sequence)
import Data.Maybe (fromMaybe, listToMaybe)
import Data.Text (Text)
import Data.Word (Word8, Word32, Word64)
import Data.Int (Int32)
import Data.Functor.Identity (Identity(..))
import Text.Printf (printf)
import qualified GHC.Exts as E
import qualified Data.Text.Encoding as TE
import qualified Data.List as List
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as BSU

ber :: AsnDecoding a -> ByteString -> Either String a
ber d bs = requireNoLeftovers =<< decodeBerInternal d Nothing bs

sequence :: FieldDecoding a -> AsnDecoding a
sequence = AsnDecodingSequence

sequenceOf :: AsnDecoding a -> AsnDecoding [a]
sequenceOf = AsnDecodingSequenceOf id

required :: FieldName -> AsnDecoding a -> FieldDecoding a
required name d = FieldDecoding (liftAp (FieldDecodingRequired name d))

optional :: FieldName -> AsnDecoding a -> FieldDecoding (Maybe a)
optional name d = FieldDecoding (liftAp (FieldDecodingOptional name d id))

defaulted :: Show a => FieldName -> AsnDecoding a -> a -> FieldDecoding a
defaulted name d defVal = FieldDecoding (liftAp (FieldDecodingDefault name d defVal show))

choice :: [OptionDecoding a] -> AsnDecoding a
choice = AsnDecodingChoice

option :: OptionName -> AsnDecoding a -> OptionDecoding a
option = OptionDecoding

tag :: TagClass -> Int -> Explicitness -> AsnDecoding a -> AsnDecoding a
tag c n e = AsnDecodingRetag (TagAndExplicitness (Tag c n) e)

utf8String :: AsnDecoding Text
utf8String = AsnDecodingUniversal $ UniverseDecodingTextualString Utf8String id (Subtypes []) (Subtypes [])

octetString :: AsnDecoding ByteString
octetString = AsnDecodingUniversal $ UniverseDecodingOctetString id (Subtypes [])

octetStringWord32 :: AsnDecoding Word32
octetStringWord32 = mapFailable
  ( \bs -> if ByteString.length bs == 4
      then Right $ (fromIntegral :: Word -> Word32)
         $ unsafeShiftL 24 (fromIntegral (BSU.unsafeIndex bs 0))
         + unsafeShiftL 16 (fromIntegral (BSU.unsafeIndex bs 1))
         + unsafeShiftL 8 (fromIntegral (BSU.unsafeIndex bs 2))
         + fromIntegral (BSU.unsafeIndex bs 3)
      else Left "octetStringWord32 expects the octet string to have exactly 4 bytes"
  ) octetString

octetStringWord8 :: AsnDecoding Word8
octetStringWord8 = mapFailable
  ( \bs -> if ByteString.length bs == 1
      then Right (BSU.unsafeIndex bs 0)
      else Left "octetStringWord8 expects the octet string to have exactly 1 byte"
  ) octetString

integer :: AsnDecoding Integer
integer = AsnDecodingUniversal (UniverseDecodingInteger id (Subtypes []))

-- This could be improved by making sure that integer in question is actually
-- in the provided bounds.
int :: AsnDecoding Int
int = AsnDecodingUniversal (UniverseDecodingInteger fromIntegral (Subtypes []))

-- This could be improved by making sure that integer in question is actually
-- in the provided bounds.
int32 :: AsnDecoding Int32
int32 = AsnDecodingUniversal (UniverseDecodingInteger fromIntegral (Subtypes []))

-- This could be improved by making sure that integer in question is actually
-- in the provided bounds.
word32 :: AsnDecoding Word32
word32 = AsnDecodingUniversal (UniverseDecodingInteger fromIntegral (Subtypes []))

-- This could be improved by making sure that integer in question is actually
-- in the provided bounds.
word64 :: AsnDecoding Word64
word64 = AsnDecodingUniversal (UniverseDecodingInteger fromIntegral (Subtypes []))

null :: AsnDecoding ()
null = AsnDecodingUniversal (UniverseDecodingNull ())

null' :: a -> AsnDecoding a
null' = AsnDecodingUniversal . UniverseDecodingNull

objectIdentifier :: AsnDecoding ObjectIdentifier
objectIdentifier = AsnDecodingUniversal (UniverseDecodingObjectIdentifier id (Subtypes []))

integerRanged :: Integer -> Integer -> AsnDecoding Integer
integerRanged lo hi = AsnDecodingUniversal
  (UniverseDecodingInteger id (Subtypes [SubtypeValueRange lo hi]))

mapFailable :: (a -> Either String b) -> AsnDecoding a -> AsnDecoding b
mapFailable f d = AsnDecodingConversion d f

repeatUntilEmpty :: Monad m => (ByteString -> m (a,ByteString)) -> ByteString -> m [a]
repeatUntilEmpty f = go where
  go bs1 = do
    (a,bs2) <- f bs1
    if ByteString.null bs2
      then return [a]
      else fmap (a:) (go bs2)

decodeBerInternal :: AsnDecoding a -> Maybe Tag -> ByteString -> Either String (a,ByteString)
decodeBerInternal x overrideTag bs1 = case x of
  AsnDecodingUniversal u -> do
    (bsContent,bsRemainder) <- takeTagAndLength Primitive (Tag Universal (universeDecodingTagNumber u))
    a <- decodeUniversal u bsContent
    return (a,bsRemainder)
  AsnDecodingRetag (TagAndExplicitness newTag expl) nextDecoding -> case expl of
    Implicit -> decodeBerInternal nextDecoding (Just $ fromMaybe newTag overrideTag) bs1
    Explicit -> do
      (bsContent,bsRemainder) <- takeTagAndLength Constructed newTag
      a <- requireNoLeftovers =<< decodeBerInternal nextDecoding Nothing bsContent
      return (a,bsRemainder)
  AsnDecodingSequence (FieldDecoding fieldDecoding) -> do
    (bsContent,bsRemainder) <- takeTagAndLength Constructed sequenceTag
    a <- requireNoLeftovers =<< getDecodePart (runAp decodeField fieldDecoding) bsContent
    return (a,bsRemainder)
  AsnDecodingSequenceOf f nextDecoding -> do
    (bsContent,bsRemainder) <- takeTagAndLength Constructed sequenceTag
    cs <- repeatUntilEmpty (decodeBerInternal nextDecoding Nothing) bsContent
    return (f cs,bsRemainder)
  AsnDecodingConversion nextDecoding conv -> do
    (b,bs2) <- decodeBerInternal nextDecoding overrideTag bs1
    a <- conv b
    return (a,bs2)
  -- Note: overrideTag is currently ignored in this case. Per
  -- ASN.1 rules, you cannot put an IMPLICIT tag over a CHOICE,
  -- which is the only thing that could cause this to happen.
  -- Still, I don't like that it's being ignored.
  AsnDecodingChoice opts -> case ByteString.uncons bs1 of
    Nothing -> Left "while trying to decode Choice tag, ran out of input"
    Just (b,bs2) -> do
      let possibilities = nextExpectedTags =<< map (\(OptionDecoding _ d) -> d) opts
          theTagNumberPrefix = b .&. 31
      (theTagNumber,_) <- decipherTagNumber theTagNumberPrefix bs2
      let mmatched = listToMaybe $ List.filter
            (\((Tag tc tn,cstn),_) -> b .&. 192 == tagClassBit tc && b .&. 32 == constructionBit cstn && tn == theTagNumber)
            possibilities
      case mmatched of
        Nothing -> Left $ concat 
          [ "while trying to decode Choice tag, the tag did not match any of the expected tags: found "
          , show theTagNumber
          , " but expected one of ["
          , List.intercalate "," $ flip map possibilities $ \((Tag tc tn, cstn),_) -> concat
              [ show tc
              , " "
              , show cstn
              , " "
              , show tn
              ]
          , "]"
          ]
        Just (_,Wrapper chosenDecoder conv2) -> do
          (c,bs3) <- decodeBerInternal chosenDecoder Nothing bs1
          r <- conv2 c
          Right (r,bs3)
  where
  takeTagAndLength :: Construction -> Tag -> Either String (ByteString,ByteString)
  takeTagAndLength construction t1 = do
    let tagToUse = fromMaybe t1 overrideTag
    bs2 <- expectTag construction tagToUse bs1
    (len,bs3) <- takeLength bs2
    splitOrFail len bs3

data Wrapper a = forall b. Wrapper (AsnDecoding b) (b -> Either String a)

idWrapper :: AsnDecoding a -> Wrapper a
idWrapper d = Wrapper d Right

nextExpectedTags :: AsnDecoding a -> [((Tag,Construction), Wrapper a)]
nextExpectedTags x = case x of
  AsnDecodingUniversal u -> [((Tag Universal (universeDecodingTagNumber u), Primitive),idWrapper x)]
  AsnDecodingSequenceOf _ _ -> [((sequenceTag, Constructed),idWrapper x)]
  AsnDecodingSequence _ -> [((sequenceTag, Constructed),idWrapper x)]
  AsnDecodingChoice opts -> join (map (\(OptionDecoding _ theDec) -> nextExpectedTags theDec) opts)
  AsnDecodingRetag (TagAndExplicitness newTag expl) nextDecoding -> case expl of
    Explicit -> [((newTag,Constructed),idWrapper x)]
    Implicit -> map (\((_,c),Wrapper theDec theConv) -> ((newTag,c), Wrapper (AsnDecodingRetag (TagAndExplicitness newTag expl) theDec) theConv)) (nextExpectedTags nextDecoding)
  AsnDecodingConversion nextDecoding conv ->
    map (\((t,c),Wrapper theDec theConv) -> ((t,c),Wrapper theDec (theConv >=> conv))) (nextExpectedTags nextDecoding)

decodeField :: FieldDecodingPart a -> DecodePart a
decodeField x = case x of
  FieldDecodingRequired _ d -> DecodePart (decodeBerInternal d Nothing)
  FieldDecodingOptional _ d conv1 -> handlePossiblyMissingField d conv1
  FieldDecodingDefault _ d a _ -> handlePossiblyMissingField d (fromMaybe a)

handlePossiblyMissingField :: AsnDecoding b -> (Maybe b -> a) -> DecodePart a
handlePossiblyMissingField d conv1 = DecodePart $ \bs1 -> case ByteString.uncons bs1 of
  Nothing -> Right (conv1 Nothing, bs1)
  Just (b,bs2) -> do
    let possibilities = nextExpectedTags d
        theTagNumberPrefix = b .&. 31
    (theTagNumber,_) <- decipherTagNumber theTagNumberPrefix bs2
    let mmatched = listToMaybe $ List.filter
          (\((Tag tc tn,cstn),_) -> b .&. 192 == tagClassBit tc && b .&. 32 == constructionBit cstn && tn == theTagNumber) possibilities
    case mmatched of
      Nothing -> Right (conv1 Nothing, bs1)
      Just (_,Wrapper chosenDecoder conv2) -> do
        (c,bs3) <- decodeBerInternal chosenDecoder Nothing bs1
        r <- conv2 c
        Right (conv1 (Just r),bs3)

-- The first argument is the full tag byte
decipherTagNumber :: Word8 -> ByteString -> Either String (Int,ByteString)
decipherTagNumber w bs = do
  let tn = w .&. 31
  if tn < 31
    then Right (fromIntegral tn,bs)
    else error "decipherTagNumber: handle tags greater than 30"


requireNoLeftovers :: (a,ByteString) -> Either String a
requireNoLeftovers (a,bs) = if ByteString.null bs then Right a else Left "expected not to have leftovers, but there were leftovers"

expectTag :: Construction -> Tag -> ByteString -> Either String ByteString
expectTag construction (Tag tc tn) bs = case ByteString.uncons bs of
  Nothing -> Left "expected a byte for the Tag but the ByteString was empty"
  Just (b,bsNext) -> do
    let expectedTagBits = tagClassBit tc
        actualTagBits = b .&. 192
    when (actualTagBits /= expectedTagBits)
      $ Left $ "while parsing the tag, the tag class bits did not match: "
            ++ "found " ++ printf "%08b" actualTagBits ++ " but expected "
            ++ printf "%08b" expectedTagBits ++ " (" ++ show tc ++ ")"
    when (b .&. 32 /= constructionBit construction) $ Left "while parsing the tag, the construction bit did not match"
    if tn < 31
      then do
        when (b .&. 31 /= fromIntegral tn) $ Left "while parsing the tag, the tag number did not match what was expected"
        Right bsNext
      else error "expectTag: handle tag numbers higher than 30"

splitOrFail :: Int -> ByteString -> Either String (ByteString,ByteString)
splitOrFail i bs = if i > ByteString.length bs
  then Left "tried to take a fixed number of bytes as specified by the encoding, but bytestring ended"
  else Right (ByteString.splitAt i bs)

takeLength :: ByteString -> Either String (Int,ByteString)
takeLength bs1 = case ByteString.uncons bs1 of
  Nothing -> Left "while trying to decode the length, expected an initial octet but the bytestring ended"
  Just (b,bs2) -> if b < 128
    then Right (fromIntegral b, bs2)
    else let bytesToTake = fromIntegral (127 .&. b) in
      if ByteString.length bs2 < bytesToTake
        then Left "while decoding multi-byte length, ran out of bytes"
        else let (bs3,bs4) = ByteString.splitAt bytesToTake bs2 in Right (parseLength bs3, bs4)


parseLength :: ByteString -> Int
parseLength = ByteString.foldl' (\i w8 -> i * 256 + fromIntegral w8) 0

-- This currently does the wrong thing for negative numbers
parseInteger :: ByteString -> Integer
parseInteger = ByteString.foldl' (\i w8 -> i * 256 + fromIntegral w8) 0

decodeUniversal :: UniverseDecoding a -> ByteString -> Either String a
decodeUniversal x bs = case x of
  UniverseDecodingInteger f _ -> Right (f (parseInteger bs))
  UniverseDecodingTextualString _ f _ _ -> case TE.decodeUtf8' bs of
    Left _ -> Left "while decoding string primitive, found that UTF8-encoding was not used"
    Right t -> Right (f t)
  UniverseDecodingObjectIdentifier f _ -> fmap f (stepOidAll bs)
  UniverseDecodingOctetString f _ -> Right (f bs)
  UniverseDecodingNull a -> Right a

stepOidAll :: ByteString -> Either String ObjectIdentifier
stepOidAll bs1 = case ByteString.uncons bs1 of
  Nothing -> Left "while decoding OID, found no bytes, the OID should have at least one octet"
  Just (b,bs2) ->
    let (w1,w2) = quotRem b 40
        Identity nums = repeatUntilEmpty (Identity . stepOid 0) bs2
     in Right (ObjectIdentifier (E.fromList $ fromIntegral w1 : fromIntegral w2 : nums))

stepOid :: Word -> ByteString -> (Word,ByteString)
stepOid !i bs1 = case ByteString.uncons bs1 of
  Nothing -> (i,bs1)
  Just (w,bs2) ->
    let !acc = i * 128 + fromIntegral (w .&. 127) in
    if w .&. 128 == 128
      then stepOid acc bs2
      else (acc,bs2)

universeDecodingTagNumber :: UniverseDecoding a -> Int
universeDecodingTagNumber x = case x of
  UniverseDecodingInteger _ _ -> 2
  UniverseDecodingTextualString typ _ _ _ -> tagNumStringType typ
  UniverseDecodingObjectIdentifier _ _ -> 6
  UniverseDecodingOctetString _ _ -> 4
  UniverseDecodingNull _ -> 5



