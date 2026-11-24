{-# LANGUAGE UndecidableInstances #-}

module Types.Shared where

import Data.Aeson
import GHC.Generics (Generic, Rep)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Word (Word64)
import Data.Char (isAsciiLower, isAsciiUpper, isDigit)
import Control.Monad (guard)

-- TODO: Why Word64?
data VersionNumber = VersionNumber
  { x :: Word64
  , y :: Word64
  , z :: Word64
  }
  deriving stock (Eq, Ord, Show)

instance FromJSON VersionNumber where
  parseJSON = withText "Version" $ \text ->
    case parseVersionNumber text of
      Just versionNumber -> pure versionNumber
      _ -> fail $ "expected a version in the form x.y.z, got: " <> Text.unpack text -- FIXME: is this error reporting good enough?

parseVersionNumber :: Text -> Maybe VersionNumber
parseVersionNumber text =
  case traverse parseDecimal (Text.splitOn "." text) of
    Just [major, minor, patch] -> Just (VersionNumber major minor patch)
    _ -> Nothing

parseDecimal :: Text -> Maybe Word64
parseDecimal digits
  | Text.null digits || not (Text.all isDigit digits) = Nothing
  | Text.length digits > 1 && "0" `Text.isPrefixOf` digits = Nothing
  | otherwise =
      let number = read (Text.unpack digits) :: Integer
       in if number <= toInteger (maxBound :: Word64) then Just (fromInteger number) else Nothing

instance ToJSON VersionNumber where
  toJSON = toJSON . renderVersionNumber
  toEncoding = toEncoding . renderVersionNumber

renderVersionNumber :: VersionNumber -> Text
renderVersionNumber (VersionNumber major minor patch) =
  Text.intercalate "." (map (Text.pack . show) [major, minor, patch])

data LfVersion = LfVersion
  { major :: Word64
  , minor :: LfMinorVersion
  }
  deriving stock (Eq, Show)

data LfMinorVersion = StableMinor Word64 | DevMinor
  deriving stock (Eq, Show)

parseLfMinorVersion :: Text -> Maybe LfMinorVersion
parseLfMinorVersion = \case
  "dev" -> Just DevMinor
  text -> StableMinor <$> parseDecimal text

renderLfVersion :: LfVersion -> Text
renderLfVersion version =
  Text.pack (show version.major) <> "." <> case version.minor of
    StableMinor number -> Text.pack (show number)
    DevMinor -> "dev"

instance FromJSON LfVersion where
  parseJSON = withText "LfVersion" $ \text ->
    maybe (fail ("expected an LF version such as 2.1, got: " <> Text.unpack text)) pure $
      case Text.splitOn "." text of
        [majorText, minorText] -> LfVersion <$> parseDecimal majorText <*> parseLfMinorVersion minorText
        _ -> Nothing

instance ToJSON LfVersion where
  toJSON = toJSON . renderLfVersion
  toEncoding = toEncoding . renderLfVersion

-- | A package name in the format that damlc accepts in @daml.yaml@: one or
-- more segments separated by @-@. Each segment is an ASCII letter followed by
-- zero or more ASCII letters and digits. The Daml-LF limit of 255 characters
-- applies to the full name.
newtype PackageName = PackageName Text
  deriving stock (Eq, Ord, Show)
  deriving newtype (ToJSON)

instance FromJSON PackageName where
  parseJSON = withText "PackageName" $ \text ->
    maybe (fail ("invalid package name: " <> Text.unpack text)) pure (parsePackageName text)

parsePackageName :: Text -> Maybe PackageName
parsePackageName text =
  let isAsciiLetter character = isAsciiUpper character || isAsciiLower character
      isValidSegment segment = case Text.uncons segment of
        Just (firstCharacter, otherCharacters) ->
          isAsciiLetter firstCharacter
            && Text.all (\character -> isAsciiLetter character || isDigit character) otherCharacters
        Nothing -> False
  in if Text.length text <= 255 && all isValidSegment (Text.splitOn "-" text)
     then Just (PackageName text)
     else Nothing

-- TODO: Rename 'ProviderId'?
-- | The provider of a package, and the name of an identity of the identity
-- repository: publishers and auditors are both identities.
newtype ProviderId = ProviderId Text
  deriving stock (Eq, Ord, Show)
  deriving newtype (ToJSON, ToJSONKey)

instance FromJSON ProviderId where
  parseJSON = withText "ProviderId" $ \text ->
    maybe (fail ("invalid provider: " <> Text.unpack text)) pure (parseProviderId text)

instance FromJSONKey ProviderId where
  fromJSONKey = FromJSONKeyTextParser $ \text ->
    maybe (fail ("invalid provider: " <> Text.unpack text)) pure (parseProviderId text)

-- | A 'ProviderId' if the text is a path component of an OCI repository name,
-- in the grammar of the OCI distribution specification:
-- @[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*@. The provider is a component of the OCI
-- repository name of each of its DARs.
parseProviderId :: Text -> Maybe ProviderId
parseProviderId text =
  ProviderId text <$ guard isRepositoryNameComponent
  where
    isLowerAlphanumeric character = isAsciiLower character || isDigit character
    runs = Text.groupBy (\left right -> isLowerAlphanumeric left == isLowerAlphanumeric right) text
    isAlphanumericRun = Text.all isLowerAlphanumeric
    isSeparatorRun characterRun = characterRun `elem` [".", "_", "__"] || Text.all (== '-') characterRun
    isRepositoryNameComponent = case (runs, reverse runs) of
      (firstRun : _, lastRun : _) ->
        isAlphanumericRun firstRun
          && isAlphanumericRun lastRun
          && all (\characterRun -> isAlphanumericRun characterRun || isSeparatorRun characterRun) runs
      _ -> False

newtype Category = Category Text
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

-- | A Daml-LF package id: the SHA-256 of the DALF's @ArchivePayload@ bytes, in
-- lowercase hexadecimal.
--
-- This is the spelling that @damlc inspect-dar@, the index, the upload
-- metadata and the DAR annotations use.
newtype PackageId = PackageId Text
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON, FromJSONKey, ToJSONKey)

renderPackageId :: PackageId -> Text
renderPackageId (PackageId text) = text

jsonOptions :: Options
jsonOptions =
  defaultOptions
    { fieldLabelModifier = camelTo2 '-'
    , rejectUnknownFields = True
    , omitNothingFields = True
    }

-- | The generic aeson instances with 'jsonOptions', for
-- @deriving (FromJSON, ToJSON) via WithJsonOptions T@.
newtype WithJsonOptions a = WithJsonOptions a

instance (Generic a, GFromJSON Zero (Rep a)) => FromJSON (WithJsonOptions a) where
  parseJSON = fmap WithJsonOptions . genericParseJSON jsonOptions

instance (Generic a, GToJSON Zero (Rep a), GToEncoding Zero (Rep a)) => ToJSON (WithJsonOptions a) where
  toJSON (WithJsonOptions value) = genericToJSON jsonOptions value
  toEncoding (WithJsonOptions value) = genericToEncoding jsonOptions value

-- Crypto types

-- | An ASCII-armored OpenPGP public key block, as @gpg --export --armor@
-- writes it and as @identities\/\<id\>\/\<FINGERPRINT\>\/key.asc@ holds it in
-- the identity repository.
--
-- The value is the armored text, not a parsed key: gpg parses the key (see
-- 'Signature').
newtype PublicKey = PublicKey Text
  deriving stock (Eq, Ord, Show)
  deriving newtype (ToJSON)

instance FromJSON PublicKey where
  parseJSON = withText "PublicKey" $ \text ->
    maybe (fail "expected an ASCII-armored OpenPGP public key block") pure (parsePublicKey text)

parsePublicKey :: Text -> Maybe PublicKey
parsePublicKey text =
  PublicKey text <$ guard (armoredPublicKeyHeader `Text.isPrefixOf` Text.stripStart text)

-- | The first line of the block that @gpg --export --armor@ writes.
armoredPublicKeyHeader :: Text
armoredPublicKeyHeader = "-----BEGIN PGP PUBLIC KEY BLOCK-----"

-- | A SHA-256 digest in the OCI spelling: @sha256:@ and 64 lowercase
-- hexadecimal characters. @Oci.Image.sha256Digest@ returns this spelling, and
-- an @oci-reference@ contains it after its @\@@.
--
-- Uppercase is rejected and not converted to lowercase, because 'Eq' and
-- 'Ord' compare the text. A digest in uppercase would not be equal to the
-- digest that the server computes for the same DAR, for example when
-- 'Types.Index.withAudits' looks up the audit reports of a DAR.
newtype Sha256 = Sha256 Text
  deriving stock (Eq, Ord, Show)
  deriving newtype (ToJSON)

instance FromJSON Sha256 where
  parseJSON = withText "Sha256" $ \text ->
    maybe (fail ("invalid sha256 digest: " <> Text.unpack text)) pure (parseSha256 text)

parseSha256 :: Text -> Maybe Sha256
parseSha256 text = Sha256 text <$ guard (isSha256 text)

isSha256 :: Text -> Bool
isSha256 text = case Text.stripPrefix "sha256:" text of
  Just hexadecimal ->
    Text.length hexadecimal == 64
      && Text.all (\character -> isDigit character || (isAsciiLower character && character <= 'f')) hexadecimal
  Nothing -> False

newtype DarDigest = DarDigest Sha256
  deriving stock (Eq, Ord, Show)
  deriving newtype (ToJSON, FromJSON)

newtype SourceDigest = SourceDigest Sha256
  deriving stock (Eq, Ord, Show)
  deriving newtype (ToJSON, FromJSON)

-- | A git commit hash, as @git rev-parse@ prints it. Its format is not
-- checked, because the code only shows it and compares it for equality.
newtype CommitHash = CommitHash Text
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)
