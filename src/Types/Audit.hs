{-# LANGUAGE DerivingVia #-}

-- | The audit reports of the identity repository, and the result of reading
-- the repository.
--
-- @audits\/dars\/@ has one directory per DAR, named by the digest of the DAR
-- in hexadecimal without the @sha256:@ prefix, because Windows does not allow
-- @:@ in a file name:
--
-- > audits/
-- >     dars/
-- >         <dar-hash>/
-- >             <identity>-<date>.json
-- >             <identity>-<date>.json.sig
-- >             <identity>-<date>.revoke.json
-- >             <identity>-<date>.revoke.json.sig
--
-- The directory name and the file name are not signed, so they only locate the
-- files. The reports of a DAR are the reports whose 'darHash' is the digest of
-- the DAR, also when they are in the directory of another DAR. The file name
-- stem pairs a report with its signature and its audit revocation.

module Types.Audit where

import Data.Aeson
import Control.Monad (guard)
import Data.Char (isAsciiLower, isDigit)
import Data.Map.Strict (Map)
import Data.Text (Text)
import Data.Time (UTCTime)
import qualified Data.Text as Text
import GHC.Generics (Generic)
import Types.Identity (Fingerprint, Identity, KeyRevocation)
import Types.Shared (DarDigest, ProviderId, SourceDigest, WithJsonOptions (..), jsonOptions)

-- | The @audit-id@ of a report, a UUID. A revocation names the report that it
-- revokes by its audit-id.
newtype AuditId = AuditId Text
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

-- | The format of an audit report, from its @version@ field. 'parseJSON'
-- rejects a report with a version that this build does not know, because the
-- meaning of every other field depends on the version.
--
-- The version is a JSON string and not a number. JSON has more than one
-- spelling of a number, for example @1@, @1.0@ and @1e0@, and a program that
-- writes a report again can change the spelling, which changes the bytes that
-- the detached signature covers.
data ReportVersion
  = ReportVersion1
  deriving stock (Eq, Ord, Show)

instance FromJSON ReportVersion where
  parseJSON = withText "ReportVersion" $ \text ->
    maybe (fail ("unknown audit report version: " <> show text)) pure (parseReportVersion text)

parseReportVersion :: Text -> Maybe ReportVersion
parseReportVersion = \case
  "1.0" -> Just ReportVersion1
  _ -> Nothing

renderReportVersion :: ReportVersion -> Text
renderReportVersion = \case
  ReportVersion1 -> "1.0"

instance ToJSON ReportVersion where
  toJSON = toJSON . renderReportVersion
  toEncoding = toEncoding . renderReportVersion

-- | An audit report about one DAR, named by its digest. The report does not
-- apply to the dependencies in the closure of the DAR, which are DARs with
-- their own audit reports.
--
-- Every field of 'Audit' is required, and 'Types.Shared.jsonOptions' rejects
-- unknown fields, so a report that does not match the format of its 'version'
-- does not decode. A field that is added to a version must be required too: a
-- report without an optional field could also be a report from before the
-- field was added, so an optional field needs a new version.
data Audit = Audit
  { version :: ReportVersion
  , auditId :: AuditId
  , -- | The identity that signed the report, by the name of its directory in
    -- @identities\/@.
    auditor :: ProviderId
  , -- | The fingerprint of the key that signed the report, in
    -- @identities\/\<auditor\>\/\<fingerprint\>\/key.asc@. Reading the
    -- repository fails when the identity 'auditor' does not have a key with
    -- this fingerprint, also when another identity has the key.
    auditorFingerprint :: Fingerprint
  , -- | The digest of the audited DAR.
    darHash :: DarDigest
  , source :: Source
  , assessment :: Assessment
  }
  deriving stock (Generic, Eq, Show)
  deriving (FromJSON, ToJSON) via WithJsonOptions Audit

-- | A git object ID in lowercase hexadecimal, as git writes it: the @rev@ of a
-- 'Source'.
--
-- A branch or a tag is not a revision here, because a branch or a tag can
-- point to another commit after the report is signed, and the audited source
-- would then change.
newtype GitRevision = GitRevision Text
  deriving stock (Eq, Ord, Show)
  deriving newtype (ToJSON)

instance FromJSON GitRevision where
  parseJSON = withText "GitRevision" $ \text ->
    maybe (fail ("invalid git revision: " <> Text.unpack text)) pure (parseGitRevision text)

parseGitRevision :: Text -> Maybe GitRevision
parseGitRevision text = GitRevision text <$ guard (isGitRevision text)

-- | A git object ID has 40 hexadecimal characters with SHA-1 and 64 with
-- SHA-256.
isGitRevision :: Text -> Bool
isGitRevision text =
  (Text.length text == 40 || Text.length text == 64)
    && Text.all (\character -> isDigit character || (isAsciiLower character && character <= 'f')) text

-- | The source code of the audited package: the digest of the source that was
-- audited, whether it is closed, and optionally the URL of its git repository
-- with the revision that was audited. 'parseJSON' rejects a @url@ without a
-- @rev@ and a @rev@ without a @url@.
data Source = Source
  { closed :: Bool
  , url :: Maybe Text
  , rev :: Maybe GitRevision
  , -- | The digest of the source that the auditor read, which binds the report
    -- to the audited source whether or not the source is published.
    hash :: SourceDigest
  }
  deriving stock (Generic, Eq, Show)
  deriving (ToJSON) via WithJsonOptions Source

instance FromJSON Source where
  parseJSON value = do
    source <- genericParseJSON jsonOptions value
    maybe (pure source) fail (sourceError source)

sourceError :: Source -> Maybe String
sourceError source = case (source.url, source.rev) of
  (Just _, Nothing) -> Just "the source has a url without the rev that was audited"
  (Nothing, Just _) -> Just "the source has a rev without the url of the repository"
  _ -> Nothing

-- | A report with a valid signature and the decision 'Failed' is a valid
-- audit report with a negative result, and its 'RepositoryAudit' has 'passed'
-- set to 'False'. A report whose signature does not verify is an error for the
-- whole repository.
data Assessment = Assessment
  { date :: UTCTime
  , decision :: Decision
  , message :: Text
  }
  deriving stock (Generic, Eq, Show)
  deriving (FromJSON, ToJSON) via WithJsonOptions Assessment

data Decision = Passed | Failed
  deriving stock (Generic, Eq, Ord, Show)

instance FromJSON Decision where
  parseJSON = withText "Decision" $ \text -> case text of
    "passed" -> pure Passed
    "failed" -> pure Failed
    other -> fail ("expected \"passed\" or \"failed\", got: " <> show other)

instance ToJSON Decision where
  toJSON = toJSON . renderDecision
  toEncoding = toEncoding . renderDecision

renderDecision :: Decision -> Text
renderDecision = \case
  Passed -> "passed"
  Failed -> "failed"

-- | The content of @audits\/dars\/\<dar-hash\>\/\<stem\>.revoke.json@.
data AuditRevocation = AuditRevocation
  { -- | The @audit-id@ of the revoked report. The file name is not signed, so
    -- reading the repository fails when this is not the @audit-id@ of
    -- @\<stem\>.json@.
    auditId :: AuditId
  , revokedAt :: UTCTime
  , -- | Free text, which can be empty. Every audit revocation with a valid
    -- signature invalidates the report, whatever its reason.
    reason :: Text
  }
  deriving stock (Generic, Eq, Show)
  deriving (FromJSON, ToJSON) via WithJsonOptions AuditRevocation

-- | An audit report of the identity repository whose signature verifies
-- against the key of its auditor, with the revocations that invalidate it.
data RepositoryAudit = RepositoryAudit
  { report :: Audit
  , path :: Text
    -- ^ The path of the report in the repository, for example
    -- @audits\/dars\/\<dar-hash\>\/\<stem\>.json@.
  , revocation :: Maybe AuditRevocation
  , keyRevocation :: Maybe KeyRevocation
    -- ^ The revocation of the auditor's key, if it invalidates the report. A
    -- report that was added or changed after its key was revoked is invalid,
    -- whatever the reason of the revocation. A key revoked as compromised or
    -- malicious also invalidates the reports from before the revocation.
  , passed :: Bool
    -- ^ Whether the report is an audit that passed, by the rules of its
    -- version.
  }
  deriving stock (Generic, Eq, Show)
  deriving (FromJSON, ToJSON) via WithJsonOptions RepositoryAudit

-- | The identities and the audit reports of a clone of the identity
-- repository.
data IdentityRepository = IdentityRepository
  { identities :: Map ProviderId Identity
  , audits :: Map DarDigest [RepositoryAudit]
    -- ^ The audit reports by the digest of their @dar-hash@ field.
  }
  deriving stock (Eq, Show)
