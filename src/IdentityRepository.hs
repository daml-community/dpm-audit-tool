-- | Reading a clone of the identity repository: the identities
-- that sign audit reports, and the audit reports. 'Types.Identity' and
-- 'Types.Audit' describe the layout.
--
-- 'readIdentityRepository' does not skip a file that does not match the
-- layout, but returns an error for the whole repository. Examples are a
-- document that does not decode, a key directory whose name is not the
-- fingerprint of its @key.asc@, an identity with more than one key without a
-- @revoke.json@, and an audit report or audit revocation without a signature
-- by the auditor's key.
module IdentityRepository
  ( RepositoryError (..)
  , renderRepositoryError
  , gitOutput
  , readIdentityRepository
  ) where

import Control.Exception (Exception (..), IOException, try)
import Control.Monad (unless, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT (..), except, runExceptT, throwE)
import Data.Bifunctor (first)
import Data.Aeson (FromJSON, eitherDecodeStrict)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Either (partitionEithers)
import Data.Foldable (for_)
import Data.List (sort)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing, listToMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding (decodeUtf8Lenient)
import Data.Traversable (for)
import Signature (SignatureError, primaryKeyFingerprints, renderSignatureError, verifySignature)
import System.Directory (doesDirectoryExist, doesFileExist, listDirectory)
import System.FilePath ((</>))
import System.Process.Typed (ExitCodeException, proc, readProcess_, setWorkingDir)
import Types.Audit
import Types.Identity
import Types.Shared (DarDigest, ProviderId (..), parseProviderId, parsePublicKey)

-- | The paths are paths in the repository, with @/@ as the separator.
data RepositoryError
  = NotADirectory FilePath
  | UnexpectedDirectory FilePath
  | CannotRead FilePath Text
  | InvalidDocument FilePath Text
  | InvalidIdentityName FilePath
  | InvalidKeyDirectoryName FilePath
  | NotOneKey FilePath Int
    -- ^ A @key.asc@ that does not hold exactly one primary key.
  | OtherKeyInKeyFile FilePath Text
    -- ^ A @key.asc@ whose key has another fingerprint than the name of its
    -- directory.
  | MoreThanOneActiveKey FilePath [Fingerprint]
  | MissingSignature FilePath
  | UnknownAuditor FilePath ProviderId
  | UnknownAuditorKey FilePath ProviderId Fingerprint
  | SignatureRejected FilePath SignatureError
    -- ^ The path is the path of the signature.
  | RevocationNotCommitted FilePath
  | AuditIdMismatch FilePath AuditId FilePath AuditId
    -- ^ An audit revocation with its @audit-id@, and the report with the same
    -- file name stem with its @audit-id@.
  | UnexpectedFile FilePath
  | CommandFailed ExitCodeException
    -- ^ git or gpg failed.

renderRepositoryError :: RepositoryError -> Text
renderRepositoryError = \case
  NotADirectory path -> Text.pack path <> " is not a directory"
  UnexpectedDirectory path -> Text.pack path <> " is a directory"
  CannotRead path message -> Text.pack path <> ": " <> message
  InvalidDocument path message -> Text.pack path <> ": " <> message
  InvalidIdentityName path -> Text.pack path <> ": the name of an identity directory has to be a provider"
  InvalidKeyDirectoryName path -> Text.pack path <> ": the name of a key directory has to be a fingerprint"
  NotOneKey path count -> Text.pack path <> " has " <> Text.pack (show count) <> " keys and must have one"
  OtherKeyInKeyFile path fingerprint ->
    "the key in " <> Text.pack path <> " is " <> fingerprint <> ", which is not the name of its directory"
  MoreThanOneActiveKey path fingerprints ->
    Text.pack path
      <> " has more than one key without a revoke.json: "
      <> Text.intercalate ", " [text | Fingerprint text <- fingerprints]
  MissingSignature path -> Text.pack path <> " does not have the signature " <> Text.pack path <> ".sig"
  UnknownAuditor path (ProviderId auditor) -> Text.pack path <> ": the auditor " <> auditor <> " is not an identity"
  UnknownAuditorKey path (ProviderId auditor) (Fingerprint fingerprint) ->
    Text.pack path <> ": the identity " <> auditor <> " does not have the key " <> fingerprint
  SignatureRejected path signatureError -> Text.pack path <> ": " <> renderSignatureError "the auditor's key" signatureError
  RevocationNotCommitted path -> Text.pack path <> " is not committed"
  AuditIdMismatch revocationPath (AuditId revocationId) reportPath (AuditId reportId) ->
    Text.pack revocationPath
      <> ": the audit-id "
      <> revocationId
      <> " does not match the audit-id "
      <> reportId
      <> " of "
      <> Text.pack reportPath
  UnexpectedFile path -> Text.pack path <> " is not an audit report, an audit revocation or the signature of one"
  CommandFailed failure -> Text.pack (displayException failure)

-- | Audits of other kinds of artifact would be in other directories of
-- @audits\/@.
auditsRoot :: FilePath
auditsRoot = "audits/dars"

-- | A clone of the identity repository on disk. The functions that take a
-- 'Clone' take paths in the repository and not on disk, so that an error
-- always names a file by its path in the repository.
newtype Clone = Clone FilePath

type Reading = ExceptT RepositoryError IO

onDisk :: Clone -> FilePath -> FilePath
onDisk (Clone clonePath) path = clonePath </> path

gitOutput :: FilePath -> [String] -> IO Text
gitOutput directory arguments =
  Text.strip . decodeUtf8Lenient . ByteString.toStrict . fst <$> readProcess_ (setWorkingDir directory (proc "git" arguments))

readIdentityRepository :: FilePath -> IO (Either RepositoryError IdentityRepository)
readIdentityRepository clonePath = runExceptT $ do
  let clone = Clone clonePath
  identities <- readIdentities clone
  audits <- readAudits clone identities
  pure IdentityRepository {identities, audits}

catchIOException :: (Text -> RepositoryError) -> IO a -> Reading a
catchIOException toError action =
  ExceptT (first (toError . Text.pack . displayException) <$> try @IOException action)

catchCommandFailure :: IO a -> Reading a
catchCommandFailure action = ExceptT (first CommandFailed <$> try action)

readRepositoryFile :: Clone -> FilePath -> Reading ByteString
readRepositoryFile clone path = catchIOException (CannotRead path) (ByteString.readFile (onDisk clone path))

decodeDocument :: (FromJSON document) => FilePath -> ByteString -> Either RepositoryError document
decodeDocument path = first (InvalidDocument path . Text.pack) . eitherDecodeStrict

readDocument :: (FromJSON document) => Clone -> FilePath -> Reading document
readDocument clone path = except . decodeDocument path =<< readRepositoryFile clone path

listRepositoryDirectory :: Clone -> FilePath -> Reading [FilePath]
listRepositoryDirectory clone path = sort <$> catchIOException (CannotRead path) (listDirectory (onDisk clone path))

isRepositoryDirectory :: Clone -> FilePath -> Reading Bool
isRepositoryDirectory clone path = liftIO (doesDirectoryExist (onDisk clone path))

requireDirectory :: Clone -> FilePath -> Reading ()
requireDirectory clone path = do
  isDirectory <- isRepositoryDirectory clone path
  unless isDirectory (throwE (NotADirectory path))

git :: Clone -> [String] -> Reading Text
git (Clone clonePath) arguments = catchCommandFailure (gitOutput clonePath arguments)

-- Identities -----------------------------------------------------------------

readIdentities :: Clone -> Reading (Map ProviderId Identity)
readIdentities clone = do
  names <- listRepositoryDirectory clone "identities"
  fmap Map.fromList . for names $ \name -> do
    let directory = "identities/" <> name
    requireDirectory clone directory
    provider <- maybe (throwE (InvalidIdentityName directory)) pure (parseProviderId (Text.pack name))
    meta <- readDocument clone (directory <> "/meta.json")
    keyNames <- filter (/= "meta.json") <$> listRepositoryDirectory clone directory
    keys <- for keyNames $ \keyName -> readIdentityKey clone (directory <> "/" <> keyName) keyName
    identity <- except (identityWithKeys directory provider meta keys)
    pure (provider, identity)

identityWithKeys :: FilePath -> ProviderId -> IdentityMeta -> [(IdentityKey, Maybe KeyRevocation)] -> Either RepositoryError Identity
identityWithKeys directory provider meta keys =
  case activeKeys of
    _ : _ : _ -> Left (MoreThanOneActiveKey directory (map (.fingerprint) activeKeys))
    _ -> Right Identity {provider, meta, activeKey = listToMaybe activeKeys, revokedKeys}
  where
    (activeKeys, revokedKeys) =
      partitionEithers [maybe (Left key) (Right . RevokedKey key) revocation | (key, revocation) <- keys]

-- | A report names its key by the name of the key directory, and the signature
-- check reads key.asc, so the two have to be the same key.
readIdentityKey :: Clone -> FilePath -> FilePath -> Reading (IdentityKey, Maybe KeyRevocation)
readIdentityKey clone directory name = do
  fingerprint <- maybe (throwE (InvalidKeyDirectoryName directory)) pure (parseFingerprint (Text.pack name))
  requireDirectory clone directory
  let keyPath = directory <> "/key.asc"
  key <-
    maybe (throwE (InvalidDocument keyPath "expected an ASCII-armored OpenPGP public key block")) pure
      . parsePublicKey
      . decodeUtf8Lenient
      =<< readRepositoryFile clone keyPath
  keyFingerprints <- catchCommandFailure (primaryKeyFingerprints key)
  case keyFingerprints of
    [keyFingerprint]
      | Fingerprint keyFingerprint == fingerprint -> pure ()
      | otherwise -> throwE (OtherKeyInKeyFile keyPath keyFingerprint)
    _ -> throwE (NotOneKey keyPath (length keyFingerprints))
  let revocationPath = directory <> "/revoke.json"
  hasRevocation <- liftIO (doesFileExist (onDisk clone revocationPath))
  revocation <- if hasRevocation then Just <$> readDocument clone revocationPath else pure Nothing
  pure (IdentityKey {fingerprint, key}, revocation)

-- Audit reports --------------------------------------------------------------

-- | Reads the reports of every subdirectory of audits/dars/, by the digest of
-- the DAR that they are about. A repository without audits/dars/ does not have
-- reports yet.
readAudits :: Clone -> Map ProviderId Identity -> Reading (Map DarDigest [RepositoryAudit])
readAudits clone identities = do
  hasAudits <- isRepositoryDirectory clone auditsRoot
  directoryNames <- if hasAudits then listRepositoryDirectory clone auditsRoot else pure []
  audits <- concat <$> for directoryNames (readDarAudits clone identities . ((auditsRoot <> "/") <>))
  pure (Map.fromListWith (flip (<>)) [(auditSubject audit.report, [audit]) | audit <- audits])
  where
    auditSubject report = case report.version of
      ReportVersion1 -> report.darHash

-- | The files of a report: the report @<stem>.json@ and its signature, and the
-- audit revocation @<stem>.revoke.json@ and its signature.
data ReportFiles = ReportFiles
  { stem :: FilePath
  , hasSignature :: Bool
  , hasRevocation :: Maybe Bool
    -- ^ Whether there is a revocation, and whether it has its signature.
  }

-- | The reports in the files of a subdirectory of audits/dars/, or the first
-- file that is neither a report, an audit revocation, nor the signature of
-- one of them. Such a file is an error, because it can be a report or an audit
-- revocation with a file name that 'readDarAudits' does not read.
reportFilesOf :: [FilePath] -> Either FilePath [ReportFiles]
reportFilesOf fileNames =
  case filter (`notElem` concatMap filesOfReport reports) fileNames of
    unexpectedFile : _ -> Left unexpectedFile
    [] -> Right reports
  where
    isPresent = (`elem` fileNames)
    reports =
      [ ReportFiles
          { stem
          , hasSignature = isPresent (stem <> ".json.sig")
          , hasRevocation =
              if isPresent (stem <> ".revoke.json") then Just (isPresent (stem <> ".revoke.json.sig")) else Nothing
          }
      | Just stem <- map (fmap Text.unpack . Text.stripSuffix ".json" . Text.pack) fileNames
      , not (".revoke" `Text.isSuffixOf` Text.pack stem)
      ]
    filesOfReport report =
      [report.stem <> ".json", report.stem <> ".json.sig"]
        <> maybe [] (const [report.stem <> ".revoke.json", report.stem <> ".revoke.json.sig"]) report.hasRevocation

readDarAudits :: Clone -> Map ProviderId Identity -> FilePath -> Reading [RepositoryAudit]
readDarAudits clone identities directory = do
  requireDirectory clone directory
  fileNames <- listRepositoryDirectory clone directory
  for_ fileNames $ \fileName -> do
    isDirectory <- isRepositoryDirectory clone (directory <> "/" <> fileName)
    when isDirectory (throwE (UnexpectedDirectory (directory <> "/" <> fileName)))
  reports <- except (first (UnexpectedFile . ((directory <> "/") <>)) (reportFilesOf fileNames))
  for reports (readAudit clone identities directory)

readSigned :: Clone -> FilePath -> Bool -> Reading (ByteString, ByteString)
readSigned clone path hasSignature = do
  unless hasSignature (throwE (MissingSignature path))
  content <- readRepositoryFile clone path
  signature <- readRepositoryFile clone (path <> ".sig")
  pure (content, signature)

verifySignedBy :: IdentityKey -> FilePath -> ByteString -> ByteString -> Reading ()
verifySignedBy key path content signature = do
  verification <- catchCommandFailure (verifySignature key.key signature content)
  except (first (SignatureRejected (path <> ".sig")) verification)

-- | Reads one report, checks its signature, and reads the revocations that
-- invalidate it.
--
-- The fields of a report other than the auditor and the fingerprint are not
-- used before the signature verifies against the key that the report names.
readAudit :: Clone -> Map ProviderId Identity -> FilePath -> ReportFiles -> Reading RepositoryAudit
readAudit clone identities directory files = do
  let path = directory <> "/" <> files.stem <> ".json"
  (content, signature) <- readSigned clone path files.hasSignature
  report <- except (decodeDocument path content)
  (identity, key, keyRevocationOfKey) <- except (findAuditor identities path report)
  verifySignedBy key path content signature
  keyRevocation <- case keyRevocationOfKey of
    Nothing -> pure Nothing
    Just keyRevocation -> do
      invalidated <- keyRevocationInvalidates clone identity key keyRevocation path
      pure (if invalidated then Just keyRevocation else Nothing)
  revocation <- for files.hasRevocation $ \hasRevocationSignature -> do
    let revocationPath = directory <> "/" <> files.stem <> ".revoke.json"
    (revocationContent, revocationSignature) <- readSigned clone revocationPath hasRevocationSignature
    revocation <- except (decodeDocument revocationPath revocationContent >>= checkRevocationAuditId revocationPath path report)
    verifySignedBy key revocationPath revocationContent revocationSignature
    pure revocation
  let passed = case report.version of
        ReportVersion1 -> isNothing revocation && isNothing keyRevocation && report.assessment.decision == Passed
  pure RepositoryAudit {report, path = Text.pack path, revocation, keyRevocation, passed}

-- | Only the auditor of a report can revoke it: the revocation has to name the
-- audit-id of the report, and is checked against the key of the report.
checkRevocationAuditId :: FilePath -> FilePath -> Audit -> AuditRevocation -> Either RepositoryError AuditRevocation
checkRevocationAuditId revocationPath reportPath report revocation
  | revocation.auditId /= report.auditId = Left (AuditIdMismatch revocationPath revocation.auditId reportPath report.auditId)
  | otherwise = Right revocation

-- | The identity of the auditor of a report, the key that the report names,
-- and the revocation of that key.
--
-- The key is the active key of the auditor or one of the revoked keys. A
-- report that a revoked key signed is still read, and
-- 'keyRevocationInvalidates' checks whether the revocation invalidates it.
findAuditor :: Map ProviderId Identity -> FilePath -> Audit -> Either RepositoryError (Identity, IdentityKey, Maybe KeyRevocation)
findAuditor identities path report = do
  identity <- maybe (Left (UnknownAuditor path report.auditor)) Right (Map.lookup report.auditor identities)
  let activeKey = [(key, Nothing) | Just key <- [identity.activeKey], key.fingerprint == report.auditorFingerprint]
      revokedKeys =
        [ (revokedKey.revokedKey, Just revokedKey.revocation)
        | revokedKey <- identity.revokedKeys
        , revokedKey.revokedKey.fingerprint == report.auditorFingerprint
        ]
  case activeKey <> revokedKeys of
    (key, keyRevocation) : _ -> Right (identity, key, keyRevocation)
    [] -> Left (UnknownAuditorKey path report.auditor report.auditorFingerprint)

-- | A key revoked for any reason but rotation invalidates every report that it
-- signed. A key revoked as rotated invalidates the reports that were added or
-- changed after its revoke.json: a report is valid when the commit that added
-- the revoke.json has the report with the same content. The order comes from
-- the commit history and not from a date in a document, because the holder of
-- the key chooses the dates.
keyRevocationInvalidates :: Clone -> Identity -> IdentityKey -> KeyRevocation -> FilePath -> Reading Bool
keyRevocationInvalidates clone identity key keyRevocation auditPath
  | revokesEveryAudit keyRevocation.reason = pure True
  | otherwise = do
      let ProviderId provider = identity.provider
          Fingerprint fingerprint = key.fingerprint
          revocationPath = "identities/" <> Text.unpack provider <> "/" <> Text.unpack fingerprint <> "/revoke.json"
      -- The first commit that added the revoke.json, and not the last.
      --
      -- When a revocation is removed and added again, the last commit that
      -- added it is a later commit, and its tree has the reports that were
      -- committed in between. A report that the rotated key signed in that
      -- time would then be valid, also a report that the rotation already
      -- invalidated. gittuf cannot require a file to stay, so the repository
      -- can contain such a removal.
      --
      -- --reverse does not combine with -1: the limit applies before the
      -- reversal. --no-show-signature overrides a log.showSignature in the
      -- git configuration of the user, which adds lines before the commit.
      revocationCommits <-
        git clone ["log", "--no-show-signature", "--diff-filter=A", "--format=%H", "--reverse", "--", revocationPath]
      case Text.lines revocationCommits of
        [] -> throwE (RevocationNotCommitted revocationPath)
        revocationCommit : _ -> do
          reportAtRevocation <- git clone ["ls-tree", "--object-only", Text.unpack revocationCommit, "--", auditPath]
          reportInWorkingTree <- git clone ["hash-object", "--", auditPath]
          pure (reportAtRevocation /= reportInWorkingTree)
