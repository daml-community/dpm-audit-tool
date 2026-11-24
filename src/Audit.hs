-- | Which audit reports of the identity repository apply to a DAR, and the
-- output of the @audit@ command.
--
-- An audit report is about the DAR whose digest is its @dar-hash@.
-- 'checkReports' uses only the reports with the digest of the DAR, and not the
-- reports of the DARs of its dependencies.
module Audit
  ( MainPackage (..)
  , Dar (..)
  , ReportStatus (..)
  , CheckedReport (..)
  , AuditResult (..)
  , checkReports
  , auditExitCode
  , Style (..)
  , OutputOptions (..)
  , renderAuditResult
  , auditResultJson
  , indentedJson
  ) where

import Data.Aeson (Value (..), object, (.=))
import Data.Aeson.Encode.Pretty (Config (..), Indent (..), defConfig, encodePrettyToTextBuilder')
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Lazy as LazyText
import qualified Data.Text.Lazy.Builder as TextBuilder
import Data.Time (UTCTime, defaultTimeLocale, formatTime)
import System.Exit (ExitCode (..))
import Types.Audit
import Types.Identity (KeyRevocation (..), renderRevocationReason, revokesEveryAudit)
import Types.Shared (CommitHash (..), DarDigest, PackageName (..), ProviderId (..))

-- | The main package of a DAR, which the output of @audit@ shows.
-- 'checkReports' finds the reports of a DAR by its digest and not by its main
-- package.
data MainPackage = MainPackage
  { qualifiedPackageId :: Text
    -- ^ The file name of the main DALF in the DAR, without @.dalf@.
  , name :: PackageName
  , version :: Text
  }
  deriving stock (Eq, Show)

-- | A DAR: its digest, which is the @dar-hash@ of a report about it, and its
-- main package.
data Dar = Dar
  { digest :: DarDigest
  , mainPackage :: MainPackage
  }
  deriving stock (Eq, Show)

-- | Whether a report applies to the DAR. A report that is valid can still have
-- the decision "failed".
data ReportStatus
  = Valid
  | AuditRevoked Text
    -- ^ The reason, as the output of @audit@ shows it.
  | KeyRevoked Text
    -- ^ The reason, as the output of @audit@ shows it.
  deriving stock (Eq, Show)

renderReportStatus :: ReportStatus -> Text
renderReportStatus = \case
  Valid -> "valid"
  AuditRevoked _ -> "revoked"
  KeyRevoked _ -> "key revoked"

invalidReason :: ReportStatus -> Maybe Text
invalidReason = \case
  Valid -> Nothing
  AuditRevoked reason -> Just reason
  KeyRevoked reason -> Just reason

data CheckedReport = CheckedReport
  { path :: Text
    -- ^ The path of the report in the identity repository.
  , status :: ReportStatus
  , auditor :: ProviderId
  , decision :: Decision
  , date :: UTCTime
    -- ^ The date of the decision of the auditor.
  , message :: Text
    -- ^ The auditor's message about the audit.
  , passed :: Bool
    -- ^ Whether the status is 'Valid' and the decision is 'Passed'.
  }
  deriving stock (Eq, Show)

data AuditResult = AuditResult
  { commit :: CommitHash
    -- ^ The commit of the identity repository that was read.
  , mainPackage :: MainPackage
  , reports :: [CheckedReport]
  }
  deriving stock (Eq, Show)

-- | The reports about a DAR, checked by the rules of their version.
checkReports :: IdentityRepository -> Dar -> [CheckedReport]
checkReports repository dar = map checkReport (Map.findWithDefault [] dar.digest repository.audits)
  where
    checkReport audit = case audit.report.version of
      ReportVersion1 ->
        CheckedReport
          { path = audit.path
          , status = statusVersion1 audit
          , auditor = audit.report.auditor
          , decision = audit.report.assessment.decision
          , date = audit.report.assessment.date
          , message = audit.report.assessment.message
          , passed = audit.passed
          }

    statusVersion1 audit = case (audit.revocation, audit.keyRevocation) of
      (Just revocation, _) ->
        AuditRevoked ("the auditor revoked the report" <> if Text.null revocation.reason then "" else ": " <> revocation.reason)
      (Nothing, Just keyRevocation)
        | revokesEveryAudit keyRevocation.reason ->
            KeyRevoked
              ( "the auditor's key is revoked as "
                  <> renderRevocationReason keyRevocation.reason
                  <> ", which invalidates every report that it signed"
              )
        | otherwise -> KeyRevoked "the auditor's key is revoked as rotated, and the report was added after the revocation"
      (Nothing, Nothing) -> Valid

-- | The exit code of @audit@: 0 when the DAR has a valid report that passed, 2
-- when it does not have reports, and 4 when none of its reports is a valid
-- report that passed. 1 is for a failure of the command.
auditExitCode :: AuditResult -> ExitCode
auditExitCode auditResult
  | any (.passed) auditResult.reports = ExitSuccess
  | null auditResult.reports = ExitFailure 2
  | otherwise = ExitFailure 4

-- | Whether the text gets ANSI colours.
newtype Style = Style Bool

paint :: Style -> Text -> Text -> Text
paint (Style enabled) codes text
  | not enabled || Text.null text = text
  | otherwise = codes <> text <> "\ESC[0m"

bold, dim, red, green, yellow, warning :: Style -> Text -> Text
bold style = paint style "\ESC[1m"
dim style = paint style "\ESC[2m"
red style = paint style "\ESC[31m"
green style = paint style "\ESC[32m"
yellow style = paint style "\ESC[33m"
warning style = paint style "\ESC[1m\ESC[33m"

data OutputOptions = OutputOptions
  { style :: Style
  , showUnverified :: Bool
    -- ^ List the reports that are not valid, instead of only counting them.
  , showPath :: Bool
  }

-- | The output of @audit@ as text.
--
-- A report that is not valid does not apply to the DAR, so it is not listed
-- with the valid reports. The output gives the number of these reports, and
-- lists them after the valid reports when 'showUnverified' is set.
renderAuditResult :: OutputOptions -> AuditResult -> Text
renderAuditResult options auditResult =
  Text.unlines $
    ["identity repository at " <> dim options.style commitText, ""]
      <> renderReports validReports
      <> case otherReports of
        [] -> []
        _
          | not options.showUnverified ->
              [ ""
              , yellow options.style $
                  countOfOthers <> " not valid and " <> were <> " ignored. Pass --show-unverified to see " <> them <> "."
              ]
          | otherwise ->
              ["", warning options.style ("!! " <> countOfOthers <> " not valid and " <> were <> " ignored")]
                <> renderReports otherReports
  where
    validReports = filter ((== Valid) . (.status)) auditResult.reports
    otherReports = filter ((/= Valid) . (.status)) auditResult.reports
    (countOfOthers, were, them) = case length otherReports of
      1 -> ("1 audit is", "was", "it")
      count -> (Text.pack (show count) <> " audits are", "were", "them")
    PackageName packageName = auditResult.mainPackage.name
    CommitHash commitText = auditResult.commit

    renderReports reports =
      [ "  " <> bold options.style (Text.unwords (filter (not . Text.null) [packageName, auditResult.mainPackage.version]))
      , "    " <> dim options.style auditResult.mainPackage.qualifiedPackageId
      ]
        <> case reports of
          -- "no audit" is not correct when there are reports that are not
          -- valid.
          [] -> ["    " <> yellow options.style (if null auditResult.reports then "no audit" else "no valid audit")]
          _ ->
            concatMap
              (renderReport (maximum (map (Text.length . leadOf) reports)) (maximum (map (Text.length . auditorName) reports)))
              reports

    renderReport leadWidth auditorWidth report =
      [ "    "
          <> pad leadWidth (leadOf report) (colourOf report (leadOf report))
          <> "  "
          <> pad auditorWidth (auditorName report) (auditorName report)
          <> "  "
          <> dim options.style (Text.pack (formatTime defaultTimeLocale "%Y-%m-%d" report.date))
      ]
        <> ["      " <> dim options.style report.path | options.showPath]
        -- Show the auditor's message for a valid report, and the reason for a
        -- report that is not valid.
        <> map ("      " <>) (wrap 72 (fromMaybe report.message (invalidReason report.status)))

    -- The text at the start of the line of a report: the decision of a valid
    -- report, and the status of a report that is not valid.
    leadOf report = case report.status of
      Valid -> renderDecision report.decision
      status -> renderReportStatus status

    auditorName report = let ProviderId auditor = report.auditor in auditor

    colourOf report = case report.status of
      Valid | report.passed -> green options.style
      Valid -> red options.style
      _ -> yellow options.style

    -- The padding counts the characters of the text and not its colour codes.
    pad width plain painted = painted <> Text.replicate (width - Text.length plain) " "

-- | Breaks a text into lines of at most the width, at spaces. A word that is
-- longer than the width gets a line of its own.
wrap :: Int -> Text -> [Text]
wrap width text = case Text.words text of
  [] -> []
  firstWord : otherWords -> reverse (foldl addWord [firstWord] otherWords)
  where
    addWord wrapped word = case wrapped of
      line : earlierLines
        | Text.length line + 1 + Text.length word <= width -> (line <> " " <> word) : earlierLines
      _ -> word : wrapped

-- | The output of @audit --json@. Unlike 'renderAuditResult', it has all
-- reports, because a program that reads it can filter on @status@.
auditResultJson :: AuditResult -> Value
auditResultJson auditResult =
  object
    [ "commit" .= auditResult.commit
    , "exit-code" .= case auditExitCode auditResult of ExitSuccess -> 0; ExitFailure code -> code
    , "main"
        .= object
          [ "package-id" .= auditResult.mainPackage.qualifiedPackageId
          , "name" .= auditResult.mainPackage.name
          , "version" .= auditResult.mainPackage.version
          , "audits" .= map reportJson auditResult.reports
          ]
    ]
  where
    reportJson report =
      object $
        [ "path" .= report.path
        , "status" .= renderReportStatus report.status
        , "auditor" .= report.auditor
        , "decision" .= report.decision
        , "passed" .= report.passed
        ]
          <> ["reason" .= reason | Just reason <- [invalidReason report.status]]

indentedJson :: Value -> Text
indentedJson =
  LazyText.toStrict
    . TextBuilder.toLazyText
    . encodePrettyToTextBuilder' defConfig {confIndent = Spaces 2, confCompare = compare, confTrailingNewline = True}
