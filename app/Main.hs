-- | dpm-registry-audit checks the audit reports of a DAR in a checkout of the
-- identity repository.
module Main (main) where

import Audit (AuditResult (..), Dar (..), OutputOptions (..), Style (..), auditExitCode, checkReports, renderAuditResult)
import Command (CommandError (..), catchFailures)
import Control.Exception (throwIO)
import Dar (readDar)
import qualified Data.Text as Text
import qualified Data.Text.IO as Text
import IdentityRepository (gitOutput, readIdentityRepository)
import Options.Applicative
import System.Directory (findExecutable)
import System.Exit (ExitCode (..), exitWith)
import System.IO (hSetEncoding, stderr, stdout, utf8)
import Types.Shared (CommitHash (..))

main :: IO ()
main = do
  hSetEncoding stdout utf8
  hSetEncoding stderr utf8
  (darPath, repositoryPath) <-
    execParser $
      info
        (((,) <$> strArgument (metavar "DAR") <*> strArgument (metavar "IDENTITY_REPOSITORY")) <**> helper)
        (fullDesc <> progDesc "Report which audits exist for a DAR and which of them are valid")
  result <- catchFailures $ do
    dpmBinary <- maybe (throwIO MissingProgram {program = "dpm", purpose = "read the DAR"}) pure =<< findExecutable "dpm"
    dar <- readDar dpmBinary darPath
    commit <- CommitHash <$> gitOutput repositoryPath ["rev-parse", "HEAD"]
    repository <-
      either (throwIO . IdentityRepositoryUnreadable (Text.pack repositoryPath) commit) pure
        =<< readIdentityRepository repositoryPath
    let auditResult = AuditResult {commit, mainPackage = dar.mainPackage, reports = checkReports repository dar}
    Text.putStr (renderAuditResult OutputOptions {style = Style False, showUnverified = True, showPath = False} auditResult)
    pure (auditExitCode auditResult)
  case result of
    Right exitCode -> exitWith exitCode
    Left message -> do
      Text.hPutStrLn stderr ("dpm-registry-audit: " <> message)
      exitWith (ExitFailure 1)
