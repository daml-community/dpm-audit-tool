-- | The failures of dpm-registry-audit.
module Command
  ( CommandError (..)
  , catchFailures
  ) where

import Control.Exception (Exception (..), Handler (..), IOException, catches)
import Data.Text (Text)
import qualified Data.Text as Text
import DAR.Inspect (InspectError)
import IdentityRepository (RepositoryError, renderRepositoryError)
import System.Process.Typed (ExitCodeException)
import Types.Shared (CommitHash (..))

data CommandError
  = MissingProgram {program :: Text, purpose :: Text}
  | IdentityRepositoryUnreadable {location :: Text, commit :: CommitHash, repositoryError :: RepositoryError}

instance Show CommandError where
  show = displayException

instance Exception CommandError where
  displayException = Text.unpack . \case
    MissingProgram {program, purpose} -> program <> " is not on the PATH; it is needed to " <> purpose
    IdentityRepositoryUnreadable {location, commit = CommitHash commitHash, repositoryError} ->
      "the identity repository " <> location <> " at commit " <> commitHash <> ": " <> renderRepositoryError repositoryError

-- | Runs an action, and returns the message of a failure that is shown to the
-- user.
catchFailures :: IO a -> IO (Either Text a)
catchFailures action =
  (Right <$> action)
    `catches` [ Handler (report @InspectError)
              , Handler (report @CommandError)
              , Handler (report @ExitCodeException)
              , Handler (report @IOException)
              ]
  where
    report :: forall failure a. (Exception failure) => failure -> IO (Either Text a)
    report = pure . Left . Text.pack . displayException
