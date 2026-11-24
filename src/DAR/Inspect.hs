-- | The JSON output of @damlc inspect-dar --json <dar>@.
module DAR.Inspect
  ( DarInspection (..)
  , DarPackage (..)
  , inspectDar
  , InspectError (..)
  ) where

import Data.Aeson
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as Text
import Control.Exception (Exception (..), try)
import Data.Bifunctor (first)
import GHC.Generics (Generic)
import System.Process.Typed (ExitCodeException, proc, readProcess_)
import Types.Shared (PackageId, PackageName, renderPackageId)

data DarInspection = DarInspection
  { mainPackageId :: PackageId
  , mainPackage :: DarPackage
    -- ^ The package of 'mainPackageId' in 'packages'.
  , packages :: DarPackages
    -- ^ The main package and all its dependencies, by package ID.
  }
  deriving stock (Eq, Show)

instance FromJSON DarInspection where
  parseJSON = withObject "DarInspection" $ \fields -> do
    mainPackageId <- fields .: "main_package_id"
    packages <- fields .: "packages"
    mainPackage <-
      maybe (fail ("the main package " <> Text.unpack (renderPackageId mainPackageId) <> " is not one of the packages")) pure $
        Map.lookup mainPackageId packages
    pure DarInspection {mainPackageId, mainPackage, packages}

type DarPackages = Map PackageId DarPackage

-- | One DALF in the DAR.
data DarPackage = DarPackage
  { name :: PackageName
    -- ^ The package name in the DALF metadata.
  , version :: Text
    -- ^ The package version in the DALF metadata.
  , path :: FilePath
    -- ^ Path of the DALF in the zip archive.
  }
  deriving stock (Eq, Show, Generic)

instance FromJSON DarPackage

data InspectError
  = DamlcFailed ExitCodeException
  | UnexpectedOutput Text
    -- ^ The output does not decode as a 'DarInspection'.
  deriving stock (Show)

instance Exception InspectError where
  displayException = \case
    DamlcFailed failure -> displayException failure
    UnexpectedOutput decodeError -> "dpm damlc inspect-dar printed output that does not decode: " <> Text.unpack decodeError

inspectDar
  :: FilePath
  -- ^ The dpm binary.
  -> FilePath
  -- ^ The DAR.
  -> IO (Either InspectError DarInspection)
inspectDar dpmPath darPath = do
  damlcOutput <- try (readProcess_ (proc dpmPath ["damlc", "inspect-dar", "--json", darPath]))
  pure $ do
    (output, _) <- first DamlcFailed damlcOutput
    first (UnexpectedOutput . Text.pack) (eitherDecode output)
