-- | Reading a DAR file.
module Dar
  ( readDarFile
  , readDar
  ) where

import Audit (Dar (..), MainPackage (..))
import Control.Exception (throwIO)
import Crypto.Hash (SHA256, hash)
import qualified Crypto.Hash as Hash
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Text as Text
import DAR.Inspect (DarInspection (..), DarPackage (..), inspectDar)
import System.FilePath (takeBaseName)
import Types.Shared (DarDigest (..), Sha256 (..))

-- | The content and the digest of a DAR file, and the output of @dpm damlc
-- inspect-dar@ for it. Throws a 'DAR.Inspect.InspectError'.
readDarFile :: FilePath -> FilePath -> IO (ByteString, DarDigest, DarInspection)
readDarFile dpmBinary darPath = do
  inspection <- either throwIO pure =<< inspectDar dpmBinary darPath
  content <- ByteString.readFile darPath
  pure (content, DarDigest (sha256Of content), inspection)

-- | The digest and the main package of a DAR file, for @audit@. Throws a
-- 'DAR.Inspect.InspectError'.
readDar :: FilePath -> FilePath -> IO Dar
readDar dpmBinary darPath = do
  (_, digest, inspection) <- readDarFile dpmBinary darPath
  let package = inspection.mainPackage
  pure
    Dar
      { digest
      , mainPackage = MainPackage {qualifiedPackageId = Text.pack (takeBaseName package.path), name = package.name, version = package.version}
      }

-- | The digest of the bytes in the form @sha256:<hex>@, as
-- @Oci.Image.sha256Of@ of the registry computes it.
sha256Of :: ByteString -> Sha256
sha256Of bytes = Sha256 ("sha256:" <> Text.pack (show (hash bytes :: Hash.Digest SHA256)))
