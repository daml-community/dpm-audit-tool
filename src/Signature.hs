-- | OpenPGP keys and detached signatures, through gpg and gpgv.
--
-- gpgv reads keys only from binary keyrings, so gpg --dearmor converts the
-- armored key first. Both programs get an empty temporary directory as their
-- home directory, so they do not use the keys or the configuration of the
-- user.
module Signature
  ( SignatureError (..)
  , renderSignatureError
  , verifySignature
  , primaryKeyFingerprints
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding (decodeUtf8Lenient, encodeUtf8)
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import System.Process.Typed (proc, readProcess, readProcess_)
import Types.Shared (PublicKey (..))

data SignatureError
  = NoSignature
  | MoreThanOneSignature
  | OtherKey
    -- ^ The signature is by a key that is not the given key or one of its
    -- subkeys.
  | BadSignature
    -- ^ The signature is by the given key, but over other data.
  | ExpiredKey
    -- ^ The signature is by the given key, which has expired.
  | SignatureNotAccepted Text
    -- ^ gpgv does not report a good signature for another reason, for example
    -- because the key has an OpenPGP revocation. The text is the status
    -- output of gpgv.
  deriving stock (Eq, Show)

renderSignatureError :: Text -> SignatureError -> Text
renderSignatureError keyDescription = \case
  NoSignature -> "the signature does not hold an OpenPGP signature"
  MoreThanOneSignature -> "the signature holds more than one OpenPGP signature"
  OtherKey -> "the signature is not made by " <> keyDescription
  BadSignature -> "the signature by " <> keyDescription <> " is not over the signed data"
  ExpiredKey -> keyDescription <> " has expired"
  SignatureNotAccepted statusOutput -> "gpgv does not accept the signature:\n" <> statusOutput

withArmoredKey :: PublicKey -> (FilePath -> FilePath -> IO a) -> IO a
withArmoredKey (PublicKey keyText) action =
  withSystemTempDirectory "gpg" $ \homeDirectory -> do
    let armoredKeyPath = homeDirectory </> "key.asc"
    ByteString.writeFile armoredKeyPath (encodeUtf8 keyText)
    action homeDirectory armoredKeyPath

-- | Checks that the signature is one OpenPGP signature over the signed data,
-- made by the key or one of its subkeys. Throws an 'ExitCodeException' when
-- gpg cannot read the key.
verifySignature
  :: PublicKey
  -> ByteString
  -- ^ The armored or binary detached signature.
  -> ByteString
  -- ^ The signed data.
  -> IO (Either SignatureError ())
verifySignature key signature signedData =
  withArmoredKey key $ \homeDirectory armoredKeyPath -> do
    let keyringPath = homeDirectory </> "key.gpg"
        signaturePath = homeDirectory </> "signature"
        signedDataPath = homeDirectory </> "signed-data"
    ByteString.writeFile signaturePath signature
    ByteString.writeFile signedDataPath signedData
    _ <- readProcess_ (proc "gpg" ["--homedir", homeDirectory, "--batch", "--quiet", "--dearmor", "--output", keyringPath, armoredKeyPath])
    -- Decide from the status lines and not from the exit code: gpgv exits
    -- with 0 also for a signature by an expired key, and reports it with
    -- EXPKEYSIG instead of GOODSIG. For each signature gpgv reports one of
    -- GOODSIG, BADSIG, EXPSIG, EXPKEYSIG, REVKEYSIG and ERRSIG.
    --
    -- The status output is read as bytes, because a user ID in it can have
    -- characters that are not UTF-8.
    (_, statusOutput, _) <-
      readProcess (proc "gpgv" ["--homedir", homeDirectory, "--quiet", "--status-fd", "1", "--keyring", keyringPath, signaturePath, signedDataPath])
    let statusLines = [statusLine | Just statusLine <- map (ByteString.stripPrefix "[GNUPG:] ") (ByteString8.lines (ByteString.toStrict statusOutput))]
        statusKeywords = [keyword | keyword : _ <- map ByteString8.words statusLines]
        hasStatus keyword = keyword `elem` statusKeywords
    pure $ case length (filter (== "NEWSIG") statusKeywords) of
      0 -> Left NoSignature
      1
        | hasStatus "GOODSIG" -> Right ()
        | hasStatus "BADSIG" -> Left BadSignature
        | hasStatus "EXPKEYSIG" -> Left ExpiredKey
        | hasStatus "NO_PUBKEY" -> Left OtherKey
        | otherwise -> Left (SignatureNotAccepted (Text.unlines (map decodeUtf8Lenient statusLines)))
      _ -> Left MoreThanOneSignature

-- | The fingerprints of the primary keys in an armored key block, as gpg
-- writes them: uppercase hexadecimal without separators. Throws an
-- 'ExitCodeException' when gpg cannot read the key block.
primaryKeyFingerprints :: PublicKey -> IO [Text]
primaryKeyFingerprints key =
  withArmoredKey key $ \homeDirectory armoredKeyPath -> do
    (listing, _) <- readProcess_ (proc "gpg" ["--homedir", homeDirectory, "--batch", "--with-colons", "--show-keys", armoredKeyPath])
    -- A "pub" record starts a primary key, and the "fpr" record after it has
    -- the fingerprint of the primary key in field 10. A "sub" record starts a
    -- subkey, and the "fpr" record after it has the fingerprint of the subkey.
    let fingerprintsOfPrimaryKeys = \case
          ("pub" : _) : ("fpr" : fields) : otherRecords ->
            take 1 (drop 8 fields) <> fingerprintsOfPrimaryKeys otherRecords
          _ : otherRecords -> fingerprintsOfPrimaryKeys otherRecords
          [] -> []
    pure (fingerprintsOfPrimaryKeys (map (Text.splitOn ":" . decodeUtf8Lenient) (ByteString8.lines (ByteString.toStrict listing))))
