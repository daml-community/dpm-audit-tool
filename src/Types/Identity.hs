{-# LANGUAGE DerivingVia #-}

-- | The identities of the identity repository, in this file layout:
--
-- > identities/
-- >     <id>/
-- >         meta.json                  {"name": ..., "url": ...}
-- >         <FINGERPRINT>/
-- >             key.asc                gpg --export --armor
-- >             revoke.json            present only when the key is revoked
-- >             evidence/
--
-- A key is active when its directory does not contain a @revoke.json@. The
-- repository does not record dates of validity, so the active keys depend on
-- the commit of the repository and not on a date.
--
-- 'IdentityRepository.readIdentityRepository' builds an 'Identity' from the
-- directories of the identity: only 'IdentityMeta' and 'KeyRevocation' are
-- decoded from files. The aeson instances of the other types are for the
-- identities in the index ('Types.Index.Index').
module Types.Identity where

import Data.Aeson
import Data.Text (Text)
import Data.Time (UTCTime)
import qualified Data.Text as Text
import GHC.Generics (Generic)
import Types.Shared (ProviderId, PublicKey, WithJsonOptions (..))
import Control.Monad (guard)
import Data.Char (isAsciiUpper, isDigit)

-- | An OpenPGP primary key fingerprint, uppercase hexadecimal and without
-- separators, as the key directory is named, for example
-- @2F30549D4EEAA896C684EA18A44F55903795D721@.
newtype Fingerprint = Fingerprint Text
  deriving stock (Eq, Ord, Show)
  deriving newtype (ToJSON)

instance FromJSON Fingerprint where
  parseJSON = withText "Fingerprint" $ \text ->
    maybe (fail ("invalid fingerprint: " <> Text.unpack text)) pure (parseFingerprint text)

parseFingerprint :: Text -> Maybe Fingerprint
parseFingerprint text = Fingerprint text <$ guard (isFingerprint text)

isFingerprint :: Text -> Bool
isFingerprint text =
  Text.length text == 40
    && Text.all (\character -> isDigit character || (isAsciiUpper character && character <= 'F')) text

-- | An identity: its directory name, its @meta.json@ and its key directories.
data Identity = Identity
  { provider :: ProviderId
  , meta :: IdentityMeta
  , activeKey :: Maybe IdentityKey
  , revokedKeys :: [RevokedKey]
  }
  deriving stock (Generic, Eq, Show)
  deriving (FromJSON, ToJSON) via WithJsonOptions Identity

-- | The @meta.json@ of an identity.
data IdentityMeta = IdentityMeta
  { name :: Text
  , url :: Text
  }
  deriving stock (Generic, Eq, Show)
  deriving (FromJSON, ToJSON) via WithJsonOptions IdentityMeta

-- | The key of a @\<FINGERPRINT\>\/@ directory of an identity. The
-- @evidence\/@ directory is material for the committee of the identity
-- repository, and the code does not read it.
data IdentityKey = IdentityKey
  { fingerprint :: Fingerprint
  , key :: PublicKey
  }
  deriving stock (Generic, Eq, Show)
  deriving (FromJSON, ToJSON) via WithJsonOptions IdentityKey

-- | A key directory with a @revoke.json@.
data RevokedKey = RevokedKey
  { revokedKey :: IdentityKey
  , revocation :: KeyRevocation
  }
  deriving stock (Generic, Eq, Show)
  deriving (FromJSON, ToJSON) via WithJsonOptions RevokedKey

-- | The content of @identities\/\<id\>\/\<FINGERPRINT\>\/revoke.json@. It does
-- not have a version field, so it cannot have optional fields, for the reason
-- in 'Types.Audit.Audit'.
data KeyRevocation = KeyRevocation
  { reason :: RevocationReason
  , -- | When control of the key was believed lost, for people to read. For
    -- 'Rotated', 'IdentityRepository.readIdentityRepository' compares each
    -- report with the first commit that added the @revoke.json@, and not with
    -- this date.
    revokedAt :: UTCTime
  , -- | Free text, which can be empty.
    note :: Text
  }
  deriving stock (Generic, Eq, Show)
  deriving (FromJSON, ToJSON) via WithJsonOptions KeyRevocation

-- | 'parseRevocationReason' reads every text other than @rotated@ and
-- @malicious@ as 'Compromised', which invalidates the most audit reports,
-- because an unknown reason most likely describes a problem with the key and
-- not a routine replacement.
data RevocationReason
  = -- | The key was replaced. The audit reports from before the revocation
    -- stay valid.
    Rotated
  | -- | Control of the key was lost. Every audit report that the key signed
    -- is invalid.
    Compromised
  | -- | The holder of the key acted in bad faith. The effect is the same as
    -- for 'Compromised'.
    Malicious
  deriving stock (Eq, Ord, Show)

instance ToJSON RevocationReason where
  toJSON = toJSON . renderRevocationReason
  toEncoding = toEncoding . renderRevocationReason

instance FromJSON RevocationReason where
  parseJSON = withText "RevocationReason" (pure . parseRevocationReason)

revokesEveryAudit :: RevocationReason -> Bool
revokesEveryAudit = \case
  Rotated -> False
  Compromised -> True
  Malicious -> True

renderRevocationReason :: RevocationReason -> Text
renderRevocationReason = \case
  Rotated -> "rotated"
  Compromised -> "compromised"
  Malicious -> "malicious"

parseRevocationReason :: Text -> RevocationReason
parseRevocationReason = \case
  "rotated" -> Rotated
  "malicious" -> Malicious
  _ -> Compromised
