//! File-backed package/release signing-key boundary.
//!
//! The key file is caller-selected and intentionally outside the repository.
//! It contains root material only long enough to derive the typed
//! `PackageRelease` key; neither the source checkout nor a release manifest
//! receives the root secret bytes.

use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use fgit_crypto::{KeyEpoch, KeyScope, PackageRelease, RootSecret, SecretKey};

/// Loads the release-signing key from an explicit capability boundary.
pub trait ReleaseKeyProvider {
    /// Derives one package/release key or refuses with an actionable typed
    /// boundary error.  Providers must never substitute an ambient default.
    fn load_release_key(&self) -> Result<SecretKey<PackageRelease>, ReleaseKeyRefusal>;
}

/// Production provider for a caller-supplied, owner-only key file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileReleaseKeyProvider {
    path: PathBuf,
}

impl FileReleaseKeyProvider {
    /// Selects an explicit key file.  The path is not read until
    /// [`ReleaseKeyProvider::load_release_key`], so command/environment
    /// parsing stays outside this cryptographic capability boundary.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Caller-selected key file path, retained for diagnostics and policy.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ReleaseKeyProvider for FileReleaseKeyProvider {
    fn load_release_key(&self) -> Result<SecretKey<PackageRelease>, ReleaseKeyRefusal> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ReleaseKeyRefusal::KeyFileAbsent {
                    path: self.path.clone(),
                }
            } else {
                key_io("inspect key file", self.path.clone(), error)
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ReleaseKeyRefusal::KeyFileSymlink {
                path: self.path.clone(),
            });
        }
        if !metadata.is_file() {
            return Err(ReleaseKeyRefusal::KeyFileNotRegular {
                path: self.path.clone(),
            });
        }
        check_owner_only_permissions(&self.path)?;
        if metadata.len() > MAX_KEY_FILE_BYTES {
            return Err(ReleaseKeyRefusal::KeyFileTooLarge {
                path: self.path.clone(),
                bytes: metadata.len(),
            });
        }
        let mut file = File::open(&self.path)
            .map_err(|error| key_io("open key file", self.path.clone(), error))?;
        let mut bytes =
            Vec::with_capacity(usize::try_from(metadata.len()).expect("key file bound fits usize"));
        file.read_to_end(&mut bytes)
            .map_err(|error| key_io("read key file", self.path.clone(), error))?;
        if u64::try_from(bytes.len()).expect("usize fits u64") > MAX_KEY_FILE_BYTES {
            return Err(ReleaseKeyRefusal::KeyFileTooLarge {
                path: self.path.clone(),
                bytes: u64::try_from(bytes.len()).expect("usize fits u64"),
            });
        }
        let encoded =
            std::str::from_utf8(&bytes).map_err(|_| ReleaseKeyRefusal::KeyFileMalformed)?;
        let record = parse_key_record(encoded)?;
        let epoch = KeyEpoch::new(record.epoch).ok_or(ReleaseKeyRefusal::KeyEpochZero)?;
        Ok(SecretKey::derive(
            &RootSecret::from_bytes(record.root_secret),
            epoch,
            KeyScope::OPERATOR,
        ))
    }
}

/// Why a release key could not be loaded without widening authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseKeyRefusal {
    /// No caller-selected key file existed.
    KeyFileAbsent { path: PathBuf },
    /// A symlink would make the selected capability ambiguous.
    KeyFileSymlink { path: PathBuf },
    /// The selected path was not a regular file.
    KeyFileNotRegular { path: PathBuf },
    /// POSIX owner-only mode was absent.  Group/world-readable key material is refused.
    KeyFilePermissions { path: PathBuf, mode: u32 },
    /// This platform cannot inspect the permission boundary required here.
    PermissionInspectionUnsupported { path: PathBuf },
    /// Key input exceeded the bounded parser surface.
    KeyFileTooLarge { path: PathBuf, bytes: u64 },
    /// The key file had no exact supported record framing.
    KeyFileMalformed,
    /// A record declared another cryptographic purpose/domain.
    WrongKeyDomain { observed: String },
    /// A key epoch cannot be zero.
    KeyEpochZero,
    /// Ambient I/O failed without exposing path contents.
    Io {
        operation: &'static str,
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
}

impl fmt::Display for ReleaseKeyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyFileAbsent { path } => {
                write!(f, "release key file {} is absent", path.display())
            }
            Self::KeyFileSymlink { path } => {
                write!(f, "release key file {} is a symlink", path.display())
            }
            Self::KeyFileNotRegular { path } => {
                write!(f, "release key file {} is not regular", path.display())
            }
            Self::KeyFilePermissions { path, mode } => write!(
                f,
                "release key file {} has non-owner-only mode {mode:o}",
                path.display()
            ),
            Self::PermissionInspectionUnsupported { path } => write!(
                f,
                "cannot inspect owner-only permissions for release key file {}",
                path.display()
            ),
            Self::KeyFileTooLarge { path, bytes } => write!(
                f,
                "release key file {} is {bytes} bytes, exceeding its bounded format",
                path.display()
            ),
            Self::KeyFileMalformed => {
                f.write_str("release key file does not match the exact FGIT_RELEASE_KEY_V1 format")
            }
            Self::WrongKeyDomain { observed } => write!(
                f,
                "release key file declares {observed:?}, not package-release"
            ),
            Self::KeyEpochZero => f.write_str("release key file uses reserved epoch zero"),
            Self::Io {
                operation,
                path,
                kind,
            } => write!(
                f,
                "release key {operation} at {} failed with {kind:?}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ReleaseKeyRefusal {}

const MAX_KEY_FILE_BYTES: u64 = 512;
const KEY_HEADER: &str = "FGIT_RELEASE_KEY_V1";

struct KeyRecord {
    epoch: u32,
    root_secret: [u8; 32],
}

fn parse_key_record(input: &str) -> Result<KeyRecord, ReleaseKeyRefusal> {
    let mut lines = input.lines();
    if lines.next() != Some(KEY_HEADER) {
        return Err(ReleaseKeyRefusal::KeyFileMalformed);
    }
    let purpose = lines.next().ok_or(ReleaseKeyRefusal::KeyFileMalformed)?;
    let epoch = lines.next().ok_or(ReleaseKeyRefusal::KeyFileMalformed)?;
    let root_secret = lines.next().ok_or(ReleaseKeyRefusal::KeyFileMalformed)?;
    if lines.next().is_some() {
        return Err(ReleaseKeyRefusal::KeyFileMalformed);
    }
    let observed = purpose
        .strip_prefix("purpose=")
        .ok_or(ReleaseKeyRefusal::KeyFileMalformed)?;
    if observed != "package-release" {
        return Err(ReleaseKeyRefusal::WrongKeyDomain {
            observed: observed.to_owned(),
        });
    }
    let epoch = epoch
        .strip_prefix("epoch=")
        .ok_or(ReleaseKeyRefusal::KeyFileMalformed)?
        .parse::<u32>()
        .map_err(|_| ReleaseKeyRefusal::KeyFileMalformed)?;
    let root_secret = root_secret
        .strip_prefix("root-secret=")
        .ok_or(ReleaseKeyRefusal::KeyFileMalformed)?;
    Ok(KeyRecord {
        epoch,
        root_secret: parse_lower_hex_32(root_secret)?,
    })
}

fn parse_lower_hex_32(text: &str) -> Result<[u8; 32], ReleaseKeyRefusal> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte >= b'a'))
    {
        return Err(ReleaseKeyRefusal::KeyFileMalformed);
    }
    let mut output = [0_u8; 32];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(pair[0]).ok_or(ReleaseKeyRefusal::KeyFileMalformed)?;
        let low = hex_nibble(pair[1]).ok_or(ReleaseKeyRefusal::KeyFileMalformed)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(unix)]
fn check_owner_only_permissions(path: &Path) -> Result<(), ReleaseKeyRefusal> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .map_err(|error| key_io("read key permissions", path.to_path_buf(), error))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(ReleaseKeyRefusal::KeyFilePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_only_permissions(path: &Path) -> Result<(), ReleaseKeyRefusal> {
    Err(ReleaseKeyRefusal::PermissionInspectionUnsupported {
        path: path.to_path_buf(),
    })
}

fn key_io(operation: &'static str, path: PathBuf, error: std::io::Error) -> ReleaseKeyRefusal {
    ReleaseKeyRefusal::Io {
        operation,
        path,
        kind: error.kind(),
    }
}

#[cfg(test)]
pub struct TestRootSecretKeyProvider {
    root: RootSecret,
    epoch: KeyEpoch,
}

#[cfg(test)]
impl TestRootSecretKeyProvider {
    pub(crate) const fn new(root: RootSecret, epoch: KeyEpoch) -> Self {
        Self { root, epoch }
    }
}

#[cfg(test)]
impl ReleaseKeyProvider for TestRootSecretKeyProvider {
    fn load_release_key(&self) -> Result<SecretKey<PackageRelease>, ReleaseKeyRefusal> {
        Ok(SecretKey::derive(
            &self.root,
            self.epoch,
            KeyScope::OPERATOR,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{ReleaseKeyProvider, TestRootSecretKeyProvider};
    use fgit_crypto::{KeyEpoch, RootSecret};

    #[test]
    fn test_root_secret_provider_is_cfg_test_only_and_derives_the_requested_epoch() {
        let provider =
            TestRootSecretKeyProvider::new(RootSecret::from_bytes([0x33; 32]), KeyEpoch::FIRST);
        let key = provider
            .load_release_key()
            .expect("test-only root fixture derives a release-purpose key");
        assert_eq!(key.id().epoch(), KeyEpoch::FIRST);
    }
}
