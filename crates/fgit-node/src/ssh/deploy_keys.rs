//! Live operator-owned deploy-key authorization for one SSH repository.
//!
//! The source retains a path and repository bindings, never an accepted table.
//! Every command reads and validates a complete bounded snapshot. Operators
//! replace the private regular file atomically; an interrupted or invalid
//! replacement refuses authorization until a complete valid file is available.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use fgit_identity::deploy_key::{
    DeployKeyBinding, DeployKeyTableRefusal, MAX_DEPLOY_KEY_TABLE_BYTES, parse_deploy_key_table,
};
use fgit_identity::revocation::RevocationEvidence;
use fgit_ssh::command::SshGitService;
use fgit_ssh::{AuthRefusal, SshCommandAuthorizer, authorize_deploy_key};
use fgit_types::{PrincipalId, RepositoryId};

/// A live SSH authorization file could not be validated completely.
///
/// Diagnostics contain no path, key material or file contents. Command-time
/// failures map to the fixed SSH authorization-source refusal; the constructor
/// exposes this more specific error to the trusted local operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileDeployKeyRefusal {
    /// The source could not be opened, read or inspected.
    Unavailable(io::ErrorKind),
    /// The source is not a stable private regular file.
    UnsafeFile,
    /// The descriptor or source contains more bytes than the admitted envelope.
    TooLarge { observed: u64, limit: usize },
    /// Any row, including a row unrelated to the presented key, is invalid.
    InvalidTable(DeployKeyTableRefusal),
    /// The platform lacks the admitted no-follow/nonblocking file-open profile.
    UnsupportedPlatform,
}

impl Display for FileDeployKeyRefusal {
    fn fmt(&self, out: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(kind) => write!(out, "SSH deploy-key file is unavailable: {kind}"),
            Self::UnsafeFile => {
                out.write_str("SSH deploy-key file must be a stable private regular file")
            }
            Self::TooLarge { observed, limit } => {
                write!(
                    out,
                    "SSH deploy-key file has {observed} bytes; limit is {limit}"
                )
            }
            Self::InvalidTable(error) => write!(out, "SSH deploy-key file is invalid: {error}"),
            Self::UnsupportedPlatform => out.write_str(
                "live SSH deploy-key files require the supported Unix regular-file profile",
            ),
        }
    }
}

impl Error for FileDeployKeyRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidTable(error) => Some(error),
            _ => None,
        }
    }
}

/// Reloads a complete private deploy-key table for every SSH Git command.
///
/// This is an operator-maintained authentication configuration. Each row is
/// `<pubkey-hex> <principal-hex> <scopes>`, where scopes contain `read` and/or
/// `write`. Blank lines and `#` comments are accepted; an empty table revokes
/// every grant. The exact grammar and finite bounds belong to
/// [`parse_deploy_key_table`]. Both repository identifiers are explicit aliases
/// for the same served repository, preserving the static transport profile.
///
/// Construction validates the current file, but authorizations never reuse that
/// table. Atomically replacing the file changes subsequent commands, including
/// a connection that authenticated its SSH signature before the replacement.
/// A command that already received a grant keeps its principal and scopes for
/// its bounded lifetime. An invalid or missing replacement grants nothing.
///
/// The configured path is operator-owned. Final-component symlinks, special
/// files and nonprivate Unix modes are refused; this is not a containment API
/// for hostile parent directories. Unix opens use no-follow and nonblocking
/// flags so racing in a FIFO cannot stall authorization waiting for its writer.
/// Other platforms return [`FileDeployKeyRefusal::UnsupportedPlatform`].
#[derive(Clone)]
pub struct FileDeployKeyAuthorizer {
    path: PathBuf,
    repository_id: RepositoryId,
    route_repository_id: RepositoryId,
}

impl FileDeployKeyAuthorizer {
    /// Validates a live source without caching any of its current grants.
    pub fn try_new(
        path: PathBuf,
        repository_id: RepositoryId,
        route_repository_id: RepositoryId,
    ) -> Result<Self, FileDeployKeyRefusal> {
        #[cfg(not(unix))]
        {
            let _ = (path, repository_id, route_repository_id);
            Err(FileDeployKeyRefusal::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            // Preserve the named path rather than canonicalizing through a
            // symlink, and pin a relative path to the startup working directory.
            let source = Self {
                path: std::path::absolute(path).map_err(unavailable)?,
                repository_id,
                route_repository_id,
            };
            source.read_bindings()?;
            Ok(source)
        }
    }

    fn read_bindings(&self) -> Result<Vec<DeployKeyBinding>, FileDeployKeyRefusal> {
        let before = fs::symlink_metadata(&self.path).map_err(unavailable)?;
        private_regular_metadata(&before)?;
        let file = open_regular_file(&self.path)?;
        let opened = file.metadata().map_err(unavailable)?;
        if !same_file(&before, &opened) {
            return Err(FileDeployKeyRefusal::UnsafeFile);
        }
        let bytes = read_snapshot(file, &opened)?;
        // A replacement during this read may refuse this attempt. It cannot
        // turn an already opened old table into the current path's authority.
        let named = fs::symlink_metadata(&self.path).map_err(unavailable)?;
        private_regular_metadata(&named)?;
        if !same_snapshot(&opened, &named)? {
            return Err(FileDeployKeyRefusal::UnsafeFile);
        }
        parse_deploy_key_table(&bytes, self.repository_id, self.route_repository_id)
            .map_err(FileDeployKeyRefusal::InvalidTable)
    }
}

impl SshCommandAuthorizer for FileDeployKeyAuthorizer {
    fn authorize_command(
        &self,
        authenticated_key: &[u8; 32],
        repository_id: RepositoryId,
        service: SshGitService,
    ) -> Result<PrincipalId, AuthRefusal> {
        let bindings = self
            .read_bindings()
            .map_err(|_| AuthRefusal::AuthorizationSourceUnavailable)?;
        authorize_deploy_key(
            &bindings,
            authenticated_key,
            repository_id,
            service,
            RevocationEvidence::Live,
        )
    }
}

fn unavailable(error: io::Error) -> FileDeployKeyRefusal {
    FileDeployKeyRefusal::Unavailable(error.kind())
}

fn private_regular_metadata(metadata: &Metadata) -> Result<(), FileDeployKeyRefusal> {
    if !metadata.is_file() {
        return Err(FileDeployKeyRefusal::UnsafeFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(FileDeployKeyRefusal::UnsafeFile);
        }
    }
    if metadata.len() > MAX_DEPLOY_KEY_TABLE_BYTES as u64 {
        return Err(FileDeployKeyRefusal::TooLarge {
            observed: metadata.len(),
            limit: MAX_DEPLOY_KEY_TABLE_BYTES,
        });
    }
    Ok(())
}

fn open_regular_file(path: &Path) -> Result<File, FileDeployKeyRefusal> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(FileDeployKeyRefusal::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        // Both flags are required: no-follow refuses a swapped symlink, while
        // nonblocking prevents a swapped FIFO from hanging before fstat.
        let descriptor = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| unavailable(io::Error::from(error)))?;
        let file = File::from(descriptor);
        private_regular_metadata(&file.metadata().map_err(unavailable)?)?;
        Ok(file)
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

fn same_snapshot(left: &Metadata, right: &Metadata) -> Result<bool, FileDeployKeyRefusal> {
    if !same_file(left, right)
        || left.len() != right.len()
        || left.modified().map_err(unavailable)? != right.modified().map_err(unavailable)?
    {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (left.mode(), left.ctime(), left.ctime_nsec())
            != (right.mode(), right.ctime(), right.ctime_nsec())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn read_snapshot(mut file: File, opened: &Metadata) -> Result<Vec<u8>, FileDeployKeyRefusal> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(MAX_DEPLOY_KEY_TABLE_BYTES + 1)
        .map_err(|_| FileDeployKeyRefusal::Unavailable(io::ErrorKind::OutOfMemory))?;
    (&mut file)
        .take((MAX_DEPLOY_KEY_TABLE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    if bytes.len() > MAX_DEPLOY_KEY_TABLE_BYTES {
        return Err(FileDeployKeyRefusal::TooLarge {
            observed: bytes.len() as u64,
            limit: MAX_DEPLOY_KEY_TABLE_BYTES,
        });
    }
    let after = file.metadata().map_err(unavailable)?;
    private_regular_metadata(&after)?;
    if after.len() != bytes.len() as u64 || !same_snapshot(opened, &after)? {
        return Err(FileDeployKeyRefusal::UnsafeFile);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
