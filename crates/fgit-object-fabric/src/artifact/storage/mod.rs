//! Immutable local artifact payloads using the existing ArtifactIdentity.
//! This is staged byte custody, never a repository decision or a cache grant.
//! The root and its ancestors must be protected by the trusted local operator.
use crate::{ArtifactIdentity, ArtifactRefusal};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant};
mod codec;
pub mod lfs;
mod local;
pub use local::LocalArtifactStore;

pub const DEFAULT_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_PAYLOAD_BYTES: u64 = 512 * 1024 * 1024;
const HEADER_BYTES: usize = 8192;
const CHUNK_BYTES: usize = 64 * 1024;
const MAGIC: &[u8; 8] = b"FGAF\0\0\0\x01";

/// A physical isolation namespace, not an authenticated identity or permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactScope {
    tenant: TenantId,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    trust: String,
}
impl ArtifactScope {
    pub fn new(
        tenant: TenantId,
        repository: RepositoryId,
        incarnation: RepositoryIncarnationId,
        trust: &str,
    ) -> Result<Self, ArtifactStorageError> {
        if trust.is_empty()
            || trust.len() > 256
            || !trust
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(ArtifactStorageError::InvalidInput(
                "trust domain must be 1..256 ASCII identifier bytes",
            ));
        }
        Ok(Self {
            tenant,
            repository,
            incarnation,
            trust: trust.to_owned(),
        })
    }
    pub fn trust_domain(&self) -> &str {
        &self.trust
    }
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }
    pub const fn incarnation(&self) -> RepositoryIncarnationId {
        self.incarnation
    }
    pub fn commitment(&self) -> Digest {
        let mut bytes = b"frankengit/artifact-scope/v1\0".to_vec();
        codec::scope_bytes(self, &mut bytes);
        digest(&bytes)
    }
}

/// One absolute operation deadline. Sharing it across calls never resets time.
pub struct ArtifactOperation<'a> {
    maximum_bytes: u64,
    deadline: Instant,
    live: &'a dyn Fn() -> bool,
}
impl<'a> ArtifactOperation<'a> {
    pub fn new(
        maximum_bytes: u64,
        timeout: Duration,
        live: &'a dyn Fn() -> bool,
    ) -> Result<Self, ArtifactStorageError> {
        if maximum_bytes == 0
            || maximum_bytes > MAX_PAYLOAD_BYTES
            || timeout.is_zero()
            || timeout > Duration::from_secs(3600)
        {
            return Err(ArtifactStorageError::InvalidInput(
                "invalid artifact byte or time envelope",
            ));
        }
        Ok(Self {
            maximum_bytes,
            deadline: Instant::now() + timeout,
            live,
        })
    }
    fn checkpoint(&self) -> Result<(), ArtifactStorageError> {
        if !(self.live)() {
            return Err(ArtifactStorageError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(ArtifactStorageError::Deadline);
        }
        Ok(())
    }
    fn admit(&self, bytes: u64) -> Result<(), ArtifactStorageError> {
        self.checkpoint()?;
        if bytes > self.maximum_bytes {
            return Err(ArtifactStorageError::PayloadLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactPut {
    Created,
    AlreadyPresent,
}

#[derive(Debug)]
pub enum ArtifactStorageError {
    InvalidInput(&'static str),
    InvalidIdentity,
    InvalidEncoding,
    ScopeMismatch,
    IdentityMismatch,
    PayloadMismatch,
    PayloadLimit,
    Cancelled,
    Deadline,
    NotFound,
    DestinationExists,
    UnsafePath,
    Io {
        operation: &'static str,
        kind: std::io::ErrorKind,
    },
    /// A final link may exist. Retry/read by exact identity; never overwrite it.
    PublicationUncertain {
        operation: &'static str,
    },
    Artifact(ArtifactRefusal),
}
impl std::fmt::Display for ArtifactStorageError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "artifact storage refused: {self:?}")
    }
}
impl std::error::Error for ArtifactStorageError {}
impl From<ArtifactRefusal> for ArtifactStorageError {
    fn from(error: ArtifactRefusal) -> Self {
        Self::Artifact(error)
    }
}
fn io(operation: &'static str, error: std::io::Error) -> ArtifactStorageError {
    ArtifactStorageError::Io {
        operation,
        kind: error.kind(),
    }
}
fn digest(bytes: &[u8]) -> Digest {
    let mut hash = Sha256Hasher::new();
    DigestHasher::update(&mut hash, bytes);
    finish(hash)
}
fn finish(hash: Sha256Hasher) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(2).expect("registered SHA-256"),
        DigestBytes::try_new(&DigestHasher::finish(hash)).expect("SHA-256 width"),
    )
}
fn valid_digest(value: &Digest) -> Result<(), ArtifactStorageError> {
    if value.algorithm() != DigestAlgorithmId::try_new(2).expect("registered SHA-256")
        || value.bytes().as_bytes().len() != 32
    {
        return Err(ArtifactStorageError::InvalidIdentity);
    }
    Ok(())
}
fn hex(value: &Digest) -> String {
    value
        .bytes()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl LocalArtifactStore {
    /// Verify all bytes before linking an immutable payload. Uses one budget for
    /// source read, durable staging, readback, collision verification and commit.
    pub fn put(
        &self,
        identity: &ArtifactIdentity,
        source: &mut File,
        op: &ArtifactOperation<'_>,
    ) -> Result<ArtifactPut, ArtifactStorageError> {
        self.put_inner(identity, source, op)
    }
    /// Stream a finite, already framed input into the same verified root-last
    /// store as file uploads. Reads exactly the declared length plus one EOF
    /// probe; callers must supply an HTTP body reader, not an unframed socket.
    /// A short, long, interrupted or corrupt stream never installs its name.
    pub fn put_reader(
        &self,
        identity: &ArtifactIdentity,
        source: &mut impl std::io::Read,
        op: &ArtifactOperation<'_>,
    ) -> Result<ArtifactPut, ArtifactStorageError> {
        self.put_reader_inner(identity, source, op)
    }

    /// Verify the complete payload, not just its metadata, without disclosing it.
    pub fn inspect(
        &self,
        id: &Digest,
        op: &ArtifactOperation<'_>,
    ) -> Result<ArtifactIdentity, ArtifactStorageError> {
        self.inspect_inner(id, op)
    }
    /// Verify into a private staging file, then publish to an absent destination.
    /// No corrupt/unverified payload prefix is exposed at the destination path.
    pub fn export(
        &self,
        id: &Digest,
        destination: &Path,
        op: &ArtifactOperation<'_>,
    ) -> Result<ArtifactIdentity, ArtifactStorageError> {
        self.export_inner(id, destination, op)
    }
}
