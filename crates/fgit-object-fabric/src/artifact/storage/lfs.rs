//! SHA-256-content-addressed LFS custody in the existing artifact fabric.
//! OIDs are not Git object IDs. No index, mutable alias or ref publication is
//! introduced. Payloads are retained permanently until pointer-aware retention
//! is implemented; this module never decides what Git history may discard.
use super::{
    ArtifactOperation, ArtifactPut, ArtifactScope, ArtifactStorageError, LocalArtifactStore,
};
use crate::{ArtifactIdentity, ArtifactPayloadKind, MediaType, RetentionProfile};
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::fmt;
use std::io::Read;
use std::path::Path;

pub const TRUST_DOMAIN: &str = "git-lfs-basic-v1";
pub const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const VERSION: &str = "version https://git-lfs.github.com/spec/v1";

/// Raw payload SHA-256, deliberately distinct from native GitOid and artifact ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LfsOid([u8; 32]);
impl LfsOid {
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        if text.len() != 64
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid_lfs_oid");
        }
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        let mut bytes = [0; 32];
        for (out, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
            *out = digit(pair[0]) * 16 + digit(pair[1]);
        }
        Ok(Self(bytes))
    }
    #[must_use]
    pub fn of_payload(bytes: &[u8]) -> Self {
        Self(fgit_crypto::sha256_digest(bytes))
    }
    fn digest(self) -> Digest {
        Digest::new(
            DigestAlgorithmId::try_new(2).expect("SHA-256"),
            DigestBytes::try_new(&self.0).expect("SHA-256 width"),
        )
    }
}
impl fmt::Display for LfsOid {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(out, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// One immutable expected object, including its exact raw byte length.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct LfsObject {
    pub oid: LfsOid,
    pub size: u64,
}
impl LfsObject {
    pub fn parse(oid: &str, size: &str) -> Result<Self, &'static str> {
        if size.is_empty()
            || (size.len() > 1 && size.starts_with('0'))
            || !size.bytes().all(|b| b.is_ascii_digit())
        {
            return Err("invalid_lfs_size");
        }
        Ok(Self {
            oid: LfsOid::parse(oid)?,
            size: size.parse().map_err(|_| "invalid_lfs_size")?,
        })
    }
    /// Canonical, extension-free v1 pointers only. Unsupported extensions,
    /// duplicate fields, alternate versions and trailing content are refused.
    pub fn parse_pointer(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > 1024 {
            return Err("lfs_pointer_limit");
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "invalid_lfs_pointer")?;
        let mut lines = text.split('\n');
        if lines.next() != Some(VERSION) {
            return Err("invalid_lfs_pointer_version");
        }
        let oid = lines
            .next()
            .and_then(|s| s.strip_prefix("oid sha256:"))
            .ok_or("invalid_lfs_pointer_oid")?;
        let size = lines
            .next()
            .and_then(|s| s.strip_prefix("size "))
            .ok_or("invalid_lfs_pointer_size")?;
        if lines.next() != Some("") || lines.next().is_some() {
            return Err("unsupported_lfs_pointer_fields");
        }
        Self::parse(oid, size)
    }
    #[must_use]
    pub fn pointer(self) -> String {
        format!("{VERSION}\noid sha256:{}\nsize {}\n", self.oid, self.size)
    }
    #[must_use]
    pub fn artifact_identity(self) -> ArtifactIdentity {
        ArtifactIdentity::new(
            self.oid.digest(),
            self.size,
            MediaType::parse("application/octet-stream").expect("constant media type"),
            ArtifactPayloadKind::GitLfs,
            None,
            None,
            None,
            RetentionProfile::ReleasePermanent,
        )
    }
}

/// The same immutable storage and verification used by workflow artifacts.
/// The owning authenticated service grants access; this type does not grant it.
#[derive(Clone, Debug)]
pub struct LfsStore(LocalArtifactStore);
impl LfsStore {
    pub fn open(
        root: &Path,
        tenant: TenantId,
        repository: RepositoryId,
        incarnation: RepositoryIncarnationId,
    ) -> Result<Self, ArtifactStorageError> {
        LocalArtifactStore::open(
            root,
            ArtifactScope::new(tenant, repository, incarnation, TRUST_DOMAIN)?,
        )
        .map(Self)
    }
    pub fn put(
        &self,
        object: LfsObject,
        input: &mut impl Read,
        op: &ArtifactOperation<'_>,
    ) -> Result<ArtifactPut, ArtifactStorageError> {
        self.0.put_reader(&object.artifact_identity(), input, op)
    }
    /// A valid name is never enough: verify the complete stored payload.
    pub fn contains(
        &self,
        object: LfsObject,
        op: &ArtifactOperation<'_>,
    ) -> Result<bool, ArtifactStorageError> {
        let identity = object.artifact_identity();
        match self.0.inspect(identity.artifact_id(), op) {
            Ok(observed) if observed == identity => Ok(true),
            Ok(_) => Err(ArtifactStorageError::IdentityMismatch),
            Err(ArtifactStorageError::NotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }
    /// No bytes are disclosed until the entire object verifies. The existing
    /// in-memory artifact profile enforces a 64 MiB maximum independently.
    pub fn read(
        &self,
        object: LfsObject,
        op: &ArtifactOperation<'_>,
    ) -> Result<Vec<u8>, ArtifactStorageError> {
        let identity = object.artifact_identity();
        let (observed, bytes) = self.0.read_payload(identity.artifact_id(), op)?;
        if observed != identity {
            return Err(ArtifactStorageError::IdentityMismatch);
        }
        Ok(bytes)
    }
}
