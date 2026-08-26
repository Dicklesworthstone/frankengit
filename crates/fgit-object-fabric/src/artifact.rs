#![forbid(unsafe_code)]
//! FG-060: Unified immutable payload fabric for artifacts, logs, release assets,
//! SBOMs, provenance, and signatures.
//!
//! # Identity discipline (§30.2)
//!
//! A filename is not an identity. An artifact identity binds:
//! 1. raw payload digest (domain-separated SHA-256),
//! 2. payload byte length,
//! 3. media type (MIME / format slug),
//! 4. payload kind (CI artifact, build log, release asset, SBOM, signature, provenance, Git LFS),
//! 5. producer `BuildInputCapsule` ID (if produced by runner),
//! 6. workflow check receipt ID (if produced by check),
//! 7. source authority head / RCR (source commit),
//! 8. retention / repair profile.
//!
//! # Immutability and canonical manifest
//!
//! Artifact payloads are stored immutably in the object fabric. Multiple artifacts
//! produced by a build or release are assembled into an [`ArtifactManifest`]
//! whose entries are canonically sorted by logical path.

use std::fmt;

use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes, SchemaFamily, SchemaId};

fn digest_from_hasher(hasher: Sha256Hasher) -> Digest {
    let raw = DigestHasher::finish(hasher);
    let bytes = DigestBytes::try_new(&raw).expect("32 bytes is valid digest length");
    Digest::new(
        DigestAlgorithmId::try_new(2).expect("SHA-256 is code point 2"),
        bytes,
    )
}

/// Maximum allowed length in bytes for an artifact media type string.
pub const MAX_MEDIA_TYPE_LEN: usize = 128;
/// Maximum allowed length in bytes for a logical artifact path in a manifest.
pub const MAX_LOGICAL_PATH_LEN: usize = 1024;
/// Maximum number of artifact entries in a single manifest.
pub const MAX_MANIFEST_ENTRIES: usize = 65_536;

/// Schema ID for artifact identity preimages.
pub const ARTIFACT_IDENTITY_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("frankengit.artifact-identity"),
    1,
    0,
);

/// Schema ID for canonical artifact manifests.
pub const ARTIFACT_MANIFEST_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("frankengit.artifact-manifest"),
    1,
    0,
);

/// Domain tag for artifact identity hashing.
const ARTIFACT_IDENTITY_DOMAIN: &[u8] = b"frankengit/artifact-identity/v1\0";
/// Domain tag for artifact manifest hashing.
const ARTIFACT_MANIFEST_DOMAIN: &[u8] = b"frankengit/artifact-manifest/v1\0";

/// Typed classification of an immutable payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ArtifactPayloadKind {
    /// CI workflow job build artifact (tarball, binary, test report).
    CiArtifact = 1,
    /// Raw console / execution log from a workflow or runner.
    BuildLog = 2,
    /// Distribution binary / tarball / package for a software release.
    ReleaseAsset = 3,
    /// Software Bill of Materials (SPDX / CycloneDX).
    Sbom = 4,
    /// Cryptographic detached signature or certificate.
    Signature = 5,
    /// In-toto / build provenance attestation document.
    Provenance = 6,
    /// Git LFS pointer-addressed large blob.
    GitLfs = 7,
}

impl ArtifactPayloadKind {
    /// Canonical wire code for this payload kind.
    #[must_use]
    pub const fn wire_code(self) -> u8 {
        self as u8
    }

    /// Decodes a payload kind from its wire code.
    pub fn from_wire_code(code: u8) -> Result<Self, ArtifactRefusal> {
        match code {
            1 => Ok(Self::CiArtifact),
            2 => Ok(Self::BuildLog),
            3 => Ok(Self::ReleaseAsset),
            4 => Ok(Self::Sbom),
            5 => Ok(Self::Signature),
            6 => Ok(Self::Provenance),
            7 => Ok(Self::GitLfs),
            other => Err(ArtifactRefusal::UnknownPayloadKind(other)),
        }
    }

    /// Descriptive label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CiArtifact => "ci_artifact",
            Self::BuildLog => "build_log",
            Self::ReleaseAsset => "release_asset",
            Self::Sbom => "sbom",
            Self::Signature => "signature",
            Self::Provenance => "provenance",
            Self::GitLfs => "git_lfs",
        }
    }
}

impl fmt::Display for ArtifactPayloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Retention and lifecycle profile for an artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetentionProfile {
    /// Ephemeral scratch payload with explicit time-to-live.
    HotEphemeral { ttl_seconds: u64 },
    /// Standard workflow build log with day-based retention.
    StandardLog { retain_days: u32 },
    /// Permanent release asset that is never automatically purged by GC.
    ReleasePermanent,
    /// Indefinite hold for compliance or legal investigations.
    LegalHold { hold_id: u64, reason: String },
}

impl RetentionProfile {
    /// Encodes the retention profile into deterministic canonical bytes.
    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::HotEphemeral { ttl_seconds } => {
                buf.push(1);
                buf.extend_from_slice(&ttl_seconds.to_be_bytes());
            }
            Self::StandardLog { retain_days } => {
                buf.push(2);
                buf.extend_from_slice(&retain_days.to_be_bytes());
            }
            Self::ReleasePermanent => {
                buf.push(3);
            }
            Self::LegalHold { hold_id, reason } => {
                buf.push(4);
                buf.extend_from_slice(&hold_id.to_be_bytes());
                let reason_bytes = reason.as_bytes();
                buf.extend_from_slice(&(reason_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(reason_bytes);
            }
        }
        buf
    }

    /// Decodes a retention profile from canonical bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ArtifactRefusal> {
        if bytes.is_empty() {
            return Err(ArtifactRefusal::Truncated);
        }
        match bytes[0] {
            1 => {
                if bytes.len() != 9 {
                    return Err(ArtifactRefusal::MalformedRetentionProfile);
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes[1..9]);
                Ok(Self::HotEphemeral {
                    ttl_seconds: u64::from_be_bytes(arr),
                })
            }
            2 => {
                if bytes.len() != 5 {
                    return Err(ArtifactRefusal::MalformedRetentionProfile);
                }
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&bytes[1..5]);
                Ok(Self::StandardLog {
                    retain_days: u32::from_be_bytes(arr),
                })
            }
            3 => {
                if bytes.len() != 1 {
                    return Err(ArtifactRefusal::MalformedRetentionProfile);
                }
                Ok(Self::ReleasePermanent)
            }
            4 => {
                if bytes.len() < 13 {
                    return Err(ArtifactRefusal::MalformedRetentionProfile);
                }
                let mut id_arr = [0u8; 8];
                id_arr.copy_from_slice(&bytes[1..9]);
                let hold_id = u64::from_be_bytes(id_arr);

                let mut len_arr = [0u8; 4];
                len_arr.copy_from_slice(&bytes[9..13]);
                let reason_len = u32::from_be_bytes(len_arr) as usize;
                if bytes.len() != 13 + reason_len {
                    return Err(ArtifactRefusal::MalformedRetentionProfile);
                }
                let reason = String::from_utf8(bytes[13..13 + reason_len].to_vec())
                    .map_err(|_| ArtifactRefusal::InvalidUtf8)?;
                Ok(Self::LegalHold { hold_id, reason })
            }
            _ => Err(ArtifactRefusal::MalformedRetentionProfile),
        }
    }

    /// True if this profile protects the asset permanently from GC.
    #[must_use]
    pub const fn is_permanent(&self) -> bool {
        matches!(self, Self::ReleasePermanent | Self::LegalHold { .. })
    }
}

/// Validated media type / MIME string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MediaType(String);

impl MediaType {
    /// Creates a validated media type.
    pub fn parse(s: impl Into<String>) -> Result<Self, ArtifactRefusal> {
        let string = s.into();
        if string.is_empty() {
            return Err(ArtifactRefusal::EmptyMediaType);
        }
        if string.len() > MAX_MEDIA_TYPE_LEN {
            return Err(ArtifactRefusal::MediaTypeTooLong {
                offered: string.len(),
                maximum: MAX_MEDIA_TYPE_LEN,
            });
        }
        if !string.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b == b'/'
                || b == b'.'
                || b == b'-'
                || b == b'+'
                || b == b'_'
        }) {
            return Err(ArtifactRefusal::InvalidMediaTypeCharacters);
        }
        Ok(Self(string))
    }

    /// Accesses the underlying media type string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Canonical, immutable identity of an artifact (§30.2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactIdentity {
    payload_digest: Digest,
    payload_len: u64,
    media_type: MediaType,
    payload_kind: ArtifactPayloadKind,
    build_capsule_id: Option<Digest>,
    check_receipt_id: Option<Digest>,
    source_rcr: Option<Digest>,
    retention_profile: RetentionProfile,
    artifact_id: Digest,
}

impl ArtifactIdentity {
    /// Constructs a verified artifact identity from its structural parameters.
    pub fn new(
        payload_digest: Digest,
        payload_len: u64,
        media_type: MediaType,
        payload_kind: ArtifactPayloadKind,
        build_capsule_id: Option<Digest>,
        check_receipt_id: Option<Digest>,
        source_rcr: Option<Digest>,
        retention_profile: RetentionProfile,
    ) -> Self {
        let artifact_id = Self::compute_artifact_id(
            &payload_digest,
            payload_len,
            &media_type,
            payload_kind,
            build_capsule_id.as_ref(),
            check_receipt_id.as_ref(),
            source_rcr.as_ref(),
            &retention_profile,
        );

        Self {
            payload_digest,
            payload_len,
            media_type,
            payload_kind,
            build_capsule_id,
            check_receipt_id,
            source_rcr,
            retention_profile,
            artifact_id,
        }
    }

    /// Computes the deterministic SHA-256 artifact ID over the canonical preimage.
    fn compute_artifact_id(
        payload_digest: &Digest,
        payload_len: u64,
        media_type: &MediaType,
        payload_kind: ArtifactPayloadKind,
        build_capsule_id: Option<&Digest>,
        check_receipt_id: Option<&Digest>,
        source_rcr: Option<&Digest>,
        retention_profile: &RetentionProfile,
    ) -> Digest {
        let mut hasher = Sha256Hasher::new();
        DigestHasher::update(&mut hasher, ARTIFACT_IDENTITY_DOMAIN);
        DigestHasher::update(&mut hasher, payload_digest.bytes().as_bytes());
        DigestHasher::update(&mut hasher, &payload_len.to_be_bytes());
        DigestHasher::update(&mut hasher, &[payload_kind.wire_code()]);
        DigestHasher::update(
            &mut hasher,
            &(media_type.as_str().len() as u32).to_be_bytes(),
        );
        DigestHasher::update(&mut hasher, media_type.as_str().as_bytes());

        match build_capsule_id {
            Some(id) => {
                DigestHasher::update(&mut hasher, &[1]);
                DigestHasher::update(&mut hasher, id.bytes().as_bytes());
            }
            None => {
                DigestHasher::update(&mut hasher, &[0]);
            }
        }

        match check_receipt_id {
            Some(id) => {
                DigestHasher::update(&mut hasher, &[1]);
                DigestHasher::update(&mut hasher, id.bytes().as_bytes());
            }
            None => {
                DigestHasher::update(&mut hasher, &[0]);
            }
        }

        match source_rcr {
            Some(id) => {
                DigestHasher::update(&mut hasher, &[1]);
                DigestHasher::update(&mut hasher, id.bytes().as_bytes());
            }
            None => {
                DigestHasher::update(&mut hasher, &[0]);
            }
        }

        let retention_bytes = retention_profile.encode_canonical();
        DigestHasher::update(&mut hasher, &(retention_bytes.len() as u32).to_be_bytes());
        DigestHasher::update(&mut hasher, &retention_bytes);

        digest_from_hasher(hasher)
    }

    /// The computed unique canonical artifact identifier.
    #[must_use]
    pub const fn artifact_id(&self) -> &Digest {
        &self.artifact_id
    }

    /// Digest of the raw payload bytes.
    #[must_use]
    pub const fn payload_digest(&self) -> &Digest {
        &self.payload_digest
    }

    /// Length of the raw payload in bytes.
    #[must_use]
    pub const fn payload_len(&self) -> u64 {
        self.payload_len
    }

    /// Media / MIME type.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }

    /// Payload classification.
    #[must_use]
    pub const fn payload_kind(&self) -> ArtifactPayloadKind {
        self.payload_kind
    }

    /// Optional producer `BuildInputCapsule` identifier.
    #[must_use]
    pub const fn build_capsule_id(&self) -> Option<&Digest> {
        self.build_capsule_id.as_ref()
    }

    /// Optional check receipt identifier.
    #[must_use]
    pub const fn check_receipt_id(&self) -> Option<&Digest> {
        self.check_receipt_id.as_ref()
    }

    /// Optional source commit authority head / RCR identifier.
    #[must_use]
    pub const fn source_rcr(&self) -> Option<&Digest> {
        self.source_rcr.as_ref()
    }

    /// Retention policy.
    #[must_use]
    pub const fn retention_profile(&self) -> &RetentionProfile {
        &self.retention_profile
    }

    /// Verifies that the provided raw payload bytes match this identity exactly.
    pub fn verify_payload(&self, bytes: &[u8]) -> Result<(), ArtifactRefusal> {
        if bytes.len() as u64 != self.payload_len {
            return Err(ArtifactRefusal::PayloadLengthMismatch {
                expected: self.payload_len,
                actual: bytes.len() as u64,
            });
        }
        let mut hasher = Sha256Hasher::new();
        DigestHasher::update(&mut hasher, bytes);
        let actual_digest = digest_from_hasher(hasher);
        if actual_digest != self.payload_digest {
            return Err(ArtifactRefusal::PayloadDigestMismatch {
                expected: self.payload_digest,
                actual: actual_digest,
            });
        }
        Ok(())
    }
}

/// An entry in an [`ArtifactManifest`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactEntry {
    logical_path: String,
    artifact_id: Digest,
    payload_digest: Digest,
    size_bytes: u64,
    payload_kind: ArtifactPayloadKind,
    media_type: MediaType,
}

impl ArtifactEntry {
    /// Constructs a validated artifact entry.
    pub fn new(
        logical_path: impl Into<String>,
        identity: &ArtifactIdentity,
    ) -> Result<Self, ArtifactRefusal> {
        let path = logical_path.into();
        Self::validate_path(&path)?;

        Ok(Self {
            logical_path: path,
            artifact_id: *identity.artifact_id(),
            payload_digest: *identity.payload_digest(),
            size_bytes: identity.payload_len(),
            payload_kind: identity.payload_kind(),
            media_type: identity.media_type().clone(),
        })
    }

    fn validate_path(path: &str) -> Result<(), ArtifactRefusal> {
        if path.is_empty() {
            return Err(ArtifactRefusal::EmptyLogicalPath);
        }
        if path.len() > MAX_LOGICAL_PATH_LEN {
            return Err(ArtifactRefusal::LogicalPathTooLong {
                offered: path.len(),
                maximum: MAX_LOGICAL_PATH_LEN,
            });
        }
        if path.starts_with('/') || path.starts_with('\\') {
            return Err(ArtifactRefusal::AbsolutePathForbidden);
        }
        for component in path.split('/') {
            if component == ".." {
                return Err(ArtifactRefusal::PathTraversalForbidden);
            }
            if component == "." {
                return Err(ArtifactRefusal::DotComponentForbidden);
            }
        }
        Ok(())
    }

    /// Logical relative path.
    #[must_use]
    pub fn logical_path(&self) -> &str {
        &self.logical_path
    }

    /// Canonical artifact identifier.
    #[must_use]
    pub const fn artifact_id(&self) -> &Digest {
        &self.artifact_id
    }

    /// Raw payload digest.
    #[must_use]
    pub const fn payload_digest(&self) -> &Digest {
        &self.payload_digest
    }

    /// Payload size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Payload kind.
    #[must_use]
    pub const fn payload_kind(&self) -> ArtifactPayloadKind {
        self.payload_kind
    }

    /// Media type.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }
}

/// A canonical manifest grouping multiple immutable artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactManifest {
    entries: Vec<ArtifactEntry>,
    manifest_digest: Digest,
}

impl ArtifactManifest {
    /// Constructs a verified artifact manifest from entries.
    ///
    /// Entries are canonically sorted by logical path and deduplicated.
    pub fn new(mut entries: Vec<ArtifactEntry>) -> Result<Self, ArtifactRefusal> {
        if entries.is_empty() {
            return Err(ArtifactRefusal::EmptyManifest);
        }
        if entries.len() > MAX_MANIFEST_ENTRIES {
            return Err(ArtifactRefusal::TooManyManifestEntries {
                offered: entries.len(),
                maximum: MAX_MANIFEST_ENTRIES,
            });
        }

        // Canonical sort by logical_path
        entries.sort_by(|a, b| a.logical_path.cmp(&b.logical_path));

        // Ensure distinct paths
        for window in entries.windows(2) {
            if window[0].logical_path == window[1].logical_path {
                return Err(ArtifactRefusal::DuplicateLogicalPath(
                    window[0].logical_path.clone(),
                ));
            }
        }

        let manifest_digest = Self::compute_manifest_digest(&entries);
        Ok(Self {
            entries,
            manifest_digest,
        })
    }

    fn compute_manifest_digest(entries: &[ArtifactEntry]) -> Digest {
        let mut hasher = Sha256Hasher::new();
        DigestHasher::update(&mut hasher, ARTIFACT_MANIFEST_DOMAIN);
        DigestHasher::update(&mut hasher, &(entries.len() as u32).to_be_bytes());
        for entry in entries {
            DigestHasher::update(
                &mut hasher,
                &(entry.logical_path.len() as u32).to_be_bytes(),
            );
            DigestHasher::update(&mut hasher, entry.logical_path.as_bytes());
            DigestHasher::update(&mut hasher, entry.artifact_id.bytes().as_bytes());
            DigestHasher::update(&mut hasher, entry.payload_digest.bytes().as_bytes());
            DigestHasher::update(&mut hasher, &entry.size_bytes.to_be_bytes());
            DigestHasher::update(&mut hasher, &[entry.payload_kind.wire_code()]);
            DigestHasher::update(
                &mut hasher,
                &(entry.media_type.as_str().len() as u32).to_be_bytes(),
            );
            DigestHasher::update(&mut hasher, entry.media_type.as_str().as_bytes());
        }
        digest_from_hasher(hasher)
    }

    /// The list of sorted entries in this manifest.
    #[must_use]
    pub fn entries(&self) -> &[ArtifactEntry] {
        &self.entries
    }

    /// The canonical manifest digest.
    #[must_use]
    pub const fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    /// Looks up an entry by its logical path.
    #[must_use]
    pub fn find_entry(&self, path: &str) -> Option<&ArtifactEntry> {
        self.entries
            .binary_search_by(|entry| entry.logical_path.as_str().cmp(path))
            .ok()
            .map(|idx| &self.entries[idx])
    }
}

/// Typed refusals for artifact operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactRefusal {
    EmptyMediaType,
    MediaTypeTooLong { offered: usize, maximum: usize },
    InvalidMediaTypeCharacters,
    EmptyLogicalPath,
    LogicalPathTooLong { offered: usize, maximum: usize },
    AbsolutePathForbidden,
    PathTraversalForbidden,
    DotComponentForbidden,
    EmptyManifest,
    TooManyManifestEntries { offered: usize, maximum: usize },
    DuplicateLogicalPath(String),
    UnknownPayloadKind(u8),
    Truncated,
    MalformedRetentionProfile,
    InvalidUtf8,
    PayloadLengthMismatch { expected: u64, actual: u64 },
    PayloadDigestMismatch { expected: Digest, actual: Digest },
    ArtifactNotFound(Digest),
}

impl fmt::Display for ArtifactRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMediaType => f.write_str("media type string cannot be empty"),
            Self::MediaTypeTooLong { offered, maximum } => write!(
                f,
                "media type string is too long: offered {offered} bytes, maximum {maximum}"
            ),
            Self::InvalidMediaTypeCharacters => {
                f.write_str("media type string contains invalid non-MIME characters")
            }
            Self::EmptyLogicalPath => f.write_str("logical path cannot be empty"),
            Self::LogicalPathTooLong { offered, maximum } => write!(
                f,
                "logical path is too long: offered {offered} bytes, maximum {maximum}"
            ),
            Self::AbsolutePathForbidden => f.write_str("absolute paths are forbidden in manifests"),
            Self::PathTraversalForbidden => {
                f.write_str("path traversal ('..') is forbidden in logical paths")
            }
            Self::DotComponentForbidden => {
                f.write_str("relative dot component ('.') is forbidden in logical paths")
            }
            Self::EmptyManifest => f.write_str("artifact manifest cannot be empty"),
            Self::TooManyManifestEntries { offered, maximum } => write!(
                f,
                "too many entries in manifest: offered {offered}, maximum {maximum}"
            ),
            Self::DuplicateLogicalPath(path) => {
                write!(f, "duplicate logical path in manifest: '{path}'")
            }
            Self::UnknownPayloadKind(code) => {
                write!(f, "unknown artifact payload kind wire code: {code}")
            }
            Self::Truncated => f.write_str("truncated byte stream"),
            Self::MalformedRetentionProfile => f.write_str("malformed retention profile encoding"),
            Self::InvalidUtf8 => f.write_str("invalid UTF-8 string encoding"),
            Self::PayloadLengthMismatch { expected, actual } => write!(
                f,
                "payload length mismatch: expected {expected} bytes, actual {actual} bytes"
            ),
            Self::PayloadDigestMismatch { expected, actual } => write!(
                f,
                "payload digest mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ArtifactNotFound(id) => write!(f, "artifact not found: {id:?}"),
        }
    }
}

impl std::error::Error for ArtifactRefusal {}
