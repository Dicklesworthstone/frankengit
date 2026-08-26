#![forbid(unsafe_code)]
//! FG-060: Package namespace publication, version aliases, and lifecycle events (§30.3).
//!
//! # Namespace publication discipline
//!
//! Publishing a package version, artifact alias, or release asset is an intent over
//! an exact namespace basis:
//! 1. expected absence / current value / yank state (CAS precondition),
//! 2. admitted verified artifact payload,
//! 3. provenance and retention obligations,
//! 4. immutable publication event emitted upon success.
//!
//! Conflicting concurrent publish claims are ordered strictly: exactly one winner succeeds,
//! and the loser receives a typed refusal (`VersionAlreadyExists`). Hidden storage overwrites
//! are impossible. Yanking or deprecating a version emits an immutable event without
//! deleting the payload.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::RwLock;

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

use crate::artifact::RetentionProfile;

/// Maximum allowed length in bytes for a package namespace string.
pub const MAX_NAMESPACE_LEN: usize = 256;
/// Maximum allowed length in bytes for a package version string.
pub const MAX_VERSION_LEN: usize = 128;

/// Schema ID for package publication events.
pub const PACKAGE_PUBLICATION_EVENT_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("frankengit.package-publication-event"),
    1,
    0,
);

/// Domain tag for package event hashing.
const PACKAGE_EVENT_DOMAIN: &[u8] = b"frankengit/package-event/v1\0";

/// Validated package namespace (e.g. `pkg:generic/org/tool` or `workflow-artifacts/run-99`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageNamespace(String);

impl PackageNamespace {
    /// Parses and validates a package namespace.
    pub fn parse(s: impl Into<String>) -> Result<Self, PackageRefusal> {
        let string = s.into();
        if string.is_empty() {
            return Err(PackageRefusal::EmptyNamespace);
        }
        if string.len() > MAX_NAMESPACE_LEN {
            return Err(PackageRefusal::NamespaceTooLong {
                offered: string.len(),
                maximum: MAX_NAMESPACE_LEN,
            });
        }
        if !string.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b == b':'
                || b == b'/'
                || b == b'.'
                || b == b'-'
                || b == b'_'
                || b == b'@'
        }) {
            return Err(PackageRefusal::InvalidNamespaceCharacters);
        }
        if string.starts_with('/') || string.ends_with('/') {
            return Err(PackageRefusal::InvalidNamespaceFormatting);
        }
        Ok(Self(string))
    }

    /// Accesses the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackageNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validated package version (e.g. `1.2.3`, `v0.1.0-alpha`, `build-20260826`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageVersion(String);

impl PackageVersion {
    /// Parses and validates a package version string.
    pub fn parse(s: impl Into<String>) -> Result<Self, PackageRefusal> {
        let string = s.into();
        if string.is_empty() {
            return Err(PackageRefusal::EmptyVersion);
        }
        if string.len() > MAX_VERSION_LEN {
            return Err(PackageRefusal::VersionTooLong {
                offered: string.len(),
                maximum: MAX_VERSION_LEN,
            });
        }
        if !string
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'+' || b == b'_')
        {
            return Err(PackageRefusal::InvalidVersionCharacters);
        }
        Ok(Self(string))
    }

    /// Accesses the underlying version string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lifecycle status of a published package version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VersionState {
    /// Active and available for download.
    Active,
    /// Yanked with a reason and timestamp (prevents new dependency resolution, retained for reproducibility).
    Yanked {
        reason: String,
        yanked_at_unix_secs: u64,
    },
    /// Deprecated with an advisory message.
    Deprecated { message: String },
}

impl VersionState {
    /// Wire tag for this state.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Yanked { .. } => 2,
            Self::Deprecated { .. } => 3,
        }
    }

    /// True if the version is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// True if the version is yanked.
    #[must_use]
    pub const fn is_yanked(&self) -> bool {
        matches!(self, Self::Yanked { .. })
    }
}

/// Expected state precondition for atomic publication / mutation (§30.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedNamespaceBasis {
    /// Version must not exist yet. Fails closed if the version is already published.
    MustNotExist,
    /// Version must already exist with the exact specified artifact ID and state.
    MustMatchState {
        expected_artifact_id: Digest,
        expected_state_tag: u8,
    },
    /// Any existing state is accepted (used for metadata updates).
    AnyExisting,
}

/// Intent to publish a package version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishIntent {
    pub namespace: PackageNamespace,
    pub version: PackageVersion,
    pub artifact_id: Digest,
    pub expected_basis: ExpectedNamespaceBasis,
    pub retention_profile: RetentionProfile,
    pub publisher: String,
    pub timestamp_unix_secs: u64,
}

/// Intent to yank an existing package version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YankIntent {
    pub namespace: PackageNamespace,
    pub version: PackageVersion,
    pub expected_artifact_id: Digest,
    pub reason: String,
    pub yanked_by: String,
    pub timestamp_unix_secs: u64,
}

/// Immutable event emitted when a namespace mutation commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespacePublicationEvent {
    VersionPublished {
        event_id: Digest,
        namespace: PackageNamespace,
        version: PackageVersion,
        artifact_id: Digest,
        retention_profile: RetentionProfile,
        publisher: String,
        published_at_unix_secs: u64,
    },
    VersionYanked {
        event_id: Digest,
        namespace: PackageNamespace,
        version: PackageVersion,
        artifact_id: Digest,
        reason: String,
        yanked_by: String,
        yanked_at_unix_secs: u64,
    },
    VersionDeprecated {
        event_id: Digest,
        namespace: PackageNamespace,
        version: PackageVersion,
        message: String,
        deprecated_by: String,
        deprecated_at_unix_secs: u64,
    },
}

impl NamespacePublicationEvent {
    /// The unique canonical event ID.
    #[must_use]
    pub const fn event_id(&self) -> &Digest {
        match self {
            Self::VersionPublished { event_id, .. }
            | Self::VersionYanked { event_id, .. }
            | Self::VersionDeprecated { event_id, .. } => event_id,
        }
    }
}

/// Stored record of a published version in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredVersionRecord {
    pub artifact_id: Digest,
    pub state: VersionState,
    pub retention_profile: RetentionProfile,
    pub initial_published_at_unix_secs: u64,
    pub publisher: String,
    pub history_events: Vec<NamespacePublicationEvent>,
}

/// In-memory / thread-safe registry tracking published package namespaces.
#[derive(Debug, Default)]
pub struct PackageRegistry {
    namespaces: RwLock<BTreeMap<(PackageNamespace, PackageVersion), StoredVersionRecord>>,
}

impl PackageRegistry {
    /// Creates a new empty package registry.
    pub fn new() -> Self {
        Self {
            namespaces: RwLock::new(BTreeMap::new()),
        }
    }

    /// Atomically executes a [`PublishIntent`].
    ///
    /// If another publisher concurrently raced and published the same `(namespace, version)`,
    /// this function refuses with [`PackageRefusal::VersionAlreadyExists`].
    pub fn publish(
        &self,
        intent: PublishIntent,
    ) -> Result<NamespacePublicationEvent, PackageRefusal> {
        let mut map = self
            .namespaces
            .write()
            .map_err(|_| PackageRefusal::RegistryLockPoisoned)?;

        let key = (intent.namespace.clone(), intent.version.clone());

        match &intent.expected_basis {
            ExpectedNamespaceBasis::MustNotExist => {
                if let Some(existing) = map.get(&key) {
                    return Err(PackageRefusal::VersionAlreadyExists {
                        namespace: intent.namespace.to_string(),
                        version: intent.version.to_string(),
                        existing_artifact_id: existing.artifact_id,
                    });
                }
            }
            ExpectedNamespaceBasis::MustMatchState {
                expected_artifact_id,
                expected_state_tag,
            } => match map.get(&key) {
                None => {
                    return Err(PackageRefusal::VersionNotFound {
                        namespace: intent.namespace.to_string(),
                        version: intent.version.to_string(),
                    });
                }
                Some(existing) => {
                    if existing.artifact_id != *expected_artifact_id
                        || existing.state.tag() != *expected_state_tag
                    {
                        return Err(PackageRefusal::StatePreconditionFailed {
                            namespace: intent.namespace.to_string(),
                            version: intent.version.to_string(),
                            expected_artifact: *expected_artifact_id,
                            actual_artifact: existing.artifact_id,
                        });
                    }
                }
            },
            ExpectedNamespaceBasis::AnyExisting => {
                if !map.contains_key(&key) {
                    return Err(PackageRefusal::VersionNotFound {
                        namespace: intent.namespace.to_string(),
                        version: intent.version.to_string(),
                    });
                }
            }
        }

        let event_id = Self::compute_publish_event_id(
            &intent.namespace,
            &intent.version,
            &intent.artifact_id,
            intent.timestamp_unix_secs,
            &intent.publisher,
        );

        let event = NamespacePublicationEvent::VersionPublished {
            event_id,
            namespace: intent.namespace.clone(),
            version: intent.version.clone(),
            artifact_id: intent.artifact_id,
            retention_profile: intent.retention_profile.clone(),
            publisher: intent.publisher.clone(),
            published_at_unix_secs: intent.timestamp_unix_secs,
        };

        let record = StoredVersionRecord {
            artifact_id: intent.artifact_id,
            state: VersionState::Active,
            retention_profile: intent.retention_profile,
            initial_published_at_unix_secs: intent.timestamp_unix_secs,
            publisher: intent.publisher,
            history_events: vec![event.clone()],
        };

        map.insert(key, record);
        Ok(event)
    }

    /// Atomically executes a [`YankIntent`].
    pub fn yank(&self, intent: YankIntent) -> Result<NamespacePublicationEvent, PackageRefusal> {
        let mut map = self
            .namespaces
            .write()
            .map_err(|_| PackageRefusal::RegistryLockPoisoned)?;

        let key = (intent.namespace.clone(), intent.version.clone());
        let record = map
            .get_mut(&key)
            .ok_or_else(|| PackageRefusal::VersionNotFound {
                namespace: intent.namespace.to_string(),
                version: intent.version.to_string(),
            })?;

        if record.artifact_id != intent.expected_artifact_id {
            return Err(PackageRefusal::StatePreconditionFailed {
                namespace: intent.namespace.to_string(),
                version: intent.version.to_string(),
                expected_artifact: intent.expected_artifact_id,
                actual_artifact: record.artifact_id,
            });
        }

        if record.state.is_yanked() {
            return Err(PackageRefusal::VersionAlreadyYanked {
                namespace: intent.namespace.to_string(),
                version: intent.version.to_string(),
            });
        }

        let event_id = Self::compute_yank_event_id(
            &intent.namespace,
            &intent.version,
            &intent.expected_artifact_id,
            &intent.reason,
            intent.timestamp_unix_secs,
            &intent.yanked_by,
        );

        let event = NamespacePublicationEvent::VersionYanked {
            event_id,
            namespace: intent.namespace.clone(),
            version: intent.version.clone(),
            artifact_id: intent.expected_artifact_id,
            reason: intent.reason.clone(),
            yanked_by: intent.yanked_by,
            yanked_at_unix_secs: intent.timestamp_unix_secs,
        };

        record.state = VersionState::Yanked {
            reason: intent.reason,
            yanked_at_unix_secs: intent.timestamp_unix_secs,
        };
        record.history_events.push(event.clone());

        Ok(event)
    }

    /// Looks up a package version record.
    pub fn get_version(
        &self,
        namespace: &PackageNamespace,
        version: &PackageVersion,
    ) -> Result<Option<StoredVersionRecord>, PackageRefusal> {
        let map = self
            .namespaces
            .read()
            .map_err(|_| PackageRefusal::RegistryLockPoisoned)?;
        Ok(map.get(&(namespace.clone(), version.clone())).cloned())
    }

    /// Lists all versions published under a namespace.
    pub fn list_versions(
        &self,
        namespace: &PackageNamespace,
    ) -> Result<Vec<(PackageVersion, StoredVersionRecord)>, PackageRefusal> {
        let map = self
            .namespaces
            .read()
            .map_err(|_| PackageRefusal::RegistryLockPoisoned)?;

        let mut results = Vec::new();
        for ((ns, ver), record) in map.iter() {
            if ns == namespace {
                results.push((ver.clone(), record.clone()));
            }
        }
        results.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(results)
    }

    /// Computes all active artifact IDs across the registry for GC root calculations.
    pub fn collect_live_artifact_ids(&self) -> Result<Vec<Digest>, PackageRefusal> {
        let map = self
            .namespaces
            .read()
            .map_err(|_| PackageRefusal::RegistryLockPoisoned)?;
        let mut ids = Vec::with_capacity(map.len());
        for record in map.values() {
            ids.push(record.artifact_id);
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    fn compute_publish_event_id(
        ns: &PackageNamespace,
        ver: &PackageVersion,
        art: &Digest,
        ts: u64,
        pub_actor: &str,
    ) -> Digest {
        let mut hasher = Sha256Hasher::new();
        DigestHasher::update(&mut hasher, PACKAGE_EVENT_DOMAIN);
        DigestHasher::update(&mut hasher, &[1]); // publish tag
        DigestHasher::update(&mut hasher, &(ns.as_str().len() as u32).to_be_bytes());
        DigestHasher::update(&mut hasher, ns.as_str().as_bytes());
        DigestHasher::update(&mut hasher, &(ver.as_str().len() as u32).to_be_bytes());
        DigestHasher::update(&mut hasher, ver.as_str().as_bytes());
        DigestHasher::update(&mut hasher, art.bytes().as_bytes());
        DigestHasher::update(&mut hasher, &ts.to_be_bytes());
        DigestHasher::update(&mut hasher, &(pub_actor.len() as u32).to_be_bytes());
        DigestHasher::update(&mut hasher, pub_actor.as_bytes());
        digest_from_hasher(hasher)
    }

    fn compute_yank_event_id(
        ns: &PackageNamespace,
        ver: &PackageVersion,
        art: &Digest,
        reason: &str,
        ts: u64,
        yank_actor: &str,
    ) -> Digest {
        let mut hasher = Sha256Hasher::new();
        DigestHasher::update(&mut hasher, PACKAGE_EVENT_DOMAIN);
        DigestHasher::update(&mut hasher, &[2]); // yank tag
        DigestHasher::update(&mut hasher, &(ns.as_str().len() as u32).to_be_bytes());
        DigestHasher::update(&mut hasher, ns.as_str().as_bytes());
        DigestHasher::update(&mut hasher, &(ver.as_str().len() as u32).to_be_bytes());
        DigestHasher::update(&mut hasher, ver.as_str().as_bytes());
        DigestHasher::update(&mut hasher, art.bytes().as_bytes());
        DigestHasher::update(&mut hasher, &(reason.len() as u32).to_be_bytes());
        DigestHasher::update(&mut hasher, reason.as_bytes());
        DigestHasher::update(&mut hasher, &ts.to_be_bytes());
        DigestHasher::update(&mut hasher, &(yank_actor.len() as u32).to_be_bytes());
        DigestHasher::update(&mut hasher, yank_actor.as_bytes());
        digest_from_hasher(hasher)
    }
}

/// Typed refusals for package namespace operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageRefusal {
    EmptyNamespace,
    NamespaceTooLong {
        offered: usize,
        maximum: usize,
    },
    InvalidNamespaceCharacters,
    InvalidNamespaceFormatting,
    EmptyVersion,
    VersionTooLong {
        offered: usize,
        maximum: usize,
    },
    InvalidVersionCharacters,
    VersionAlreadyExists {
        namespace: String,
        version: String,
        existing_artifact_id: Digest,
    },
    VersionNotFound {
        namespace: String,
        version: String,
    },
    VersionAlreadyYanked {
        namespace: String,
        version: String,
    },
    StatePreconditionFailed {
        namespace: String,
        version: String,
        expected_artifact: Digest,
        actual_artifact: Digest,
    },
    RegistryLockPoisoned,
}

impl fmt::Display for PackageRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyNamespace => f.write_str("package namespace cannot be empty"),
            Self::NamespaceTooLong { offered, maximum } => write!(
                f,
                "package namespace is too long: offered {offered} bytes, maximum {maximum}"
            ),
            Self::InvalidNamespaceCharacters => {
                f.write_str("package namespace contains invalid characters")
            }
            Self::InvalidNamespaceFormatting => {
                f.write_str("package namespace has invalid leading or trailing slashes")
            }
            Self::EmptyVersion => f.write_str("package version cannot be empty"),
            Self::VersionTooLong { offered, maximum } => write!(
                f,
                "package version is too long: offered {offered} bytes, maximum {maximum}"
            ),
            Self::InvalidVersionCharacters => {
                f.write_str("package version contains invalid characters")
            }
            Self::VersionAlreadyExists {
                namespace,
                version,
                existing_artifact_id,
            } => write!(
                f,
                "version '{version}' in namespace '{namespace}' already exists with artifact ID {existing_artifact_id:?}"
            ),
            Self::VersionNotFound { namespace, version } => {
                write!(
                    f,
                    "version '{version}' not found in namespace '{namespace}'"
                )
            }
            Self::VersionAlreadyYanked { namespace, version } => {
                write!(
                    f,
                    "version '{version}' in namespace '{namespace}' is already yanked"
                )
            }
            Self::StatePreconditionFailed {
                namespace,
                version,
                expected_artifact,
                actual_artifact,
            } => write!(
                f,
                "state precondition failed for '{namespace}@{version}': expected artifact {expected_artifact:?}, actual {actual_artifact:?}"
            ),
            Self::RegistryLockPoisoned => f.write_str("package registry lock poisoned"),
        }
    }
}

impl std::error::Error for PackageRefusal {}
