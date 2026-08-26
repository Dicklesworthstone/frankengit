#![forbid(unsafe_code)]
//! FG-060: Retention roots and GC integration for the artifact payload fabric (§30.5).
//!
//! # GC and retention roots discipline
//!
//! Artifact roots participate in retention and garbage collection exactly like Git objects:
//! 1. Active package versions and permanent release assets are authenticated GC roots.
//! 2. Unexpired logs (`StandardLog` / `HotEphemeral`) are protected until their TTL / retention period expires.
//! 3. Assets marked with `LegalHold` are indefinitely pinned regardless of namespace state.
//! 4. Any artifact not reachable from any active root is eligible for reclamation.

use std::collections::{BTreeMap, BTreeSet};

use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes};

fn digest_from_hasher(hasher: Sha256Hasher) -> Digest {
    let raw = DigestHasher::finish(hasher);
    let bytes = DigestBytes::try_new(&raw).expect("32 bytes is valid digest length");
    Digest::new(
        DigestAlgorithmId::try_new(2).expect("SHA-256 is code point 2"),
        bytes,
    )
}

use crate::artifact::{ArtifactIdentity, RetentionProfile};

/// Domain tag for retention root calculation.
const RETENTION_ROOT_DOMAIN: &[u8] = b"frankengit/artifact-retention-root/v1\0";

/// Authenticated retention root holding all live artifact commitments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRetentionRoot {
    pub live_artifact_ids: BTreeSet<Digest>,
    pub permanent_artifact_ids: BTreeSet<Digest>,
    pub legal_hold_ids: BTreeSet<Digest>,
    pub root_digest: Digest,
}

impl ArtifactRetentionRoot {
    /// Computes an authenticated retention root from categorized live artifact sets.
    pub fn new(
        live_artifact_ids: BTreeSet<Digest>,
        permanent_artifact_ids: BTreeSet<Digest>,
        legal_hold_ids: BTreeSet<Digest>,
    ) -> Self {
        let root_digest =
            Self::compute_root_digest(&live_artifact_ids, &permanent_artifact_ids, &legal_hold_ids);
        Self {
            live_artifact_ids,
            permanent_artifact_ids,
            legal_hold_ids,
            root_digest,
        }
    }

    fn compute_root_digest(
        live: &BTreeSet<Digest>,
        perm: &BTreeSet<Digest>,
        holds: &BTreeSet<Digest>,
    ) -> Digest {
        let mut hasher = Sha256Hasher::new();
        DigestHasher::update(&mut hasher, RETENTION_ROOT_DOMAIN);
        DigestHasher::update(&mut hasher, &(live.len() as u32).to_be_bytes());
        for id in live {
            DigestHasher::update(&mut hasher, id.bytes().as_bytes());
        }
        DigestHasher::update(&mut hasher, &(perm.len() as u32).to_be_bytes());
        for id in perm {
            DigestHasher::update(&mut hasher, id.bytes().as_bytes());
        }
        DigestHasher::update(&mut hasher, &(holds.len() as u32).to_be_bytes());
        for id in holds {
            DigestHasher::update(&mut hasher, id.bytes().as_bytes());
        }
        digest_from_hasher(hasher)
    }

    /// True if the given artifact ID is protected from GC sweep.
    #[must_use]
    pub fn is_retained(&self, artifact_id: &Digest) -> bool {
        self.live_artifact_ids.contains(artifact_id)
            || self.permanent_artifact_ids.contains(artifact_id)
            || self.legal_hold_ids.contains(artifact_id)
    }
}

/// Registry tracking all stored artifact metadata and computing retention roots.
#[derive(Debug, Default)]
pub struct ArtifactRetentionRegistry {
    artifacts: BTreeMap<Digest, (ArtifactIdentity, u64)>, // id -> (identity, created_at)
}

impl ArtifactRetentionRegistry {
    /// Creates a new empty retention registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            artifacts: BTreeMap::new(),
        }
    }

    /// Registers a newly stored artifact.
    pub fn register_artifact(&mut self, identity: ArtifactIdentity, created_at_unix_secs: u64) {
        self.artifacts
            .insert(*identity.artifact_id(), (identity, created_at_unix_secs));
    }

    /// Computes the complete set of retained roots and returns the authenticated root.
    pub fn compute_retention_root(
        &self,
        active_package_versions: &BTreeSet<Digest>,
        current_time_unix_secs: u64,
    ) -> ArtifactRetentionRoot {
        let mut live = BTreeSet::new();
        let mut perm = BTreeSet::new();
        let mut holds = BTreeSet::new();

        for (id, (identity, created_at)) in &self.artifacts {
            // If actively referenced by a package version, it is live
            if active_package_versions.contains(id) {
                live.insert(*id);
            }

            match identity.retention_profile() {
                RetentionProfile::ReleasePermanent => {
                    perm.insert(*id);
                    live.insert(*id);
                }
                RetentionProfile::LegalHold { .. } => {
                    holds.insert(*id);
                    live.insert(*id);
                }
                RetentionProfile::HotEphemeral { ttl_seconds } => {
                    let age = current_time_unix_secs.saturating_sub(*created_at);
                    if age < *ttl_seconds {
                        live.insert(*id);
                    }
                }
                RetentionProfile::StandardLog { retain_days } => {
                    let age_secs = current_time_unix_secs.saturating_sub(*created_at);
                    let max_age_secs = u64::from(*retain_days) * 86_400;
                    if age_secs < max_age_secs {
                        live.insert(*id);
                    }
                }
            }
        }

        ArtifactRetentionRoot::new(live, perm, holds)
    }

    /// Executes a GC sweep: returns the list of expired / unreferenced artifact IDs to prune.
    pub fn sweep(&mut self, retention_root: &ArtifactRetentionRoot) -> Vec<Digest> {
        let mut to_prune = Vec::new();
        for id in self.artifacts.keys() {
            if !retention_root.is_retained(id) {
                to_prune.push(*id);
            }
        }

        for id in &to_prune {
            self.artifacts.remove(id);
        }

        to_prune
    }
}
