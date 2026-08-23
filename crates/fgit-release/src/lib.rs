#![forbid(unsafe_code)]
//! FG-035a: DSR attempt identities, asset contracts, and the root-last release
//! manifest.
//!
//! A release is the one artefact nobody can re-derive after the fact. If the
//! tree it was built from is not pinned, or the manifest signs a subset of what
//! shipped, or a mirror serves bytes the manifest never named, then every later
//! question — *what exactly was published, and from what* — is unanswerable.
//! This crate is the vocabulary that makes those questions answerable, and it
//! refuses rather than guessing when they are not.
//!
//! # Everything here is declared, and that is the design
//!
//! Nothing in this crate reads the filesystem, spawns a process, consults a
//! clock, or reaches the network. Attempt inputs are *declared by the caller*
//! and this crate binds them into an identity. Three reasons, in order of how
//! much they matter:
//!
//! 1. **§3.1 forbids invoking `git`**, so a "source tree digest" cannot be
//!    `git status` or `git rev-parse` behind a Rust function. It has to be a
//!    declaration the caller assembled from `FrankenGit`'s own object machinery.
//! 2. **A release identity must be reproducible from its record.** If this
//!    crate sampled ambient state, two verifiers replaying the same record
//!    would compute different identities and neither could say which was right.
//! 3. **No network during builds** (§3.3), which rules out mirror probing from
//!    inside the identity path.
//!
//! The cost is real and stated: this crate cannot detect a caller that declares
//! a clean tree while sitting on a dirty one. It refuses what it is *told* is
//! dirty. Whoever assembles [`TreeSnapshot`] owns that truthfulness, and the
//! e2e lane is where the declaration gets checked against a real checkout.
//!
//! # Publication is a typed refusal here, deliberately
//!
//! `ops/dsr/frankengit.yaml.example` states the operative constraint: *"`full`
//! and `release` deliberately return exit 3 until real implementation
//! conformance/fault/native-artifact gates exist. DSR must not publish a
//! release manifest from this architecture-only repository."*
//!
//! So [`publish`] does not publish. It returns
//! [`ReleaseRefusal::PublicationUnsupported`] naming the gate that is missing.
//! §4 permits exactly this — a subset whose unsupported surface is a typed
//! refusal — and the alternative, a publish path that works before the gates
//! exist, is the forbidden substitute.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;

/// Hex, lowercase, for rendering digests inside identity preimages.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // `write!` into the buffer rather than allocating a String per byte.
        let _ignored = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a release attempt, asset contract, or reconciliation was refused.
///
/// Every variant carries the numbers or names that produced it. A refusal a
/// release engineer cannot act on at 3am is barely better than a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseRefusal {
    /// The declared source tree has uncommitted modifications.
    ///
    /// A release built from an unpinned tree cannot be reproduced, so this is
    /// refused before an identity is minted rather than recorded as a caveat.
    DirtyWorkingTree {
        /// How many declared entries were dirty.
        dirty: usize,
        /// The first dirty path in canonical order, so the message names one.
        first: String,
    },
    /// The tree declared no files at all.
    EmptyTree,
    /// An asset set with nothing in it cannot be a release.
    EmptyAssetSet,
    /// The same path was declared twice.
    ///
    /// Two entries for one path make "the complete asset set" ambiguous, and an
    /// ambiguous denominator defeats the coverage check below.
    DuplicateAsset {
        /// The repeated path.
        path: String,
    },
    /// The signature does not cover every declared asset.
    ///
    /// This is the acceptance line "manifest signature covers the complete
    /// asset set", enforced as a denominator rather than a spot check.
    SignatureCoverageIncomplete {
        /// Assets the signature covers.
        signed: usize,
        /// Assets the manifest declares.
        declared: usize,
        /// First declared-but-unsigned path, in canonical order.
        first_unsigned: String,
    },
    /// The signature covers a path the manifest never declared.
    ///
    /// The mirror image of incomplete coverage, and the more dangerous
    /// direction: it means something was signed that the contract does not
    /// account for.
    SignatureCoversUndeclared {
        /// The signed path with no declaration.
        path: String,
    },
    /// A mirror is missing an asset the manifest declares.
    MirrorMissingAsset {
        /// The absent path.
        path: String,
    },
    /// A mirror serves an asset the manifest never declared.
    MirrorUndeclaredAsset {
        /// The extra path.
        path: String,
    },
    /// A mirror's bytes do not match the declared digest.
    MirrorDigestMismatch {
        /// The tampered path.
        path: String,
        /// What the manifest committed to.
        declared: String,
        /// What the mirror served.
        observed: String,
    },
    /// Publication is not available in this repository yet.
    PublicationUnsupported {
        /// The gate that must exist first.
        missing_gate: &'static str,
    },
}

impl fmt::Display for ReleaseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirtyWorkingTree { dirty, first } => write!(
                f,
                "{dirty} declared source entries are dirty (first: {first}); a release \
                 built from an unpinned tree cannot be reproduced"
            ),
            Self::EmptyTree => f.write_str("a source tree declaring no files has no identity"),
            Self::EmptyAssetSet => f.write_str("an empty asset set is not a release"),
            Self::DuplicateAsset { path } => write!(
                f,
                "asset {path} is declared twice, so the complete asset set is ambiguous"
            ),
            Self::SignatureCoverageIncomplete {
                signed,
                declared,
                first_unsigned,
            } => write!(
                f,
                "the signature covers {signed} of {declared} declared assets; {first_unsigned} \
                 is unsigned, so the manifest does not commit to what shipped"
            ),
            Self::SignatureCoversUndeclared { path } => write!(
                f,
                "the signature covers {path}, which the manifest never declared"
            ),
            Self::MirrorMissingAsset { path } => {
                write!(f, "the mirror is missing declared asset {path}")
            }
            Self::MirrorUndeclaredAsset { path } => {
                write!(
                    f,
                    "the mirror serves {path}, which the manifest never declared"
                )
            }
            Self::MirrorDigestMismatch {
                path,
                declared,
                observed,
            } => write!(
                f,
                "mirror asset {path} is {observed} but the manifest committed to {declared}"
            ),
            Self::PublicationUnsupported { missing_gate } => write!(
                f,
                "release publication is unavailable until {missing_gate} exists; \
                 this repository must not publish a release manifest"
            ),
        }
    }
}

impl std::error::Error for ReleaseRefusal {}

// ---------------------------------------------------------------------------
// Attempt identity
// ---------------------------------------------------------------------------

/// Whether a declared source entry matches its committed content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryState {
    /// The working copy matches what was committed.
    Clean,
    /// The working copy differs, so the tree is not pinned.
    Dirty,
}

/// One declared source file and its content digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceEntry {
    path: String,
    digest: [u8; 32],
    state: EntryState,
}

impl SourceEntry {
    /// Declare a source entry.
    #[must_use]
    pub fn new(path: impl Into<String>, digest: [u8; 32], state: EntryState) -> Self {
        Self {
            path: path.into(),
            digest,
            state,
        }
    }

    /// The declared path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether this entry is pinned.
    #[must_use]
    pub const fn state(&self) -> EntryState {
        self.state
    }
}

/// The declared state of a source tree at attempt time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TreeSnapshot {
    entries: BTreeMap<String, SourceEntry>,
}

impl TreeSnapshot {
    /// An empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare one entry, replacing any previous declaration for that path.
    ///
    /// Replacement rather than duplication is deliberate: a `BTreeMap` keyed by
    /// path makes "two states for one file" unrepresentable, so the dirty check
    /// below cannot be defeated by declaring a path twice.
    #[must_use]
    pub fn with(mut self, entry: SourceEntry) -> Self {
        self.entries.insert(entry.path.clone(), entry);
        self
    }

    /// Number of declared entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every dirty path, in canonical order.
    #[must_use]
    pub fn dirty_paths(&self) -> Vec<&str> {
        self.entries
            .values()
            .filter(|entry| entry.state == EntryState::Dirty)
            .map(|entry| entry.path.as_str())
            .collect()
    }

    /// The tree digest, over paths and content digests in canonical order.
    ///
    /// Ordering comes from the `BTreeMap`, never from iteration order of a hash
    /// container — §5.3 forbids publication semantics that depend on map
    /// iteration order, and a tree digest is exactly that kind of semantics.
    #[must_use]
    pub fn tree_digest(&self) -> [u8; 32] {
        let mut preimage = String::new();
        for entry in self.entries.values() {
            preimage.push_str(&entry.path);
            preimage.push('\0');
            preimage.push_str(&hex(&entry.digest));
            preimage.push('\n');
        }
        fgit_crypto::sha256_digest(preimage.as_bytes())
    }
}

/// Toolchain identity, declared rather than probed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolchainIdentity {
    /// Exact `rustc` version string.
    pub rustc: String,
    /// Exact `cargo` version string.
    pub cargo: String,
    /// The dated nightly pinned by `rust-toolchain.toml`.
    pub pinned_channel: String,
}

/// Where the attempt ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostFingerprint {
    /// Target triple.
    pub target: String,
    /// Operating-system identifier.
    pub os: String,
    /// Architecture identifier.
    pub arch: String,
}

/// Everything an attempt is a function of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptInputs {
    /// Declared source tree.
    pub tree: TreeSnapshot,
    /// Declared toolchain.
    pub toolchain: ToolchainIdentity,
    /// Declared host.
    pub host: HostFingerprint,
    /// The exact command, already split.
    pub command: Vec<String>,
    /// Allowlisted environment, canonically ordered.
    pub env: BTreeMap<String, String>,
}

/// A reproducible identity for one release attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptIdentity {
    digest: [u8; 32],
    tree_digest: [u8; 32],
}

impl AttemptIdentity {
    /// The attempt identity.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The tree digest it was bound to.
    #[must_use]
    pub const fn tree_digest(&self) -> [u8; 32] {
        self.tree_digest
    }

    /// Lowercase hex rendering of the identity.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex(&self.digest)
    }
}

/// Bind declared inputs into an attempt identity.
///
/// # Errors
///
/// [`ReleaseRefusal::EmptyTree`] when nothing is declared, and
/// [`ReleaseRefusal::DirtyWorkingTree`] when any declared entry is dirty — the
/// acceptance line "dirty working tree refuses release attempts", enforced
/// before an identity exists rather than annotated onto one.
pub fn attempt_identity(inputs: &AttemptInputs) -> Result<AttemptIdentity, ReleaseRefusal> {
    if inputs.tree.is_empty() {
        return Err(ReleaseRefusal::EmptyTree);
    }
    let dirty = inputs.tree.dirty_paths();
    if let Some(first) = dirty.first() {
        return Err(ReleaseRefusal::DirtyWorkingTree {
            dirty: dirty.len(),
            first: (*first).to_owned(),
        });
    }

    let tree_digest = inputs.tree.tree_digest();
    let mut preimage = String::new();
    preimage.push_str("fgit-release/attempt/v1\n");
    preimage.push_str(&hex(&tree_digest));
    preimage.push('\n');
    preimage.push_str(&inputs.toolchain.rustc);
    preimage.push('\n');
    preimage.push_str(&inputs.toolchain.cargo);
    preimage.push('\n');
    preimage.push_str(&inputs.toolchain.pinned_channel);
    preimage.push('\n');
    preimage.push_str(&inputs.host.target);
    preimage.push('\n');
    preimage.push_str(&inputs.host.os);
    preimage.push('\n');
    preimage.push_str(&inputs.host.arch);
    preimage.push('\n');
    for argument in &inputs.command {
        preimage.push_str(argument);
        preimage.push('\0');
    }
    preimage.push('\n');
    for (key, value) in &inputs.env {
        preimage.push_str(key);
        preimage.push('=');
        preimage.push_str(value);
        preimage.push('\n');
    }

    Ok(AttemptIdentity {
        digest: fgit_crypto::sha256_digest(preimage.as_bytes()),
        tree_digest,
    })
}

// ---------------------------------------------------------------------------
// Asset contract and manifest
// ---------------------------------------------------------------------------

/// One released artefact and the digest the manifest commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    path: String,
    digest: [u8; 32],
}

impl Asset {
    /// Declare an asset.
    #[must_use]
    pub fn new(path: impl Into<String>, digest: [u8; 32]) -> Self {
        Self {
            path: path.into(),
            digest,
        }
    }

    /// The declared path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The committed digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// The root-last release manifest.
///
/// "Root-last" is the §5.4 discipline: the manifest — the root that makes the
/// release canonical — is only valid once every asset beneath it is accounted
/// for. [`ReleaseManifest::validate`] is that check, and it is a denominator
/// comparison rather than a sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseManifest {
    attempt: AttemptIdentity,
    assets: Vec<Asset>,
    signed_paths: BTreeSet<String>,
}

impl ReleaseManifest {
    /// Assemble a manifest from an attempt, its assets, and the paths the
    /// signature covers.
    ///
    /// # Errors
    ///
    /// [`ReleaseRefusal::EmptyAssetSet`] for no assets, and
    /// [`ReleaseRefusal::DuplicateAsset`] when one path is declared twice —
    /// refused here rather than deduplicated, because silently collapsing a
    /// duplicate would change what "the complete asset set" means.
    pub fn new(
        attempt: AttemptIdentity,
        assets: Vec<Asset>,
        signed_paths: BTreeSet<String>,
    ) -> Result<Self, ReleaseRefusal> {
        if assets.is_empty() {
            return Err(ReleaseRefusal::EmptyAssetSet);
        }
        let mut seen = BTreeSet::new();
        for asset in &assets {
            if !seen.insert(asset.path.clone()) {
                return Err(ReleaseRefusal::DuplicateAsset {
                    path: asset.path.clone(),
                });
            }
        }
        Ok(Self {
            attempt,
            assets,
            signed_paths,
        })
    }

    /// The attempt this manifest is bound to.
    #[must_use]
    pub const fn attempt(&self) -> &AttemptIdentity {
        &self.attempt
    }

    /// Declared assets.
    #[must_use]
    pub fn assets(&self) -> &[Asset] {
        &self.assets
    }

    /// Check that the signature covers exactly the declared asset set.
    ///
    /// Both directions are checked. Incomplete coverage means the manifest does
    /// not commit to something that shipped; coverage of an undeclared path
    /// means something was signed that the contract does not account for. A
    /// check that only counted would miss the second.
    ///
    /// # Errors
    ///
    /// [`ReleaseRefusal::SignatureCoverageIncomplete`] or
    /// [`ReleaseRefusal::SignatureCoversUndeclared`].
    pub fn validate(&self) -> Result<(), ReleaseRefusal> {
        let declared: BTreeSet<&str> = self
            .assets
            .iter()
            .map(|asset| asset.path.as_str())
            .collect();

        for path in &self.signed_paths {
            if !declared.contains(path.as_str()) {
                return Err(ReleaseRefusal::SignatureCoversUndeclared { path: path.clone() });
            }
        }
        for path in &declared {
            if !self.signed_paths.contains(*path) {
                return Err(ReleaseRefusal::SignatureCoverageIncomplete {
                    signed: self.signed_paths.len(),
                    declared: declared.len(),
                    first_unsigned: (*path).to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Compare what a mirror serves against what the manifest declared.
///
/// # Errors
///
/// A missing, extra, or altered asset, each named. The manifest is validated
/// first, so a reconciliation never reports a mirror problem for a manifest
/// that was never coherent.
pub fn reconcile_mirror(
    manifest: &ReleaseManifest,
    observed: &BTreeMap<String, [u8; 32]>,
) -> Result<(), ReleaseRefusal> {
    manifest.validate()?;

    for asset in &manifest.assets {
        let Some(seen) = observed.get(&asset.path) else {
            return Err(ReleaseRefusal::MirrorMissingAsset {
                path: asset.path.clone(),
            });
        };
        if *seen != asset.digest {
            return Err(ReleaseRefusal::MirrorDigestMismatch {
                path: asset.path.clone(),
                declared: hex(&asset.digest),
                observed: hex(seen),
            });
        }
    }

    let declared: BTreeSet<&str> = manifest
        .assets
        .iter()
        .map(|asset| asset.path.as_str())
        .collect();
    for path in observed.keys() {
        if !declared.contains(path.as_str()) {
            return Err(ReleaseRefusal::MirrorUndeclaredAsset { path: path.clone() });
        }
    }
    Ok(())
}

/// Publish a validated manifest.
///
/// # Errors
///
/// Always [`ReleaseRefusal::PublicationUnsupported`]. This is not a stub: the
/// DSR configuration states that `full` and `release` return exit 3 until real
/// conformance, fault, and native-artifact gates exist, and that this
/// repository must not publish a release manifest. §4 permits a subset whose
/// unsupported surface is a typed refusal; it forbids a publish path that
/// appears to work before the gates it depends on are real.
///
/// The manifest is still validated first, so a caller learns about a broken
/// asset contract now rather than on the day publication becomes available.
pub fn publish(manifest: &ReleaseManifest) -> Result<(), ReleaseRefusal> {
    manifest.validate()?;
    Err(ReleaseRefusal::PublicationUnsupported {
        missing_gate: "the FG-091 run_all.sh release gate and the native-artifact matrix",
    })
}
