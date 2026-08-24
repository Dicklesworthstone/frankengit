//! Durable, local release-attempt execution evidence.
//!
//! This module owns the state that the declaration-only FG-035a vocabulary
//! intentionally did not: an append-only on-disk attempt journal, inventory of
//! actual staged files, target-result records, verified reuse on resume, and a
//! local root-last manifest. It does **not** publish a release. [`crate::publish`]
//! remains the authority boundary and still returns its typed refusal until the
//! complete native matrix and signing gates exist.
//!
//! Process execution is deliberately an injected [`TargetStep`]. A production
//! caller must connect that trait to the bounded `fgit-runner` obligation; this
//! crate supplies [`UnavailableTargetStep`] as the safe default. It refuses
//! rather than pretending that a target was built successfully.
//!
//! The inventory refuses symlinks observed during its bounded walk. It does not
//! claim a platform-specific TOCTOU-resistant path-resolution boundary; that
//! requires an admitted operating-system containment/filesystem capability and
//! remains outside this std-only slice.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::{Asset, AttemptIdentity, ReleaseManifest, ReleaseRefusal, hex};

/// Bound one individual target name and a journal detail before allocating it.
pub const MAX_TARGET_TEXT_BYTES: usize = 256;
/// Bound the set of targets admitted to one local attempt.
pub const MAX_TARGETS: usize = 64;
/// Bound the assets that one target may claim.
pub const MAX_ASSETS_PER_TARGET: usize = 512;
/// Bound one regular staged asset before it is read to calculate SHA-256.
pub const MAX_STAGED_ASSET_BYTES: u64 = 1024 * 1024 * 1024;
/// Bound the append-only replay surface.
pub const MAX_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;
/// Bound one contract path before it becomes a filesystem traversal input.
pub const MAX_ASSET_PATH_BYTES: usize = 512;
/// Bound directory enumeration work even under a hostile staging root.
pub const MAX_STAGING_DIRECTORY_ENTRIES: usize = MAX_ASSETS_PER_TARGET * 4;

const JOURNAL_HEADER: &[u8] = b"FGIT_RELEASE_ATTEMPT_JOURNAL_V1\n";
const JOURNAL_ENTRY_DOMAIN: &[u8] = b"frankengit/release-attempt-journal-entry/v1\0";
const MATRIX_DOMAIN: &[u8] = b"frankengit/release-target-matrix/v1\0";
const INVENTORY_DOMAIN: &[u8] = b"frankengit/release-filesystem-inventory/v1\0";
const MANIFEST_DOMAIN: &[u8] = b"frankengit/release-local-manifest/v1\0";
const MAX_JOURNAL_EVENT_BYTES: usize = 4 * 1024;
const JOURNAL_FRAME_PREFIX_BYTES: usize = 4 + 32 + 32;

/// A typed refusal while managing a local release attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptRunnerRefusal {
    /// The caller's previously declared release contract was not coherent.
    Release(ReleaseRefusal),
    /// The caller-supplied attempt root is not a directory safe for this slice.
    AttemptRootNotDirectory { path: PathBuf },
    /// The caller-supplied root or a generated attempt path was a symlink.
    SymlinkedAttemptPath { path: PathBuf },
    /// A different immutable attempt already owns this deterministic directory.
    AttemptAlreadyExists { path: PathBuf },
    /// An I/O operation failed. Error kind is retained without exposing ambient
    /// strings as a protocol field.
    Io {
        operation: &'static str,
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
    /// The append-only evidence failed structural or hash-chain verification.
    JournalCorrupt { reason: &'static str },
    /// The supplied matrix does not match the immutable declaration at the
    /// beginning of an existing journal.
    MatrixIdentityMismatch,
    /// A requested target was absent from the declared matrix.
    UnknownTarget { target: String },
    /// Target names must be bounded printable protocol identifiers.
    InvalidTargetName { target: String },
    /// Target names cannot repeat in one exact matrix.
    DuplicateTarget { target: String },
    /// A target has no declared output contract.
    EmptyTargetAssetContract { target: String },
    /// A target asset contract contains a duplicate path.
    DuplicateTargetAsset { target: String, path: String },
    /// A contract path can escape the selected staging directory.
    AssetTraversal { path: String },
    /// An actual staged entry is a symlink.
    AssetSymlink { path: String },
    /// An actual staged entry that should be an asset is not a regular file.
    AssetNonRegular { path: String },
    /// The expected contract listed a file that was not staged.
    AssetMissing { path: String },
    /// The staging directory contained a file not present in the exact contract.
    AssetUnlisted { path: String },
    /// The real staged bytes do not match the caller's declared contract.
    AssetDigestMismatch {
        path: String,
        expected: [u8; 32],
        observed: [u8; 32],
    },
    /// A regular staged file exceeded the pre-allocation work bound.
    AssetTooLarge { path: String, bytes: u64 },
    /// A staging directory exceeded its bounded enumeration budget.
    StagingEntryLimit { directory: String },
    /// A target already has immutable terminal evidence in this journal.
    TargetAlreadyRecorded { target: String },
    /// A completed target cannot be reused after its verified byte identity
    /// changed; it needs a new target attempt rather than an overwrite.
    ResumeNeedsNewTargetAttempt { target: String },
    /// The injected production runner was not available to execute a target.
    TargetRunnerUnavailable { target: String, reason: String },
    /// A root-last local manifest cannot be constructed from this matrix state.
    ManifestWithheld { target: String, state: &'static str },
    /// The manifest root exists but does not match the journal commitment.
    ManifestRootMismatch,
    /// The manifest path was unexpectedly occupied before root-last publish.
    ManifestAlreadyExists { path: PathBuf },
}

impl fmt::Display for AttemptRunnerRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Release(refusal) => fmt::Display::fmt(refusal, formatter),
            Self::AttemptRootNotDirectory { path } => {
                write!(
                    formatter,
                    "release attempt root {} is not a directory",
                    path.display()
                )
            }
            Self::SymlinkedAttemptPath { path } => write!(
                formatter,
                "release attempt path {} is a symlink and is refused",
                path.display()
            ),
            Self::AttemptAlreadyExists { path } => write!(
                formatter,
                "release attempt directory {} already exists",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                kind,
            } => write!(
                formatter,
                "release attempt {operation} at {} failed with {kind:?}",
                path.display()
            ),
            Self::JournalCorrupt { reason } => {
                write!(formatter, "release attempt journal is corrupt: {reason}")
            }
            Self::MatrixIdentityMismatch => formatter.write_str(
                "the requested target matrix differs from the journal's immutable declaration",
            ),
            Self::UnknownTarget { target } => write!(formatter, "target {target} is not declared"),
            Self::InvalidTargetName { target } => write!(
                formatter,
                "target {target:?} is not a bounded printable target identifier"
            ),
            Self::DuplicateTarget { target } => {
                write!(
                    formatter,
                    "target {target} appears more than once in the matrix"
                )
            }
            Self::EmptyTargetAssetContract { target } => {
                write!(formatter, "target {target} declares no release assets")
            }
            Self::DuplicateTargetAsset { target, path } => write!(
                formatter,
                "target {target} declares asset {path} more than once"
            ),
            Self::AssetTraversal { path } => write!(
                formatter,
                "asset contract path {path:?} is absolute or traverses outside staging"
            ),
            Self::AssetSymlink { path } => {
                write!(formatter, "staged asset {path} is a symlink and is refused")
            }
            Self::AssetNonRegular { path } => {
                write!(formatter, "staged asset {path} is not a regular file")
            }
            Self::AssetMissing { path } => write!(formatter, "staged asset {path} is missing"),
            Self::AssetUnlisted { path } => write!(
                formatter,
                "staged asset {path} is not listed by the exact asset contract"
            ),
            Self::AssetDigestMismatch {
                path,
                expected,
                observed,
            } => write!(
                formatter,
                "staged asset {path} has digest {} but contract requires {}",
                hex(observed),
                hex(expected)
            ),
            Self::AssetTooLarge { path, bytes } => write!(
                formatter,
                "staged asset {path} is {bytes} bytes, exceeding the inventory bound"
            ),
            Self::StagingEntryLimit { directory } => write!(
                formatter,
                "staging directory {directory} exceeds the bounded enumeration budget"
            ),
            Self::TargetAlreadyRecorded { target } => write!(
                formatter,
                "target {target} already has immutable terminal journal evidence"
            ),
            Self::ResumeNeedsNewTargetAttempt { target } => write!(
                formatter,
                "target {target} changed after completion and needs a new target attempt"
            ),
            Self::TargetRunnerUnavailable { target, reason } => write!(
                formatter,
                "target {target} was not executed because the bounded runner is unavailable: {reason}"
            ),
            Self::ManifestWithheld { target, state } => write!(
                formatter,
                "local release manifest is withheld because target {target} is {state}"
            ),
            Self::ManifestRootMismatch => formatter.write_str(
                "the local manifest root does not match its hash-chained journal commitment",
            ),
            Self::ManifestAlreadyExists { path } => write!(
                formatter,
                "local manifest root {} already exists and will not be overwritten",
                path.display()
            ),
        }
    }
}

impl std::error::Error for AttemptRunnerRefusal {}

impl From<ReleaseRefusal> for AttemptRunnerRefusal {
    fn from(value: ReleaseRefusal) -> Self {
        Self::Release(value)
    }
}

/// One target's immutable declared staging directory and exact asset contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetSpec {
    name: String,
    staging_directory: PathBuf,
    assets: Vec<Asset>,
}

impl TargetSpec {
    /// Declares one target's filesystem staging boundary and expected assets.
    ///
    /// Asset paths themselves are validated while inventorying so every
    /// filesystem-facing refusal is emitted by the same operation that would
    /// otherwise read the path.
    pub fn new(
        name: impl Into<String>,
        staging_directory: impl Into<PathBuf>,
        assets: Vec<Asset>,
    ) -> Result<Self, AttemptRunnerRefusal> {
        let name = name.into();
        validate_target_name(&name)?;
        if assets.is_empty() {
            return Err(AttemptRunnerRefusal::EmptyTargetAssetContract { target: name });
        }
        if assets.len() > MAX_ASSETS_PER_TARGET {
            return Err(AttemptRunnerRefusal::JournalCorrupt {
                reason: "target asset contract exceeds its bounded size",
            });
        }
        Ok(Self {
            name,
            staging_directory: staging_directory.into(),
            assets,
        })
    }

    /// Stable target identifier.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Caller-supplied staging root for this exact target attempt.
    #[must_use]
    pub fn staging_directory(&self) -> &Path {
        &self.staging_directory
    }

    /// Exact declared asset contract.
    #[must_use]
    pub fn assets(&self) -> &[Asset] {
        &self.assets
    }
}

/// An observable, ordered release target matrix bound to one attempt identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetMatrix {
    attempt: AttemptIdentity,
    targets: Vec<TargetSpec>,
}

impl TargetMatrix {
    /// Binds a finite ordered target matrix to the release attempt.
    pub fn new(
        attempt: AttemptIdentity,
        targets: Vec<TargetSpec>,
    ) -> Result<Self, AttemptRunnerRefusal> {
        if targets.is_empty() || targets.len() > MAX_TARGETS {
            return Err(AttemptRunnerRefusal::JournalCorrupt {
                reason: "target matrix is empty or exceeds its bounded size",
            });
        }
        let mut names = BTreeSet::new();
        for target in &targets {
            validate_target_name(&target.name)?;
            if !names.insert(target.name.clone()) {
                return Err(AttemptRunnerRefusal::DuplicateTarget {
                    target: target.name.clone(),
                });
            }
        }
        Ok(Self { attempt, targets })
    }

    /// Release attempt bound to this matrix.
    #[must_use]
    pub const fn attempt(&self) -> &AttemptIdentity {
        &self.attempt
    }

    /// Ordered target declarations.
    #[must_use]
    pub fn targets(&self) -> &[TargetSpec] {
        &self.targets
    }

    fn identity(&self) -> [u8; 32] {
        let mut bytes = MATRIX_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.attempt.digest());
        for target in &self.targets {
            push_field(&mut bytes, target.name.as_bytes());
            for asset in &target.assets {
                push_field(&mut bytes, asset.path().as_bytes());
                bytes.extend_from_slice(&asset.digest());
            }
            bytes.push(0xff);
        }
        fgit_crypto::sha256_digest(&bytes)
    }

    fn target(&self, name: &str) -> Option<&TargetSpec> {
        self.targets.iter().find(|target| target.name == name)
    }
}

/// SHA-256 inventory of real regular files discovered under a staging root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemAssetInventory {
    assets: BTreeMap<String, [u8; 32]>,
    identity: [u8; 32],
}

impl FilesystemAssetInventory {
    /// Computes the exact real-file inventory for a target staging directory.
    pub fn collect(target: &TargetSpec) -> Result<Self, AttemptRunnerRefusal> {
        let expected = expected_assets(target)?;
        let root_metadata =
            symlink_metadata(&target.staging_directory, "inspect staging directory")?;
        if root_metadata.file_type().is_symlink() {
            return Err(AttemptRunnerRefusal::AssetSymlink {
                path: target.staging_directory.display().to_string(),
            });
        }
        if !root_metadata.is_dir() {
            return Err(AttemptRunnerRefusal::AssetNonRegular {
                path: target.staging_directory.display().to_string(),
            });
        }

        let mut observed = BTreeMap::new();
        let mut entry_count = 0;
        collect_directory(
            &target.staging_directory,
            Path::new(""),
            &expected,
            &mut observed,
            &mut entry_count,
        )?;
        for path in expected.keys() {
            if !observed.contains_key(path) {
                return Err(AttemptRunnerRefusal::AssetMissing { path: path.clone() });
            }
        }

        let mut bytes = INVENTORY_DOMAIN.to_vec();
        for (path, digest) in &observed {
            push_field(&mut bytes, path.as_bytes());
            bytes.extend_from_slice(digest);
        }
        Ok(Self {
            assets: observed,
            identity: fgit_crypto::sha256_digest(&bytes),
        })
    }

    /// Assets observed in canonical relative-path order.
    #[must_use]
    pub const fn assets(&self) -> &BTreeMap<String, [u8; 32]> {
        &self.assets
    }

    /// Content identity over every path and verified byte digest.
    #[must_use]
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

/// The immutable terminal record for one target in an attempt journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetRecord {
    /// All expected staged files had their exact declared bytes.
    Passed { inventory_identity: [u8; 32] },
    /// The target runner reported a terminal failure.
    Failed { detail: String },
}

/// Whether an existing target record may be reused on resume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResumeDecision {
    /// The stored record and current real files have exactly the same identity.
    Reuse { inventory_identity: [u8; 32] },
    /// The target must be run again. This is never reported as reuse.
    Rerun { reason: &'static str },
}

/// The outcome of running a matrix through a supplied target executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatrixOutcome {
    /// Every target passed and the local root-last manifest was written.
    Completed { manifest: ReleaseManifest },
    /// A target failed; its journal evidence was retained and no root was made.
    Failed { target: String },
    /// Cancellation stopped new target work and retained resumable evidence.
    Cancelled { target: String },
}

/// A bounded external target execution result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetStepResult {
    /// The executor reports that it completed the target; the runner still
    /// verifies all staged asset bytes before recording success.
    Passed,
    /// The executor reports a terminal target failure.
    Failed { detail: String },
    /// The executor received cancellation before a terminal target result.
    Cancelled,
    /// There is no compliant executor available for this requested target.
    Unavailable { reason: String },
}

/// A pluggable, shell-free target execution boundary.
///
/// Production wiring must lower an `fgit-runner` obligation into this trait.
/// The release journal refuses when no such boundary is available; it has no
/// success-returning placeholder.
pub trait TargetStep {
    /// Executes exactly one declared target.
    fn execute(&mut self, target: &TargetSpec) -> TargetStepResult;
}

/// The safe default for callers before an `fgit-runner` integration is wired.
#[derive(Clone, Debug, Default)]
pub struct UnavailableTargetStep;

impl TargetStep for UnavailableTargetStep {
    fn execute(&mut self, _target: &TargetSpec) -> TargetStepResult {
        TargetStepResult::Unavailable {
            reason: "no fgit-runner-backed target execution obligation is registered".to_owned(),
        }
    }
}

/// A durable, hash-chained local attempt journal rooted under caller storage.
#[derive(Debug)]
pub struct AttemptJournal {
    matrix: TargetMatrix,
    attempt_directory: PathBuf,
    journal_path: PathBuf,
    manifest_path: PathBuf,
    state: JournalState,
}

impl AttemptJournal {
    /// Creates a new attempt directory and atomically durable matrix declaration.
    pub fn create(
        root: impl AsRef<Path>,
        matrix: TargetMatrix,
    ) -> Result<Self, AttemptRunnerRefusal> {
        let attempt_directory = attempt_directory(root.as_ref(), matrix.attempt())?;
        if attempt_directory.exists() {
            return Err(AttemptRunnerRefusal::AttemptAlreadyExists {
                path: attempt_directory,
            });
        }
        fs::create_dir(&attempt_directory).map_err(|error| {
            io_refusal("create attempt directory", attempt_directory.clone(), error)
        })?;
        let journal_path = attempt_directory.join("journal.bin");
        let mut journal = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&journal_path)
            .map_err(|error| io_refusal("create journal", journal_path.clone(), error))?;
        journal
            .write_all(JOURNAL_HEADER)
            .and_then(|()| journal.sync_all())
            .map_err(|error| io_refusal("write journal header", journal_path.clone(), error))?;

        let mut result = Self {
            matrix,
            manifest_path: attempt_directory.join("release-manifest"),
            attempt_directory,
            journal_path,
            state: JournalState::default(),
        };
        result.append(JournalEvent::MatrixDeclared {
            identity: result.matrix.identity(),
        })?;
        Ok(result)
    }

    /// Opens an existing journal, verifies its hash chain, and truncates only a
    /// non-record partial crash tail. A complete malformed or hash-mismatched
    /// record is never silently skipped.
    pub fn open(
        root: impl AsRef<Path>,
        matrix: TargetMatrix,
    ) -> Result<Self, AttemptRunnerRefusal> {
        let attempt_directory = attempt_directory(root.as_ref(), matrix.attempt())?;
        let journal_path = attempt_directory.join("journal.bin");
        let bytes = read_bounded(&journal_path, MAX_JOURNAL_BYTES, "read journal")?;
        let replay = replay_journal(&bytes)?;
        let result = Self {
            manifest_path: attempt_directory.join("release-manifest"),
            matrix,
            attempt_directory,
            journal_path,
            state: replay.state,
        };
        result.validate_replayed_state()?;
        if replay.valid_len < bytes.len() {
            let journal_path = result.journal_path.clone();
            let journal = OpenOptions::new()
                .write(true)
                .open(&journal_path)
                .map_err(|error| {
                    io_refusal("open partial journal tail", journal_path.clone(), error)
                })?;
            journal
                .set_len(replay.valid_len as u64)
                .and_then(|()| journal.sync_all())
                .map_err(|error| {
                    io_refusal("truncate partial journal tail", journal_path, error)
                })?;
        }
        result.verify_existing_manifest()?;
        Ok(result)
    }

    /// The immutable matrix for this attempt.
    #[must_use]
    pub const fn matrix(&self) -> &TargetMatrix {
        &self.matrix
    }

    /// Append-only journal location for crash/replay evidence.
    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    /// Root-last local manifest location. Its presence is not an external
    /// publication and never changes [`crate::publish`]'s typed refusal.
    #[must_use]
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Target's terminal immutable journal record, if one exists.
    #[must_use]
    pub fn target_record(&self, target: &str) -> Option<&TargetRecord> {
        self.state.targets.get(target)
    }

    /// Returns true when the journal can be reopened and contains no manifest
    /// root. Cancellation leaves this true so receipts are available for resume.
    #[must_use]
    pub const fn is_resumable(&self) -> bool {
        self.state.manifest_prepared.is_none()
    }

    /// Rechecks real staged bytes before allowing a completed target to be reused.
    pub fn resume_target(&self, target: &str) -> Result<ResumeDecision, AttemptRunnerRefusal> {
        let spec =
            self.matrix
                .target(target)
                .ok_or_else(|| AttemptRunnerRefusal::UnknownTarget {
                    target: target.to_owned(),
                })?;
        let Some(TargetRecord::Passed { inventory_identity }) = self.state.targets.get(target)
        else {
            return Ok(ResumeDecision::Rerun {
                reason: "no completed target record",
            });
        };
        match FilesystemAssetInventory::collect(spec) {
            Ok(inventory) if inventory.identity == *inventory_identity => {
                Ok(ResumeDecision::Reuse {
                    inventory_identity: *inventory_identity,
                })
            }
            Ok(_) => Ok(ResumeDecision::Rerun {
                reason: "verified asset identity changed",
            }),
            Err(AttemptRunnerRefusal::AssetDigestMismatch { .. }) => Ok(ResumeDecision::Rerun {
                reason: "staged asset bytes no longer satisfy the recorded contract",
            }),
            Err(refusal) => Err(refusal),
        }
    }

    /// Runs missing targets through a typed executor, preserving every terminal
    /// record. A reused target is byte-verified first; a changed completed
    /// target is refused instead of overwriting its evidence.
    pub fn run_matrix<E: TargetStep>(
        &mut self,
        executor: &mut E,
    ) -> Result<MatrixOutcome, AttemptRunnerRefusal> {
        if self.state.cancelled {
            return Ok(MatrixOutcome::Cancelled {
                target: "matrix".to_owned(),
            });
        }
        for target in self.matrix.targets.clone() {
            match self.resume_target(target.name())? {
                ResumeDecision::Reuse { .. } => continue,
                ResumeDecision::Rerun { .. } if self.state.targets.contains_key(target.name()) => {
                    return Err(AttemptRunnerRefusal::ResumeNeedsNewTargetAttempt {
                        target: target.name.clone(),
                    });
                }
                ResumeDecision::Rerun { .. } => {}
            }
            match executor.execute(&target) {
                TargetStepResult::Passed => self.record_target_passed(&target)?,
                TargetStepResult::Failed { detail } => {
                    self.record_target_failed(&target, detail)?;
                    return Ok(MatrixOutcome::Failed {
                        target: target.name.clone(),
                    });
                }
                TargetStepResult::Cancelled => {
                    self.cancel(&target.name)?;
                    return Ok(MatrixOutcome::Cancelled {
                        target: target.name.clone(),
                    });
                }
                TargetStepResult::Unavailable { reason } => {
                    return Err(AttemptRunnerRefusal::TargetRunnerUnavailable {
                        target: target.name.clone(),
                        reason: bounded_detail(reason),
                    });
                }
            }
        }
        self.emit_manifest()
            .map(|manifest| MatrixOutcome::Completed { manifest })
    }

    /// Emits the local manifest only after every declared target passed.
    pub fn emit_manifest(&mut self) -> Result<ReleaseManifest, AttemptRunnerRefusal> {
        self.ensure_manifest_allowed()?;
        let manifest = self.build_manifest()?;
        let body = manifest_body(&manifest);
        let body_digest = fgit_crypto::sha256_digest(&body);
        if let Some(prepared) = self.state.manifest_prepared {
            if prepared != body_digest {
                return Err(AttemptRunnerRefusal::JournalCorrupt {
                    reason: "prepared manifest does not match current complete matrix",
                });
            }
            if self.manifest_path.exists() {
                self.verify_existing_manifest()?;
                return Ok(manifest);
            }
        } else {
            if self.manifest_path.exists() {
                return Err(AttemptRunnerRefusal::ManifestAlreadyExists {
                    path: self.manifest_path.clone(),
                });
            }
            self.append(JournalEvent::ManifestPrepared {
                digest: body_digest,
            })?;
        }
        let temporary = self.attempt_directory.join("release-manifest.tmp");
        if temporary.exists() {
            return Err(AttemptRunnerRefusal::ManifestAlreadyExists { path: temporary });
        }
        let mut staged = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| io_refusal("create staged manifest", temporary.clone(), error))?;
        staged
            .write_all(&body)
            .and_then(|()| staged.sync_all())
            .map_err(|error| io_refusal("write staged manifest", temporary.clone(), error))?;
        fs::rename(&temporary, &self.manifest_path).map_err(|error| {
            io_refusal(
                "publish root-last local manifest",
                self.manifest_path.clone(),
                error,
            )
        })?;
        File::open(&self.attempt_directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                io_refusal(
                    "sync manifest parent directory",
                    self.attempt_directory.clone(),
                    error,
                )
            })?;
        Ok(manifest)
    }

    fn record_target_passed(&mut self, target: &TargetSpec) -> Result<(), AttemptRunnerRefusal> {
        self.ensure_new_target(target.name())?;
        let inventory = FilesystemAssetInventory::collect(target)?;
        self.append(JournalEvent::TargetPassed {
            target: target.name.clone(),
            inventory_identity: inventory.identity,
        })
    }

    fn record_target_failed(
        &mut self,
        target: &TargetSpec,
        detail: String,
    ) -> Result<(), AttemptRunnerRefusal> {
        self.ensure_new_target(target.name())?;
        self.append(JournalEvent::TargetFailed {
            target: target.name.clone(),
            detail: bounded_detail(detail),
        })
    }

    fn cancel(&mut self, target: &str) -> Result<(), AttemptRunnerRefusal> {
        if self.state.cancelled {
            return Ok(());
        }
        self.append(JournalEvent::Cancelled {
            target: target.to_owned(),
        })
    }

    fn ensure_new_target(&self, target: &str) -> Result<(), AttemptRunnerRefusal> {
        if self.matrix.target(target).is_none() {
            return Err(AttemptRunnerRefusal::UnknownTarget {
                target: target.to_owned(),
            });
        }
        if self.state.targets.contains_key(target) {
            return Err(AttemptRunnerRefusal::TargetAlreadyRecorded {
                target: target.to_owned(),
            });
        }
        Ok(())
    }

    fn ensure_manifest_allowed(&self) -> Result<(), AttemptRunnerRefusal> {
        if self.state.cancelled {
            return Err(AttemptRunnerRefusal::ManifestWithheld {
                target: "matrix".to_owned(),
                state: "cancelled",
            });
        }
        for target in self.matrix.targets() {
            match self.state.targets.get(target.name()) {
                Some(TargetRecord::Passed { .. }) => {}
                Some(TargetRecord::Failed { .. }) => {
                    return Err(AttemptRunnerRefusal::ManifestWithheld {
                        target: target.name.clone(),
                        state: "failed",
                    });
                }
                None => {
                    return Err(AttemptRunnerRefusal::ManifestWithheld {
                        target: target.name.clone(),
                        state: "incomplete",
                    });
                }
            }
        }
        Ok(())
    }

    fn build_manifest(&self) -> Result<ReleaseManifest, AttemptRunnerRefusal> {
        let assets = self
            .matrix
            .targets()
            .iter()
            .flat_map(|target| target.assets().iter().cloned())
            .collect::<Vec<_>>();
        let signed_paths = assets
            .iter()
            .map(|asset| asset.path().to_owned())
            .collect::<BTreeSet<_>>();
        ReleaseManifest::new(self.matrix.attempt.clone(), assets, signed_paths).map_err(Into::into)
    }

    fn append(&mut self, event: JournalEvent) -> Result<(), AttemptRunnerRefusal> {
        let body = encode_event(&event);
        let sequence = self.state.events + 1;
        let digest = entry_digest(sequence, &self.state.last_digest, &body);
        let body_length =
            u32::try_from(body.len()).map_err(|_| AttemptRunnerRefusal::JournalCorrupt {
                reason: "journal event length cannot be represented",
            })?;
        let mut frame = Vec::with_capacity(JOURNAL_FRAME_PREFIX_BYTES + body.len());
        frame.extend_from_slice(&body_length.to_be_bytes());
        frame.extend_from_slice(&digest);
        frame.extend_from_slice(&self.state.last_digest);
        frame.extend_from_slice(&body);
        let mut journal = OpenOptions::new()
            .append(true)
            .open(&self.journal_path)
            .map_err(|error| {
                io_refusal("open journal for append", self.journal_path.clone(), error)
            })?;
        journal
            .write_all(&frame)
            .and_then(|()| journal.sync_data())
            .map_err(|error| {
                io_refusal(
                    "append durable journal event",
                    self.journal_path.clone(),
                    error,
                )
            })?;
        self.state.apply(event, digest)?;
        Ok(())
    }

    fn validate_replayed_state(&self) -> Result<(), AttemptRunnerRefusal> {
        if self.state.matrix_identity != Some(self.matrix.identity()) {
            return Err(AttemptRunnerRefusal::MatrixIdentityMismatch);
        }
        for target in self.state.targets.keys() {
            if self.matrix.target(target).is_none() {
                return Err(AttemptRunnerRefusal::JournalCorrupt {
                    reason: "journal names a target missing from matrix declaration",
                });
            }
        }
        if self.state.manifest_prepared.is_some() {
            self.ensure_manifest_allowed()?;
            let expected = fgit_crypto::sha256_digest(&manifest_body(&self.build_manifest()?));
            if self.state.manifest_prepared != Some(expected) {
                return Err(AttemptRunnerRefusal::JournalCorrupt {
                    reason: "journal manifest commitment does not match complete matrix",
                });
            }
        }
        Ok(())
    }

    fn verify_existing_manifest(&self) -> Result<(), AttemptRunnerRefusal> {
        if !self.manifest_path.exists() {
            return Ok(());
        }
        let metadata = symlink_metadata(&self.manifest_path, "inspect manifest root")?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(AttemptRunnerRefusal::ManifestRootMismatch);
        }
        let Some(expected) = self.state.manifest_prepared else {
            return Err(AttemptRunnerRefusal::ManifestRootMismatch);
        };
        let bytes = read_bounded(&self.manifest_path, MAX_JOURNAL_BYTES, "read manifest root")?;
        if fgit_crypto::sha256_digest(&bytes) != expected {
            return Err(AttemptRunnerRefusal::ManifestRootMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct JournalState {
    matrix_identity: Option<[u8; 32]>,
    targets: BTreeMap<String, TargetRecord>,
    cancelled: bool,
    manifest_prepared: Option<[u8; 32]>,
    events: u64,
    last_digest: [u8; 32],
}

impl JournalState {
    fn apply(&mut self, event: JournalEvent, digest: [u8; 32]) -> Result<(), AttemptRunnerRefusal> {
        match event {
            JournalEvent::MatrixDeclared { identity } => {
                if self.events != 0 || self.matrix_identity.replace(identity).is_some() {
                    return Err(AttemptRunnerRefusal::JournalCorrupt {
                        reason: "matrix declaration is not the first unique event",
                    });
                }
            }
            JournalEvent::TargetPassed {
                target,
                inventory_identity,
            } => {
                if self.matrix_identity.is_none() || self.targets.contains_key(&target) {
                    return Err(AttemptRunnerRefusal::JournalCorrupt {
                        reason: "target pass precedes matrix declaration or overwrites evidence",
                    });
                }
                self.targets
                    .insert(target, TargetRecord::Passed { inventory_identity });
            }
            JournalEvent::TargetFailed { target, detail } => {
                if self.matrix_identity.is_none() || self.targets.contains_key(&target) {
                    return Err(AttemptRunnerRefusal::JournalCorrupt {
                        reason: "target failure precedes matrix declaration or overwrites evidence",
                    });
                }
                self.targets.insert(target, TargetRecord::Failed { detail });
            }
            JournalEvent::Cancelled { .. } => {
                if self.matrix_identity.is_none()
                    || self.cancelled
                    || self.manifest_prepared.is_some()
                {
                    return Err(AttemptRunnerRefusal::JournalCorrupt {
                        reason: "cancellation is duplicated or follows manifest preparation",
                    });
                }
                self.cancelled = true;
            }
            JournalEvent::ManifestPrepared { digest: manifest } => {
                if self.matrix_identity.is_none()
                    || self.manifest_prepared.replace(manifest).is_some()
                {
                    return Err(AttemptRunnerRefusal::JournalCorrupt {
                        reason: "manifest preparation is duplicated or precedes matrix declaration",
                    });
                }
            }
        }
        self.events += 1;
        self.last_digest = digest;
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum JournalEvent {
    MatrixDeclared {
        identity: [u8; 32],
    },
    TargetPassed {
        target: String,
        inventory_identity: [u8; 32],
    },
    TargetFailed {
        target: String,
        detail: String,
    },
    Cancelled {
        target: String,
    },
    ManifestPrepared {
        digest: [u8; 32],
    },
}

struct Replay {
    state: JournalState,
    valid_len: usize,
}

fn replay_journal(bytes: &[u8]) -> Result<Replay, AttemptRunnerRefusal> {
    if !bytes.starts_with(JOURNAL_HEADER) {
        return Err(AttemptRunnerRefusal::JournalCorrupt {
            reason: "journal header is absent or wrong",
        });
    }
    let mut cursor = JOURNAL_HEADER.len();
    let mut state = JournalState::default();
    while cursor < bytes.len() {
        if bytes.len() - cursor < JOURNAL_FRAME_PREFIX_BYTES {
            break;
        }
        let body_len = usize::try_from(u32::from_be_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .expect("four-byte journal frame prefix"),
        ))
        .expect("u32 length always fits usize on supported Rust targets");
        if body_len > MAX_JOURNAL_EVENT_BYTES {
            return Err(AttemptRunnerRefusal::JournalCorrupt {
                reason: "journal event exceeds bounded length",
            });
        }
        let frame_len = JOURNAL_FRAME_PREFIX_BYTES + body_len;
        if bytes.len() - cursor < frame_len {
            break;
        }
        let digest_start = cursor + 4;
        let previous_start = digest_start + 32;
        let body_start = previous_start + 32;
        let digest: [u8; 32] = bytes[digest_start..previous_start]
            .try_into()
            .expect("journal digest width");
        let previous: [u8; 32] = bytes[previous_start..body_start]
            .try_into()
            .expect("journal previous digest width");
        if previous != state.last_digest {
            return Err(AttemptRunnerRefusal::JournalCorrupt {
                reason: "journal predecessor link mismatches",
            });
        }
        let body = &bytes[body_start..body_start + body_len];
        if entry_digest(state.events + 1, &previous, body) != digest {
            return Err(AttemptRunnerRefusal::JournalCorrupt {
                reason: "journal entry content digest mismatches",
            });
        }
        state.apply(decode_event(body)?, digest)?;
        cursor += frame_len;
    }
    Ok(Replay {
        state,
        valid_len: cursor,
    })
}

fn encode_event(event: &JournalEvent) -> Vec<u8> {
    let mut bytes = Vec::new();
    match event {
        JournalEvent::MatrixDeclared { identity } => {
            bytes.push(1);
            bytes.extend_from_slice(identity);
        }
        JournalEvent::TargetPassed {
            target,
            inventory_identity,
        } => {
            bytes.push(2);
            push_journal_text(&mut bytes, target);
            bytes.extend_from_slice(inventory_identity);
        }
        JournalEvent::TargetFailed { target, detail } => {
            bytes.push(3);
            push_journal_text(&mut bytes, target);
            push_journal_text(&mut bytes, detail);
        }
        JournalEvent::Cancelled { target } => {
            bytes.push(4);
            push_journal_text(&mut bytes, target);
        }
        JournalEvent::ManifestPrepared { digest } => {
            bytes.push(5);
            bytes.extend_from_slice(digest);
        }
    }
    bytes
}

fn decode_event(bytes: &[u8]) -> Result<JournalEvent, AttemptRunnerRefusal> {
    let Some((&kind, mut tail)) = bytes.split_first() else {
        return Err(AttemptRunnerRefusal::JournalCorrupt {
            reason: "journal event has no kind",
        });
    };
    match kind {
        1 => {
            let identity = take_digest(&mut tail)?;
            require_empty(tail)?;
            Ok(JournalEvent::MatrixDeclared { identity })
        }
        2 => {
            let target = take_journal_text(&mut tail)?;
            let inventory_identity = take_digest(&mut tail)?;
            require_empty(tail)?;
            Ok(JournalEvent::TargetPassed {
                target,
                inventory_identity,
            })
        }
        3 => {
            let target = take_journal_text(&mut tail)?;
            let detail = take_journal_text(&mut tail)?;
            require_empty(tail)?;
            Ok(JournalEvent::TargetFailed { target, detail })
        }
        4 => {
            let target = take_journal_text(&mut tail)?;
            require_empty(tail)?;
            Ok(JournalEvent::Cancelled { target })
        }
        5 => {
            let digest = take_digest(&mut tail)?;
            require_empty(tail)?;
            Ok(JournalEvent::ManifestPrepared { digest })
        }
        _ => Err(AttemptRunnerRefusal::JournalCorrupt {
            reason: "journal event kind is unknown",
        }),
    }
}

fn take_digest(tail: &mut &[u8]) -> Result<[u8; 32], AttemptRunnerRefusal> {
    if tail.len() < 32 {
        return Err(AttemptRunnerRefusal::JournalCorrupt {
            reason: "journal event is missing a digest",
        });
    }
    let digest = tail[..32].try_into().expect("checked digest length");
    *tail = &tail[32..];
    Ok(digest)
}

fn take_journal_text(tail: &mut &[u8]) -> Result<String, AttemptRunnerRefusal> {
    if tail.len() < 2 {
        return Err(AttemptRunnerRefusal::JournalCorrupt {
            reason: "journal text length is missing",
        });
    }
    let length = usize::from(u16::from_be_bytes([tail[0], tail[1]]));
    *tail = &tail[2..];
    if length > MAX_TARGET_TEXT_BYTES || tail.len() < length {
        return Err(AttemptRunnerRefusal::JournalCorrupt {
            reason: "journal text is oversized or truncated",
        });
    }
    let text = std::str::from_utf8(&tail[..length])
        .map_err(|_| AttemptRunnerRefusal::JournalCorrupt {
            reason: "journal text is not UTF-8",
        })?
        .to_owned();
    *tail = &tail[length..];
    Ok(text)
}

const fn require_empty(tail: &[u8]) -> Result<(), AttemptRunnerRefusal> {
    if tail.is_empty() {
        Ok(())
    } else {
        Err(AttemptRunnerRefusal::JournalCorrupt {
            reason: "journal event has trailing bytes",
        })
    }
}

fn push_journal_text(bytes: &mut Vec<u8>, text: &str) {
    let bounded = bounded_detail(text.to_owned());
    let length = u16::try_from(bounded.len()).expect("bounded journal text fits u16");
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(bounded.as_bytes());
}

fn entry_digest(sequence: u64, previous: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut bytes = JOURNAL_ENTRY_DOMAIN.to_vec();
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(previous);
    bytes.extend_from_slice(body);
    fgit_crypto::sha256_digest(&bytes)
}

fn expected_assets(
    target: &TargetSpec,
) -> Result<BTreeMap<String, [u8; 32]>, AttemptRunnerRefusal> {
    let mut expected = BTreeMap::new();
    for asset in &target.assets {
        validate_asset_path(asset.path())?;
        if expected
            .insert(asset.path().to_owned(), asset.digest())
            .is_some()
        {
            return Err(AttemptRunnerRefusal::DuplicateTargetAsset {
                target: target.name.clone(),
                path: asset.path().to_owned(),
            });
        }
    }
    Ok(expected)
}

fn collect_directory(
    root: &Path,
    relative: &Path,
    expected: &BTreeMap<String, [u8; 32]>,
    observed: &mut BTreeMap<String, [u8; 32]>,
    entry_count: &mut usize,
) -> Result<(), AttemptRunnerRefusal> {
    let directory = root.join(relative);
    let raw_entries = fs::read_dir(&directory)
        .map_err(|error| io_refusal("read staging directory", directory.clone(), error))?;
    let mut entries = Vec::new();
    for entry in raw_entries {
        if *entry_count + entries.len() >= MAX_STAGING_DIRECTORY_ENTRIES {
            return Err(AttemptRunnerRefusal::StagingEntryLimit {
                directory: directory.display().to_string(),
            });
        }
        entries.push(
            entry.map_err(|error| io_refusal("read staging entry", directory.clone(), error))?,
        );
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        *entry_count += 1;
        let name = entry
            .file_name()
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| AttemptRunnerRefusal::AssetTraversal {
                path: entry.path().display().to_string(),
            })?;
        let child_relative = relative.join(name);
        let child_name = child_relative.to_string_lossy().replace('\\', "/");
        let path = entry.path();
        let metadata = symlink_metadata(&path, "inspect staged entry")?;
        if metadata.file_type().is_symlink() {
            return Err(AttemptRunnerRefusal::AssetSymlink { path: child_name });
        }
        if metadata.is_dir() {
            if expected.contains_key(&child_name) {
                return Err(AttemptRunnerRefusal::AssetNonRegular { path: child_name });
            }
            let prefix = format!("{child_name}/");
            if !expected
                .keys()
                .any(|expected_path| expected_path.starts_with(&prefix))
            {
                return Err(AttemptRunnerRefusal::AssetUnlisted { path: child_name });
            }
            collect_directory(root, &child_relative, expected, observed, entry_count)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(AttemptRunnerRefusal::AssetNonRegular { path: child_name });
        }
        let Some(expected_digest) = expected.get(&child_name) else {
            return Err(AttemptRunnerRefusal::AssetUnlisted { path: child_name });
        };
        let observed_digest = digest_regular_file(&path, &child_name, metadata.len())?;
        if observed_digest != *expected_digest {
            return Err(AttemptRunnerRefusal::AssetDigestMismatch {
                path: child_name,
                expected: *expected_digest,
                observed: observed_digest,
            });
        }
        if observed
            .insert(child_name.clone(), observed_digest)
            .is_some()
        {
            return Err(AttemptRunnerRefusal::JournalCorrupt {
                reason: "filesystem inventory produced a duplicate relative path",
            });
        }
    }
    Ok(())
}

fn digest_regular_file(
    path: &Path,
    display_path: &str,
    length: u64,
) -> Result<[u8; 32], AttemptRunnerRefusal> {
    if length > MAX_STAGED_ASSET_BYTES {
        return Err(AttemptRunnerRefusal::AssetTooLarge {
            path: display_path.to_owned(),
            bytes: length,
        });
    }
    let capacity = usize::try_from(length).map_err(|_| AttemptRunnerRefusal::AssetTooLarge {
        path: display_path.to_owned(),
        bytes: length,
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .and_then(|file| {
            let mut bounded = file.take(length.saturating_add(1));
            bounded.read_to_end(&mut bytes)
        })
        .map_err(|error| io_refusal("read staged asset", path.to_path_buf(), error))?;
    if u64::try_from(bytes.len()).expect("usize fits u64") != length {
        return Err(AttemptRunnerRefusal::JournalCorrupt {
            reason: "staged asset changed while it was being inventoried",
        });
    }
    Ok(fgit_crypto::sha256_digest(&bytes))
}

fn manifest_body(manifest: &ReleaseManifest) -> Vec<u8> {
    let mut body = MANIFEST_DOMAIN.to_vec();
    body.extend_from_slice(manifest.attempt().to_hex().as_bytes());
    body.push(b'\n');
    for asset in manifest.assets() {
        body.extend_from_slice(asset.path().as_bytes());
        body.push(b'\0');
        body.extend_from_slice(hex(&asset.digest()).as_bytes());
        body.push(b'\n');
    }
    body
}

fn attempt_directory(
    root: &Path,
    attempt: &AttemptIdentity,
) -> Result<PathBuf, AttemptRunnerRefusal> {
    ensure_directory(root)?;
    let attempts = root.join("attempts");
    ensure_directory(&attempts)?;
    Ok(attempts.join(attempt.to_hex()))
}

fn ensure_directory(path: &Path) -> Result<(), AttemptRunnerRefusal> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(AttemptRunnerRefusal::SymlinkedAttemptPath {
                    path: path.to_path_buf(),
                });
            }
            if !metadata.is_dir() {
                return Err(AttemptRunnerRefusal::AttemptRootNotDirectory {
                    path: path.to_path_buf(),
                });
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|error| io_refusal("create attempt root", path.to_path_buf(), error))?;
            let metadata = symlink_metadata(path, "verify created attempt root")?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AttemptRunnerRefusal::SymlinkedAttemptPath {
                    path: path.to_path_buf(),
                });
            }
            Ok(())
        }
        Err(error) => Err(io_refusal(
            "inspect attempt root",
            path.to_path_buf(),
            error,
        )),
    }
}

fn validate_target_name(target: &str) -> Result<(), AttemptRunnerRefusal> {
    if target.is_empty()
        || target.len() > MAX_TARGET_TEXT_BYTES
        || !target.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(AttemptRunnerRefusal::InvalidTargetName {
            target: target.to_owned(),
        });
    }
    Ok(())
}

fn validate_asset_path(path: &str) -> Result<(), AttemptRunnerRefusal> {
    let candidate = Path::new(path);
    if path.is_empty()
        || path.len() > MAX_ASSET_PATH_BYTES
        || path.contains('\0')
        || candidate.is_absolute()
    {
        return Err(AttemptRunnerRefusal::AssetTraversal {
            path: path.to_owned(),
        });
    }
    for component in candidate.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(AttemptRunnerRefusal::AssetTraversal {
                path: path.to_owned(),
            });
        }
    }
    Ok(())
}

fn read_bounded(
    path: &Path,
    limit: u64,
    operation: &'static str,
) -> Result<Vec<u8>, AttemptRunnerRefusal> {
    let metadata = symlink_metadata(path, operation)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(AttemptRunnerRefusal::JournalCorrupt {
            reason: "journal or manifest is not a bounded regular file",
        });
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| {
        AttemptRunnerRefusal::JournalCorrupt {
            reason: "bounded file length is not addressable",
        }
    })?);
    File::open(path)
        .and_then(|file| {
            let mut bounded = file.take(metadata.len().saturating_add(1));
            bounded.read_to_end(&mut bytes)
        })
        .map_err(|error| io_refusal(operation, path.to_path_buf(), error))?;
    if u64::try_from(bytes.len()).expect("usize fits u64") != metadata.len() {
        return Err(AttemptRunnerRefusal::JournalCorrupt {
            reason: "bounded journal or manifest changed while it was being read",
        });
    }
    Ok(bytes)
}

fn symlink_metadata(
    path: &Path,
    operation: &'static str,
) -> Result<fs::Metadata, AttemptRunnerRefusal> {
    fs::symlink_metadata(path).map_err(|error| io_refusal(operation, path.to_path_buf(), error))
}

fn io_refusal(
    operation: &'static str,
    path: PathBuf,
    error: std::io::Error,
) -> AttemptRunnerRefusal {
    AttemptRunnerRefusal::Io {
        operation,
        path,
        kind: error.kind(),
    }
}

fn bounded_detail(mut detail: String) -> String {
    if detail.len() > MAX_TARGET_TEXT_BYTES {
        detail.truncate(MAX_TARGET_TEXT_BYTES);
    }
    detail
}

fn push_field(bytes: &mut Vec<u8>, field: &[u8]) {
    let length = u32::try_from(field.len()).expect("bounded release field fits u32");
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(field);
}
