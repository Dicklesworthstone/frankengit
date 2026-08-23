//! Capability-scoped sparse-directory materialization manifests.
//!
//! A [`SparseManifest`] is the verified, immutable input to a host-directory
//! adapter.  It is deliberately not a filesystem writer or mount: creating a
//! directory, owning its temporary paths, and reconciling declared outputs are
//! side effects that belong to the runner-owned adapter and its obligations.
//! This module owns the preceding final boundary: deterministic discovery,
//! per-object identity verification, capability charging, path containment,
//! and a typed representation in which symlinks remain link-text data.

use crate::base::{BaseError, BaseView, ObjectSource, ObjectSourceError};
use crate::capability::{CapabilityRefusal, TreeCapability};
use crate::overlay::FileMode;
use crate::path::TreePath;
use core::fmt::{self, Display, Formatter};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid};
use fgit_types::{RepositoryCommitId, RepositoryId};
use std::collections::BTreeMap;

/// Bounds for the retained, sparse materialization manifest.
///
/// The source view has its own object-parse limit.  These bounds apply before
/// this module retains a member body or extends its output vector, preventing a
/// permissive source from turning an authorised sparse read into unbounded
/// process memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SparseLimits {
    /// Most entries, including generated-parent directory entries.
    pub max_entries: usize,
    /// Most bytes retained for one file or symlink's link-text body.
    pub max_entry_bytes: usize,
    /// Most bytes retained across all file and symlink bodies.
    pub max_payload_bytes: usize,
}

impl Default for SparseLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_entry_bytes: 128 * 1024 * 1024,
            max_payload_bytes: 512 * 1024 * 1024,
        }
    }
}

/// The deterministic sparse-materialization profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SparseProfile {
    /// Canonically ordered `TreeFS` entries with files and symlinks represented
    /// as verified byte bodies and no host filesystem effect.
    ManifestV1,
}

/// The selection rule represented by a sparse materialization receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SparseCompleteness {
    /// Every and only the entries visible through the supplied capability at
    /// discovery time, in canonical path order.
    CapabilityVisibleTreeV1,
}

/// The verification boundary crossed while building a sparse manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SparseVerification {
    /// Every tree and retained payload passed `BaseView`'s source-object
    /// identity check before entering the manifest.
    SourceObjectIdentitiesVerifiedV1,
}

/// The exact source and selection boundary for a sparse manifest.
///
/// This receipt is derived evidence only.  A matching manifest must still be
/// paired with a current authority read before a service uses it; it cannot
/// publish a ref or prove that the named RCR is current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseReceipt<A: GitHashAlgorithm> {
    repository_id: RepositoryId,
    source_rcr_id: RepositoryCommitId,
    source_commit_oid: GitOid<A>,
    source_tree_oid: GitOid<A>,
    profile: SparseProfile,
    completeness: SparseCompleteness,
    verification: SparseVerification,
    entry_count: usize,
    payload_bytes: usize,
}

impl<A: GitHashAlgorithm> SparseReceipt<A> {
    /// Repository whose authenticated base was materialized.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Canonical RCR that selected the immutable source commit.
    #[must_use]
    pub const fn source_rcr_id(&self) -> RepositoryCommitId {
        self.source_rcr_id
    }

    /// Source commit selected by the RCR.
    #[must_use]
    pub const fn source_commit_oid(&self) -> &GitOid<A> {
        &self.source_commit_oid
    }

    /// Root tree materialized from the selected source commit.
    #[must_use]
    pub const fn source_tree_oid(&self) -> &GitOid<A> {
        &self.source_tree_oid
    }

    /// Deterministic format used for retained manifest entries.
    #[must_use]
    pub const fn profile(&self) -> SparseProfile {
        self.profile
    }

    /// Capability-scoped selection rule applied before payload reads.
    #[must_use]
    pub const fn completeness(&self) -> SparseCompleteness {
        self.completeness
    }

    /// Identity-verification boundary crossed before retaining input bytes.
    #[must_use]
    pub const fn verification(&self) -> SparseVerification {
        self.verification
    }

    /// Number of capability-visible entries retained in this manifest.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Total retained bytes for file bodies and symlink link-text data.
    #[must_use]
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
}

/// One entry in a [`SparseManifest`], in canonical path order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseEntry<A: GitHashAlgorithm> {
    path: TreePath,
    source_oid: GitOid<A>,
    kind: SparseEntryKind,
}

impl<A: GitHashAlgorithm> SparseEntry<A> {
    /// Canonical relative repository path; never a host-absolute path.
    #[must_use]
    pub const fn path(&self) -> &TreePath {
        &self.path
    }

    /// Git object identity whose checked body or tree produced this entry.
    #[must_use]
    pub const fn source_oid(&self) -> &GitOid<A> {
        &self.source_oid
    }

    /// Directory, regular-file, or data-only symlink representation.
    #[must_use]
    pub const fn kind(&self) -> &SparseEntryKind {
        &self.kind
    }
}

/// A host-independent representation of one sparse directory member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SparseEntryKind {
    /// A generated parent directory.  No object body is retained.
    Directory,
    /// A regular file with a closed `TreeFS` file-mode set and verified body.
    File {
        /// The only file modes the `TreeFS` host adapter may create.
        mode: FileMode,
        /// Checked blob body.
        body: Vec<u8>,
    },
    /// A repository symlink represented as data, never followed by this layer.
    Symlink {
        /// Checked blob body containing raw link-text bytes.
        target: Vec<u8>,
    },
}

impl SparseEntryKind {
    /// The regular-file mode, if this is a file entry.
    #[must_use]
    pub const fn file_mode(&self) -> Option<FileMode> {
        match self {
            Self::File { mode, .. } => Some(*mode),
            Self::Directory | Self::Symlink { .. } => None,
        }
    }

    /// File body or symlink link-text, if this entry carries source bytes.
    #[must_use]
    pub fn body(&self) -> Option<&[u8]> {
        match self {
            Self::File { body, .. } => Some(body),
            Self::Symlink { target } => Some(target),
            Self::Directory => None,
        }
    }
}

/// A deterministic, capability-scoped sparse directory input manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseManifest<A: GitHashAlgorithm> {
    entries: Vec<SparseEntry<A>>,
    receipt: SparseReceipt<A>,
}

impl<A: GitHashAlgorithm> SparseManifest<A> {
    /// Builds a sparse manifest from the capability-visible part of `base`.
    ///
    /// Discovery is completed before payload reads, preserving canonical order
    /// and refusing entry-count excess before retaining file data.  Every
    /// retained payload crosses `BaseView`'s Git-object identity check and is
    /// charged to `capability`.  Symlink bodies are retained only as data.
    pub fn build<S: ObjectSource<A>>(
        base: &BaseView<A>,
        source: &S,
        capability: &mut TreeCapability,
        now: u64,
        limits: SparseLimits,
    ) -> Result<Self, SparseRefusal> {
        let mut planned = BTreeMap::new();
        discover(base, source, capability, None, now, limits, &mut planned)?;

        let mut entries = Vec::new();
        entries
            .try_reserve_exact(planned.len())
            .map_err(|_| SparseRefusal::AllocationFailed {
                requested: planned.len(),
            })?;
        let mut payload_bytes = 0_usize;
        for (path, entry) in planned {
            let (source_oid, kind) = match entry {
                PlannedEntry::Directory { oid } => (oid, SparseEntryKind::Directory),
                PlannedEntry::File { oid, mode } => {
                    let body = read_payload(base, source, capability, &path, &oid, now)?;
                    check_entry_bytes(&path, body.len(), limits.max_entry_bytes)?;
                    payload_bytes =
                        add_payload_bytes(payload_bytes, body.len(), limits.max_payload_bytes)?;
                    (oid, SparseEntryKind::File { mode, body })
                }
                PlannedEntry::Symlink { oid } => {
                    let target = read_payload(base, source, capability, &path, &oid, now)?;
                    check_entry_bytes(&path, target.len(), limits.max_entry_bytes)?;
                    payload_bytes =
                        add_payload_bytes(payload_bytes, target.len(), limits.max_payload_bytes)?;
                    (oid, SparseEntryKind::Symlink { target })
                }
            };
            entries.push(SparseEntry {
                path,
                source_oid,
                kind,
            });
        }

        let receipt = SparseReceipt {
            repository_id: base.repository_id(),
            source_rcr_id: base.base_rcr_id(),
            source_commit_oid: *base.base_commit_oid(),
            source_tree_oid: *base.base_tree_oid(),
            profile: SparseProfile::ManifestV1,
            completeness: SparseCompleteness::CapabilityVisibleTreeV1,
            verification: SparseVerification::SourceObjectIdentitiesVerifiedV1,
            entry_count: entries.len(),
            payload_bytes,
        };
        Ok(Self { entries, receipt })
    }

    /// Capability-visible input members, in canonical path order.
    #[must_use]
    pub fn entries(&self) -> &[SparseEntry<A>] {
        &self.entries
    }

    /// Exact source coordinates and retained-payload accounting.
    #[must_use]
    pub const fn receipt(&self) -> &SparseReceipt<A> {
        &self.receipt
    }
}

/// Why a sparse materialization was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SparseRefusal {
    /// Traversing the authenticated base failed.
    Base(BaseError),
    /// A source object could not be read or did not match its requested OID.
    Source(ObjectSourceError),
    /// The `TreeFS` capability refused a read, symlink, or budget charge.
    Capability(CapabilityRefusal),
    /// The source tree produced the same canonical path more than once.
    DuplicatePath {
        /// Duplicate path.
        path: TreePath,
    },
    /// The configured entry ceiling would be exceeded.
    EntryLimitExceeded {
        /// Entry count that would result.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// One retained body exceeds the configured per-entry ceiling.
    EntryBytesExceeded {
        /// Entry whose body was too large.
        path: TreePath,
        /// Body bytes observed.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Retained payload bodies together exceed the configured ceiling.
    PayloadBytesExceeded {
        /// Total bytes that would be retained.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A gitlink has no ordinary sparse-directory representation in this
    /// profile.
    SubmoduleUnsupported {
        /// Gitlink path.
        path: TreePath,
    },
    /// A file mode lies outside the closed set a `TreeFS` host adapter creates.
    UnsupportedFileMode {
        /// File path.
        path: TreePath,
        /// Raw Git mode bytes.
        mode: Vec<u8>,
    },
    /// Retained metadata or member bytes could not reserve memory.
    AllocationFailed {
        /// Entry or byte count requested from the allocator.
        requested: usize,
    },
    /// A payload-length conversion or aggregate calculation overflowed.
    SizeOverflow,
}

impl Display for SparseRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(error) => write!(formatter, "base traversal failed: {error}"),
            Self::Source(error) => write!(formatter, "verified object read failed: {error}"),
            Self::Capability(error) => write!(formatter, "sparse capability refused: {error}"),
            Self::DuplicatePath { path } => write!(formatter, "duplicate sparse path {path}"),
            Self::EntryLimitExceeded { observed, limit } => {
                write!(
                    formatter,
                    "{observed} sparse entries exceeds the limit of {limit}"
                )
            }
            Self::EntryBytesExceeded {
                path,
                observed,
                limit,
            } => write!(
                formatter,
                "sparse entry {path} is {observed} bytes, limit is {limit}"
            ),
            Self::PayloadBytesExceeded {
                observed, limit, ..
            } => write!(
                formatter,
                "sparse payload would retain {observed} bytes, limit is {limit}"
            ),
            Self::SubmoduleUnsupported { path } => {
                write!(
                    formatter,
                    "submodule {path} is unsupported in sparse materialization"
                )
            }
            Self::UnsupportedFileMode { path, mode } => write!(
                formatter,
                "file {path} has unsupported sparse mode {:?}",
                String::from_utf8_lossy(mode)
            ),
            Self::AllocationFailed { requested } => {
                write!(
                    formatter,
                    "sparse manifest could not reserve {requested} bytes or entries"
                )
            }
            Self::SizeOverflow => formatter.write_str("sparse materialization size overflowed"),
        }
    }
}

impl core::error::Error for SparseRefusal {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PlannedEntry<A: GitHashAlgorithm> {
    Directory { oid: GitOid<A> },
    File { oid: GitOid<A>, mode: FileMode },
    Symlink { oid: GitOid<A> },
}

fn discover<A: GitHashAlgorithm, S: ObjectSource<A>>(
    base: &BaseView<A>,
    source: &S,
    capability: &mut TreeCapability,
    directory: Option<&TreePath>,
    now: u64,
    limits: SparseLimits,
    planned: &mut BTreeMap<TreePath, PlannedEntry<A>>,
) -> Result<(), SparseRefusal> {
    let children = base
        .list(source, capability, directory, now)
        .map_err(SparseRefusal::Base)?;
    for (name, entry) in children {
        let path = match directory {
            Some(parent) => parent
                .join(&name, base.path_policy())
                .map_err(|error| SparseRefusal::Base(BaseError::Path(error)))?,
            None => TreePath::parse(&name, base.path_policy())
                .map_err(|error| SparseRefusal::Base(BaseError::Path(error)))?,
        };
        if planned.len() >= limits.max_entries {
            return Err(SparseRefusal::EntryLimitExceeded {
                observed: planned.len().saturating_add(1),
                limit: limits.max_entries,
            });
        }

        let entry = match entry {
            crate::base::BaseEntry::Directory { oid } => PlannedEntry::Directory { oid },
            crate::base::BaseEntry::File { oid, mode } => PlannedEntry::File {
                oid,
                mode: file_mode(&path, &mode)?,
            },
            crate::base::BaseEntry::Symlink { oid } => {
                capability
                    .check_symlink(&path)
                    .map_err(SparseRefusal::Capability)?;
                PlannedEntry::Symlink { oid }
            }
            crate::base::BaseEntry::Submodule { .. } => {
                return Err(SparseRefusal::SubmoduleUnsupported { path });
            }
        };
        if planned.insert(path.clone(), entry).is_some() {
            return Err(SparseRefusal::DuplicatePath { path });
        }
        if matches!(planned.get(&path), Some(PlannedEntry::Directory { .. })) {
            discover(base, source, capability, Some(&path), now, limits, planned)?;
        }
    }
    Ok(())
}

fn read_payload<A: GitHashAlgorithm, S: ObjectSource<A>>(
    base: &BaseView<A>,
    source: &S,
    capability: &mut TreeCapability,
    path: &TreePath,
    oid: &GitOid<A>,
    now: u64,
) -> Result<Vec<u8>, SparseRefusal> {
    let grant = capability
        .authorize_read(path, now)
        .map_err(SparseRefusal::Capability)?;
    let body = base
        .read_object(source, oid, GitObjectKind::Blob, &grant)
        .map_err(SparseRefusal::Source)?;
    capability
        .charge_fetch(u64::try_from(body.len()).map_err(|_| SparseRefusal::SizeOverflow)?)
        .map_err(SparseRefusal::Capability)?;
    Ok(body)
}

fn file_mode(path: &TreePath, mode: &[u8]) -> Result<FileMode, SparseRefusal> {
    match mode {
        b"100644" => Ok(FileMode::Regular),
        b"100755" => Ok(FileMode::Executable),
        _ => Err(SparseRefusal::UnsupportedFileMode {
            path: path.clone(),
            mode: mode.to_vec(),
        }),
    }
}

fn check_entry_bytes(path: &TreePath, observed: usize, limit: usize) -> Result<(), SparseRefusal> {
    if observed > limit {
        return Err(SparseRefusal::EntryBytesExceeded {
            path: path.clone(),
            observed,
            limit,
        });
    }
    Ok(())
}

fn add_payload_bytes(current: usize, next: usize, limit: usize) -> Result<usize, SparseRefusal> {
    let observed = current
        .checked_add(next)
        .ok_or(SparseRefusal::SizeOverflow)?;
    if observed > limit {
        return Err(SparseRefusal::PayloadBytesExceeded { observed, limit });
    }
    Ok(observed)
}
