//! Bounded staging of an ordinary local Git directory.
//!
//! This module owns only the pre-publication half of import: it validates a
//! local Git directory, follows the closure named by its direct refs, resolves
//! those objects from checksum-bound loose or idx/pack storage, and places
//! verified immutable object bodies in the node's fabric.  The returned
//! [`StagedLooseGitImport`] is not a publication capability.  In particular,
//! objects staged here remain non-canonical until the caller has sealed an
//! import request, recorded its admission, and published an RCR through the
//! authority head's conditional replacement.

#[cfg(test)]
mod cancellation_tests;
mod control;
pub mod graph;
mod profile;
mod spool;

pub use control::checkpoint_request;
use control::{ImportControl, ReadFailure};

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io;
#[cfg(test)]
use std::io::Read;
use std::path::{Path, PathBuf};

use fgit_admission::{CanonicalRefState, PermittedObjectClosure};
use fgit_git_object::{
    AcceptanceProfile, InflateLimits, LooseObjectDecodeError, ObjectError, ParseLimits,
};
use fgit_pack::{
    CachedResolver, Deadline, IdxV2, NativeChecksumVerifier, PackError, PackLimits,
    ResolutionBudget, read_verified_pack, validate_idx_entry_crc, validate_idx_pack_count,
    verify_native_object,
};
use fgit_types::{GitHashAlgorithm, GitOid, MAX_REF_NAME_LEN, RefName, TypeRefusal};

use super::{NodeRefusal, NodeRequestContext, OneNode};

const MAX_IMPORT_REFS: usize = 65_536;
const MAX_IMPORT_OBJECTS: usize = 1_000_000;
const MAX_IMPORT_TOTAL_OBJECT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMPORT_COMPRESSED_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMPORT_COMPRESSED_OBJECT_BYTES_USIZE: usize = 64 * 1024 * 1024;
const MAX_IMPORT_PACKS: usize = 128;
const MAX_IMPORT_PACK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMPORT_TOTAL_PACK_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMPORT_TOTAL_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMPORT_PACKED_REFS_HEADER_BYTES: usize = 1024;
const MAX_IMPORT_REF_DEPTH: usize = 32;
const MAX_IMPORT_DIRECTORY_ENTRIES: usize = 1_000_000;

/// Verified, non-canonical state staged from a local Git directory.
///
/// This type has no public constructor.  Its refs and closure can only be
/// produced after every object reachable from a direct source ref was parsed,
/// re-identified, and placed through the immutable fabric.  It is still only
/// a candidate: publishing it requires the separate sealed import path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedLooseGitImport {
    refs: CanonicalRefState,
    closure: PermittedObjectClosure,
    object_count: usize,
    total_object_bytes: u64,
}

impl StagedLooseGitImport {
    /// Candidate canonical refs copied from the source's direct refs.
    #[must_use]
    pub const fn refs(&self) -> &CanonicalRefState {
        &self.refs
    }

    /// Exact verified native object closure reachable from those refs.
    #[must_use]
    pub const fn closure(&self) -> &PermittedObjectClosure {
        &self.closure
    }

    /// Number of unique reachable objects staged in immutable fabric.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.object_count
    }

    /// Sum of the uncompressed bodies staged by this candidate import.
    #[must_use]
    pub const fn total_object_bytes(&self) -> u64 {
        self.total_object_bytes
    }
}

/// Refusal while reading a bounded ordinary local Git directory.
#[derive(Debug)]
pub enum LooseGitImportRefusal {
    /// Preparation stopped under its caller-owned control. This is not proof
    /// of rollback or a canonical terminal decision. A runtime exhaustion keeps
    /// its exact dimension; no replacement budget is minted to continue.
    Interrupted {
        code: fgit_types::RefusalCode,
        exhaustion: Option<fgit_runtime::Exhaustion>,
    },
    /// The source path or one required child could not be inspected or read.
    Io {
        /// Operation that refused.
        operation: &'static str,
        /// Path passed to the operating system.
        path: Box<PathBuf>,
        /// Operating-system failure.
        source: Box<io::Error>,
    },
    /// The source or one of its entries was a symlink, which this local import
    /// profile deliberately does not follow.
    SymbolicLink(Box<PathBuf>),
    /// Neither a bare Git directory nor a worktree `.git` directory was found.
    GitDirectoryMissing(Box<PathBuf>),
    /// A worktree used a `.git` indirection file, unsupported by this bounded
    /// first import profile.
    GitDirectoryFileUnsupported(Box<PathBuf>),
    /// A required path had the wrong filesystem kind.
    PathKind {
        /// Expected kind.
        expected: &'static str,
        /// Observed path.
        path: Box<PathBuf>,
    },
    /// One `.pack` or `.idx` file lacked its same-stem companion.
    PackPairMissing(Box<PathBuf>),
    /// A pack-directory entry was neither a pack pair nor a recognized derived
    /// accelerator that this import profile can safely ignore.
    PackDirectoryEntryUnsupported(Box<PathBuf>),
    /// The source exceeded the bounded number of local pack pairs before any
    /// pack body was opened.
    PackFileLimitExceeded { limit: usize },
    /// One pack/index file or the selected aggregate exceeded its pre-read
    /// byte envelope.
    PackInputBytesExceeded {
        /// File or pack directory whose envelope was exceeded.
        path: Box<PathBuf>,
        /// Selected byte ceiling.
        limit: u64,
        /// Observed or attempted bytes.
        observed: u64,
    },
    /// `HEAD`, one loose ref, or `packed-refs` exceeded its derived byte
    /// envelope before the importer parsed or retained the complete file.
    RefInputBytesExceeded {
        /// Exact ref-control file whose envelope was exceeded.
        path: Box<PathBuf>,
        /// Derived byte ceiling for this file and import profile.
        limit: u64,
        /// Observed bytes, or the first byte beyond `limit` for a growing file.
        observed: u64,
    },
    /// A selected idx/pack pair failed structural, checksum, association,
    /// delta, resource, or native-object verification.
    PackedObject {
        /// Exact pack or index file at the failing boundary.
        path: Box<PathBuf>,
        /// Stable first-party pack refusal.
        source: Box<PackError>,
    },
    /// Git alternates would add an undeclared object source.
    ObjectAlternatesUnsupported(Box<PathBuf>),
    /// A ref path was not representable in the canonical ref vocabulary.
    RefName {
        /// Source path for the invalid name.
        path: Box<PathBuf>,
        /// Canonical-name refusal.
        source: Box<TypeRefusal>,
    },
    /// A direct ref, packed-ref line, or object filename did not use canonical
    /// lowercase native object hex.
    ObjectIdentity {
        /// Source path containing the identity text.
        path: Box<PathBuf>,
        /// Native-identity refusal.
        source: Box<TypeRefusal>,
    },
    /// A symbolic source ref would require an additional ref-resolution
    /// policy, so it is refused rather than guessed.
    SymbolicRefUnsupported(Box<PathBuf>),
    /// The source repository did not carry the required `HEAD` symbolic-ref
    /// file. Import must not manufacture a default branch target.
    HeadMissing(Box<PathBuf>),
    /// The source `HEAD` was direct rather than symbolic.
    HeadNotSymbolic(Box<PathBuf>),
    /// The source `HEAD` symbolic-ref line was ambiguous or malformed.
    HeadContents(Box<PathBuf>),
    /// The source `HEAD` symbolic ref named a namespace other than
    /// `refs/heads/*`.
    HeadTargetNotBranch(Box<PathBuf>),
    /// A direct ref file did not contain exactly one native object identity.
    RefContents(Box<PathBuf>),
    /// A packed-refs file did not contain its closed direct-ref grammar.
    PackedRefContents(Box<PathBuf>),
    /// The source named an object unavailable from every declared loose or
    /// checksum-bound packed source.
    ObjectMissing(GitOid),
    /// A reconstructed object body did not reproduce the object identity that
    /// selected it.
    ObjectIdentityMismatch {
        /// Identity requested by a ref or parent object.
        expected: GitOid,
        /// Identity reproduced from the verified loose body.
        observed: GitOid,
    },
    /// A native graph edge is ambiguous, has the wrong kind, or exceeds its
    /// bounded validation work. This is a pre-staging failure, not a decision.
    ObjectGraph {
        identity: GitOid,
        code: fgit_types::RefusalCode,
    },
    /// Bounded zlib/loose decoding refused the source object.
    LooseObject(Box<LooseObjectDecodeError>),
    /// A parsed object could not yield a complete closure edge set.
    ObjectStructure(Box<ObjectError>),
    /// A commit reachable from a source ref lacked its required tree edge.
    CommitTreeMissing(GitOid),
    /// An annotated tag reachable from a source ref lacked exactly one object
    /// edge.
    TagObjectMissing(GitOid),
    /// The source exceeded the explicit direct-ref bound before more state was
    /// allocated.
    RefLimitExceeded { limit: usize },
    /// The source exceeded the explicit reachable-object bound before another
    /// object was opened.
    ObjectLimitExceeded { limit: usize },
    /// The next validated object would exceed the aggregate import byte bound.
    TotalObjectBytesExceeded { limit: u64, observed: u64 },
    /// A reachable compressed loose file exceeded the pre-read bound.
    CompressedObjectBytesExceeded { limit: u64, observed: u64 },
    /// One ref directory was nested beyond the explicit traversal limit.
    RefDepthExceeded { limit: usize },
    /// One directory listed more entries than the bounded profile permits.
    DirectoryEntryLimitExceeded { limit: usize },
    /// Verified object placement refused before the import could become a
    /// candidate publication.
    Node(Box<NodeRefusal>),
}

impl Display for LooseGitImportRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interrupted { code, exhaustion } => write!(
                formatter,
                "source import interrupted: {code:?}; exhaustion={exhaustion:?}"
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "cannot {operation} {}: {source}", path.display()),
            Self::SymbolicLink(path) => {
                write!(
                    formatter,
                    "loose import refuses symbolic link {}",
                    path.display()
                )
            }
            Self::GitDirectoryMissing(path) => write!(
                formatter,
                "source {} is neither a bare Git directory nor a worktree with .git",
                path.display()
            ),
            Self::GitDirectoryFileUnsupported(path) => write!(
                formatter,
                "loose import does not support .git indirection file {}",
                path.display()
            ),
            Self::PathKind { expected, path } => {
                write!(formatter, "expected {expected} at {}", path.display())
            }
            Self::PackPairMissing(path) => write!(
                formatter,
                "local Git import requires a same-stem .pack/.idx pair for {}",
                path.display()
            ),
            Self::PackDirectoryEntryUnsupported(path) => write!(
                formatter,
                "local Git import does not recognize pack-directory entry {}",
                path.display()
            ),
            Self::PackFileLimitExceeded { limit } => {
                write!(formatter, "local Git import pack count exceeds {limit}")
            }
            Self::PackInputBytesExceeded {
                path,
                limit,
                observed,
            } => write!(
                formatter,
                "local Git import input {} is {observed} bytes, exceeding {limit}",
                path.display()
            ),
            Self::RefInputBytesExceeded {
                path,
                limit,
                observed,
            } => write!(
                formatter,
                "local Git ref input {} is {observed} bytes, exceeding {limit}",
                path.display()
            ),
            Self::PackedObject { path, source } => write!(
                formatter,
                "local Git packed object source {} refused: {source}",
                path.display()
            ),
            Self::ObjectAlternatesUnsupported(path) => write!(
                formatter,
                "loose import refuses undeclared object alternates at {}",
                path.display()
            ),
            Self::RefName { path, source } => {
                write!(formatter, "invalid source ref {}: {source}", path.display())
            }
            Self::ObjectIdentity { path, source } => {
                write!(
                    formatter,
                    "invalid native object identity at {}: {source}",
                    path.display()
                )
            }
            Self::SymbolicRefUnsupported(path) => {
                write!(
                    formatter,
                    "loose import refuses symbolic ref {}",
                    path.display()
                )
            }
            Self::HeadMissing(path) => write!(
                formatter,
                "loose import requires symbolic HEAD at {}",
                path.display()
            ),
            Self::HeadNotSymbolic(path) => write!(
                formatter,
                "loose import requires HEAD at {} to be symbolic",
                path.display()
            ),
            Self::HeadContents(path) => write!(
                formatter,
                "source HEAD {} does not contain one symbolic-ref target",
                path.display()
            ),
            Self::HeadTargetNotBranch(path) => write!(
                formatter,
                "source HEAD {} targets a non-branch ref",
                path.display()
            ),
            Self::RefContents(path) => {
                write!(
                    formatter,
                    "source ref {} does not contain one native object id",
                    path.display()
                )
            }
            Self::PackedRefContents(path) => {
                write!(
                    formatter,
                    "packed refs file {} is malformed",
                    path.display()
                )
            }
            Self::ObjectMissing(identity) => {
                write!(formatter, "source is missing reachable object {identity}")
            }
            Self::ObjectIdentityMismatch { expected, observed } => write!(
                formatter,
                "source object named {expected} re-identifies as {observed}"
            ),
            Self::ObjectGraph { identity, code } => write!(
                formatter,
                "source object {identity} has an invalid native graph: {code:?}"
            ),
            Self::LooseObject(source) => Display::fmt(source, formatter),
            Self::ObjectStructure(source) => Display::fmt(source, formatter),
            Self::CommitTreeMissing(identity) => {
                write!(formatter, "reachable commit {identity} has no tree edge")
            }
            Self::TagObjectMissing(identity) => {
                write!(
                    formatter,
                    "reachable annotated tag {identity} has no unique object edge"
                )
            }
            Self::RefLimitExceeded { limit } => {
                write!(formatter, "source ref count exceeds {limit}")
            }
            Self::ObjectLimitExceeded { limit } => {
                write!(formatter, "reachable object count exceeds {limit}")
            }
            Self::TotalObjectBytesExceeded { limit, observed } => write!(
                formatter,
                "reachable object bytes {observed} exceed import limit {limit}"
            ),
            Self::CompressedObjectBytesExceeded { limit, observed } => write!(
                formatter,
                "compressed loose object bytes {observed} exceed import limit {limit}"
            ),
            Self::RefDepthExceeded { limit } => {
                write!(formatter, "source ref nesting exceeds {limit}")
            }
            Self::DirectoryEntryLimitExceeded { limit } => {
                write!(formatter, "source directory entry count exceeds {limit}")
            }
            Self::Node(source) => Display::fmt(source, formatter),
        }
    }
}

impl Error for LooseGitImportRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source.as_ref()),
            Self::RefName { source, .. } | Self::ObjectIdentity { source, .. } => {
                Some(source.as_ref())
            }
            Self::LooseObject(source) => Some(source.as_ref()),
            Self::ObjectStructure(source) => Some(source.as_ref()),
            Self::PackedObject { source, .. } => Some(source.as_ref()),
            Self::Node(source) => Some(source.as_ref()),
            Self::Interrupted { .. }
            | Self::SymbolicLink(_)
            | Self::GitDirectoryMissing(_)
            | Self::GitDirectoryFileUnsupported(_)
            | Self::PathKind { .. }
            | Self::PackPairMissing(_)
            | Self::PackDirectoryEntryUnsupported(_)
            | Self::PackFileLimitExceeded { .. }
            | Self::PackInputBytesExceeded { .. }
            | Self::RefInputBytesExceeded { .. }
            | Self::ObjectAlternatesUnsupported(_)
            | Self::SymbolicRefUnsupported(_)
            | Self::HeadMissing(_)
            | Self::HeadNotSymbolic(_)
            | Self::HeadContents(_)
            | Self::HeadTargetNotBranch(_)
            | Self::RefContents(_)
            | Self::PackedRefContents(_)
            | Self::ObjectMissing(_)
            | Self::ObjectIdentityMismatch { .. }
            | Self::ObjectGraph { .. }
            | Self::CommitTreeMissing(_)
            | Self::TagObjectMissing(_)
            | Self::RefLimitExceeded { .. }
            | Self::ObjectLimitExceeded { .. }
            | Self::TotalObjectBytesExceeded { .. }
            | Self::CompressedObjectBytesExceeded { .. }
            | Self::RefDepthExceeded { .. }
            | Self::DirectoryEntryLimitExceeded { .. } => None,
        }
    }
}

impl OneNode {
    /// Validates and stages an ordinary local Git directory.
    ///
    /// This accepts a bare directory or a worktree directory containing a
    /// `.git` directory. Direct refs may reach loose objects or objects in
    /// checksum-bound idx-v2/pack-v2 pairs. Alternates, symbolic refs, and
    /// `.git` indirection files are explicit typed refusals rather than paths
    /// that can quietly select a different object source.
    ///
    /// Success proves that every returned closure member was native-hash
    /// verified with a complete required-kind graph before the first placement.
    /// Gitlinks remain external and are not fetched. Verified bodies are then
    /// immutably placed through this node's fabric. It does not
    /// make refs visible and does not publish an authority head.
    pub fn stage_loose_git_import(
        &self,
        source: &Path,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        self.stage_loose_git_import_with_ref_limit(source, MAX_IMPORT_REFS)
    }

    /// Standalone compatibility entrypoint with hard resource bounds but no
    /// caller deadline. Request-handling code uses the `_in` variant below.
    pub(crate) fn stage_loose_git_import_with_ref_limit(
        &self,
        source: &Path,
        max_refs: usize,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        self.stage_loose_git_import_with_control(source, max_refs, &mut || true)
    }

    /// Verify and stage under a caller-owned cooperative deadline. Returning an
    /// interruption may leave verified unselected placement, never a ref update.
    /// No OS read already in progress can be preempted by this synchronous API.
    pub fn stage_loose_git_import_with_deadline(
        &self,
        source: &Path,
        deadline: &mut impl Deadline,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        self.stage_loose_git_import_with_control(source, MAX_IMPORT_REFS, deadline)
    }

    pub(crate) fn stage_loose_git_import_with_ref_limit_in(
        &self,
        request: &NodeRequestContext,
        source: &Path,
        max_refs: usize,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        let mut stopped = None;
        let result = self.stage_loose_git_import_with_control(source, max_refs, &mut || {
            match checkpoint_request(request) {
                Ok(()) => true,
                Err(error) => {
                    stopped = Some(error);
                    false
                }
            }
        });
        match stopped {
            Some(error) => Err(error),
            None => result,
        }
    }

    fn stage_loose_git_import_with_control(
        &self,
        source: &Path,
        max_refs: usize,
        deadline: &mut impl Deadline,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        let control = ImportControl::new(deadline);
        let result = self.stage_loose_git_import_controlled(
            source,
            max_refs,
            graph::MAX_REACHABLE_OBJECT_BYTES,
            &control,
        );
        // All effects here are noncanonical placement. Never apply this
        // post-operation cancellation rule to the result of authority CAS.
        control.after(result, |error| error)
    }

    fn stage_loose_git_import_controlled(
        &self,
        source: &Path,
        max_refs: usize,
        maximum_bytes: u64,
        control: &ImportControl<'_>,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        control.checkpoint()?;
        if max_refs > MAX_IMPORT_REFS {
            return Err(LooseGitImportRefusal::RefLimitExceeded {
                limit: MAX_IMPORT_REFS,
            });
        }
        profile::validate_limit(maximum_bytes)?;
        let graph_limits = graph::Limits {
            bytes: maximum_bytes,
            ..graph::Limits::default()
        };
        let git_directory = resolve_git_directory(source, control)?;
        reject_object_alternates(&git_directory, control)?;
        let mut packed = PackedObjectSources::open(
            &git_directory,
            self.object_format,
            self.max_object_bytes,
            control,
        )?;
        let refs = read_direct_refs(&git_directory, self.object_format, max_refs, control)?;
        let head_target = read_head_target(&git_directory, control)?;
        let mut spool = spool::Spool::create(self.storage_root(), maximum_bytes, control)?;
        let validated = graph::validate_typed_with_custody(
            refs.iter().map(|(name, id)| {
                (
                    *id,
                    fgit_git_object::required_ref_target_kind(name.as_bytes()),
                )
            }),
            self.object_format,
            &parse_limits(self.object_format, self.max_object_bytes),
            graph_limits,
            |identity| {
                read_local_object(
                    &git_directory,
                    identity,
                    self.object_format,
                    self.max_object_bytes,
                    &mut packed,
                    control,
                )
            },
            |identity, object| spool.retain(identity, object, control),
            control,
        )?;
        let refs = CanonicalRefState::new_with_head_target(refs, head_target)
            .map_err(|_| LooseGitImportRefusal::HeadTargetNotBranch(Box::new(git_directory)))?;
        // Release pack decoding caches before placement. The proof retains only
        // bounded spool handles; no mutable source file is reread.
        drop(packed);
        let mut closure = BTreeSet::new();
        for identity in validated.objects.keys() {
            control.checkpoint()?;
            closure.insert(*identity);
        }
        let total_object_bytes = validated.total_bytes;
        // All required local edges and object bodies have now verified. Only
        // placement failures or cancellation can leave verified, noncanonical objects.
        for (identity, entry) in validated.objects {
            control.checkpoint()?;
            let object = spool.read(identity, entry, control)?;
            let stored = self
                .put_git_object(object.object_type, object.body)
                .map_err(|error| LooseGitImportRefusal::Node(Box::new(error)))?;
            if stored.identity() != identity {
                return Err(LooseGitImportRefusal::ObjectIdentityMismatch {
                    expected: identity,
                    observed: stored.identity(),
                });
            }
        }

        spool.finish()?;
        control.checkpoint()?;
        Ok(StagedLooseGitImport {
            refs,
            object_count: closure.len(),
            closure: PermittedObjectClosure::new(closure),
            total_object_bytes,
        })
    }
}

fn resolve_git_directory(
    source: &Path,
    control: &ImportControl<'_>,
) -> Result<PathBuf, LooseGitImportRefusal> {
    control.checkpoint()?;
    require_directory(source, "Git source directory", control)?;
    let dot_git = source.join(".git");
    let git_directory = match control.run(|| fs::symlink_metadata(&dot_git))? {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(LooseGitImportRefusal::SymbolicLink(Box::new(dot_git)));
            }
            if metadata.is_dir() {
                dot_git
            } else {
                return Err(LooseGitImportRefusal::GitDirectoryFileUnsupported(
                    Box::new(dot_git),
                ));
            }
        }
        Err(source_error) if source_error.kind() == io::ErrorKind::NotFound => source.to_path_buf(),
        Err(source_error) => return Err(io_refusal("inspect .git", dot_git, source_error)),
    };
    let objects = git_directory.join("objects");
    match control.run(|| fs::symlink_metadata(&objects))? {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(LooseGitImportRefusal::SymbolicLink(Box::new(objects)))
        }
        Ok(metadata) if metadata.is_dir() => Ok(git_directory),
        Ok(_) => Err(LooseGitImportRefusal::GitDirectoryMissing(Box::new(
            git_directory,
        ))),
        Err(source_error) if source_error.kind() == io::ErrorKind::NotFound => Err(
            LooseGitImportRefusal::GitDirectoryMissing(Box::new(git_directory)),
        ),
        Err(source_error) => Err(io_refusal(
            "inspect Git objects directory",
            objects,
            source_error,
        )),
    }
}

fn reject_object_alternates(
    git_directory: &Path,
    control: &ImportControl<'_>,
) -> Result<(), LooseGitImportRefusal> {
    control.checkpoint()?;
    let alternates = git_directory.join("objects/info/alternates");
    if path_exists(&alternates, control)? {
        return Err(LooseGitImportRefusal::ObjectAlternatesUnsupported(
            Box::new(alternates),
        ));
    }
    Ok(())
}

#[derive(Default)]
struct PackPairPaths {
    index: Option<PathBuf>,
    pack: Option<PathBuf>,
}

struct PackedObjectSource {
    index_path: PathBuf,
    pack_path: PathBuf,
    index: IdxV2,
    verified_objects: Option<BTreeMap<GitOid, fgit_git_object::LooseObject>>,
}

struct PackedObjectSources {
    sources: Vec<PackedObjectSource>,
    limits: PackLimits,
    parse_limits: ParseLimits,
    resolution_budget: ResolutionBudget,
    loaded_pack_bytes: u64,
    loaded_inflated_bytes: u64,
}

impl PackedObjectSources {
    fn open(
        git_directory: &Path,
        object_format: GitHashAlgorithm,
        max_object_bytes: u64,
        control: &ImportControl<'_>,
    ) -> Result<Self, LooseGitImportRefusal> {
        control.checkpoint()?;
        let limits = import_pack_limits(max_object_bytes);
        let parse_limits = parse_limits(object_format, max_object_bytes);
        let pack_directory = git_directory.join("objects/pack");
        let Some(metadata) =
            path_metadata(&pack_directory, "inspect packed-object directory", control)?
        else {
            return Ok(Self::empty(limits, parse_limits));
        };
        if metadata.file_type().is_symlink() {
            return Err(LooseGitImportRefusal::SymbolicLink(Box::new(
                pack_directory,
            )));
        }
        if !metadata.is_dir() {
            return Err(LooseGitImportRefusal::PathKind {
                expected: "packed-object directory",
                path: Box::new(pack_directory),
            });
        }

        let mut pairs = BTreeMap::<OsString, PackPairPaths>::new();
        for entry in bounded_directory_entries(&pack_directory, control)? {
            control.checkpoint()?;
            let path = entry.path();
            let metadata = control
                .run(|| fs::symlink_metadata(&path))?
                .map_err(|error| io_refusal("inspect pack-directory entry", path.clone(), error))?;
            if metadata.file_type().is_symlink() {
                return Err(LooseGitImportRefusal::SymbolicLink(Box::new(path)));
            }
            if !metadata.is_file() {
                return Err(LooseGitImportRefusal::PathKind {
                    expected: "regular pack-directory file",
                    path: Box::new(path),
                });
            }
            let file_name = path.file_name().unwrap_or_else(|| OsStr::new(""));
            if file_name == OsStr::new("multi-pack-index") || is_ignored_pack_accelerator(&path) {
                continue;
            }
            let Some(extension) = path.extension().and_then(OsStr::to_str) else {
                return Err(LooseGitImportRefusal::PackDirectoryEntryUnsupported(
                    Box::new(path),
                ));
            };
            if !matches!(extension, "idx" | "pack") {
                return Err(LooseGitImportRefusal::PackDirectoryEntryUnsupported(
                    Box::new(path),
                ));
            }
            let Some(stem) = path.file_stem() else {
                return Err(LooseGitImportRefusal::PackDirectoryEntryUnsupported(
                    Box::new(path),
                ));
            };
            let pair = pairs.entry(stem.to_os_string()).or_default();
            let slot = if extension == "idx" {
                &mut pair.index
            } else {
                &mut pair.pack
            };
            if slot.replace(path.clone()).is_some() {
                return Err(LooseGitImportRefusal::PackDirectoryEntryUnsupported(
                    Box::new(path),
                ));
            }
        }
        if pairs.len() > MAX_IMPORT_PACKS {
            return Err(LooseGitImportRefusal::PackFileLimitExceeded {
                limit: MAX_IMPORT_PACKS,
            });
        }

        let mut sources = Vec::new();
        let mut total_index_bytes = 0_u64;
        for (_, pair) in pairs {
            control.checkpoint()?;
            let (index_path, pack_path) = match (pair.index, pair.pack) {
                (Some(index), Some(pack)) => (index, pack),
                (Some(index), None) => {
                    return Err(LooseGitImportRefusal::PackPairMissing(Box::new(index)));
                }
                (None, Some(pack)) => {
                    return Err(LooseGitImportRefusal::PackPairMissing(Box::new(pack)));
                }
                (None, None) => unreachable!("a pack pair is created only for a pack or index"),
            };
            let index_bytes = read_regular_bounded(
                &index_path,
                "read pack index",
                "regular pack index file",
                MAX_IMPORT_PACK_BYTES,
                BoundedInputClass::PackOrIndex,
                control,
            )?;
            total_index_bytes = total_index_bytes
                .saturating_add(u64::try_from(index_bytes.len()).unwrap_or(u64::MAX));
            if total_index_bytes > MAX_IMPORT_TOTAL_INDEX_BYTES {
                return Err(LooseGitImportRefusal::PackInputBytesExceeded {
                    path: Box::new(pack_directory),
                    limit: MAX_IMPORT_TOTAL_INDEX_BYTES,
                    observed: total_index_bytes,
                });
            }
            let index = IdxV2::parse_verified(
                &index_bytes,
                object_format,
                &limits,
                &mut control.cpu_probe(),
                &NativeChecksumVerifier,
            )
            .map_err(|source| pack_refusal(index_path.clone(), source))?;
            sources.push(PackedObjectSource {
                index_path,
                pack_path,
                index,
                verified_objects: None,
            });
        }

        Ok(Self {
            sources,
            limits,
            parse_limits,
            resolution_budget: ResolutionBudget::new(),
            loaded_pack_bytes: 0,
            loaded_inflated_bytes: 0,
        })
    }

    fn empty(limits: PackLimits, parse_limits: ParseLimits) -> Self {
        Self {
            sources: Vec::new(),
            limits,
            parse_limits,
            resolution_budget: ResolutionBudget::new(),
            loaded_pack_bytes: 0,
            loaded_inflated_bytes: 0,
        }
    }

    fn read(
        &mut self,
        identity: GitOid,
        control: &ImportControl<'_>,
    ) -> Result<Option<fgit_git_object::LooseObject>, LooseGitImportRefusal> {
        control.checkpoint()?;
        let Some(source_index) = self
            .sources
            .iter()
            .position(|source| source.index.lookup(&identity).is_some())
        else {
            return Ok(None);
        };
        self.load(source_index, control)?;
        Ok(self.sources[source_index]
            .verified_objects
            .as_ref()
            .and_then(|objects| objects.get(&identity))
            .cloned())
    }

    fn load(
        &mut self,
        source_index: usize,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        control.checkpoint()?;
        if self.sources[source_index].verified_objects.is_some() {
            return Ok(());
        }
        let source = &self.sources[source_index];
        let pack_path = source.pack_path.clone();
        let pack_bytes = read_regular_bounded(
            &pack_path,
            "read packed object file",
            "regular packed object file",
            MAX_IMPORT_PACK_BYTES,
            BoundedInputClass::PackOrIndex,
            control,
        )?;
        let next_pack_bytes = self
            .loaded_pack_bytes
            .saturating_add(u64::try_from(pack_bytes.len()).unwrap_or(u64::MAX));
        if next_pack_bytes > MAX_IMPORT_TOTAL_PACK_BYTES {
            return Err(LooseGitImportRefusal::PackInputBytesExceeded {
                path: Box::new(pack_path),
                limit: MAX_IMPORT_TOTAL_PACK_BYTES,
                observed: next_pack_bytes,
            });
        }
        let quarantined = read_verified_pack(
            &pack_bytes,
            source.index.format(),
            &self.limits,
            &mut control.cpu_probe(),
            &NativeChecksumVerifier,
        )
        .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
        if &quarantined.trailer != source.index.pack_checksum() {
            return Err(pack_refusal(
                source.index_path.clone(),
                PackError::TrailerChecksumMismatch,
            ));
        }
        validate_idx_pack_count(&source.index, quarantined.header)
            .map_err(|error| pack_refusal(source.index_path.clone(), error))?;

        let mut entries_by_offset = BTreeMap::new();
        for entry in source.index.entries() {
            control.checkpoint()?;
            if entries_by_offset.insert(entry.pack_offset, entry).is_some() {
                return Err(pack_refusal(
                    source.index_path.clone(),
                    PackError::DuplicateObjectOffset(entry.pack_offset),
                ));
            }
        }
        let pack_body_end = pack_bytes
            .len()
            .checked_sub(source.index.format().digest_len())
            .ok_or_else(|| {
                pack_refusal(
                    source.pack_path.clone(),
                    PackError::Truncated {
                        context: "pack checksum",
                    },
                )
            })?;
        for (position, entry) in quarantined.entries().iter().enumerate() {
            control.checkpoint()?;
            let Some(index_entry) = entries_by_offset.get(&entry.offset) else {
                return Err(pack_refusal(
                    source.index_path.clone(),
                    PackError::ObjectCountMismatch {
                        declared: u32::try_from(source.index.entries().len()).unwrap_or(u32::MAX),
                        actual: u32::try_from(quarantined.entries().len()).unwrap_or(u32::MAX),
                    },
                ));
            };
            let end = quarantined
                .entries()
                .get(position + 1)
                .and_then(|next| usize::try_from(next.offset).ok())
                .unwrap_or(pack_body_end);
            let start = usize::try_from(entry.offset).map_err(|_| {
                pack_refusal(
                    source.pack_path.clone(),
                    PackError::IntegerOverflow {
                        context: "pack entry offset",
                    },
                )
            })?;
            let raw_entry = pack_bytes.get(start..end).ok_or_else(|| {
                pack_refusal(
                    source.pack_path.clone(),
                    PackError::Truncated {
                        context: "indexed pack entry",
                    },
                )
            })?;
            validate_idx_entry_crc(
                index_entry,
                raw_entry,
                &self.limits,
                &mut control.cpu_probe(),
            )
            .map_err(|error| pack_refusal(source.index_path.clone(), error))?;
        }
        let inflated_bytes = quarantined
            .entries()
            .iter()
            .try_fold(0_u64, |total, entry| {
                total.checked_add(u64::try_from(entry.inflated.len()).ok()?)
            })
            .unwrap_or(u64::MAX);
        let next_inflated = self.loaded_inflated_bytes.saturating_add(inflated_bytes);
        if next_inflated > MAX_IMPORT_TOTAL_OBJECT_BYTES {
            return Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
                limit: MAX_IMPORT_TOTAL_OBJECT_BYTES,
                observed: next_inflated,
            });
        }
        control.checkpoint()?;
        let objects = quarantined
            .into_scalar_objects(|offset| entries_by_offset.get(&offset).map(|entry| entry.oid))
            .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
        control.checkpoint()?;
        let mut resolver =
            CachedResolver::new(&objects, &(), &self.limits, &mut control.cpu_probe())
                .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
        let mut verified_objects = BTreeMap::new();
        for entry in source.index.entries() {
            control.checkpoint()?;
            let (object_type, body) = resolver
                .resolve_id_typed_with_budget(
                    &entry.oid,
                    &mut self.resolution_budget,
                    &mut control.cpu_probe(),
                )
                .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
            verify_native_object(
                source.index.format(),
                object_type,
                &body,
                &entry.oid,
                AcceptanceProfile::GitCompatibleImport,
                &self.parse_limits,
            )
            .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
            control.checkpoint()?;
            verified_objects.insert(
                entry.oid,
                fgit_git_object::LooseObject {
                    object_type,
                    declared_size: body.len(),
                    body,
                },
            );
        }
        control.checkpoint()?;
        self.loaded_pack_bytes = next_pack_bytes;
        self.loaded_inflated_bytes = next_inflated;
        self.sources[source_index].verified_objects = Some(verified_objects);
        Ok(())
    }
}

fn import_pack_limits(max_object_bytes: u64) -> PackLimits {
    PackLimits {
        max_input_bytes: usize::try_from(MAX_IMPORT_PACK_BYTES).unwrap_or(usize::MAX),
        max_object_bytes: usize::try_from(max_object_bytes).unwrap_or(usize::MAX),
        max_total_expanded_bytes: usize::try_from(MAX_IMPORT_TOTAL_OBJECT_BYTES)
            .unwrap_or(usize::MAX),
        max_cached_bytes: usize::try_from(MAX_IMPORT_TOTAL_OBJECT_BYTES).unwrap_or(usize::MAX),
        ..PackLimits::default()
    }
}

fn is_ignored_pack_accelerator(path: &Path) -> bool {
    matches!(
        path.extension().and_then(OsStr::to_str),
        Some("bitmap" | "keep" | "mtimes" | "promisor" | "rev")
    )
}

#[derive(Clone, Copy)]
enum BoundedInputClass {
    PackOrIndex,
    RefControl,
    CompressedLooseObject,
}

impl BoundedInputClass {
    fn limit_refusal(self, path: &Path, limit: u64, observed: u64) -> LooseGitImportRefusal {
        match self {
            Self::PackOrIndex => LooseGitImportRefusal::PackInputBytesExceeded {
                path: Box::new(path.to_path_buf()),
                limit,
                observed,
            },
            Self::RefControl => LooseGitImportRefusal::RefInputBytesExceeded {
                path: Box::new(path.to_path_buf()),
                limit,
                observed,
            },
            Self::CompressedLooseObject => {
                LooseGitImportRefusal::CompressedObjectBytesExceeded { limit, observed }
            }
        }
    }
}

fn read_regular_bounded(
    path: &Path,
    operation: &'static str,
    expected: &'static str,
    limit: u64,
    class: BoundedInputClass,
    control: &ImportControl<'_>,
) -> Result<Vec<u8>, LooseGitImportRefusal> {
    control.checkpoint()?;
    let metadata = control
        .run(|| fs::symlink_metadata(path))?
        .map_err(|error| io_refusal(operation, path.to_path_buf(), error))?;
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(
            path.to_path_buf(),
        )));
    }
    if !metadata.is_file() {
        return Err(LooseGitImportRefusal::PathKind {
            expected,
            path: Box::new(path.to_path_buf()),
        });
    }
    if metadata.len() > limit {
        return Err(class.limit_refusal(path, limit, metadata.len()));
    }

    // The path can grow or be replaced after the first metadata check. Read
    // from one opened handle and stop after the first byte beyond the selected
    // envelope, so growth beyond the envelope causes a typed refusal rather
    // than an unbounded `fs::read` allocation.
    let file = control
        .run(|| fs::File::open(path))?
        .map_err(|error| io_refusal(operation, path.to_path_buf(), error))?;
    let opened_metadata = control
        .run(|| file.metadata())?
        .map_err(|error| io_refusal(operation, path.to_path_buf(), error))?;
    if !opened_metadata.is_file() {
        return Err(LooseGitImportRefusal::PathKind {
            expected,
            path: Box::new(path.to_path_buf()),
        });
    }
    if opened_metadata.len() > limit {
        return Err(class.limit_refusal(path, limit, opened_metadata.len()));
    }
    let bytes = control::read_bytes(file, limit, control).map_err(|error| match error {
        ReadFailure::Io(error) => io_refusal(operation, path.to_path_buf(), error),
        ReadFailure::Interrupted(error) => error,
    })?;
    let observed = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if observed > limit {
        return Err(class.limit_refusal(path, limit, observed));
    }
    Ok(bytes)
}

#[cfg(test)]
fn read_through_first_excess_byte(reader: impl Read, limit: u64) -> Result<Vec<u8>, io::Error> {
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    control::read_bytes(reader, limit, &control).map_err(|error| match error {
        ReadFailure::Io(error) => error,
        ReadFailure::Interrupted(error) => io::Error::other(error.to_string()),
    })
}

fn pack_refusal(path: PathBuf, source: PackError) -> LooseGitImportRefusal {
    LooseGitImportRefusal::PackedObject {
        path: Box::new(path),
        source: Box::new(source),
    }
}

fn direct_ref_input_limit(object_format: GitHashAlgorithm) -> u64 {
    u64::try_from(
        object_format
            .digest_len()
            .saturating_mul(2)
            .saturating_add(1),
    )
    .unwrap_or(u64::MAX)
}

fn head_input_limit() -> u64 {
    u64::try_from(
        b"ref: "
            .len()
            .saturating_add(MAX_REF_NAME_LEN)
            .saturating_add(1),
    )
    .unwrap_or(u64::MAX)
}

fn packed_refs_input_limit(object_format: GitHashAlgorithm, max_refs: usize) -> u64 {
    let oid_hex_bytes = object_format.digest_len().saturating_mul(2);
    let direct_line_bytes = oid_hex_bytes
        .saturating_add(1)
        .saturating_add(MAX_REF_NAME_LEN)
        // `str::lines` admits both LF and CRLF, so the input envelope must
        // retain the larger line ending even though Git normally writes LF.
        .saturating_add(2);
    let peeled_line_bytes = oid_hex_bytes.saturating_add(3);
    let per_ref_bytes = direct_line_bytes.saturating_add(peeled_line_bytes);
    let total = max_refs
        .saturating_mul(per_ref_bytes)
        .saturating_add(MAX_IMPORT_PACKED_REFS_HEADER_BYTES);
    u64::try_from(total).unwrap_or(u64::MAX)
}

fn read_direct_refs(
    git_directory: &Path,
    object_format: GitHashAlgorithm,
    max_refs: usize,
    control: &ImportControl<'_>,
) -> Result<BTreeMap<RefName, GitOid>, LooseGitImportRefusal> {
    control.checkpoint()?;
    let mut refs = read_packed_refs(git_directory, object_format, max_refs, control)?;
    let loose_root = git_directory.join("refs");
    let Some(metadata) = path_metadata(&loose_root, "inspect loose refs directory", control)?
    else {
        return Ok(refs);
    };
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(loose_root)));
    }
    if !metadata.is_dir() {
        return Err(LooseGitImportRefusal::PathKind {
            expected: "loose refs directory",
            path: Box::new(loose_root),
        });
    }
    collect_loose_refs(
        &loose_root,
        &loose_root,
        object_format,
        0,
        max_refs,
        &mut refs,
        control,
    )?;
    if refs.len() > max_refs {
        return Err(LooseGitImportRefusal::RefLimitExceeded { limit: max_refs });
    }
    Ok(refs)
}

fn read_head_target(
    git_directory: &Path,
    control: &ImportControl<'_>,
) -> Result<RefName, LooseGitImportRefusal> {
    control.checkpoint()?;
    let head = git_directory.join("HEAD");
    let metadata = match control.run(|| fs::symlink_metadata(&head))? {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(LooseGitImportRefusal::HeadMissing(Box::new(head)));
        }
        Err(error) => return Err(io_refusal("inspect HEAD", head, error)),
    };
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(head)));
    }
    if !metadata.is_file() {
        return Err(LooseGitImportRefusal::PathKind {
            expected: "HEAD file",
            path: Box::new(head),
        });
    }

    let bytes = read_regular_bounded(
        &head,
        "read HEAD",
        "HEAD file",
        head_input_limit(),
        BoundedInputClass::RefControl,
        control,
    )?;
    let Some(rest) = bytes.strip_prefix(b"ref: ") else {
        return Err(LooseGitImportRefusal::HeadNotSymbolic(Box::new(head)));
    };
    let Some(target) = rest.strip_suffix(b"\n") else {
        return Err(LooseGitImportRefusal::HeadContents(Box::new(head)));
    };
    if target.is_empty() || target.contains(&b'\n') || target.contains(&b'\r') {
        return Err(LooseGitImportRefusal::HeadContents(Box::new(head)));
    }
    let target = RefName::try_new(target).map_err(|source| LooseGitImportRefusal::RefName {
        path: Box::new(head.clone()),
        source: Box::new(source),
    })?;
    if !target.as_bytes().starts_with(b"refs/heads/") {
        return Err(LooseGitImportRefusal::HeadTargetNotBranch(Box::new(head)));
    }
    Ok(target)
}

fn read_packed_refs(
    git_directory: &Path,
    object_format: GitHashAlgorithm,
    max_refs: usize,
    control: &ImportControl<'_>,
) -> Result<BTreeMap<RefName, GitOid>, LooseGitImportRefusal> {
    control.checkpoint()?;
    let packed = git_directory.join("packed-refs");
    let Some(metadata) = path_metadata(&packed, "inspect packed refs", control)? else {
        return Ok(BTreeMap::new());
    };
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(packed)));
    }
    if !metadata.is_file() {
        return Err(LooseGitImportRefusal::PathKind {
            expected: "packed refs file",
            path: Box::new(packed),
        });
    }
    let bytes = read_regular_bounded(
        &packed,
        "read packed refs",
        "packed refs file",
        packed_refs_input_limit(object_format, max_refs),
        BoundedInputClass::RefControl,
        control,
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| LooseGitImportRefusal::PackedRefContents(Box::new(packed.clone())))?;
    let mut refs = BTreeMap::new();
    for line in text.lines() {
        control.checkpoint()?;
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        let Some((identity, name)) = line.split_once(' ') else {
            return Err(LooseGitImportRefusal::PackedRefContents(Box::new(
                packed.clone(),
            )));
        };
        if identity.is_empty() || name.is_empty() || name.contains(' ') {
            return Err(LooseGitImportRefusal::PackedRefContents(Box::new(
                packed.clone(),
            )));
        }
        let name =
            RefName::try_new(name.as_bytes()).map_err(|error| LooseGitImportRefusal::RefName {
                path: Box::new(packed.clone()),
                source: Box::new(error),
            })?;
        let identity = GitOid::from_hex(object_format, identity).map_err(|error| {
            LooseGitImportRefusal::ObjectIdentity {
                path: Box::new(packed.clone()),
                source: Box::new(error),
            }
        })?;
        // A repeated name is a contents-law violation (one ref, one
        // identity), not a size problem: it gets the malformed-contents
        // refusal, and only a genuinely over-limit set names the limit.
        if refs.insert(name, identity).is_some() {
            return Err(LooseGitImportRefusal::PackedRefContents(Box::new(
                packed.clone(),
            )));
        }
        if refs.len() > max_refs {
            return Err(LooseGitImportRefusal::RefLimitExceeded { limit: max_refs });
        }
    }
    Ok(refs)
}

fn collect_loose_refs(
    root: &Path,
    directory: &Path,
    object_format: GitHashAlgorithm,
    depth: usize,
    max_refs: usize,
    refs: &mut BTreeMap<RefName, GitOid>,
    control: &ImportControl<'_>,
) -> Result<(), LooseGitImportRefusal> {
    control.checkpoint()?;
    if depth > MAX_IMPORT_REF_DEPTH {
        return Err(LooseGitImportRefusal::RefDepthExceeded {
            limit: MAX_IMPORT_REF_DEPTH,
        });
    }
    for entry in bounded_directory_entries(directory, control)? {
        control.checkpoint()?;
        let path = entry.path();
        let metadata = control
            .run(|| fs::symlink_metadata(&path))?
            .map_err(|error| io_refusal("inspect loose ref", path.clone(), error))?;
        if metadata.file_type().is_symlink() {
            return Err(LooseGitImportRefusal::SymbolicLink(Box::new(path)));
        }
        if metadata.is_dir() {
            collect_loose_refs(
                root,
                &path,
                object_format,
                depth + 1,
                max_refs,
                refs,
                control,
            )?;
            continue;
        }
        if !metadata.is_file() {
            return Err(LooseGitImportRefusal::PathKind {
                expected: "loose ref file",
                path: Box::new(path),
            });
        }
        let name = ref_name_from_path(root, &path)?;
        let bytes = read_regular_bounded(
            &path,
            "read loose ref",
            "loose ref file",
            direct_ref_input_limit(object_format),
            BoundedInputClass::RefControl,
            control,
        )?;
        let identity = parse_direct_ref(&path, &bytes, object_format)?;
        refs.insert(name, identity);
        if refs.len() > max_refs {
            return Err(LooseGitImportRefusal::RefLimitExceeded { limit: max_refs });
        }
    }
    Ok(())
}

fn ref_name_from_path(root: &Path, path: &Path) -> Result<RefName, LooseGitImportRefusal> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| LooseGitImportRefusal::RefContents(Box::new(path.to_path_buf())))?;
    let mut name = String::from("refs");
    for component in relative.components() {
        let Some(part) = component.as_os_str().to_str() else {
            return Err(LooseGitImportRefusal::RefContents(Box::new(
                path.to_path_buf(),
            )));
        };
        name.push('/');
        name.push_str(part);
    }
    RefName::try_new(name.as_bytes()).map_err(|error| LooseGitImportRefusal::RefName {
        path: Box::new(path.to_path_buf()),
        source: Box::new(error),
    })
}

fn parse_direct_ref(
    path: &Path,
    bytes: &[u8],
    object_format: GitHashAlgorithm,
) -> Result<GitOid, LooseGitImportRefusal> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| LooseGitImportRefusal::RefContents(Box::new(path.to_path_buf())))?;
    if text.starts_with("ref: ") {
        return Err(LooseGitImportRefusal::SymbolicRefUnsupported(Box::new(
            path.to_path_buf(),
        )));
    }
    let Some(identity) = text.strip_suffix('\n') else {
        return Err(LooseGitImportRefusal::RefContents(Box::new(
            path.to_path_buf(),
        )));
    };
    if identity.is_empty() || identity.contains(['\n', '\r', ' ', '\t']) {
        return Err(LooseGitImportRefusal::RefContents(Box::new(
            path.to_path_buf(),
        )));
    }
    GitOid::from_hex(object_format, identity).map_err(|error| {
        LooseGitImportRefusal::ObjectIdentity {
            path: Box::new(path.to_path_buf()),
            source: Box::new(error),
        }
    })
}

fn read_local_object(
    git_directory: &Path,
    identity: GitOid,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    packed: &mut PackedObjectSources,
    control: &ImportControl<'_>,
) -> Result<fgit_git_object::LooseObject, LooseGitImportRefusal> {
    control.checkpoint()?;
    if let Some(object) = try_read_loose_object(
        git_directory,
        identity,
        object_format,
        max_object_bytes,
        control,
    )? {
        return Ok(object);
    }
    packed
        .read(identity, control)?
        .ok_or(LooseGitImportRefusal::ObjectMissing(identity))
}

fn try_read_loose_object(
    git_directory: &Path,
    identity: GitOid,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    control: &ImportControl<'_>,
) -> Result<Option<fgit_git_object::LooseObject>, LooseGitImportRefusal> {
    control.checkpoint()?;
    let identity_text = identity.to_string();
    let (directory, file) = identity_text.split_at(2);
    let path = git_directory.join("objects").join(directory).join(file);
    let metadata = match control.run(|| fs::symlink_metadata(&path))? {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_refusal("inspect loose object", path, error)),
    };
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(path)));
    }
    if !metadata.is_file() {
        return Err(LooseGitImportRefusal::PathKind {
            expected: "loose object file",
            path: Box::new(path),
        });
    }
    let compressed = read_regular_bounded(
        &path,
        "read loose object",
        "loose object file",
        MAX_IMPORT_COMPRESSED_OBJECT_BYTES,
        BoundedInputClass::CompressedLooseObject,
        control,
    )?;
    let maximum = usize::try_from(max_object_bytes).unwrap_or(usize::MAX);
    let inflate_limits = InflateLimits {
        max_input_bytes: MAX_IMPORT_COMPRESSED_OBJECT_BYTES_USIZE,
        max_pending_input_bytes: MAX_IMPORT_COMPRESSED_OBJECT_BYTES_USIZE,
        max_output_bytes: maximum,
        ..InflateLimits::GIT_OBJECT
    };
    control::decode_loose(
        &compressed,
        inflate_limits,
        parse_limits(object_format, max_object_bytes),
        control,
    )
    .map(Some)
}

fn parse_limits(object_format: GitHashAlgorithm, max_object_bytes: u64) -> ParseLimits {
    ParseLimits {
        max_object_bytes: usize::try_from(max_object_bytes).unwrap_or(usize::MAX),
        tree_reference_bytes: match object_format {
            GitHashAlgorithm::Sha1 => 20,
            GitHashAlgorithm::Sha256 => 32,
        },
        ..ParseLimits::default()
    }
}

fn require_directory(
    path: &Path,
    expected: &'static str,
    control: &ImportControl<'_>,
) -> Result<(), LooseGitImportRefusal> {
    control.checkpoint()?;
    let metadata = control
        .run(|| fs::symlink_metadata(path))?
        .map_err(|error| io_refusal("inspect Git source", path.to_path_buf(), error))?;
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(
            path.to_path_buf(),
        )));
    }
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(LooseGitImportRefusal::PathKind {
            expected,
            path: Box::new(path.to_path_buf()),
        })
    }
}

fn path_exists(path: &Path, control: &ImportControl<'_>) -> Result<bool, LooseGitImportRefusal> {
    control.checkpoint()?;
    match control.run(|| fs::symlink_metadata(path))? {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_refusal("inspect import path", path.to_path_buf(), error)),
    }
}

fn path_metadata(
    path: &Path,
    operation: &'static str,
    control: &ImportControl<'_>,
) -> Result<Option<fs::Metadata>, LooseGitImportRefusal> {
    control.checkpoint()?;
    match control.run(|| fs::symlink_metadata(path))? {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_refusal(operation, path.to_path_buf(), error)),
    }
}

fn bounded_directory_entries(
    path: &Path,
    control: &ImportControl<'_>,
) -> Result<Vec<fs::DirEntry>, LooseGitImportRefusal> {
    control.checkpoint()?;
    let entries = control
        .run(|| fs::read_dir(path))?
        .map_err(|error| io_refusal("list import directory", path.to_path_buf(), error))?;
    let mut collected = Vec::new();
    for entry in entries {
        control.checkpoint()?;
        if collected.len() == MAX_IMPORT_DIRECTORY_ENTRIES {
            return Err(LooseGitImportRefusal::DirectoryEntryLimitExceeded {
                limit: MAX_IMPORT_DIRECTORY_ENTRIES,
            });
        }
        collected.push(entry.map_err(|error| {
            io_refusal("read import directory entry", path.to_path_buf(), error)
        })?);
    }
    control.run(|| collected.sort_by_key(fs::DirEntry::path))?;
    Ok(collected)
}

fn io_refusal(operation: &'static str, path: PathBuf, source: io::Error) -> LooseGitImportRefusal {
    LooseGitImportRefusal::Io {
        operation,
        path: Box::new(path),
        source: Box::new(source),
    }
}

#[cfg(test)]
mod tests;
