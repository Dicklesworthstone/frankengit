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

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use fgit_admission::{CanonicalRefState, PermittedObjectClosure};
use fgit_git_object::{
    AcceptanceProfile, InflateLimits, LooseObjectDecodeError, ObjectError, ParseLimits,
    ParsedObject, parse_object_body, parse_zlib_loose,
};
use fgit_pack::{
    CachedResolver, IdxV2, NativeChecksumVerifier, PackError, PackLimits, ResolutionBudget,
    read_verified_pack, validate_idx_entry_crc, validate_idx_pack_count, verify_native_object,
};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, TypeRefusal};

use super::{NodeRefusal, OneNode, crypto_object_kind};

const MAX_IMPORT_REFS: usize = 65_536;
const MAX_IMPORT_OBJECTS: usize = 1_000_000;
const MAX_IMPORT_TOTAL_OBJECT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMPORT_COMPRESSED_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMPORT_COMPRESSED_OBJECT_BYTES_USIZE: usize = 64 * 1024 * 1024;
const MAX_IMPORT_PACKS: usize = 128;
const MAX_IMPORT_PACK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMPORT_TOTAL_PACK_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMPORT_TOTAL_INDEX_BYTES: u64 = 64 * 1024 * 1024;
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

/// Refusal while reading a bounded ordinary loose-object Git directory.
#[derive(Debug)]
pub enum LooseGitImportRefusal {
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
            Self::SymbolicLink(_)
            | Self::GitDirectoryMissing(_)
            | Self::GitDirectoryFileUnsupported(_)
            | Self::PathKind { .. }
            | Self::PackPairMissing(_)
            | Self::PackDirectoryEntryUnsupported(_)
            | Self::PackFileLimitExceeded { .. }
            | Self::PackInputBytesExceeded { .. }
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
    /// verified and immutably placed through this node's fabric.  It does not
    /// make refs visible and does not publish an authority head.
    pub fn stage_loose_git_import(
        &self,
        source: &Path,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        self.stage_loose_git_import_with_ref_limit(source, MAX_IMPORT_REFS)
    }

    /// Stages a local Git source under a caller-owned ref limit before opening
    /// any object named by that source.
    ///
    /// The durable admission entrypoint uses this narrower form so its
    /// command bound is enforced before it starts closure traversal and
    /// immutable object placement.  The public staging-only profile retains
    /// its independently documented import ceiling above.
    pub(crate) fn stage_loose_git_import_with_ref_limit(
        &self,
        source: &Path,
        max_refs: usize,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        let git_directory = resolve_git_directory(source)?;
        reject_object_alternates(&git_directory)?;
        let mut packed =
            PackedObjectSources::open(&git_directory, self.object_format, self.max_object_bytes)?;
        let refs = read_direct_refs(&git_directory, self.object_format, max_refs)?;
        let head_target = read_head_target(&git_directory)?;
        let mut pending = refs.values().copied().collect::<BTreeSet<_>>();
        let mut closure = BTreeSet::new();
        let mut total_object_bytes = 0_u64;

        while let Some(identity) = pending.pop_first() {
            if closure.len() == MAX_IMPORT_OBJECTS {
                return Err(LooseGitImportRefusal::ObjectLimitExceeded {
                    limit: MAX_IMPORT_OBJECTS,
                });
            }
            let object = read_local_object(
                &git_directory,
                identity,
                self.object_format,
                self.max_object_bytes,
                &mut packed,
            )?;
            let observed = fgit_crypto::git_object_id(
                self.object_format,
                crypto_object_kind(object.object_type),
                &object.body,
            );
            if observed != identity {
                return Err(LooseGitImportRefusal::ObjectIdentityMismatch {
                    expected: identity,
                    observed,
                });
            }
            let next_total = total_object_bytes
                .saturating_add(u64::try_from(object.body.len()).unwrap_or(u64::MAX));
            if next_total > MAX_IMPORT_TOTAL_OBJECT_BYTES {
                return Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
                    limit: MAX_IMPORT_TOTAL_OBJECT_BYTES,
                    observed: next_total,
                });
            }
            let parsed = parse_object_body(
                object.object_type,
                &object.body,
                AcceptanceProfile::GitCompatibleImport,
                &parse_limits(self.object_format, self.max_object_bytes),
            )
            .map_err(|error| LooseGitImportRefusal::ObjectStructure(Box::new(error)))?;
            let references = referenced_objects(identity, parsed, self.object_format)?;
            self.put_git_object(object.object_type, object.body)
                .map_err(|error| LooseGitImportRefusal::Node(Box::new(error)))?;
            total_object_bytes = next_total;
            closure.insert(identity);
            pending.extend(
                references
                    .into_iter()
                    .filter(|child| !closure.contains(child)),
            );
        }

        Ok(StagedLooseGitImport {
            refs: CanonicalRefState::new_with_head_target(refs, head_target)
                .map_err(|_| LooseGitImportRefusal::HeadTargetNotBranch(Box::new(git_directory)))?,
            object_count: closure.len(),
            closure: PermittedObjectClosure::new(closure),
            total_object_bytes,
        })
    }
}

fn resolve_git_directory(source: &Path) -> Result<PathBuf, LooseGitImportRefusal> {
    require_directory(source, "Git source directory")?;
    let dot_git = source.join(".git");
    let git_directory = match fs::symlink_metadata(&dot_git) {
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
    match fs::symlink_metadata(&objects) {
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

fn reject_object_alternates(git_directory: &Path) -> Result<(), LooseGitImportRefusal> {
    let alternates = git_directory.join("objects/info/alternates");
    if path_exists(&alternates)? {
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
    ) -> Result<Self, LooseGitImportRefusal> {
        let limits = import_pack_limits(max_object_bytes);
        let parse_limits = parse_limits(object_format, max_object_bytes);
        let pack_directory = git_directory.join("objects/pack");
        let Some(metadata) = path_metadata(&pack_directory, "inspect packed-object directory")?
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
        for entry in bounded_directory_entries(&pack_directory)? {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
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
            let index_bytes =
                read_regular_bounded(&index_path, "read pack index", MAX_IMPORT_PACK_BYTES)?;
            total_index_bytes = total_index_bytes
                .checked_add(u64::try_from(index_bytes.len()).unwrap_or(u64::MAX))
                .unwrap_or(u64::MAX);
            if total_index_bytes > MAX_IMPORT_TOTAL_INDEX_BYTES {
                return Err(LooseGitImportRefusal::PackInputBytesExceeded {
                    path: Box::new(pack_directory.clone()),
                    limit: MAX_IMPORT_TOTAL_INDEX_BYTES,
                    observed: total_index_bytes,
                });
            }
            let index = IdxV2::parse_verified(
                &index_bytes,
                object_format,
                &limits,
                &mut || true,
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
    ) -> Result<Option<fgit_git_object::LooseObject>, LooseGitImportRefusal> {
        let Some(source_index) = self
            .sources
            .iter()
            .position(|source| source.index.lookup(&identity).is_some())
        else {
            return Ok(None);
        };
        self.load(source_index)?;
        Ok(self.sources[source_index]
            .verified_objects
            .as_ref()
            .and_then(|objects| objects.get(&identity))
            .cloned())
    }

    fn load(&mut self, source_index: usize) -> Result<(), LooseGitImportRefusal> {
        if self.sources[source_index].verified_objects.is_some() {
            return Ok(());
        }
        let source = &self.sources[source_index];
        let pack_path = source.pack_path.clone();
        let pack_bytes =
            read_regular_bounded(&pack_path, "read packed object file", MAX_IMPORT_PACK_BYTES)?;
        let next_pack_bytes = self
            .loaded_pack_bytes
            .checked_add(u64::try_from(pack_bytes.len()).unwrap_or(u64::MAX))
            .unwrap_or(u64::MAX);
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
            &mut || true,
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
            let Some(index_entry) = entries_by_offset.get(&entry.offset) else {
                return Err(pack_refusal(
                    source.index_path.clone(),
                    PackError::ObjectCountMismatch {
                        declared: source.index.entries().len() as u32,
                        actual: quarantined.entries().len() as u32,
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
            validate_idx_entry_crc(index_entry, raw_entry, &self.limits, &mut || true)
                .map_err(|error| pack_refusal(source.index_path.clone(), error))?;
        }
        let inflated_bytes = quarantined
            .entries()
            .iter()
            .try_fold(0_u64, |total, entry| {
                total.checked_add(u64::try_from(entry.inflated.len()).ok()?)
            })
            .unwrap_or(u64::MAX);
        let next_inflated = self
            .loaded_inflated_bytes
            .checked_add(inflated_bytes)
            .unwrap_or(u64::MAX);
        if next_inflated > MAX_IMPORT_TOTAL_OBJECT_BYTES {
            return Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
                limit: MAX_IMPORT_TOTAL_OBJECT_BYTES,
                observed: next_inflated,
            });
        }
        let objects = quarantined
            .into_scalar_objects(|offset| entries_by_offset.get(&offset).map(|entry| entry.oid))
            .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
        let mut resolver = CachedResolver::new(&objects, &(), &self.limits, &mut || true)
            .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
        let mut verified_objects = BTreeMap::new();
        for entry in source.index.entries() {
            let (object_type, body) = resolver
                .resolve_id_typed_with_budget(&entry.oid, &mut self.resolution_budget, &mut || true)
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
            verified_objects.insert(
                entry.oid,
                fgit_git_object::LooseObject {
                    object_type,
                    declared_size: body.len(),
                    body,
                },
            );
        }
        self.loaded_pack_bytes = next_pack_bytes;
        self.loaded_inflated_bytes = next_inflated;
        self.sources[source_index].verified_objects = Some(verified_objects);
        Ok(())
    }
}

fn import_pack_limits(max_object_bytes: u64) -> PackLimits {
    PackLimits {
        max_input_bytes: MAX_IMPORT_PACK_BYTES as usize,
        max_object_bytes: usize::try_from(max_object_bytes).unwrap_or(usize::MAX),
        max_total_expanded_bytes: MAX_IMPORT_TOTAL_OBJECT_BYTES as usize,
        max_cached_bytes: MAX_IMPORT_TOTAL_OBJECT_BYTES as usize,
        ..PackLimits::default()
    }
}

fn is_ignored_pack_accelerator(path: &Path) -> bool {
    matches!(
        path.extension().and_then(OsStr::to_str),
        Some("bitmap" | "keep" | "mtimes" | "promisor" | "rev")
    )
}

fn read_regular_bounded(
    path: &Path,
    operation: &'static str,
    limit: u64,
) -> Result<Vec<u8>, LooseGitImportRefusal> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_refusal(operation, path.to_path_buf(), error))?;
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(
            path.to_path_buf(),
        )));
    }
    if !metadata.is_file() {
        return Err(LooseGitImportRefusal::PathKind {
            expected: "regular pack or index file",
            path: Box::new(path.to_path_buf()),
        });
    }
    if metadata.len() > limit {
        return Err(LooseGitImportRefusal::PackInputBytesExceeded {
            path: Box::new(path.to_path_buf()),
            limit,
            observed: metadata.len(),
        });
    }
    let bytes = fs::read(path).map_err(|error| io_refusal(operation, path.to_path_buf(), error))?;
    let observed = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if observed > limit {
        return Err(LooseGitImportRefusal::PackInputBytesExceeded {
            path: Box::new(path.to_path_buf()),
            limit,
            observed,
        });
    }
    Ok(bytes)
}

fn pack_refusal(path: PathBuf, source: PackError) -> LooseGitImportRefusal {
    LooseGitImportRefusal::PackedObject {
        path: Box::new(path),
        source: Box::new(source),
    }
}

fn read_direct_refs(
    git_directory: &Path,
    object_format: GitHashAlgorithm,
    max_refs: usize,
) -> Result<BTreeMap<RefName, GitOid>, LooseGitImportRefusal> {
    let mut refs = read_packed_refs(git_directory, object_format, max_refs)?;
    let loose_root = git_directory.join("refs");
    let Some(metadata) = path_metadata(&loose_root, "inspect loose refs directory")? else {
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
    )?;
    if refs.len() > max_refs {
        return Err(LooseGitImportRefusal::RefLimitExceeded { limit: max_refs });
    }
    Ok(refs)
}

fn read_head_target(git_directory: &Path) -> Result<RefName, LooseGitImportRefusal> {
    let head = git_directory.join("HEAD");
    let metadata = match fs::symlink_metadata(&head) {
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

    let bytes = fs::read(&head).map_err(|error| io_refusal("read HEAD", head.clone(), error))?;
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
) -> Result<BTreeMap<RefName, GitOid>, LooseGitImportRefusal> {
    let packed = git_directory.join("packed-refs");
    let Some(metadata) = path_metadata(&packed, "inspect packed refs")? else {
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
    let bytes =
        fs::read(&packed).map_err(|error| io_refusal("read packed refs", packed.clone(), error))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| LooseGitImportRefusal::PackedRefContents(Box::new(packed.clone())))?;
    let mut refs = BTreeMap::new();
    for line in text.lines() {
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
) -> Result<(), LooseGitImportRefusal> {
    if depth > MAX_IMPORT_REF_DEPTH {
        return Err(LooseGitImportRefusal::RefDepthExceeded {
            limit: MAX_IMPORT_REF_DEPTH,
        });
    }
    for entry in bounded_directory_entries(directory)? {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_refusal("inspect loose ref", path.clone(), error))?;
        if metadata.file_type().is_symlink() {
            return Err(LooseGitImportRefusal::SymbolicLink(Box::new(path)));
        }
        if metadata.is_dir() {
            collect_loose_refs(root, &path, object_format, depth + 1, max_refs, refs)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(LooseGitImportRefusal::PathKind {
                expected: "loose ref file",
                path: Box::new(path),
            });
        }
        let name = ref_name_from_path(root, &path)?;
        let bytes =
            fs::read(&path).map_err(|error| io_refusal("read loose ref", path.clone(), error))?;
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
) -> Result<fgit_git_object::LooseObject, LooseGitImportRefusal> {
    if let Some(object) =
        try_read_loose_object(git_directory, identity, object_format, max_object_bytes)?
    {
        return Ok(object);
    }
    packed
        .read(identity)?
        .ok_or(LooseGitImportRefusal::ObjectMissing(identity))
}

fn try_read_loose_object(
    git_directory: &Path,
    identity: GitOid,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
) -> Result<Option<fgit_git_object::LooseObject>, LooseGitImportRefusal> {
    let identity_text = identity.to_string();
    let (directory, file) = identity_text.split_at(2);
    let path = git_directory.join("objects").join(directory).join(file);
    let metadata = match fs::symlink_metadata(&path) {
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
    let compressed_bytes = metadata.len();
    if compressed_bytes > MAX_IMPORT_COMPRESSED_OBJECT_BYTES {
        return Err(LooseGitImportRefusal::CompressedObjectBytesExceeded {
            limit: MAX_IMPORT_COMPRESSED_OBJECT_BYTES,
            observed: compressed_bytes,
        });
    }
    let compressed =
        fs::read(&path).map_err(|error| io_refusal("read loose object", path, error))?;
    let maximum = usize::try_from(max_object_bytes).unwrap_or(usize::MAX);
    let inflate_limits = InflateLimits {
        max_input_bytes: MAX_IMPORT_COMPRESSED_OBJECT_BYTES_USIZE,
        max_pending_input_bytes: MAX_IMPORT_COMPRESSED_OBJECT_BYTES_USIZE,
        max_output_bytes: maximum,
        ..InflateLimits::GIT_OBJECT
    };
    parse_zlib_loose(
        &compressed,
        inflate_limits,
        parse_limits(object_format, max_object_bytes),
    )
    .map(Some)
    .map_err(|error| LooseGitImportRefusal::LooseObject(Box::new(error)))
}

fn referenced_objects(
    identity: GitOid,
    parsed: ParsedObject,
    object_format: GitHashAlgorithm,
) -> Result<BTreeSet<GitOid>, LooseGitImportRefusal> {
    let mut references = BTreeSet::new();
    match parsed {
        ParsedObject::Blob(_) => {}
        ParsedObject::Tree(entries) => {
            for entry in entries {
                references.insert(oid_from_native_bytes(
                    identity,
                    &entry.object_id,
                    object_format,
                )?);
            }
        }
        ParsedObject::Commit(commit) => {
            let Some(tree) = commit.tree_reference() else {
                return Err(LooseGitImportRefusal::CommitTreeMissing(identity));
            };
            references.insert(oid_from_hex_reference(identity, tree, object_format)?);
            for parent in commit.parent_references() {
                references.insert(oid_from_hex_reference(identity, parent, object_format)?);
            }
        }
        ParsedObject::Tag(tag) => {
            let mut targets = tag
                .headers()
                .iter()
                .filter(|header| header.name == b"object")
                .map(|header| header.value.as_slice());
            let Some(target) = targets.next() else {
                return Err(LooseGitImportRefusal::TagObjectMissing(identity));
            };
            if targets.next().is_some() {
                return Err(LooseGitImportRefusal::TagObjectMissing(identity));
            }
            references.insert(oid_from_hex_reference(identity, target, object_format)?);
        }
    }
    Ok(references)
}

fn oid_from_native_bytes(
    source: GitOid,
    bytes: &[u8],
    object_format: GitHashAlgorithm,
) -> Result<GitOid, LooseGitImportRefusal> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    oid_from_hex_reference(source, text.as_bytes(), object_format)
}

fn oid_from_hex_reference(
    source: GitOid,
    bytes: &[u8],
    object_format: GitHashAlgorithm,
) -> Result<GitOid, LooseGitImportRefusal> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| LooseGitImportRefusal::ObjectMissing(source))?;
    GitOid::from_hex(object_format, text).map_err(|error| LooseGitImportRefusal::ObjectIdentity {
        path: Box::new(PathBuf::from(format!("reachable from {source}"))),
        source: Box::new(error),
    })
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

fn require_directory(path: &Path, expected: &'static str) -> Result<(), LooseGitImportRefusal> {
    let metadata = fs::symlink_metadata(path)
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

fn path_exists(path: &Path) -> Result<bool, LooseGitImportRefusal> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_refusal("inspect import path", path.to_path_buf(), error)),
    }
}

fn path_metadata(
    path: &Path,
    operation: &'static str,
) -> Result<Option<fs::Metadata>, LooseGitImportRefusal> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_refusal(operation, path.to_path_buf(), error)),
    }
}

fn bounded_directory_entries(path: &Path) -> Result<Vec<fs::DirEntry>, LooseGitImportRefusal> {
    let entries = fs::read_dir(path)
        .map_err(|error| io_refusal("list import directory", path.to_path_buf(), error))?;
    let mut collected = Vec::new();
    for entry in entries {
        if collected.len() == MAX_IMPORT_DIRECTORY_ENTRIES {
            return Err(LooseGitImportRefusal::DirectoryEntryLimitExceeded {
                limit: MAX_IMPORT_DIRECTORY_ENTRIES,
            });
        }
        collected.push(entry.map_err(|error| {
            io_refusal("read import directory entry", path.to_path_buf(), error)
        })?);
    }
    collected.sort_by_key(fs::DirEntry::path);
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
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use fgit_crypto::GitObjectKind;
    use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId, TenantId};

    use super::{LooseGitImportRefusal, OneNode};

    static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct ScratchDirectory(PathBuf);

    impl ScratchDirectory {
        fn new() -> Self {
            let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "frankengit-node-loose-import-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("scratch directory creates");
            Self(path)
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        let (pairs, remainder) = text.trim().as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty(), "fixture has an even hex length");
        pairs
            .iter()
            .map(|[high, low]| (hex_nibble(*high) * 16) + hex_nibble(*low))
            .collect()
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("fixture contains hex"),
        }
    }

    fn node(root: PathBuf) -> OneNode {
        OneNode::init(super::super::NodeConfig::new(
            root,
            TenantId::from_hex("11111111111111111111111111111111").expect("tenant parses"),
            RepositoryId::from_hex("22222222222222222222222222222222").expect("repository parses"),
        ))
        .expect("node initializes")
        .0
    }

    fn write_loose_blob_repository(root: &Path) -> GitOid {
        write_branch_head(root);
        let oid = GitOid::from_hex(
            GitHashAlgorithm::Sha1,
            "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0",
        )
        .expect("fixed blob identity parses");
        let object_path = root.join("objects/b6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
        fs::create_dir_all(object_path.parent().expect("object parent exists"))
            .expect("object directory creates");
        fs::write(
            object_path,
            decode_hex(include_str!(
                "../../fgit-git-object/tests/corpus/blob-hello.zlib.hex"
            )),
        )
        .expect("fixture loose object writes");
        let ref_path = root.join("refs/heads/main");
        fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
            .expect("ref directory creates");
        fs::write(ref_path, format!("{oid}\n")).expect("fixture ref writes");
        oid
    }

    fn write_branch_head(root: &Path) {
        fs::write(root.join("HEAD"), "ref: refs/heads/main\n")
            .expect("symbolic branch HEAD writes");
    }

    fn write_loose_object(root: &Path, kind: GitObjectKind, body: &[u8]) -> GitOid {
        let oid = fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, kind, body);
        let identity = oid.to_string();
        let (directory, file) = identity.split_at(2);
        let path = root.join("objects").join(directory).join(file);
        fs::create_dir_all(path.parent().expect("object parent exists"))
            .expect("object directory creates");
        let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
        framed.extend_from_slice(body);
        fs::write(path, zlib_stored_member(&framed)).expect("zlib loose object writes");
        oid
    }

    fn zlib_stored_member(bytes: &[u8]) -> Vec<u8> {
        let length = u16::try_from(bytes.len()).expect("small test member fits one stored block");
        let mut member = Vec::with_capacity(bytes.len() + 11);
        member.extend_from_slice(&[0x78, 0x01, 0x01]);
        member.extend_from_slice(&length.to_le_bytes());
        member.extend_from_slice(&(!length).to_le_bytes());
        member.extend_from_slice(bytes);
        member.extend_from_slice(&adler32(bytes).to_be_bytes());
        member
    }

    fn adler32(bytes: &[u8]) -> u32 {
        let mut a = 1_u32;
        let mut b = 0_u32;
        for byte in bytes {
            a = (a + u32::from(*byte)) % 65_521;
            b = (b + a) % 65_521;
        }
        (b << 16) | a
    }

    #[test]
    fn loose_import_stages_a_verified_direct_ref_closure_without_publishing_it() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(&source).expect("source directory creates");
        let oid = write_loose_blob_repository(&source);
        let node = node(scratch.0.join("node"));

        let staged = node
            .stage_loose_git_import(&source)
            .expect("reachable loose object stages through verified fabric");
        assert_eq!(staged.object_count(), 1);
        assert_eq!(staged.total_object_bytes(), 5);
        assert_eq!(
            staged
                .refs()
                .refs()
                .get(&fgit_types::RefName::try_new(b"refs/heads/main").expect("fixed ref parses")),
            Some(&oid)
        );
        assert_eq!(
            staged.closure().objects(),
            &std::collections::BTreeSet::from([oid])
        );
        assert!(node.read_git_object(oid).is_ok());

        let materialized = node
            .runtime()
            .block_on(node.materialize_admission())
            .expect("genesis remains authoritative after staging");
        assert!(materialized.snapshot().refs.is_empty());
        assert!(
            materialized
                .selected_closure()
                .closure()
                .objects()
                .is_empty()
        );
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_captures_a_symbolic_branch_head_in_canonical_state() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(&source).expect("source directory creates");
        let _ = write_loose_blob_repository(&source);
        let node = node(scratch.0.join("node"));

        let staged = node
            .stage_loose_git_import(&source)
            .expect("a symbolic branch HEAD is admitted with the source refs");
        assert_eq!(
            staged.refs().head_target(),
            Some(&fgit_types::RefName::try_new(b"refs/heads/main").expect("fixed ref parses"))
        );
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_missing_direct_and_non_branch_heads() {
        for (name, contents, expected) in [
            ("missing", None, "missing"),
            (
                "direct",
                Some("b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0\n"),
                "direct",
            ),
            ("tag", Some("ref: refs/tags/v1\n"), "non-branch"),
        ] {
            let scratch = ScratchDirectory::new();
            let source = scratch.0.join(name);
            fs::create_dir_all(&source).expect("source directory creates");
            fs::create_dir_all(source.join("objects")).expect("object directory creates");
            if let Some(contents) = contents {
                fs::write(source.join("HEAD"), contents).expect("HEAD fixture writes");
            }
            let node = node(scratch.0.join("node"));

            let refusal = node
                .stage_loose_git_import(&source)
                .expect_err("invalid HEAD must refuse before import staging");
            assert!(
                matches!(
                    (expected, refusal),
                    ("missing", LooseGitImportRefusal::HeadMissing(_))
                        | ("direct", LooseGitImportRefusal::HeadNotSymbolic(_))
                        | ("non-branch", LooseGitImportRefusal::HeadTargetNotBranch(_))
                ),
                "{expected} HEAD form must retain its typed refusal"
            );
            node.shutdown().expect("node drains");
        }
    }

    #[test]
    fn loose_import_refuses_a_ref_that_names_an_unstaged_object() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(&source).expect("source directory creates");
        write_branch_head(&source);
        let ref_path = source.join("refs/heads/main");
        fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
            .expect("ref directory creates");
        fs::create_dir_all(source.join("objects")).expect("object directory creates");
        let oid = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
        fs::write(&ref_path, format!("{oid}\n")).expect("fixture ref writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::ObjectMissing(identity)) if identity.to_string() == oid
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_uses_packed_refs_without_treating_them_as_an_object_source() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(&source).expect("source directory creates");
        let oid = write_loose_blob_repository(&source);
        fs::remove_file(source.join("refs/heads/main")).expect("direct ref is removed");
        fs::write(
            source.join("packed-refs"),
            format!("# pack-refs with: peeled fully-peeled\n{oid} refs/heads/main\n"),
        )
        .expect("packed ref writes");
        let node = node(scratch.0.join("node"));

        let staged = node
            .stage_loose_git_import(&source)
            .expect("a packed ref still names the same verified loose closure");
        assert_eq!(staged.object_count(), 1);
        assert_eq!(
            staged
                .refs()
                .refs()
                .get(&fgit_types::RefName::try_new(b"refs/heads/main").expect("fixed ref parses")),
            Some(&oid)
        );
        assert!(node.read_git_object(oid).is_ok());
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_an_alternate_even_when_its_direct_closure_is_valid() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(&source).expect("source directory creates");
        let _ = write_loose_blob_repository(&source);
        let alternates = source.join("objects/info/alternates");
        fs::create_dir_all(alternates.parent().expect("alternates parent exists"))
            .expect("alternates parent creates");
        fs::write(&alternates, "/outside/object-source\n").expect("alternate writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::ObjectAlternatesUnsupported(path)) if *path == alternates
        ));
        node.shutdown().expect("node drains");
    }

    #[cfg(unix)]
    #[test]
    fn loose_import_refuses_a_worktree_git_directory_symlink() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("worktree");
        let dot_git = source.join(".git");
        fs::create_dir_all(&source).expect("worktree directory creates");
        std::os::unix::fs::symlink(scratch.0.join("outside"), &dot_git)
            .expect("fixture symbolic link creates");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::SymbolicLink(path)) if *path == dot_git
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_worktree_git_directory_file() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("worktree");
        let dot_git = source.join(".git");
        fs::create_dir_all(&source).expect("worktree directory creates");
        fs::write(&dot_git, "gitdir: /outside\n").expect("indirection fixture writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::GitDirectoryFileUnsupported(path)) if *path == dot_git
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn local_import_refuses_an_unpaired_pack_instead_of_ignoring_it() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        let pack_directory = source.join("objects/pack");
        fs::create_dir_all(&pack_directory).expect("packed-object directory creates");
        let pack_path = pack_directory.join("fixture.pack");
        fs::write(&pack_path, b"not a complete pack pair").expect("packed-object fixture writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::PackPairMissing(path)) if *path == pack_path
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_symbolic_ref_instead_of_resolving_it() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        let ref_path = source.join("refs/heads/main");
        fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
            .expect("ref directory creates");
        fs::create_dir_all(source.join("objects")).expect("object directory creates");
        fs::write(&ref_path, "ref: refs/heads/other\n").expect("symbolic ref fixture writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::SymbolicRefUnsupported(path)) if *path == ref_path
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_loose_body_that_does_not_match_its_path_identity() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(&source).expect("source directory creates");
        let observed = write_loose_blob_repository(&source);
        let expected = "a6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
        let original_path = source.join("objects/b6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
        let mismatched_path = source.join("objects/a6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
        fs::create_dir_all(mismatched_path.parent().expect("mismatched parent exists"))
            .expect("mismatched object directory creates");
        fs::rename(&original_path, &mismatched_path).expect("fixture object moves");
        fs::write(source.join("refs/heads/main"), format!("{expected}\n"))
            .expect("mismatched ref writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::ObjectIdentityMismatch {
                expected: refused_expected,
                observed: refused_observed,
            }) if refused_expected.to_string() == expected && refused_observed == observed
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_source_without_a_git_objects_directory() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("not-a-git-directory");
        fs::create_dir_all(&source).expect("source directory creates");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::GitDirectoryMissing(path)) if *path == source
        ));
        node.shutdown().expect("node drains");
    }

    #[cfg(unix)]
    #[test]
    fn loose_import_maps_an_invalid_source_path_to_the_typed_io_refusal() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("invalid\0source");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::Io { operation, path, .. })
                if operation == "inspect Git source" && *path == source
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_file_where_the_packed_object_directory_belongs() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        let pack_directory = source.join("objects/pack");
        fs::create_dir_all(source.join("objects")).expect("object directory creates");
        fs::write(&pack_directory, b"not a directory").expect("wrong-kind fixture writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::PathKind { expected, path })
                if expected == "packed-object directory" && *path == pack_directory
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_loose_ref_path_outside_the_canonical_vocabulary() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        let ref_path = source.join("refs/heads/bad..name");
        fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
            .expect("ref directory creates");
        fs::create_dir_all(source.join("objects")).expect("object directory creates");
        fs::write(&ref_path, "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0\n")
            .expect("invalid-name ref writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::RefName { path, .. }) if *path == ref_path
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_direct_ref_with_noncanonical_object_hex() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        let ref_path = source.join("refs/heads/main");
        fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
            .expect("ref directory creates");
        fs::create_dir_all(source.join("objects")).expect("object directory creates");
        fs::write(&ref_path, "NOT-AN-OBJECT\n").expect("invalid-identity ref writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::ObjectIdentity { path, .. }) if *path == ref_path
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_direct_ref_with_ambiguous_contents() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        let ref_path = source.join("refs/heads/main");
        fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
            .expect("ref directory creates");
        fs::create_dir_all(source.join("objects")).expect("object directory creates");
        fs::write(&ref_path, "one identity plus another\n").expect("ambiguous ref fixture writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::RefContents(path)) if *path == ref_path
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_malformed_packed_refs() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        let packed_refs = source.join("packed-refs");
        fs::create_dir_all(source.join("objects")).expect("object directory creates");
        fs::write(&packed_refs, "not a packed ref\n").expect("malformed packed refs write");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::PackedRefContents(path)) if *path == packed_refs
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_duplicate_packed_ref_name_as_contents_not_size() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        let packed_refs = source.join("packed-refs");
        fs::create_dir_all(source.join("objects")).expect("object directory creates");
        let oid = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
        let duplicate = format!("{oid} refs/heads/duplicated\n{oid} refs/heads/duplicated\n");
        fs::write(&packed_refs, duplicate).expect("duplicate packed refs write");
        let node = node(scratch.0.join("node"));

        // One name carried twice is a contents-law violation even though the
        // set is far below any limit: it must not be misreported as
        // RefLimitExceeded.
        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::PackedRefContents(path)) if *path == packed_refs
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_packed_refs_over_the_direct_ref_limit() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(source.join("objects")).expect("object directory creates");
        let oid = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
        let mut packed_refs = String::with_capacity((super::MAX_IMPORT_REFS + 1) * 64);
        for index in 0..=super::MAX_IMPORT_REFS {
            packed_refs.push_str(oid);
            packed_refs.push_str(" refs/heads/ref-");
            packed_refs.push_str(&index.to_string());
            packed_refs.push('\n');
        }
        fs::write(source.join("packed-refs"), packed_refs).expect("packed refs fixture writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::RefLimitExceeded { limit })
                if limit == super::MAX_IMPORT_REFS
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_reachable_file_that_is_not_a_zlib_loose_object() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(&source).expect("source directory creates");
        write_branch_head(&source);
        let oid = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
        let ref_path = source.join("refs/heads/main");
        let object_path = source.join("objects/b6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
        fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
            .expect("ref directory creates");
        fs::create_dir_all(object_path.parent().expect("object parent exists"))
            .expect("object directory creates");
        fs::write(&ref_path, format!("{oid}\n")).expect("fixture ref writes");
        fs::write(&object_path, b"not a zlib stream").expect("invalid loose object writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::LooseObject(_))
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_compressed_object_before_reading_it_over_the_bound() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(&source).expect("source directory creates");
        write_branch_head(&source);
        let oid = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
        let ref_path = source.join("refs/heads/main");
        let object_path = source.join("objects/b6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
        fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
            .expect("ref directory creates");
        fs::create_dir_all(object_path.parent().expect("object parent exists"))
            .expect("object directory creates");
        fs::write(&ref_path, format!("{oid}\n")).expect("fixture ref writes");
        let compressed_bytes = super::MAX_IMPORT_COMPRESSED_OBJECT_BYTES + 1;
        fs::File::create(&object_path)
            .expect("oversized loose object creates")
            .set_len(compressed_bytes)
            .expect("oversized loose object is sparse");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::CompressedObjectBytesExceeded { limit, observed })
                if limit == super::MAX_IMPORT_COMPRESSED_OBJECT_BYTES
                    && observed == compressed_bytes
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_reachable_tree_with_an_incomplete_edge() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(&source).expect("source directory creates");
        write_branch_head(&source);
        let tree = decode_hex(include_str!(
            "../../fgit-git-object/tests/corpus/malformed/tree-truncated-reference.hex"
        ));
        let oid = write_loose_object(&source, GitObjectKind::Tree, &tree);
        let ref_path = source.join("refs/heads/main");
        fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
            .expect("ref directory creates");
        fs::write(&ref_path, format!("{oid}\n")).expect("fixture ref writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::ObjectStructure(_))
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_reachable_commit_without_a_tree_edge() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(&source).expect("source directory creates");
        write_branch_head(&source);
        let oid = write_loose_object(
            &source,
            GitObjectKind::Commit,
            b"author Example <example@invalid> 1 +0000\ncommitter Example <example@invalid> 1 +0000\n",
        );
        let ref_path = source.join("refs/heads/main");
        fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
            .expect("ref directory creates");
        fs::write(&ref_path, format!("{oid}\n")).expect("fixture ref writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::CommitTreeMissing(identity)) if identity == oid
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_a_reachable_tag_without_exactly_one_target() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        fs::create_dir_all(&source).expect("source directory creates");
        write_branch_head(&source);
        let oid = write_loose_object(
            &source,
            GitObjectKind::Tag,
            b"type commit\ntag v1.0.0\ntagger Example <example@invalid> 1 +0000\n",
        );
        let ref_path = source.join("refs/tags/v1.0.0");
        fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
            .expect("ref directory creates");
        fs::write(&ref_path, format!("{oid}\n")).expect("fixture ref writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::TagObjectMissing(identity)) if identity == oid
        ));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn loose_import_refuses_ref_directories_deeper_than_the_profile_limit() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        let mut nested = source.join("refs");
        for index in 0..=super::MAX_IMPORT_REF_DEPTH {
            nested.push(format!("level-{index}"));
        }
        fs::create_dir_all(&nested).expect("deep ref directory creates");
        fs::create_dir_all(source.join("objects")).expect("object directory creates");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::RefDepthExceeded { limit })
                if limit == super::MAX_IMPORT_REF_DEPTH
        ));
        node.shutdown().expect("node drains");
    }
}
