//! Bounded staging of an ordinary loose-object Git directory.
//!
//! This module owns only the pre-publication half of import: it validates a
//! local Git directory, follows the closure named by its direct refs, and
//! places verified immutable object bodies in the node's fabric.  The returned
//! [`StagedLooseGitImport`] is not a publication capability.  In particular,
//! objects staged here remain non-canonical until the caller has sealed an
//! import request, recorded its admission, and published an RCR through the
//! authority head's conditional replacement.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use fgit_admission::{CanonicalRefState, PermittedObjectClosure};
use fgit_git_object::{
    AcceptanceProfile, InflateLimits, LooseObjectDecodeError, ObjectError, ParseLimits,
    ParsedObject, parse_object_body, parse_zlib_loose,
};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, TypeRefusal};

use super::{NodeRefusal, OneNode, crypto_object_kind};

const MAX_IMPORT_REFS: usize = 65_536;
const MAX_IMPORT_OBJECTS: usize = 1_000_000;
const MAX_IMPORT_TOTAL_OBJECT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMPORT_COMPRESSED_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMPORT_COMPRESSED_OBJECT_BYTES_USIZE: usize = 64 * 1024 * 1024;
const MAX_IMPORT_REF_DEPTH: usize = 32;
const MAX_IMPORT_DIRECTORY_ENTRIES: usize = 1_000_000;

/// Verified, non-canonical state staged from a loose-object Git directory.
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
    /// Packed objects exist; the loose-object profile must not silently ignore
    /// them or substitute a different object source.
    PackedObjectsUnsupported(Box<PathBuf>),
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
    /// A direct ref file did not contain exactly one native object identity.
    RefContents(Box<PathBuf>),
    /// A packed-refs file did not contain its closed direct-ref grammar.
    PackedRefContents(Box<PathBuf>),
    /// The source named an object that was not available as a loose file.
    ObjectMissing(GitOid),
    /// A loose object body did not reproduce the object identity that named
    /// its source path.
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
            Self::PackedObjectsUnsupported(path) => write!(
                formatter,
                "loose import refuses packed objects at {}; use the pack quarantine import path",
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
                write!(
                    formatter,
                    "source is missing reachable loose object {identity}"
                )
            }
            Self::ObjectIdentityMismatch { expected, observed } => write!(
                formatter,
                "loose object named {expected} re-identifies as {observed}"
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
            Self::Node(source) => Some(source.as_ref()),
            Self::SymbolicLink(_)
            | Self::GitDirectoryMissing(_)
            | Self::GitDirectoryFileUnsupported(_)
            | Self::PathKind { .. }
            | Self::PackedObjectsUnsupported(_)
            | Self::ObjectAlternatesUnsupported(_)
            | Self::SymbolicRefUnsupported(_)
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
    /// Validates and stages an ordinary loose-object Git directory.
    ///
    /// This accepts a bare directory or a worktree directory containing a
    /// `.git` directory.  The intentionally narrow first profile accepts direct
    /// refs and loose objects only.  Packed objects, alternates, symbolic refs,
    /// and `.git` indirection files are explicit typed refusals rather than
    /// paths that can quietly select a different object source.
    ///
    /// Success proves that every returned closure member was native-hash
    /// verified and immutably placed through this node's fabric.  It does not
    /// make refs visible and does not publish an authority head.
    pub fn stage_loose_git_import(
        &self,
        source: &Path,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        let git_directory = resolve_git_directory(source)?;
        reject_unsupported_object_sources(&git_directory)?;
        let refs = read_direct_refs(&git_directory, self.object_format)?;
        let mut pending = refs.values().copied().collect::<BTreeSet<_>>();
        let mut closure = BTreeSet::new();
        let mut total_object_bytes = 0_u64;

        while let Some(identity) = pending.pop_first() {
            if closure.len() == MAX_IMPORT_OBJECTS {
                return Err(LooseGitImportRefusal::ObjectLimitExceeded {
                    limit: MAX_IMPORT_OBJECTS,
                });
            }
            let loose = read_loose_object(
                &git_directory,
                identity,
                self.object_format,
                self.max_object_bytes,
            )?;
            let observed = fgit_crypto::git_object_id(
                self.object_format,
                crypto_object_kind(loose.object_type),
                &loose.body,
            );
            if observed != identity {
                return Err(LooseGitImportRefusal::ObjectIdentityMismatch {
                    expected: identity,
                    observed,
                });
            }
            let next_total = total_object_bytes
                .saturating_add(u64::try_from(loose.body.len()).unwrap_or(u64::MAX));
            if next_total > MAX_IMPORT_TOTAL_OBJECT_BYTES {
                return Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
                    limit: MAX_IMPORT_TOTAL_OBJECT_BYTES,
                    observed: next_total,
                });
            }
            let parsed = parse_object_body(
                loose.object_type,
                &loose.body,
                AcceptanceProfile::GitCompatibleImport,
                &parse_limits(self.object_format, self.max_object_bytes),
            )
            .map_err(|error| LooseGitImportRefusal::ObjectStructure(Box::new(error)))?;
            let references = referenced_objects(identity, parsed, self.object_format)?;
            self.put_git_object(loose.object_type, loose.body)
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
            refs: CanonicalRefState::new(refs),
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

fn reject_unsupported_object_sources(git_directory: &Path) -> Result<(), LooseGitImportRefusal> {
    let alternates = git_directory.join("objects/info/alternates");
    if path_exists(&alternates)? {
        return Err(LooseGitImportRefusal::ObjectAlternatesUnsupported(
            Box::new(alternates),
        ));
    }
    let pack_directory = git_directory.join("objects/pack");
    let Some(metadata) = path_metadata(&pack_directory, "inspect packed-object directory")? else {
        return Ok(());
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
    let mut entries = bounded_directory_entries(&pack_directory)?;
    if entries.pop().is_some() {
        return Err(LooseGitImportRefusal::PackedObjectsUnsupported(Box::new(
            pack_directory,
        )));
    }
    Ok(())
}

fn read_direct_refs(
    git_directory: &Path,
    object_format: GitHashAlgorithm,
) -> Result<BTreeMap<RefName, GitOid>, LooseGitImportRefusal> {
    let mut refs = read_packed_refs(git_directory, object_format)?;
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
    collect_loose_refs(&loose_root, &loose_root, object_format, 0, &mut refs)?;
    if refs.len() > MAX_IMPORT_REFS {
        return Err(LooseGitImportRefusal::RefLimitExceeded {
            limit: MAX_IMPORT_REFS,
        });
    }
    Ok(refs)
}

fn read_packed_refs(
    git_directory: &Path,
    object_format: GitHashAlgorithm,
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
        if refs.insert(name, identity).is_some() || refs.len() > MAX_IMPORT_REFS {
            return Err(LooseGitImportRefusal::RefLimitExceeded {
                limit: MAX_IMPORT_REFS,
            });
        }
    }
    Ok(refs)
}

fn collect_loose_refs(
    root: &Path,
    directory: &Path,
    object_format: GitHashAlgorithm,
    depth: usize,
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
            collect_loose_refs(root, &path, object_format, depth + 1, refs)?;
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
        if refs.len() > MAX_IMPORT_REFS {
            return Err(LooseGitImportRefusal::RefLimitExceeded {
                limit: MAX_IMPORT_REFS,
            });
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

fn read_loose_object(
    git_directory: &Path,
    identity: GitOid,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
) -> Result<fgit_git_object::LooseObject, LooseGitImportRefusal> {
    let identity_text = identity.to_string();
    let (directory, file) = identity_text.split_at(2);
    let path = git_directory.join("objects").join(directory).join(file);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(LooseGitImportRefusal::ObjectMissing(identity));
        }
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
    fn loose_import_refuses_a_ref_that_names_an_unstaged_object() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
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
    fn loose_import_refuses_packed_objects_instead_of_ignoring_them() {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        let pack_directory = source.join("objects/pack");
        fs::create_dir_all(&pack_directory).expect("packed-object directory creates");
        fs::write(pack_directory.join("fixture.pack"), b"not a loose object")
            .expect("packed-object fixture writes");
        let node = node(scratch.0.join("node"));

        assert!(matches!(
            node.stage_loose_git_import(&source),
            Err(LooseGitImportRefusal::PackedObjectsUnsupported(path)) if *path == pack_directory
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
