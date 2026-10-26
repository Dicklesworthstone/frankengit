//! Typed source-import refusals, shared by loose and packed validation.
use super::*;

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
    /// Canonical metadata cannot fit both the store and its readers. Detected
    /// after graph validation but before durable object placement/publication.
    PublicationMetadataTooLarge {
        body: &'static str,
        observed: u64,
        limit: u64,
    },
    /// The canonical metadata encoder refused a verified source description.
    PublicationMetadataInvalid {
        body: &'static str,
        source: Box<fgit_codec::CodecRefusal>,
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
    /// The caller requested a staging ref bound above this implementation's
    /// hard profile. No source ref count has been observed.
    RefLimitInvalid { requested: usize, maximum: usize },
    /// The source exceeded the explicit direct-ref bound before more state was
    /// allocated.
    RefLimitExceeded {
        /// Unique refs observed when traversal first exceeded the bound.
        observed: usize,
        limit: usize,
    },
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
            Self::PublicationMetadataTooLarge {
                body,
                observed,
                limit,
            } => write!(
                formatter,
                "source import publication metadata {body} needs {observed} bytes; limit is {limit}; refused before object placement; increasing the timeout or expanded-byte limit cannot change this metadata bound"
            ),
            Self::PublicationMetadataInvalid { body, source } => write!(
                formatter,
                "source import publication metadata {body} is invalid before object placement: {source}"
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
            Self::RefLimitInvalid { requested, maximum } => write!(
                formatter,
                "requested source import ref limit {requested} exceeds supported staging maximum {maximum}; select a limit no greater than {maximum}; this invocation stopped before reading source refs"
            ),
            Self::RefLimitExceeded { observed, limit } => write!(
                formatter,
                "source import observed {observed} refs; limit is {limit}; reduce the source ref set or transfer refs in bounded receive requests; this invocation stopped before admission"
            ),
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
            Self::PublicationMetadataInvalid { source, .. } => Some(source.as_ref()),
            Self::Io { source, .. } => Some(source.as_ref()),
            Self::RefName { source, .. } | Self::ObjectIdentity { source, .. } => {
                Some(source.as_ref())
            }
            Self::LooseObject(source) => Some(source.as_ref()),
            Self::ObjectStructure(source) => Some(source.as_ref()),
            Self::PackedObject { source, .. } => Some(source.as_ref()),
            Self::Node(source) => Some(source.as_ref()),
            Self::PublicationMetadataTooLarge { .. }
            | Self::Interrupted { .. }
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
            | Self::RefLimitInvalid { .. }
            | Self::RefLimitExceeded { .. }
            | Self::ObjectLimitExceeded { .. }
            | Self::TotalObjectBytesExceeded { .. }
            | Self::CompressedObjectBytesExceeded { .. }
            | Self::RefDepthExceeded { .. }
            | Self::DirectoryEntryLimitExceeded { .. } => None,
        }
    }
}
