//! The immutable base view, pinned to one exact repository state.
//!
//! `docs/GIT_TREE_FS.md` §3.1 and §5. The base is a Git commit/tree closure
//! pinned to one canonical RCR. Unchanged subtrees keep their original OIDs, so
//! resolving a path is a walk over immutable objects and never a copy.
//!
//! # Why this crate does not fetch
//!
//! [`ObjectSource`] is a trait the caller implements. `TreeFS` decides *what* to
//! read and *whether the capability permits it*, then verifies what comes back.
//! Owning the transport here would drag the fabric, ATP, and a runtime into a
//! pure tree model, and would put the authorisation decision and the fetch in
//! the same place — which is precisely the arrangement that makes a lazy fetch
//! able to skip its recheck.
//!
//! # Verification is not optional
//!
//! [`BaseView::read_object`] recomputes the object identity of the returned
//! bytes and compares it with the identity that was asked for. A source that
//! returns the wrong bytes — a corrupted cache, a confused mirror, a hostile
//! peer — is refused, not trusted. `docs/GIT_TREE_FS.md` §5 is explicit that an
//! unverified cache buffer is never exposed as a Git object.

use crate::capability::{CapabilityRefusal, ReadGrant, TreeCapability};
use crate::path::{PathPolicy, PathRefusal, TreePath};
use core::fmt::{self, Display, Formatter};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity};
use fgit_git_object::{AcceptanceProfile, ObjectError, ParseLimits, TreeEntry, parse_tree};
use fgit_types::{RepositoryCommitId, RepositoryId};

/// Why an object could not be produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectSourceError {
    /// The source does not have the object.
    NotFound {
        /// Lowercase hexadecimal identity that was requested.
        oid_hex: String,
    },
    /// The source refused for its own reason.
    Refused {
        /// Human-readable reason from the source.
        reason: String,
    },
    /// The source returned bytes whose identity is not the one requested.
    ///
    /// This is the case that must never be downgraded to a warning.
    IdentityMismatch {
        /// What was asked for.
        requested_hex: String,
        /// What the returned bytes actually hash to.
        observed_hex: String,
    },
    /// The object exceeded the configured parse budget.
    TooLarge {
        /// Observed size in bytes.
        observed: usize,
        /// Configured ceiling.
        limit: usize,
    },
}

impl Display for ObjectSourceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { oid_hex } => write!(formatter, "object {oid_hex} not found"),
            Self::Refused { reason } => write!(formatter, "object source refused: {reason}"),
            Self::IdentityMismatch {
                requested_hex,
                observed_hex,
            } => write!(
                formatter,
                "object identity mismatch: requested {requested_hex}, bytes hash to {observed_hex}"
            ),
            Self::TooLarge { observed, limit } => {
                write!(formatter, "object is {observed} bytes, limit {limit}")
            }
        }
    }
}

impl core::error::Error for ObjectSourceError {}

/// A lazy, authorised source of Git object bytes.
///
/// Implementors receive a [`ReadGrant`], which only [`TreeCapability`] can
/// mint, so an implementation cannot be driven without an authorisation having
/// been made. The grant names the exact path the read is for, which is what
/// lets an implementation log or re-check the decision rather than trusting an
/// ambient one.
pub trait ObjectSource<A: GitHashAlgorithm> {
    /// Returns the canonical body bytes of `oid`, which must be of `kind`.
    ///
    /// Implementations return raw object bodies without the loose-object
    /// header; identity verification happens in [`BaseView::read_object`].
    fn read_object(
        &self,
        oid: &GitOid<A>,
        kind: GitObjectKind,
        grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError>;
}

/// What the base holds at one path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaseEntry<A: GitHashAlgorithm> {
    /// A regular or executable file.
    File {
        /// Object identity of the blob.
        oid: GitOid<A>,
        /// Raw ASCII-octal mode bytes exactly as Git stored them.
        mode: Vec<u8>,
    },
    /// A symlink, whose target is link-text data and never traversal authority.
    Symlink {
        /// Object identity of the blob holding the link text.
        oid: GitOid<A>,
    },
    /// A subdirectory.
    Directory {
        /// Object identity of the tree.
        oid: GitOid<A>,
    },
    /// A gitlink pointing into a submodule.
    Submodule {
        /// The recorded commit identity.
        oid: GitOid<A>,
    },
}

impl<A: GitHashAlgorithm> BaseEntry<A> {
    /// The entry's object identity.
    #[must_use]
    pub const fn oid(&self) -> &GitOid<A> {
        match self {
            Self::File { oid, .. }
            | Self::Symlink { oid }
            | Self::Directory { oid }
            | Self::Submodule { oid } => oid,
        }
    }

    /// Whether this entry is a directory.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        matches!(self, Self::Directory { .. })
    }
}

/// Why a base lookup failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaseError {
    /// The path is not acceptable.
    Path(PathRefusal),
    /// The capability refused the access.
    Capability(CapabilityRefusal),
    /// The object source failed.
    Source(ObjectSourceError),
    /// A tree object did not parse.
    Object(String),
    /// No entry exists at the path in this base.
    NotFound {
        /// The path that was resolved.
        path: TreePath,
    },
    /// A path component resolved to a non-directory, so the remainder cannot
    /// exist.
    NotADirectory {
        /// The ancestor that is not a directory.
        path: TreePath,
    },
    /// A path traversed a symlink. Symlinks are data; resolving through one
    /// would be host traversal authority the repository must not have.
    SymlinkTraversal {
        /// The symlink that was in the way.
        path: TreePath,
    },
}

impl Display for BaseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(inner) => write!(formatter, "{inner}"),
            Self::Capability(inner) => write!(formatter, "{inner}"),
            Self::Source(inner) => write!(formatter, "{inner}"),
            Self::Object(inner) => write!(formatter, "tree object error: {inner}"),
            Self::NotFound { path } => write!(formatter, "no base entry at {path}"),
            Self::NotADirectory { path } => write!(formatter, "{path} is not a directory"),
            Self::SymlinkTraversal { path } => {
                write!(formatter, "refusing to traverse symlink at {path}")
            }
        }
    }
}

impl core::error::Error for BaseError {}

impl From<PathRefusal> for BaseError {
    fn from(value: PathRefusal) -> Self {
        Self::Path(value)
    }
}

impl From<CapabilityRefusal> for BaseError {
    fn from(value: CapabilityRefusal) -> Self {
        Self::Capability(value)
    }
}

impl From<ObjectSourceError> for BaseError {
    fn from(value: ObjectSourceError) -> Self {
        Self::Source(value)
    }
}

impl From<ObjectError> for BaseError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value.to_string())
    }
}

/// One directory's immediate children: raw entry-name bytes paired with the
/// typed entry the base holds there.
pub type DirectoryListing<A> = Vec<(Vec<u8>, BaseEntry<A>)>;

/// An immutable view of repository state pinned to one exact commit.
///
/// The view is `Clone` and carries no interior mutability: two workspaces may
/// share one base and cannot affect each other through it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaseView<A: GitHashAlgorithm> {
    repository_id: RepositoryId,
    base_rcr_id: RepositoryCommitId,
    base_commit_oid: GitOid<A>,
    base_tree_oid: GitOid<A>,
    parse_limits: ParseLimits,
    path_policy: PathPolicy,
}

impl<A: GitHashAlgorithm> BaseView<A> {
    /// Pins a base view to an exact repository state.
    #[must_use]
    pub const fn new(
        repository_id: RepositoryId,
        base_rcr_id: RepositoryCommitId,
        base_commit_oid: GitOid<A>,
        base_tree_oid: GitOid<A>,
        parse_limits: ParseLimits,
        path_policy: PathPolicy,
    ) -> Self {
        Self {
            repository_id,
            base_rcr_id,
            base_commit_oid,
            base_tree_oid,
            parse_limits,
            path_policy,
        }
    }

    /// The repository this base belongs to.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// The canonical RCR this base is pinned to.
    #[must_use]
    pub const fn base_rcr_id(&self) -> RepositoryCommitId {
        self.base_rcr_id
    }

    /// The pinned commit identity.
    #[must_use]
    pub const fn base_commit_oid(&self) -> &GitOid<A> {
        &self.base_commit_oid
    }

    /// The pinned root tree identity.
    #[must_use]
    pub const fn base_tree_oid(&self) -> &GitOid<A> {
        &self.base_tree_oid
    }

    /// The path policy this base parses against.
    #[must_use]
    pub const fn path_policy(&self) -> &PathPolicy {
        &self.path_policy
    }

    /// Reads and verifies one object.
    ///
    /// The returned bytes are hashed in the requested object domain and
    /// compared with the requested identity. A mismatch is
    /// [`ObjectSourceError::IdentityMismatch`], never a warning and never a
    /// fallback to the returned bytes.
    pub fn read_object<S: ObjectSource<A>>(
        &self,
        source: &S,
        oid: &GitOid<A>,
        kind: GitObjectKind,
        grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        let bytes = source.read_object(oid, kind, grant)?;
        if bytes.len() > self.parse_limits.max_object_bytes {
            return Err(ObjectSourceError::TooLarge {
                observed: bytes.len(),
                limit: self.parse_limits.max_object_bytes,
            });
        }
        let observed = GitOid::<A>::of_object(kind, &bytes);
        if &observed != oid {
            return Err(ObjectSourceError::IdentityMismatch {
                requested_hex: hex_of(oid.digest_bytes()),
                observed_hex: hex_of(observed.digest_bytes()),
            });
        }
        Ok(bytes)
    }

    /// Resolves one path to its base entry, walking only the trees on the way.
    ///
    /// The walk refuses to pass through a symlink. A repository symlink is data
    /// (`docs/GIT_TREE_FS.md` §15); following one during resolution would let
    /// repository content redirect a read outside the capability scope, which
    /// is a workspace escape wearing ordinary clothes.
    pub fn resolve<S: ObjectSource<A>>(
        &self,
        source: &S,
        capability: &mut TreeCapability,
        path: &TreePath,
        now: u64,
    ) -> Result<BaseEntry<A>, BaseError> {
        let mut tree_oid = self.base_tree_oid;
        let mut walked: Option<TreePath> = None;

        let components: Vec<&[u8]> = path.components().collect();
        let last_index = components.len() - 1;

        for (index, component) in components.into_iter().enumerate() {
            let here = match &walked {
                None => TreePath::parse(component, &self.path_policy)?,
                Some(prefix) => prefix.join(component, &self.path_policy)?,
            };
            // A scope refusal names the path the CALLER asked for, not the
            // ancestor component the walk happened to stop at. Reporting the
            // component leaked where the boundary sits: a holder of `docs`
            // probing `src/lib.rs` learned that the refusal came at `src`,
            // which is a coarse existence oracle for top-level names. The
            // refusal is unchanged in kind and timing -- still before any
            // source read -- only in what it discloses.
            let grant = capability
                .authorize_read(&here, now)
                .map_err(|refusal| match refusal {
                    CapabilityRefusal::ReadOutsideScope { .. } => {
                        CapabilityRefusal::ReadOutsideScope { path: path.clone() }
                    }
                    other => other,
                })?;
            let body = self.read_object(source, &tree_oid, GitObjectKind::Tree, &grant)?;
            capability.charge_fetch(body.len() as u64)?;
            let entries = parse_tree(
                &body,
                AcceptanceProfile::GitCompatibleImport,
                &self.parse_limits,
            )?;

            let found = entries
                .into_iter()
                .find(|entry| entry.name == component)
                .ok_or_else(|| BaseError::NotFound { path: here.clone() })?;

            let entry = classify(&found)?;

            // The symlink policy is enforced HERE, on the resolving path, not
            // only where a cooperative caller remembers to call check_symlink.
            // A `Refuse` capability that still hands back BaseEntry::Symlink is
            // not refusing; it is delegating the refusal to whoever asked, and
            // an attacker is not obliged to ask politely. This fires whether the
            // symlink is the target or merely on the way, so the policy cannot
            // be stepped around by resolving a descendant instead.
            if matches!(entry, BaseEntry::Symlink { .. }) {
                capability.check_symlink(&here)?;
            }

            if index == last_index {
                return Ok(entry);
            }

            match entry {
                BaseEntry::Directory { oid } => {
                    tree_oid = oid;
                    walked = Some(here);
                }
                BaseEntry::Symlink { .. } => {
                    return Err(BaseError::SymlinkTraversal { path: here });
                }
                BaseEntry::File { .. } | BaseEntry::Submodule { .. } => {
                    return Err(BaseError::NotADirectory { path: here });
                }
            }
        }

        Err(BaseError::NotFound { path: path.clone() })
    }

    /// Lists the immediate children of a tree path, or of the root for `None`.
    pub fn list<S: ObjectSource<A>>(
        &self,
        source: &S,
        capability: &mut TreeCapability,
        directory: Option<&TreePath>,
        now: u64,
    ) -> Result<DirectoryListing<A>, BaseError> {
        let (tree_oid, scope) = match directory {
            None => (self.base_tree_oid, None),
            Some(path) => match self.resolve(source, capability, path, now)? {
                BaseEntry::Directory { oid } => (oid, Some(path.clone())),
                _ => return Err(BaseError::NotADirectory { path: path.clone() }),
            },
        };

        // The root has no path of its own, so it is authorised as the root
        // rather than through a fabricated path.
        let grant = match &scope {
            Some(path) => capability.authorize_read(path, now)?,
            None => capability.authorize_root(now)?,
        };
        let body = self.read_object(source, &tree_oid, GitObjectKind::Tree, &grant)?;
        capability.charge_fetch(body.len() as u64)?;
        let entries = parse_tree(
            &body,
            AcceptanceProfile::GitCompatibleImport,
            &self.parse_limits,
        )?;

        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            // Reaching the root tree is necessary to get to any authorised
            // descendant, but the listing must not become an existence oracle
            // for the siblings alongside it. A caller holding only `docs` may
            // learn that `docs` exists; it may not learn that `src` does merely
            // because the base tree is rooted above both. authorize_root's own
            // documentation said this filtering was the caller's to do, and
            // this is the caller.
            //
            // Filtering happens BEFORE classify, so an unauthorised name is not
            // even parsed into a typed entry on its way to being discarded.
            let child = match &scope {
                Some(prefix) => prefix.join(&entry.name, &self.path_policy)?,
                None => TreePath::parse(&entry.name, &self.path_policy)?,
            };
            if !capability.admits_disclosure(&child) {
                continue;
            }
            let classified = classify(&entry)?;
            out.push((entry.name.clone(), classified));
        }
        Ok(out)
    }
}

/// Classifies one raw tree entry into a typed base entry.
///
/// A free function rather than a method: it reads nothing from the view, and a
/// `&self` it never touches would imply a dependence on view state that is not
/// there.
fn classify<A: GitHashAlgorithm>(entry: &TreeEntry) -> Result<BaseEntry<A>, BaseError> {
    let oid = oid_from_bytes::<A>(&entry.object_id)?;
    let mode: &[u8] = &entry.mode;
    Ok(match mode {
        b"40000" | b"040000" => BaseEntry::Directory { oid },
        b"120000" => BaseEntry::Symlink { oid },
        b"160000" => BaseEntry::Submodule { oid },
        _ => BaseEntry::File {
            oid,
            mode: entry.mode.clone(),
        },
    })
}

/// Converts raw native reference bytes into a typed identity.
///
/// A width mismatch means the tree was written for a different object format,
/// which is refused rather than reinterpreted: SHA-1 and SHA-256 are separate
/// typed domains (AGENTS.md §6) and coercing between them would manufacture a
/// plausible-looking identity that names nothing.
fn hex_of(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn oid_from_bytes<A: GitHashAlgorithm>(bytes: &[u8]) -> Result<GitOid<A>, BaseError> {
    if bytes.len() != A::DIGEST_LEN {
        return Err(BaseError::Object(format!(
            "tree reference is {} bytes, this object format uses {}",
            bytes.len(),
            A::DIGEST_LEN
        )));
    }
    let hex = hex_of(bytes);
    A::parse_hex(&hex).map_err(|refusal| BaseError::Object(refusal.to_string()))
}
