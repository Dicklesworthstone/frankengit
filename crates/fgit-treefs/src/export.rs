//! Deterministic export of a workspace overlay to exact Git objects.
//!
//! `docs/GIT_TREE_FS.md` §6. An immutable base plus an ordered copy-on-write
//! overlay becomes a set of Git blob and tree objects and a *proposed* root
//! tree. Nothing here publishes anything.
//!
//! # What determinism means here
//!
//! The same base, overlay and profile must produce byte-identical objects and
//! identical identities, independent of schedule or hash iteration order. Three
//! things secure that:
//!
//! * directories are rebuilt bottom-up over a `BTreeSet` of affected paths, so
//!   traversal order is path order and never map iteration order;
//! * entries within a tree are ordered by [`compare_tree_entries`], the
//!   comparator `fgit-git-object` owns — Git's rule sorts a directory as though
//!   its name ended in `/`, which a plain byte sort gets wrong;
//! * unchanged subtrees keep their original OIDs and are never re-emitted, so
//!   the output depends on the edit rather than on the walk.
//!
//! # Reuse, not copying
//!
//! A path the overlay never touched contributes its base OID. A body carried
//! from the base by a rename or a mode change ([`ContentRef::Base`]) is
//! referenced, never re-encoded. Only genuinely new bytes become new blobs.
//!
//! # This module cannot publish
//!
//! [`ExportPlan`] holds candidate objects and a root tree identity. It has no
//! method that writes to a repository, moves a ref, or produces an authority
//! head. Turning a plan into a *request* is [`crate::proposal`]'s job, and even
//! that produces only a proposal. Object existence never implies commit
//! (AGENTS.md §5.1).

use crate::base::{BaseEntry, BaseError, BaseView, ObjectSource};
use crate::capability::TreeCapability;
use crate::overlay::{ContentRef, FileMode, Overlay, OverlayEntry};
use crate::path::TreePath;
use core::fmt::{self, Display, Formatter};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity};
use fgit_git_object::{
    AcceptanceProfile, ObjectError, ParseLimits, TreeEntry, compare_tree_entries, emit_tree,
};
use std::collections::{BTreeMap, BTreeSet};

/// Git's mode bytes for a directory, as `FrankenGit` writes them.
const MODE_TREE: &[u8] = b"40000";
/// Git's mode bytes for a symlink.
const MODE_SYMLINK: &[u8] = b"120000";
/// Git's mode bytes for a gitlink.
const MODE_GITLINK: &[u8] = b"160000";

/// Bounds on a single export.
///
/// Checked before work, not after: an export that would exceed a ceiling is
/// refused rather than half-built and then discovered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportLimits {
    /// Largest number of objects one export may construct.
    pub max_objects: usize,
    /// Largest total byte count across constructed objects.
    pub max_total_bytes: usize,
    /// Largest number of entries in any one tree.
    pub max_tree_entries: usize,
}

impl Default for ExportLimits {
    fn default() -> Self {
        Self {
            max_objects: 100_000,
            max_total_bytes: 512 * 1024 * 1024,
            max_tree_entries: 100_000,
        }
    }
}

/// Why an export was refused.
///
/// Every variant is a bounded, typed refusal. None of them is a partial
/// success: an export either yields a complete plan or yields nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportRefusal {
    /// Reading the base failed.
    Base(String),
    /// A tree could not be emitted in canonical form.
    Object(String),
    /// A conflict entry is present, so the workspace is not exportable.
    ///
    /// Recorded conflict markers are for a human or a later merge-ladder rung;
    /// exporting one as ordinary content would launder an unresolved conflict
    /// into a published tree.
    UnresolvedConflict {
        /// Where the conflict sits.
        path: TreePath,
    },
    /// The overlay references a body that is not in its content store.
    MissingBody {
        /// The entry whose body is absent.
        path: TreePath,
    },
    /// The export would construct more objects than permitted.
    ObjectBudgetExceeded {
        /// Objects that would be constructed.
        observed: usize,
        /// Configured ceiling.
        limit: usize,
    },
    /// The export would construct more bytes than permitted.
    ByteBudgetExceeded {
        /// Bytes that would be constructed.
        observed: usize,
        /// Configured ceiling.
        limit: usize,
    },
    /// A single tree would hold more entries than permitted.
    TreeTooWide {
        /// Where the tree sits, or `None` for the root.
        path: Option<TreePath>,
        /// Entries the tree would hold.
        observed: usize,
        /// Configured ceiling.
        limit: usize,
    },
    /// A path would be both a file and a directory in the exported tree.
    PathTypeConflict {
        /// The contested path.
        path: TreePath,
    },
    /// The export was cancelled before it produced a plan.
    Cancelled,
}

impl Display for ExportRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(inner) => write!(formatter, "base read failed: {inner}"),
            Self::Object(inner) => write!(formatter, "object construction failed: {inner}"),
            Self::UnresolvedConflict { path } => {
                write!(formatter, "unresolved conflict at {path} is not exportable")
            }
            Self::MissingBody { path } => write!(formatter, "no body staged for {path}"),
            Self::ObjectBudgetExceeded { observed, limit } => {
                write!(formatter, "{observed} objects exceeds the limit of {limit}")
            }
            Self::ByteBudgetExceeded { observed, limit } => {
                write!(formatter, "{observed} bytes exceeds the limit of {limit}")
            }
            Self::TreeTooWide {
                path,
                observed,
                limit,
            } => match path {
                Some(path) => write!(
                    formatter,
                    "tree {path} would hold {observed} entries, limit {limit}"
                ),
                None => write!(
                    formatter,
                    "root tree would hold {observed} entries, limit {limit}"
                ),
            },
            Self::PathTypeConflict { path } => {
                write!(formatter, "{path} would be both a file and a directory")
            }
            Self::Cancelled => write!(formatter, "export cancelled before producing a plan"),
        }
    }
}

impl core::error::Error for ExportRefusal {}

impl From<BaseError> for ExportRefusal {
    fn from(value: BaseError) -> Self {
        Self::Base(value.to_string())
    }
}

impl From<ObjectError> for ExportRefusal {
    fn from(value: ObjectError) -> Self {
        Self::Object(value.to_string())
    }
}

/// One Git object this export would create.
///
/// Holds the exact canonical body bytes and the identity they hash to. The
/// identity is computed from the bytes here, not supplied, so an object cannot
/// carry a name that does not match its content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportedObject<A: GitHashAlgorithm> {
    kind: GitObjectKind,
    oid: GitOid<A>,
    body: Vec<u8>,
}

impl<A: GitHashAlgorithm> ExportedObject<A> {
    /// Builds an object from its canonical body, deriving the identity.
    #[must_use]
    pub fn new(kind: GitObjectKind, body: Vec<u8>) -> Self {
        let oid = GitOid::<A>::of_object(kind, &body);
        Self { kind, oid, body }
    }

    /// The object kind.
    #[must_use]
    pub const fn kind(&self) -> GitObjectKind {
        self.kind
    }

    /// The derived identity.
    #[must_use]
    pub const fn oid(&self) -> &GitOid<A> {
        &self.oid
    }

    /// The canonical body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Whether the body still hashes to the recorded identity.
    ///
    /// Cheap enough to assert before use; a plan whose objects fail this has
    /// been tampered with in memory.
    #[must_use]
    pub fn verify(&self) -> bool {
        GitOid::<A>::of_object(self.kind, &self.body) == self.oid
    }
}

/// A complete, deterministic export.
///
/// Objects are keyed by identity, so the plan is a set and cannot hold two
/// different bodies under one name. Iteration is in identity order, which makes
/// the plan itself diffable between runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportPlan<A: GitHashAlgorithm> {
    objects: BTreeMap<Vec<u8>, ExportedObject<A>>,
    root_tree: GitOid<A>,
    reused_base_objects: usize,
}

impl<A: GitHashAlgorithm> ExportPlan<A> {
    /// The root tree this export proposes.
    ///
    /// A tree identity, never a commit and never an authority head. Holding it
    /// grants nothing.
    #[must_use]
    pub const fn root_tree(&self) -> &GitOid<A> {
        &self.root_tree
    }

    /// Objects this export would create, in identity order.
    pub fn objects(&self) -> impl Iterator<Item = &ExportedObject<A>> {
        self.objects.values()
    }

    /// How many objects this export would create.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Total bytes across constructed objects.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.objects.values().map(|object| object.body.len()).sum()
    }

    /// How many base objects were referenced rather than re-encoded.
    ///
    /// The sparseness receipt: a large number here against a small
    /// [`Self::object_count`] is the export doing its job.
    #[must_use]
    pub const fn reused_base_objects(&self) -> usize {
        self.reused_base_objects
    }

    /// Looks an object up by identity.
    #[must_use]
    pub fn get(&self, oid: &GitOid<A>) -> Option<&ExportedObject<A>> {
        self.objects.get(oid.digest_bytes())
    }

    /// Whether every object still hashes to the identity it is filed under.
    #[must_use]
    pub fn verify_all(&self) -> bool {
        self.objects
            .iter()
            .all(|(key, object)| object.verify() && object.oid.digest_bytes() == key.as_slice())
    }
}

/// What one directory level holds after the overlay is applied.
enum Resolved<A: GitHashAlgorithm> {
    /// A file, with its mode and the blob identity it should reference.
    File { mode: Vec<u8>, oid: GitOid<A> },
    /// A symlink pointing at a blob holding the link text.
    Symlink { oid: GitOid<A> },
    /// A gitlink.
    Gitlink { oid: GitOid<A> },
    /// A subdirectory.
    ///
    /// `base_oid` is the identity the base already holds here, when the base
    /// holds one. An untouched subtree keeps that identity verbatim; dropping
    /// it instead deletes every file beneath it from the exported tree, which
    /// is the data-destroying defect this field exists to make impossible.
    Directory { base_oid: Option<GitOid<A>> },
}

/// The deterministic export planner.
#[derive(Clone, Debug)]
pub struct ExportPlanner {
    limits: ExportLimits,
    parse_limits: ParseLimits,
}

impl ExportPlanner {
    /// Builds a planner.
    #[must_use]
    pub const fn new(limits: ExportLimits, parse_limits: ParseLimits) -> Self {
        Self {
            limits,
            parse_limits,
        }
    }

    /// Plans an export of `overlay` over `base`.
    ///
    /// `cancelled` is polled at each directory boundary. Cancellation yields
    /// [`ExportRefusal::Cancelled`] and no plan at all: there is no partial
    /// export to promote, which is the property the epoch rules depend on.
    pub fn plan<A: GitHashAlgorithm, S: ObjectSource<A>>(
        &self,
        base: &BaseView<A>,
        source: &S,
        capability: &mut TreeCapability,
        overlay: &Overlay,
        now: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<ExportPlan<A>, ExportRefusal> {
        let mut objects: BTreeMap<Vec<u8>, ExportedObject<A>> = BTreeMap::new();
        let mut reused = 0_usize;

        // Blobs first: every staged body becomes a candidate blob, and every
        // base-carried body is counted as reuse rather than re-encoded.
        for (path, entry) in overlay.entries() {
            if cancelled() {
                return Err(ExportRefusal::Cancelled);
            }
            match entry {
                OverlayEntry::Conflict { .. } => {
                    return Err(ExportRefusal::UnresolvedConflict { path: path.clone() });
                }
                OverlayEntry::File {
                    content: ContentRef::Overlay(_),
                    ..
                }
                | OverlayEntry::Symlink { .. } => {
                    let body = overlay
                        .body(entry)
                        .ok_or_else(|| ExportRefusal::MissingBody { path: path.clone() })?;
                    let object = ExportedObject::<A>::new(GitObjectKind::Blob, body.to_vec());
                    objects.insert(object.oid.digest_bytes().to_vec(), object);
                }
                OverlayEntry::File {
                    content: ContentRef::Base { .. },
                    ..
                } => reused += 1,
                OverlayEntry::Directory
                | OverlayEntry::Whiteout
                | OverlayEntry::Submodule { .. } => {}
            }
        }

        // Every directory that must be rebuilt: each touched path's ancestors,
        // plus the root. A BTreeSet gives path order; rebuilding deepest-first
        // means a child's identity always exists before its parent needs it.
        let mut dirty: BTreeSet<TreePath> = BTreeSet::new();
        for path in overlay.entries().keys() {
            for ancestor in path.ancestors() {
                dirty.insert(ancestor);
            }
        }
        let mut deepest: Vec<TreePath> = dirty.into_iter().collect();
        deepest.sort_by(|left, right| {
            right
                .component_count()
                .cmp(&left.component_count())
                .then_with(|| left.cmp(right))
        });

        // `Some(oid)` = rebuilt to this identity; `None` = rebuilt and now empty;
        // absent = never touched, so the base identity stands. Encoding the
        // empty case as an absent key made it indistinguishable from untouched,
        // which silently resurrected deleted directories.
        let mut rebuilt: BTreeMap<TreePath, Option<GitOid<A>>> = BTreeMap::new();

        for directory in &deepest {
            if cancelled() {
                return Err(ExportRefusal::Cancelled);
            }
            let oid = self.rebuild_directory(
                base,
                source,
                capability,
                overlay,
                Some(directory),
                &rebuilt,
                &mut objects,
                now,
            )?;
            // Record the outcome either way. A directory that rebuilt to
            // nothing must be REMEMBERED as empty: Git has no empty tree entry,
            // so it has to disappear from its parent, and forgetting it here
            // let the parent fall back to the base identity and undo the delete.
            rebuilt.insert(directory.clone(), oid);
        }

        if cancelled() {
            return Err(ExportRefusal::Cancelled);
        }
        let root = self
            .rebuild_directory(
                base,
                source,
                capability,
                overlay,
                None,
                &rebuilt,
                &mut objects,
                now,
            )?
            .unwrap_or_else(|| {
                // An entirely empty workspace exports Git's empty tree.
                let object = ExportedObject::<A>::new(GitObjectKind::Tree, Vec::new());
                let oid = object.oid;
                objects.insert(object.oid.digest_bytes().to_vec(), object);
                oid
            });

        if objects.len() > self.limits.max_objects {
            return Err(ExportRefusal::ObjectBudgetExceeded {
                observed: objects.len(),
                limit: self.limits.max_objects,
            });
        }
        let total: usize = objects.values().map(|object| object.body.len()).sum();
        if total > self.limits.max_total_bytes {
            return Err(ExportRefusal::ByteBudgetExceeded {
                observed: total,
                limit: self.limits.max_total_bytes,
            });
        }

        Ok(ExportPlan {
            objects,
            root_tree: root,
            reused_base_objects: reused,
        })
    }

    /// Rebuilds one directory, returning its new identity or `None` if it ends
    /// up empty.
    fn rebuild_directory<A: GitHashAlgorithm, S: ObjectSource<A>>(
        &self,
        base: &BaseView<A>,
        source: &S,
        capability: &mut TreeCapability,
        overlay: &Overlay,
        directory: Option<&TreePath>,
        rebuilt: &BTreeMap<TreePath, Option<GitOid<A>>>,
        objects: &mut BTreeMap<Vec<u8>, ExportedObject<A>>,
        now: u64,
    ) -> Result<Option<GitOid<A>>, ExportRefusal> {
        // Start from what the base holds here. A directory absent from the base
        // is a new directory, not an error.
        let mut level: BTreeMap<Vec<u8>, Resolved<A>> = BTreeMap::new();
        match base.list(source, capability, directory, now) {
            Ok(entries) => {
                for (name, entry) in entries {
                    level.insert(name, resolved_from_base(&entry));
                }
            }
            Err(BaseError::NotFound { .. }) => {}
            Err(other) => return Err(other.into()),
        }

        // Apply the overlay's entries at exactly this level.
        for (path, entry) in overlay.entries() {
            let parent = path.parent();
            let at_this_level = match (directory, parent.as_ref()) {
                (None, None) => true,
                (Some(here), Some(parent)) => here == parent,
                _ => false,
            };
            if !at_this_level {
                continue;
            }
            let name = path.file_name().to_vec();
            match entry {
                OverlayEntry::Whiteout => {
                    level.remove(&name);
                }
                OverlayEntry::Directory => {
                    // An explicit directory intent must not erase the base
                    // subtree that already sits here.
                    let base_oid = match level.get(&name) {
                        Some(Resolved::Directory { base_oid }) => *base_oid,
                        _ => None,
                    };
                    level.insert(name, Resolved::Directory { base_oid });
                }
                OverlayEntry::File { content, mode, .. } => {
                    let oid = match content {
                        ContentRef::Overlay(_) => {
                            let body = overlay
                                .body(entry)
                                .ok_or_else(|| ExportRefusal::MissingBody { path: path.clone() })?;
                            GitOid::<A>::of_object(GitObjectKind::Blob, body)
                        }
                        ContentRef::Base { oid, .. } => oid_from_native::<A>(oid)?,
                    };
                    level.insert(
                        name,
                        Resolved::File {
                            mode: mode_bytes(*mode).to_vec(),
                            oid,
                        },
                    );
                }
                OverlayEntry::Symlink { .. } => {
                    let body = overlay
                        .body(entry)
                        .ok_or_else(|| ExportRefusal::MissingBody { path: path.clone() })?;
                    level.insert(
                        name,
                        Resolved::Symlink {
                            oid: GitOid::<A>::of_object(GitObjectKind::Blob, body),
                        },
                    );
                }
                OverlayEntry::Submodule { commit } => {
                    level.insert(
                        name,
                        Resolved::Gitlink {
                            oid: oid_from_native::<A>(commit)?,
                        },
                    );
                }
                OverlayEntry::Conflict { .. } => {
                    return Err(ExportRefusal::UnresolvedConflict { path: path.clone() });
                }
            }
        }

        // A directory created purely by the overlay has no base entry here and
        // no overlay entry AT this level -- an add at `new/deep/file.txt` puts
        // its only overlay entry two levels down. Without this pass the rebuilt
        // `new/` subtree exists in `rebuilt` and nothing ever looks for it, so
        // the whole added subtree is silently dropped from the export.
        for (child, child_oid) in rebuilt {
            if child_oid.is_none() {
                continue;
            }
            let parent = child.parent();
            let at_this_level = match (directory, parent.as_ref()) {
                (None, None) => true,
                (Some(here), Some(parent)) => here == parent,
                _ => false,
            };
            if !at_this_level {
                continue;
            }
            level
                .entry(child.file_name().to_vec())
                .or_insert(Resolved::Directory { base_oid: None });
        }

        // Resolve subdirectory identities from the bottom-up pass. A directory
        // that rebuilt to nothing disappears, because Git cannot represent an
        // empty tree entry.
        let mut entries: Vec<TreeEntry> = Vec::with_capacity(level.len());
        for (name, resolved) in level {
            let entry = match resolved {
                Resolved::File { mode, oid } => TreeEntry {
                    mode,
                    name,
                    object_id: oid.digest_bytes().to_vec(),
                },
                Resolved::Symlink { oid } => TreeEntry {
                    mode: MODE_SYMLINK.to_vec(),
                    name,
                    object_id: oid.digest_bytes().to_vec(),
                },
                Resolved::Gitlink { oid } => TreeEntry {
                    mode: MODE_GITLINK.to_vec(),
                    name,
                    object_id: oid.digest_bytes().to_vec(),
                },
                Resolved::Directory { base_oid } => {
                    let child = directory
                        .map_or_else(
                            || TreePath::parse(&name, base.path_policy()),
                            |here| here.join(&name, base.path_policy()),
                        )
                        .map_err(|refusal| ExportRefusal::Base(refusal.to_string()))?;
                    // Three distinct cases, and collapsing any two of them
                    // loses data:
                    //   Some(Some(oid)) -- rebuilt; the new identity wins.
                    //   Some(None)      -- rebuilt and now empty; it must
                    //                      disappear. Falling back to the base
                    //                      here undoes the deletion that
                    //                      emptied it.
                    //   None            -- never touched; the base identity is
                    //                      carried forward verbatim, which is
                    //                      what keeps untouched subtrees from
                    //                      being dropped.
                    let resolved_oid = match rebuilt.get(&child) {
                        Some(rebuilt_oid) => *rebuilt_oid,
                        None => base_oid,
                    };
                    match resolved_oid {
                        Some(oid) => TreeEntry {
                            mode: MODE_TREE.to_vec(),
                            name,
                            object_id: oid.digest_bytes().to_vec(),
                        },
                        None => continue,
                    }
                }
            };
            entries.push(entry);
        }

        if entries.len() > self.limits.max_tree_entries {
            return Err(ExportRefusal::TreeTooWide {
                path: directory.cloned(),
                observed: entries.len(),
                limit: self.limits.max_tree_entries,
            });
        }
        if entries.is_empty() {
            return Ok(None);
        }

        // Git's ordering, from the comparator fgit-git-object owns. A plain
        // byte sort is wrong: a directory sorts as though its name ended in
        // '/', so "a" as a tree sorts after "a.txt" as a blob.
        entries.sort_by(compare_tree_entries);

        let body = emit_tree(
            &entries,
            AcceptanceProfile::StrictCreate,
            &self.parse_limits,
        )?;
        let object = ExportedObject::<A>::new(GitObjectKind::Tree, body);
        let oid = object.oid;
        objects.insert(object.oid.digest_bytes().to_vec(), object);
        Ok(Some(oid))
    }
}

fn resolved_from_base<A: GitHashAlgorithm>(entry: &BaseEntry<A>) -> Resolved<A> {
    match entry {
        BaseEntry::File { oid, mode } => Resolved::File {
            mode: mode.clone(),
            oid: *oid,
        },
        BaseEntry::Symlink { oid } => Resolved::Symlink { oid: *oid },
        BaseEntry::Submodule { oid } => Resolved::Gitlink { oid: *oid },
        BaseEntry::Directory { oid } => Resolved::Directory {
            base_oid: Some(*oid),
        },
    }
}

const fn mode_bytes(mode: FileMode) -> &'static [u8] {
    mode.as_octal_bytes()
}

/// Converts raw native reference bytes to a typed identity.
///
/// A width mismatch means the reference was written for another object format
/// and is refused rather than reinterpreted: SHA-1 and SHA-256 are separate
/// typed domains (AGENTS.md §6).
fn oid_from_native<A: GitHashAlgorithm>(bytes: &[u8]) -> Result<GitOid<A>, ExportRefusal> {
    if bytes.len() != A::DIGEST_LEN {
        return Err(ExportRefusal::Object(format!(
            "reference is {} bytes, this object format uses {}",
            bytes.len(),
            A::DIGEST_LEN
        )));
    }
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    A::parse_hex(&hex).map_err(|refusal| ExportRefusal::Object(refusal.to_string()))
}
