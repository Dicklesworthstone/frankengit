//! The sparse copy-on-write overlay.
//!
//! `docs/GIT_TREE_FS.md` §3.2. The overlay records *semantic entries* for the
//! paths an edit touched. It never copies unchanged file bytes and never
//! materialises an unchanged subtree, so its size tracks the edit rather than
//! the repository. That is the property [`OverlayStats`] exists to let a test
//! assert on a large base, and it is the difference between a sparse workspace
//! and a checkout.
//!
//! # Content addressing
//!
//! Bodies live once in a [`ContentStore`], keyed by [`ContentId`]. Writing the
//! same bytes to ten paths stores one body. The id is a digest of the content,
//! so it is stable across runs and processes — which is what makes intent-log
//! replay reproduce an overlay byte for byte rather than merely equivalently.
//!
//! # Deletion is an entry, not an absence
//!
//! A delete records an explicit [`OverlayEntry::Whiteout`]. An absent overlay
//! entry means "ask the base"; it must never mean "deleted", because those two
//! are different answers and conflating them makes a delete invisible to
//! replay and to the net-effect fold.

use crate::path::TreePath;
use core::fmt::{self, Display, Formatter};
use fgit_crypto::{DigestHasher, Sha256};
use std::collections::BTreeMap;

/// A content-addressed body identity.
///
/// Derived from the bytes, not assigned, so it is identical in every process
/// that holds the same content.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentId([u8; 32]);

impl ContentId {
    /// Computes the identity of `bytes`.
    ///
    /// The preimage is domain-separated so a content id can never be confused
    /// with a native Git object identity over the same bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = <Sha256 as fgit_crypto::GitHashAlgorithm>::Hasher::new();
        hasher.update(b"frankengit.treefs.content.v1\0");
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        let digest = hasher.finish();
        let mut out = [0_u8; 32];
        out.copy_from_slice(digest.as_ref());
        Self(out)
    }

    /// The raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for ContentId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A Git file mode, as the closed set `TreeFS` will create.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FileMode {
    /// `100644`.
    #[default]
    Regular,
    /// `100755`.
    Executable,
}

impl FileMode {
    /// The canonical ASCII-octal mode bytes.
    #[must_use]
    pub const fn as_octal_bytes(self) -> &'static [u8] {
        match self {
            Self::Regular => b"100644",
            Self::Executable => b"100755",
        }
    }

    /// Parses canonical mode bytes, refusing anything `TreeFS` will not create.
    #[must_use]
    pub const fn from_octal_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"100644" => Some(Self::Regular),
            b"100755" => Some(Self::Executable),
            _ => None,
        }
    }
}

/// Whether an entry is ordinary content or a declared build product.
///
/// `docs/GIT_TREE_FS.md` §3.2 and §7: generated outputs carry provenance so a
/// reviewer can tell a hand edit from a tool product. The distinction is
/// recorded, never inferred.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum EntryClass {
    /// Ordinary authored content.
    #[default]
    Content,
    /// A declared generated output and the provenance that produced it.
    Generated {
        /// Opaque producer identity, e.g. a tool or rule name.
        producer: Vec<u8>,
    },
}

/// Where an entry's bytes actually live.
///
/// A rename or a mode-only change must not copy the file body, so an overlay
/// entry can reference a body that is still in the immutable base. That is what
/// keeps those operations O(1) in the file's size, and it is why the entry kind
/// records *where* the bytes are rather than assuming the overlay owns them.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContentRef {
    /// The body was staged into this overlay's content store.
    Overlay(ContentId),
    /// The body remains in the immutable base under these native reference
    /// bytes, carried from the recorded source path.
    Base {
        /// Raw native object-reference bytes of the base blob.
        oid: Vec<u8>,
        /// The base path the body was carried from, retained as lineage.
        from: TreePath,
    },
}

impl ContentRef {
    /// The overlay content id, when the body is staged here.
    #[must_use]
    pub const fn overlay_id(&self) -> Option<ContentId> {
        match self {
            Self::Overlay(id) => Some(*id),
            Self::Base { .. } => None,
        }
    }

    /// Whether the bytes are still in the base.
    #[must_use]
    pub const fn is_base_carried(&self) -> bool {
        matches!(self, Self::Base { .. })
    }
}

/// One overlay entry.
///
/// Every kind listed in `docs/GIT_TREE_FS.md` §3.2 is representable here, which
/// is what makes the intent totality map in [`crate::intent`] have no
/// unreachable target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OverlayEntry {
    /// A regular or executable file body.
    File {
        /// Where the body lives.
        content: ContentRef,
        /// The file mode.
        mode: FileMode,
        /// Ordinary content or a declared generated output.
        class: EntryClass,
    },
    /// A symlink stored as link-text data, never as host traversal authority.
    Symlink {
        /// Identity of the link text in the content store.
        target: ContentId,
    },
    /// An explicitly created directory that may still be empty.
    Directory,
    /// An explicit delete marker.
    ///
    /// Distinct from an absent entry, which means "consult the base".
    Whiteout,
    /// A gitlink whose recorded commit changed.
    Submodule {
        /// Raw native reference bytes of the recorded commit.
        commit: Vec<u8>,
    },
    /// A recorded merge conflict, left for a human or a later ladder rung.
    Conflict {
        /// Identity of the marker body in the content store.
        marker: ContentId,
        /// Opaque identities of the merge inputs, in stable order.
        inputs: Vec<Vec<u8>>,
    },
}

impl OverlayEntry {
    /// The content identity this entry references, if any.
    #[must_use]
    pub const fn content_id(&self) -> Option<ContentId> {
        match self {
            Self::File { content, .. } => content.overlay_id(),
            Self::Symlink { target } => Some(*target),
            Self::Conflict { marker, .. } => Some(*marker),
            Self::Directory | Self::Whiteout | Self::Submodule { .. } => None,
        }
    }

    /// The base body this entry carries, if its bytes are still in the base.
    #[must_use]
    pub const fn base_carry(&self) -> Option<(&Vec<u8>, &TreePath)> {
        match self {
            Self::File {
                content: ContentRef::Base { oid, from },
                ..
            } => Some((oid, from)),
            _ => None,
        }
    }

    /// Whether this entry hides whatever the base holds at the same path.
    #[must_use]
    pub const fn shadows_base(&self) -> bool {
        !matches!(self, Self::Directory)
    }
}

/// Deduplicating store of overlay bodies.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContentStore {
    bodies: BTreeMap<ContentId, Vec<u8>>,
}

impl ContentStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Interns `bytes` and returns its identity.
    ///
    /// Identical bytes are stored once however many paths reference them.
    pub fn insert(&mut self, bytes: Vec<u8>) -> ContentId {
        let id = ContentId::of(&bytes);
        self.bodies.entry(id).or_insert(bytes);
        id
    }

    /// Borrows a body.
    #[must_use]
    pub fn get(&self, id: ContentId) -> Option<&[u8]> {
        self.bodies.get(&id).map(Vec::as_slice)
    }

    /// How many distinct bodies are stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bodies.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bodies.is_empty()
    }

    /// Total stored body bytes.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.bodies.values().map(Vec::len).sum()
    }

    /// Drops bodies no longer referenced by any entry in `live`.
    ///
    /// Called after a fold collapses intents; a body that no surviving entry
    /// names is not evidence of anything and would otherwise make the overlay
    /// grow with edit *history* rather than with edit *result*.
    pub fn retain_referenced(&mut self, live: &BTreeMap<TreePath, OverlayEntry>) {
        let mut referenced = std::collections::BTreeSet::new();
        for entry in live.values() {
            if let Some(id) = entry.content_id() {
                referenced.insert(id);
            }
        }
        self.bodies.retain(|id, _| referenced.contains(id));
    }
}

/// Size facts about an overlay, for asserting sparseness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverlayStats {
    /// How many paths carry an overlay entry.
    pub entry_count: usize,
    /// How many distinct bodies are stored.
    pub body_count: usize,
    /// Total stored body bytes.
    pub body_bytes: usize,
}

/// The copy-on-write overlay over a base view.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Overlay {
    entries: BTreeMap<TreePath, OverlayEntry>,
    content: ContentStore,
}

/// What the overlay says about a path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OverlayLookup<'a> {
    /// The overlay has an entry that shadows the base.
    Present(&'a OverlayEntry),
    /// The overlay explicitly deleted this path.
    Deleted,
    /// An ancestor directory was deleted, so this path is gone with it.
    DeletedByAncestor {
        /// The deleted ancestor.
        ancestor: TreePath,
    },
    /// The overlay says nothing; consult the base.
    Absent,
}

impl Overlay {
    /// An empty overlay.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the content store.
    #[must_use]
    pub const fn content(&self) -> &ContentStore {
        &self.content
    }

    /// Mutably borrows the content store.
    pub const fn content_mut(&mut self) -> &mut ContentStore {
        &mut self.content
    }

    /// Borrows the entry map.
    #[must_use]
    pub const fn entries(&self) -> &BTreeMap<TreePath, OverlayEntry> {
        &self.entries
    }

    /// Size facts, for sparseness assertions.
    #[must_use]
    pub fn stats(&self) -> OverlayStats {
        OverlayStats {
            entry_count: self.entries.len(),
            body_count: self.content.len(),
            body_bytes: self.content.total_bytes(),
        }
    }

    /// Interns a body.
    pub fn intern(&mut self, bytes: Vec<u8>) -> ContentId {
        self.content.insert(bytes)
    }

    /// Places an entry at `path`.
    pub fn put(&mut self, path: TreePath, entry: OverlayEntry) {
        self.entries.insert(path, entry);
    }

    /// Removes any entry at `path`, so the base shows through again.
    pub fn clear(&mut self, path: &TreePath) -> Option<OverlayEntry> {
        self.entries.remove(path)
    }

    /// Resolves what the overlay says about `path`.
    ///
    /// Ancestors are consulted, so deleting a directory hides everything under
    /// it without the overlay having to enumerate the subtree — the whole point
    /// of a sparse delete.
    #[must_use]
    pub fn lookup(&self, path: &TreePath) -> OverlayLookup<'_> {
        for ancestor in path.ancestors() {
            if matches!(self.entries.get(&ancestor), Some(OverlayEntry::Whiteout)) {
                return OverlayLookup::DeletedByAncestor { ancestor };
            }
        }
        match self.entries.get(path) {
            Some(OverlayEntry::Whiteout) => OverlayLookup::Deleted,
            Some(entry) => OverlayLookup::Present(entry),
            None => OverlayLookup::Absent,
        }
    }

    /// Reads the body an entry references.
    #[must_use]
    pub fn body(&self, entry: &OverlayEntry) -> Option<&[u8]> {
        entry.content_id().and_then(|id| self.content.get(id))
    }

    /// Drops unreferenced bodies.
    pub fn collect_content(&mut self) {
        self.content.retain_referenced(&self.entries);
    }

    /// Every path the overlay touches, in canonical order.
    #[must_use]
    pub fn touched_paths(&self) -> Vec<TreePath> {
        self.entries.keys().cloned().collect()
    }
}
