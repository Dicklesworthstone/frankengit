#![forbid(unsafe_code)]
//! Git notes object, tree, fanout, and merge semantics.
//!
//! Git notes map annotated target object IDs (such as commits) to note blob
//! objects. A notes ref (`refs/notes/*`) points to a commit whose tree is a
//! notes tree.
//!
//! ## Structure of Notes Trees
//!
//! - **Flat (no fanout)**: Each note entry is stored directly in the root tree
//!   with mode `100644`, where the tree entry name is the full 40-hex (SHA-1) or
//!   64-hex (SHA-256) target OID, and the entry's object reference is the 20-byte
//!   or 32-byte raw note blob OID.
//! - **Fanout (2-hex subtrees)**: When the number of notes exceeds the fanout
//!   threshold, entries are partitioned into 2-hex character subtrees (e.g.
//!   `ab/cdef...` with directory mode `040000` / `40000`). Subtrees contain leaf
//!   entries whose names are the remaining 38 (or 62) hex characters of the target
//!   OID.
//!
//! ## Determinism and Total Order
//!
//! Notes are maintained in a [`BTreeMap`] keyed by [`GitOid<A>`], ensuring
//! byte-lexicographical traversal order. When serialized to Git tree objects,
//! all entries are sorted strictly using Git's canonical tree ordering.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write};

use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity};

use crate::{AcceptanceProfile, ObjectError, ParseLimits, TreeEntry, emit_tree, parse_tree};

/// Default fanout threshold matching Git's default of 256 entries.
pub const DEFAULT_NOTES_FANOUT_THRESHOLD: usize = 256;

/// Formats raw bytes as lowercase hexadecimal.
#[must_use]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Converts any native object identity to its canonical lowercase hexadecimal string.
#[must_use]
pub fn oid_to_hex<T: NativeObjectIdentity>(oid: &T) -> String {
    bytes_to_hex(oid.digest_bytes())
}

/// Parses a typed `GitOid<A>` from raw binary digest bytes.
pub fn oid_from_bytes<A: GitHashAlgorithm>(bytes: &[u8]) -> Result<GitOid<A>, NotesError> {
    if bytes.len() != A::DIGEST_LEN {
        return Err(NotesError::InvalidOid {
            details: format!(
                "expected {} digest bytes, got {}",
                A::DIGEST_LEN,
                bytes.len()
            ),
        });
    }
    let hex = bytes_to_hex(bytes);
    A::parse_hex(&hex).map_err(|e| NotesError::InvalidOid {
        details: format!("{e:?}"),
    })
}

/// Parses a typed `GitOid<A>` from a canonical lowercase hexadecimal string.
pub fn oid_from_hex<A: GitHashAlgorithm>(hex: &str) -> Result<GitOid<A>, NotesError> {
    if hex.len() != A::HEX_LEN {
        return Err(NotesError::InvalidOid {
            details: format!("expected {} hex chars, got {}", A::HEX_LEN, hex.len()),
        });
    }
    A::parse_hex(hex).map_err(|e| NotesError::InvalidOid {
        details: format!("{e:?}"),
    })
}

/// Computes the native tree object ID for `body` in hash domain `A`.
#[must_use]
pub fn tree_oid_of<A: GitHashAlgorithm>(body: &[u8]) -> GitOid<A> {
    <GitOid<A> as NativeObjectIdentity>::of_object(GitObjectKind::Tree, body)
}

/// Typed refusal or failure during notes processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotesError {
    /// Target object already has an attached note and force was not specified.
    TargetAlreadyHasNote {
        /// Target OID string.
        target: String,
    },
    /// No note was found for the target object.
    TargetNoteNotFound {
        /// Target OID string.
        target: String,
    },
    /// Malformed or non-canonical tree entry in notes tree.
    InvalidNotesTreeEntry {
        /// Explanatory reason.
        reason: String,
    },
    /// Duplicate note target discovered during tree traversal.
    DuplicateNoteTarget {
        /// Target OID string.
        target: String,
    },
    /// Requested merge strategy is unsupported.
    UnsupportedMergeStrategy {
        /// Strategy name.
        strategy: String,
    },
    /// OID parsing failed.
    InvalidOid {
        /// Error details.
        details: String,
    },
    /// Tree framing or object error.
    Object(ObjectError),
}

impl Display for NotesError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetAlreadyHasNote { target } => {
                write!(f, "target object {target} already has an attached note")
            }
            Self::TargetNoteNotFound { target } => {
                write!(f, "no note found for target object {target}")
            }
            Self::InvalidNotesTreeEntry { reason } => {
                write!(f, "invalid notes tree entry: {reason}")
            }
            Self::DuplicateNoteTarget { target } => {
                write!(f, "duplicate note target {target} in notes tree")
            }
            Self::UnsupportedMergeStrategy { strategy } => {
                write!(f, "unsupported notes merge strategy: {strategy}")
            }
            Self::InvalidOid { details } => {
                write!(f, "invalid OID in notes tree: {details}")
            }
            Self::Object(err) => write!(f, "notes object error: {err}"),
        }
    }
}

impl Error for NotesError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Object(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ObjectError> for NotesError {
    fn from(err: ObjectError) -> Self {
        Self::Object(err)
    }
}

/// A single note mapping an annotated target object to its note blob.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NotesEntry<A: GitHashAlgorithm>
where
    GitOid<A>: Ord,
{
    /// The annotated target object (e.g. commit).
    pub target: GitOid<A>,
    /// The blob containing the note content.
    pub note_blob: GitOid<A>,
}

/// Declared merge strategies for Git notes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
pub enum NotesMergeStrategy {
    /// Manual strategy: conflicting edits on the same target return a typed conflict.
    #[default]
    Manual,
    /// In case of conflicting edits, keep the note from `ours`.
    Ours,
    /// In case of conflicting edits, take the note from `theirs`.
    Theirs,
    /// Concatenate `ours` note content and `theirs` note content.
    Union,
    /// Concatenate lines from `ours` and `theirs`, sort lines, and deduplicate.
    CatSortUniq,
}

/// A typed merge conflict for a specific target object.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NotesMergeConflict<A: GitHashAlgorithm>
where
    GitOid<A>: Ord,
{
    /// The target object that received conflicting notes.
    pub target: GitOid<A>,
    /// The note blob in `ours` branch (if any).
    pub ours: Option<GitOid<A>>,
    /// The note blob in `theirs` branch (if any).
    pub theirs: Option<GitOid<A>>,
    /// The note blob in `base` branch (if any).
    pub base: Option<GitOid<A>>,
}

/// In-memory representation of a Git notes tree mapping targets to note blobs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotesTree<A: GitHashAlgorithm>
where
    GitOid<A>: Ord,
{
    entries: BTreeMap<GitOid<A>, GitOid<A>>,
    fanout_threshold: usize,
}

impl<A: GitHashAlgorithm> Default for NotesTree<A>
where
    GitOid<A>: Ord,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<A: GitHashAlgorithm> NotesTree<A>
where
    GitOid<A>: Ord,
{
    /// Creates an empty notes tree with the default fanout threshold.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            fanout_threshold: DEFAULT_NOTES_FANOUT_THRESHOLD,
        }
    }

    /// Creates an empty notes tree with a custom fanout threshold.
    #[must_use]
    pub fn with_fanout_threshold(fanout_threshold: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            fanout_threshold,
        }
    }

    /// Returns the number of notes in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the notes tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the configured fanout threshold.
    #[must_use]
    pub fn fanout_threshold(&self) -> usize {
        self.fanout_threshold
    }

    /// Sets the fanout threshold.
    pub fn set_fanout_threshold(&mut self, threshold: usize) {
        self.fanout_threshold = threshold;
    }

    /// Look up the note blob for a given target object OID.
    #[must_use]
    pub fn get(&self, target: &GitOid<A>) -> Option<&GitOid<A>> {
        self.entries.get(target)
    }

    /// Returns true if a note exists for the given target object OID.
    #[must_use]
    pub fn contains(&self, target: &GitOid<A>) -> bool {
        self.entries.contains_key(target)
    }

    /// Iterates over all notes in deterministic byte-lexicographical target order.
    pub fn iter(&self) -> impl Iterator<Item = (&GitOid<A>, &GitOid<A>)> {
        self.entries.iter()
    }

    /// Attaches a note to `target`. If a note already exists and `force` is false, returns an error.
    pub fn attach(
        &mut self,
        target: GitOid<A>,
        note_blob: GitOid<A>,
        force: bool,
    ) -> Result<(), NotesError> {
        if !force && self.entries.contains_key(&target) {
            return Err(NotesError::TargetAlreadyHasNote {
                target: oid_to_hex(&target),
            });
        }
        self.entries.insert(target, note_blob);
        Ok(())
    }

    /// Edits an existing note. If no note exists for `target`, returns an error.
    pub fn edit(&mut self, target: GitOid<A>, new_note_blob: GitOid<A>) -> Result<(), NotesError> {
        if !self.entries.contains_key(&target) {
            return Err(NotesError::TargetNoteNotFound {
                target: oid_to_hex(&target),
            });
        }
        self.entries.insert(target, new_note_blob);
        Ok(())
    }

    /// Removes a note for `target`. Returns the removed note blob OID, or an error if absent.
    pub fn remove(&mut self, target: &GitOid<A>) -> Result<GitOid<A>, NotesError> {
        self.entries
            .remove(target)
            .ok_or_else(|| NotesError::TargetNoteNotFound {
                target: oid_to_hex(target),
            })
    }

    /// Copies a note from `from_target` to `to_target`.
    pub fn copy(
        &mut self,
        from_target: &GitOid<A>,
        to_target: GitOid<A>,
        force: bool,
    ) -> Result<(), NotesError> {
        let note_blob =
            *self
                .entries
                .get(from_target)
                .ok_or_else(|| NotesError::TargetNoteNotFound {
                    target: oid_to_hex(from_target),
                })?;
        self.attach(to_target, note_blob, force)
    }

    /// Prunes notes whose target objects are absent according to predicate `is_present`.
    /// Returns the list of pruned target OIDs in deterministic order.
    pub fn prune<P>(&mut self, is_present: P) -> Vec<GitOid<A>>
    where
        P: Fn(&GitOid<A>) -> bool,
    {
        let mut pruned = Vec::new();
        let targets_to_remove: Vec<GitOid<A>> = self
            .entries
            .keys()
            .copied()
            .filter(|target| !is_present(target))
            .collect();

        for target in targets_to_remove {
            self.entries.remove(&target);
            pruned.push(target);
        }
        pruned
    }

    /// Merges `self` (ours) with `theirs`, using optional `base` and the given `strategy`.
    ///
    /// If content merging is needed (`Union` or `CatSortUniq`), `resolve_blobs` is called
    /// to merge the two blob contents and produce a new blob OID.
    pub fn merge<F>(
        &self,
        theirs: &Self,
        base: Option<&Self>,
        strategy: NotesMergeStrategy,
        resolve_blobs: F,
    ) -> Result<(Self, Vec<NotesMergeConflict<A>>), NotesError>
    where
        F: Fn(&GitOid<A>, &GitOid<A>, NotesMergeStrategy) -> Result<GitOid<A>, NotesError>,
    {
        let mut result_entries = BTreeMap::new();
        let mut conflicts = Vec::new();

        // Collect all distinct target OIDs across ours, theirs, and base
        let mut all_targets = BTreeMap::new();
        for target in self.entries.keys() {
            all_targets.insert(*target, ());
        }
        for target in theirs.entries.keys() {
            all_targets.insert(*target, ());
        }
        if let Some(b) = base {
            for target in b.entries.keys() {
                all_targets.insert(*target, ());
            }
        }

        for target in all_targets.keys() {
            let ours_val = self.entries.get(target).copied();
            let theirs_val = theirs.entries.get(target).copied();
            let base_val = base.and_then(|b| b.entries.get(target).copied());

            match (ours_val, theirs_val, base_val) {
                // Both same
                (Some(o), Some(t), _) if o == t => {
                    result_entries.insert(*target, o);
                }
                (None, None, _) => {}

                // Only one side modified from base
                (Some(o), Some(t), Some(b)) if o == b && t != b => {
                    result_entries.insert(*target, t);
                }
                (Some(o), Some(t), Some(b)) if t == b && o != b => {
                    result_entries.insert(*target, o);
                }
                (None, Some(t), Some(b)) if t == b => {
                    // Deleted in ours, unchanged in theirs -> deleted
                }
                (Some(o), None, Some(b)) if o == b => {
                    // Deleted in theirs, unchanged in ours -> deleted
                }
                (None, Some(t), None) => {
                    // Added only in theirs
                    result_entries.insert(*target, t);
                }
                (Some(o), None, None) => {
                    // Added only in ours
                    result_entries.insert(*target, o);
                }

                // Conflict: both modified differently, or added differently, or one modified & one deleted
                (ours_opt, theirs_opt, base_opt) => match strategy {
                    NotesMergeStrategy::Manual => {
                        conflicts.push(NotesMergeConflict {
                            target: *target,
                            ours: ours_opt,
                            theirs: theirs_opt,
                            base: base_opt,
                        });
                    }
                    NotesMergeStrategy::Ours => {
                        if let Some(o) = ours_opt {
                            result_entries.insert(*target, o);
                        }
                    }
                    NotesMergeStrategy::Theirs => {
                        if let Some(t) = theirs_opt {
                            result_entries.insert(*target, t);
                        }
                    }
                    NotesMergeStrategy::Union | NotesMergeStrategy::CatSortUniq => {
                        match (ours_opt, theirs_opt) {
                            (Some(o), Some(t)) => {
                                let merged_blob = resolve_blobs(&o, &t, strategy)?;
                                result_entries.insert(*target, merged_blob);
                            }
                            (Some(o), None) => {
                                result_entries.insert(*target, o);
                            }
                            (None, Some(t)) => {
                                result_entries.insert(*target, t);
                            }
                            (None, None) => {}
                        }
                    }
                },
            }
        }

        let merged_tree = Self {
            entries: result_entries,
            fanout_threshold: self.fanout_threshold,
        };

        Ok((merged_tree, conflicts))
    }
}

/// Helper function to perform line-based union or catsortuniq on raw note bytes.
#[must_use]
pub fn merge_note_blob_bytes(
    ours_bytes: &[u8],
    theirs_bytes: &[u8],
    strategy: NotesMergeStrategy,
) -> Vec<u8> {
    match strategy {
        NotesMergeStrategy::Union => {
            // Pinned-oracle byte rule (git-2.54.0, fixtures in
            // scripts/e2e/oracle/notes_corpus.sh): normalize OURS to end
            // with exactly one newline, then append one newline separator,
            // then THEIRS verbatim. Verified byte-exact on both fixture
            // variants (a: both sides end NL -> blank-line junction;
            // b: neither ends NL -> ours gains one, theirs stays raw).
            let mut result = Vec::with_capacity(ours_bytes.len() + theirs_bytes.len() + 2);
            result.extend_from_slice(ours_bytes);
            if !ours_bytes.ends_with(b"\n") {
                result.push(b'\n');
            }
            result.push(b'\n');
            result.extend_from_slice(theirs_bytes);
            result
        }
        NotesMergeStrategy::CatSortUniq => {
            let mut lines = Vec::new();
            for slice in [ours_bytes, theirs_bytes] {
                let mut iter = slice.split(|b| *b == b'\n').peekable();
                while let Some(line) = iter.next() {
                    // Skip the trailing empty slice resulting from a terminal newline
                    if iter.peek().is_none() && line.is_empty() {
                        continue;
                    }
                    lines.push(line);
                }
            }
            lines.sort();
            lines.dedup();

            let mut result = Vec::new();
            for line in lines {
                result.extend_from_slice(line);
                result.push(b'\n');
            }
            result
        }
        NotesMergeStrategy::Ours => ours_bytes.to_vec(),
        NotesMergeStrategy::Theirs => theirs_bytes.to_vec(),
        NotesMergeStrategy::Manual => ours_bytes.to_vec(),
    }
}

/// Emitted tree objects representing a notes tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotesTreeEmission<A: GitHashAlgorithm>
where
    GitOid<A>: Ord,
{
    /// The root notes tree OID.
    pub root_oid: GitOid<A>,
    /// The raw root tree body bytes.
    pub root_tree_body: Vec<u8>,
    /// All tree objects (root and any fanout subtrees) as `(oid, tree_body)`.
    pub all_trees: Vec<(GitOid<A>, Vec<u8>)>,
}

/// Emits the tree objects for a `NotesTree` respecting its fanout threshold.
///
/// When `notes.len() <= threshold`, a single flat tree is emitted.
/// When `notes.len() > threshold`, a 2-hex fanout tree structure is emitted.
pub fn emit_notes_tree<A: GitHashAlgorithm>(
    notes: &NotesTree<A>,
    limits: &ParseLimits,
) -> Result<NotesTreeEmission<A>, NotesError>
where
    GitOid<A>: Ord,
{
    if notes.is_empty() {
        let empty_body = emit_tree(&[], AcceptanceProfile::StrictCreate, limits)?;
        let root_oid = tree_oid_of::<A>(&empty_body);
        return Ok(NotesTreeEmission {
            root_oid,
            root_tree_body: empty_body.clone(),
            all_trees: vec![(root_oid, empty_body)],
        });
    }

    if notes.len() <= notes.fanout_threshold {
        // Flat notes tree: full hex names as leaf entries
        let mut entries = Vec::with_capacity(notes.len());
        for (target, note_blob) in notes.iter() {
            let hex_name = oid_to_hex(target);
            entries.push(TreeEntry {
                mode: b"100644".to_vec(),
                name: hex_name.into_bytes(),
                object_id: note_blob.digest_bytes().to_vec(),
            });
        }
        // Sort entries in canonical Git tree order
        entries.sort_by(crate::compare_tree_entries);
        let root_tree_body = emit_tree(&entries, AcceptanceProfile::StrictCreate, limits)?;
        let root_oid = tree_oid_of::<A>(&root_tree_body);
        return Ok(NotesTreeEmission {
            root_oid,
            root_tree_body: root_tree_body.clone(),
            all_trees: vec![(root_oid, root_tree_body)],
        });
    }

    // 2-hex fanout notes tree
    let mut partitioned: BTreeMap<String, Vec<(String, GitOid<A>)>> = BTreeMap::new();
    for (target, note_blob) in notes.iter() {
        let hex = oid_to_hex(target);
        let prefix = hex[..2].to_string();
        let rest = hex[2..].to_string();
        partitioned
            .entry(prefix)
            .or_default()
            .push((rest, *note_blob));
    }

    let mut all_trees = Vec::new();
    let mut root_entries = Vec::with_capacity(partitioned.len());

    for (prefix, sub_entries) in partitioned {
        let mut tree_entries = Vec::with_capacity(sub_entries.len());
        for (rest_name, blob_oid) in sub_entries {
            tree_entries.push(TreeEntry {
                mode: b"100644".to_vec(),
                name: rest_name.into_bytes(),
                object_id: blob_oid.digest_bytes().to_vec(),
            });
        }
        tree_entries.sort_by(crate::compare_tree_entries);
        let subtree_body = emit_tree(&tree_entries, AcceptanceProfile::StrictCreate, limits)?;
        let subtree_oid = tree_oid_of::<A>(&subtree_body);
        all_trees.push((subtree_oid, subtree_body));

        root_entries.push(TreeEntry {
            mode: b"40000".to_vec(),
            name: prefix.into_bytes(),
            object_id: subtree_oid.digest_bytes().to_vec(),
        });
    }

    root_entries.sort_by(crate::compare_tree_entries);
    let root_tree_body = emit_tree(&root_entries, AcceptanceProfile::StrictCreate, limits)?;
    let root_oid = tree_oid_of::<A>(&root_tree_body);
    all_trees.push((root_oid, root_tree_body.clone()));

    Ok(NotesTreeEmission {
        root_oid,
        root_tree_body,
        all_trees,
    })
}

/// Parses a notes tree recursively, resolving subtrees via the provided `tree_fetcher`.
pub fn parse_notes_tree<A, F>(
    root_tree_body: &[u8],
    profile: AcceptanceProfile,
    limits: &ParseLimits,
    tree_fetcher: F,
) -> Result<NotesTree<A>, NotesError>
where
    A: GitHashAlgorithm,
    GitOid<A>: Ord,
    F: Fn(&GitOid<A>) -> Result<Vec<u8>, NotesError>,
{
    let mut entries = BTreeMap::new();
    let mut stack = vec![(String::new(), root_tree_body.to_vec())];

    while let Some((prefix, tree_bytes)) = stack.pop() {
        let tree_entries = parse_tree(&tree_bytes, profile, limits)?;
        for entry in tree_entries {
            let name_str = std::str::from_utf8(&entry.name).map_err(|_| {
                NotesError::InvalidNotesTreeEntry {
                    reason: "non-utf8 entry name in notes tree".to_string(),
                }
            })?;

            if entry.is_tree() {
                // Subtree fanout directory (e.g. "ab")
                if name_str.len() != 2 || !name_str.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(NotesError::InvalidNotesTreeEntry {
                        reason: format!("invalid fanout directory name '{name_str}'"),
                    });
                }
                let subtree_oid = oid_from_bytes::<A>(&entry.object_id)?;
                let subtree_bytes = tree_fetcher(&subtree_oid)?;
                let next_prefix = format!("{prefix}{name_str}");
                stack.push((next_prefix, subtree_bytes));
            } else {
                // Leaf note entry
                let full_hex = format!("{prefix}{name_str}");
                if full_hex.len() != A::HEX_LEN || !full_hex.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Err(NotesError::InvalidNotesTreeEntry {
                        reason: format!(
                            "note target hex '{full_hex}' does not match algorithm hex length {}",
                            A::HEX_LEN
                        ),
                    });
                }

                let target_oid = oid_from_hex::<A>(&full_hex)?;
                let blob_oid = oid_from_bytes::<A>(&entry.object_id)?;

                if entries.insert(target_oid, blob_oid).is_some() {
                    return Err(NotesError::DuplicateNoteTarget { target: full_hex });
                }
            }
        }
    }

    Ok(NotesTree {
        entries,
        fanout_threshold: DEFAULT_NOTES_FANOUT_THRESHOLD,
    })
}
