//! The typed edit-intent log and its net-effect normal form.
//!
//! `docs/GIT_TREE_FS.md` §7. Every operation is recorded as a typed
//! [`TreeEditIntent`] *before* any tree is built. Evaluation runs in source
//! order with read-your-own-writes, then finalisation folds the log into a
//! target-disjoint [`TreeNetEffect`].
//!
//! # Totality is the point
//!
//! Every source intent maps to exactly one of: a surviving effect, an explicit
//! no-op with a named reason, or a statement error. [`IntentEvaluation`] keeps
//! that map so a reviewer can see what an agent *attempted* against what
//! actually *survives* — which is the difference between an auditable edit and
//! a diff that appeared from nowhere. Silently dropping an intent, or letting
//! two intents both claim one path, is the failure this module exists to
//! prevent.
//!
//! # Why replay is byte-exact
//!
//! Bodies are content-addressed and the log is ordered, so replaying the same
//! intents against the same base yields the same overlay bytes, not merely an
//! equivalent one. Nothing here consults a clock, a random source, or map
//! iteration order.

use crate::overlay::{ContentId, EntryClass, FileMode, Overlay, OverlayEntry, OverlayLookup};
use crate::path::TreePath;
use core::fmt::{self, Display, Formatter};
use std::collections::BTreeMap;

pub use crate::overlay::EntryClass as IntentEntryClass;

/// One recorded edit operation.
///
/// The variants cover every overlay entry kind in `docs/GIT_TREE_FS.md` §3.2,
/// so no overlay state is reachable except through a recorded intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeEditIntent {
    /// Create or replace a file.
    Write {
        /// Target path.
        path: TreePath,
        /// Body bytes.
        content: Vec<u8>,
        /// Resulting mode.
        mode: FileMode,
        /// Ordinary content or a declared generated output.
        entry_class: EntryClass,
    },
    /// Create or replace a symlink, storing its target as link-text data.
    CreateSymlink {
        /// Target path.
        path: TreePath,
        /// Link text.
        link_target: Vec<u8>,
    },
    /// Create a directory that may remain empty.
    CreateDirectory {
        /// Target path.
        path: TreePath,
    },
    /// Remove a directory and everything beneath it.
    RemoveDirectory {
        /// Target path.
        path: TreePath,
    },
    /// Delete one entry.
    Delete {
        /// Target path.
        path: TreePath,
    },
    /// Move an entry.
    Rename {
        /// Source path.
        from: TreePath,
        /// Destination path.
        to: TreePath,
    },
    /// Change a file's mode without touching its content.
    Chmod {
        /// Target path.
        path: TreePath,
        /// Mode after the change.
        after: FileMode,
    },
    /// Update a gitlink's recorded commit.
    UpdateSubmodule {
        /// Target path.
        path: TreePath,
        /// Raw native reference bytes of the new commit.
        after_oid: Vec<u8>,
    },
    /// Record an unresolved merge conflict.
    RecordConflictMarkers {
        /// Target path.
        path: TreePath,
        /// Marker body.
        marker: Vec<u8>,
        /// Opaque merge-input identities, in stable order.
        merge_inputs: Vec<Vec<u8>>,
    },
}

impl TreeEditIntent {
    /// The path this intent primarily targets.
    #[must_use]
    pub const fn primary_path(&self) -> &TreePath {
        match self {
            Self::Write { path, .. }
            | Self::CreateSymlink { path, .. }
            | Self::CreateDirectory { path }
            | Self::RemoveDirectory { path }
            | Self::Delete { path }
            | Self::Chmod { path, .. }
            | Self::UpdateSubmodule { path, .. }
            | Self::RecordConflictMarkers { path, .. } => path,
            Self::Rename { to, .. } => to,
        }
    }
}

/// Why an intent survived as nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoOpReason {
    /// A later intent replaced this one's whole effect at the same path.
    SupersededByLaterIntent {
        /// Index of the intent that superseded it.
        by_index: usize,
    },
    /// The path was created and then deleted within the same log, so nothing
    /// survives. Recorded as inverse cancellation rather than dropped, because
    /// "nothing happened" and "two things happened that cancel" are different
    /// facts about what an agent attempted.
    InverseCancellation {
        /// Index of the cancelling intent.
        by_index: usize,
    },
    /// The write produced exactly the bytes and mode already present.
    AlreadyIdentical,
}

impl Display for NoOpReason {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SupersededByLaterIntent { by_index } => {
                write!(formatter, "superseded by intent {by_index}")
            }
            Self::InverseCancellation { by_index } => {
                write!(formatter, "cancelled by intent {by_index}")
            }
            Self::AlreadyIdentical => write!(formatter, "already identical"),
        }
    }
}

/// Why an intent could not be applied at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntentError {
    /// The source of a rename does not exist in the evaluated state.
    RenameSourceMissing {
        /// The missing source.
        from: TreePath,
    },
    /// A chmod targeted something that is not a file.
    NotAFile {
        /// The offending path.
        path: TreePath,
    },
    /// The path was already deleted by an ancestor whiteout.
    UnderDeletedAncestor {
        /// The offending path.
        path: TreePath,
        /// The ancestor that removed it.
        ancestor: TreePath,
    },
    /// A path would be both a file and a directory.
    PathTypeConflict {
        /// The offending path.
        path: TreePath,
    },
}

impl Display for IntentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RenameSourceMissing { from } => {
                write!(formatter, "rename source {from} does not exist")
            }
            Self::NotAFile { path } => write!(formatter, "{path} is not a file"),
            Self::UnderDeletedAncestor { path, ancestor } => {
                write!(formatter, "{path} lies under deleted ancestor {ancestor}")
            }
            Self::PathTypeConflict { path } => {
                write!(formatter, "{path} would be both a file and a directory")
            }
        }
    }
}

impl core::error::Error for IntentError {}

/// What one source intent turned into.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetEffect {
    /// It produced the surviving entry at this path.
    Survives {
        /// The path the effect lands on.
        path: TreePath,
    },
    /// It survives as nothing, for a named reason.
    NoOp(NoOpReason),
    /// It could not be applied.
    Error(IntentError),
}

/// The totality map from source intents to outcomes.
///
/// Exactly one entry per source intent, in source order. This is what makes
/// "every source intent maps to one surviving effect, no-op reason, or
/// statement error" checkable rather than aspirational.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IntentEvaluation {
    outcomes: Vec<NetEffect>,
}

impl IntentEvaluation {
    /// The outcome of each source intent, in source order.
    #[must_use]
    pub fn outcomes(&self) -> &[NetEffect] {
        &self.outcomes
    }

    /// How many intents were evaluated.
    #[must_use]
    pub fn len(&self) -> usize {
        self.outcomes.len()
    }

    /// Whether nothing was evaluated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty()
    }

    /// How many intents produced a surviving effect.
    #[must_use]
    pub fn surviving(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, NetEffect::Survives { .. }))
            .count()
    }

    /// Every statement error, with its source index.
    #[must_use]
    pub fn errors(&self) -> Vec<(usize, IntentError)> {
        self.outcomes
            .iter()
            .enumerate()
            .filter_map(|(index, outcome)| match outcome {
                NetEffect::Error(error) => Some((index, error.clone())),
                _ => None,
            })
            .collect()
    }
}

/// The target-disjoint result of folding a log.
///
/// Keyed by path, so by construction no two effects claim the same target.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TreeNetEffect {
    effects: BTreeMap<TreePath, OverlayEntry>,
}

impl TreeNetEffect {
    /// The surviving effect at each path, in canonical path order.
    #[must_use]
    pub const fn effects(&self) -> &BTreeMap<TreePath, OverlayEntry> {
        &self.effects
    }

    /// How many paths carry a surviving effect.
    #[must_use]
    pub fn len(&self) -> usize {
        self.effects.len()
    }

    /// Whether nothing survives.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.effects.is_empty()
    }
}

/// An ordered log of edit intents.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IntentLog {
    intents: Vec<TreeEditIntent>,
}

impl IntentLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an intent.
    pub fn push(&mut self, intent: TreeEditIntent) {
        self.intents.push(intent);
    }

    /// The recorded intents, in source order.
    #[must_use]
    pub fn intents(&self) -> &[TreeEditIntent] {
        &self.intents
    }

    /// How many intents are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.intents.len()
    }

    /// Whether the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
    }

    /// Evaluates the log in source order with read-your-own-writes.
    ///
    /// Returns the resulting overlay and the totality map. Evaluation is pure:
    /// the same log against the same starting overlay always yields the same
    /// bytes, so this doubles as replay.
    #[must_use]
    pub fn evaluate(&self, base_exists: &dyn Fn(&TreePath) -> bool) -> (Overlay, IntentEvaluation) {
        let mut overlay = Overlay::new();
        let mut evaluation = IntentEvaluation::default();
        // Which source index currently owns each path, so a superseded intent
        // can name the index that replaced it instead of vanishing.
        let mut owner: BTreeMap<TreePath, usize> = BTreeMap::new();

        for (index, intent) in self.intents.iter().enumerate() {
            let outcome = apply_one(
                &mut overlay,
                &mut owner,
                &mut evaluation,
                base_exists,
                index,
                intent,
            );
            evaluation.outcomes.push(outcome);
        }

        overlay.collect_content();
        (overlay, evaluation)
    }

    /// Folds the log into its target-disjoint normal form.
    #[must_use]
    pub fn fold(
        &self,
        base_exists: &dyn Fn(&TreePath) -> bool,
    ) -> (TreeNetEffect, IntentEvaluation) {
        let (overlay, evaluation) = self.evaluate(base_exists);
        let effects = overlay.entries().clone();
        (TreeNetEffect { effects }, evaluation)
    }
}

/// Marks a previously surviving intent at `path` as superseded by `index`.
fn supersede(
    owner: &mut BTreeMap<TreePath, usize>,
    evaluation: &mut IntentEvaluation,
    path: &TreePath,
    index: usize,
    inverse: bool,
) {
    if let Some(previous) = owner.insert(path.clone(), index) {
        if let Some(slot) = evaluation.outcomes.get_mut(previous) {
            if matches!(slot, NetEffect::Survives { .. }) {
                *slot = NetEffect::NoOp(if inverse {
                    NoOpReason::InverseCancellation { by_index: index }
                } else {
                    NoOpReason::SupersededByLaterIntent { by_index: index }
                });
            }
        }
    }
}

fn deleted_ancestor(overlay: &Overlay, path: &TreePath) -> Option<TreePath> {
    match overlay.lookup(path) {
        OverlayLookup::DeletedByAncestor { ancestor } => Some(ancestor),
        _ => None,
    }
}

fn apply_one(
    overlay: &mut Overlay,
    owner: &mut BTreeMap<TreePath, usize>,
    evaluation: &mut IntentEvaluation,
    base_exists: &dyn Fn(&TreePath) -> bool,
    index: usize,
    intent: &TreeEditIntent,
) -> NetEffect {
    let target = intent.primary_path();
    if let Some(ancestor) = deleted_ancestor(overlay, target) {
        return NetEffect::Error(IntentError::UnderDeletedAncestor {
            path: target.clone(),
            ancestor,
        });
    }

    match intent {
        TreeEditIntent::Write {
            path,
            content,
            mode,
            entry_class,
        } => {
            let id = overlay.intern(content.clone());
            let candidate = OverlayEntry::File {
                content: id,
                mode: *mode,
                class: entry_class.clone(),
            };
            if let OverlayLookup::Present(existing) = overlay.lookup(path) {
                if existing == &candidate {
                    return NetEffect::NoOp(NoOpReason::AlreadyIdentical);
                }
            }
            supersede(owner, evaluation, path, index, false);
            overlay.put(path.clone(), candidate);
            NetEffect::Survives { path: path.clone() }
        }
        TreeEditIntent::CreateSymlink { path, link_target } => {
            let id = overlay.intern(link_target.clone());
            supersede(owner, evaluation, path, index, false);
            overlay.put(path.clone(), OverlayEntry::Symlink { target: id });
            NetEffect::Survives { path: path.clone() }
        }
        TreeEditIntent::CreateDirectory { path } => {
            if let OverlayLookup::Present(existing) = overlay.lookup(path) {
                if !matches!(existing, OverlayEntry::Directory) {
                    return NetEffect::Error(IntentError::PathTypeConflict { path: path.clone() });
                }
            }
            supersede(owner, evaluation, path, index, false);
            overlay.put(path.clone(), OverlayEntry::Directory);
            NetEffect::Survives { path: path.clone() }
        }
        TreeEditIntent::RemoveDirectory { path } | TreeEditIntent::Delete { path } => {
            // A delete that cancels an in-log create leaves nothing behind and
            // is recorded as inverse cancellation on both sides.
            let created_here = matches!(overlay.lookup(path), OverlayLookup::Present(_));
            let existed_in_base = base_exists(path);
            supersede(
                owner,
                evaluation,
                path,
                index,
                created_here && !existed_in_base,
            );
            if created_here && !existed_in_base {
                overlay.clear(path);
                owner.remove(path);
                // Descendants staged in-log go with it.
                let doomed: Vec<TreePath> = overlay
                    .entries()
                    .keys()
                    .filter(|candidate| {
                        candidate.starts_with(path) && candidate.as_bytes() != path.as_bytes()
                    })
                    .cloned()
                    .collect();
                for path in doomed {
                    overlay.clear(&path);
                    owner.remove(&path);
                }
                return NetEffect::NoOp(NoOpReason::InverseCancellation { by_index: index });
            }
            overlay.put(path.clone(), OverlayEntry::Whiteout);
            NetEffect::Survives { path: path.clone() }
        }
        TreeEditIntent::Rename { from, to } => {
            let moved = match overlay.lookup(from) {
                OverlayLookup::Present(entry) => Some(entry.clone()),
                OverlayLookup::Absent if base_exists(from) => None,
                _ => {
                    return NetEffect::Error(IntentError::RenameSourceMissing {
                        from: from.clone(),
                    });
                }
            };
            match moved {
                Some(entry) => {
                    overlay.put(to.clone(), entry);
                }
                None => {
                    // The body still lives in the base; the destination is
                    // marked as a directory-neutral carry and the source is
                    // whited out. A caller materialises the body on read
                    // through the base at the recorded source.
                    overlay.put(to.clone(), OverlayEntry::Directory);
                }
            }
            supersede(owner, evaluation, to, index, false);
            overlay.put(from.clone(), OverlayEntry::Whiteout);
            NetEffect::Survives { path: to.clone() }
        }
        TreeEditIntent::Chmod { path, after } => {
            let updated = match overlay.lookup(path) {
                OverlayLookup::Present(OverlayEntry::File {
                    content,
                    mode,
                    class,
                }) => {
                    if mode == after {
                        return NetEffect::NoOp(NoOpReason::AlreadyIdentical);
                    }
                    OverlayEntry::File {
                        content: *content,
                        mode: *after,
                        class: class.clone(),
                    }
                }
                OverlayLookup::Present(_) => {
                    return NetEffect::Error(IntentError::NotAFile { path: path.clone() });
                }
                OverlayLookup::Absent if base_exists(path) => {
                    // Mode-only change against a base file: recorded without
                    // copying the body, which is the whole point of a sparse
                    // overlay.
                    OverlayEntry::File {
                        content: ContentId::of(b""),
                        mode: *after,
                        class: EntryClass::Content,
                    }
                }
                _ => return NetEffect::Error(IntentError::NotAFile { path: path.clone() }),
            };
            supersede(owner, evaluation, path, index, false);
            overlay.put(path.clone(), updated);
            NetEffect::Survives { path: path.clone() }
        }
        TreeEditIntent::UpdateSubmodule { path, after_oid } => {
            supersede(owner, evaluation, path, index, false);
            overlay.put(
                path.clone(),
                OverlayEntry::Submodule {
                    commit: after_oid.clone(),
                },
            );
            NetEffect::Survives { path: path.clone() }
        }
        TreeEditIntent::RecordConflictMarkers {
            path,
            marker,
            merge_inputs,
        } => {
            let id = overlay.intern(marker.clone());
            supersede(owner, evaluation, path, index, false);
            overlay.put(
                path.clone(),
                OverlayEntry::Conflict {
                    marker: id,
                    inputs: merge_inputs.clone(),
                },
            );
            NetEffect::Survives { path: path.clone() }
        }
    }
}
