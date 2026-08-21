//! Immutable workspace snapshots and the three publication epochs.
//!
//! `docs/GIT_TREE_FS.md` §2 and §6. A snapshot is immutable; a mutable session
//! points at its latest snapshot through a local anti-rollback record.
//!
//! # The epoch invariant
//!
//! ```text
//! staged >= visible >= durable
//! ```
//!
//! These are three separate facts and are never conflated
//! (AGENTS.md §5.4): a body existing, a reader being able to observe it, and
//! the declared durability profile holding are different claims. [`EpochSet`]
//! makes the invariant unrepresentable-if-violated by refusing every transition
//! that would break it, rather than checking after the fact.
//!
//! # Anti-rollback
//!
//! A session advances to a strictly newer snapshot or refuses. Silently
//! accepting an older-but-valid snapshot is the rollback failure AGENTS.md §5.5
//! forbids: the snapshot would verify perfectly and still lose acknowledged
//! work.

use crate::capability::WorkspaceId;
use crate::overlay::Overlay;
use core::fmt::{self, Display, Formatter};
use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, GitOid, NativeObjectIdentity, Sha256};
use fgit_types::{CodecVersion, RepositoryCommitId, RepositoryId, SchemaFamily, SchemaId};

/// A monotone workspace epoch counter.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkspaceEpoch(u64);

impl WorkspaceEpoch {
    /// The zero epoch, before anything is staged.
    pub const ZERO: Self = Self(0);

    /// Wraps a raw counter.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// The raw counter.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next epoch.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl Display for WorkspaceEpoch {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Why an epoch transition was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochRefusal {
    /// Publishing would make `visible` exceed `staged`.
    VisibleAheadOfStaged {
        /// Proposed visible epoch.
        visible: WorkspaceEpoch,
        /// Current staged epoch.
        staged: WorkspaceEpoch,
    },
    /// Syncing would make `durable` exceed `visible`.
    DurableAheadOfVisible {
        /// Proposed durable epoch.
        durable: WorkspaceEpoch,
        /// Current visible epoch.
        visible: WorkspaceEpoch,
    },
    /// An epoch would move backwards.
    NonMonotone {
        /// The epoch it holds now.
        current: WorkspaceEpoch,
        /// The epoch that was proposed.
        proposed: WorkspaceEpoch,
    },
}

impl Display for EpochRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::VisibleAheadOfStaged { visible, staged } => write!(
                formatter,
                "visible epoch {visible} would exceed staged epoch {staged}"
            ),
            Self::DurableAheadOfVisible { durable, visible } => write!(
                formatter,
                "durable epoch {durable} would exceed visible epoch {visible}"
            ),
            Self::NonMonotone { current, proposed } => {
                write!(
                    formatter,
                    "epoch would move from {current} back to {proposed}"
                )
            }
        }
    }
}

impl core::error::Error for EpochRefusal {}

/// The three publication epochs of one workspace.
///
/// Every mutator preserves `staged >= visible >= durable`, so a violating state
/// cannot be constructed through the public API at all.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EpochSet {
    staged: WorkspaceEpoch,
    visible: WorkspaceEpoch,
    durable: WorkspaceEpoch,
}

impl EpochSet {
    /// A fresh set, all zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            staged: WorkspaceEpoch::ZERO,
            visible: WorkspaceEpoch::ZERO,
            durable: WorkspaceEpoch::ZERO,
        }
    }

    /// Builds a set, refusing any combination that violates the invariant.
    pub const fn try_new(
        staged: WorkspaceEpoch,
        visible: WorkspaceEpoch,
        durable: WorkspaceEpoch,
    ) -> Result<Self, EpochRefusal> {
        if visible.0 > staged.0 {
            return Err(EpochRefusal::VisibleAheadOfStaged { visible, staged });
        }
        if durable.0 > visible.0 {
            return Err(EpochRefusal::DurableAheadOfVisible { durable, visible });
        }
        Ok(Self {
            staged,
            visible,
            durable,
        })
    }

    /// The staged epoch: a body exists in the session or staging store.
    #[must_use]
    pub const fn staged(self) -> WorkspaceEpoch {
        self.staged
    }

    /// The visible epoch: subsequent workspace reads observe it.
    #[must_use]
    pub const fn visible(self) -> WorkspaceEpoch {
        self.visible
    }

    /// The durable epoch: the declared crash model holds for it.
    #[must_use]
    pub const fn durable(self) -> WorkspaceEpoch {
        self.durable
    }

    /// Whether the invariant holds. Always true for a value built here; used by
    /// tests to assert the type cannot be talked into violating it.
    #[must_use]
    pub const fn invariant_holds(self) -> bool {
        self.staged.0 >= self.visible.0 && self.visible.0 >= self.durable.0
    }

    /// Stages new work, advancing only `staged`.
    #[must_use]
    pub const fn stage(mut self) -> Self {
        self.staged = self.staged.next();
        self
    }

    /// Publishes staged work so readers observe it.
    ///
    /// Advances `visible` to `staged` and never past it.
    pub const fn publish(mut self) -> Result<Self, EpochRefusal> {
        if self.visible.0 > self.staged.0 {
            return Err(EpochRefusal::VisibleAheadOfStaged {
                visible: self.visible,
                staged: self.staged,
            });
        }
        self.visible = self.staged;
        Ok(self)
    }

    /// Makes visible work durable.
    ///
    /// Advances `durable` to `visible` and never past it. Syncing what is not
    /// yet visible is refused rather than quietly clamped, because a caller who
    /// asked for that has a bug worth surfacing.
    pub const fn sync(mut self) -> Result<Self, EpochRefusal> {
        if self.durable.0 > self.visible.0 {
            return Err(EpochRefusal::DurableAheadOfVisible {
                durable: self.durable,
                visible: self.visible,
            });
        }
        self.durable = self.visible;
        Ok(self)
    }
}

/// A digest over overlay state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OverlayRoot([u8; 32]);

impl OverlayRoot {
    /// Computes the root of an overlay.
    ///
    /// The preimage walks entries in canonical path order and includes each
    /// entry's kind, mode, class and content identity. Ordering is by path, not
    /// by map iteration, so the root is identical across processes — which is
    /// what lets a snapshot golden be a real golden.
    #[must_use]
    pub fn of(overlay: &Overlay) -> Self {
        let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
        hasher.update(b"frankengit.treefs.overlay-root.v1\0");
        for (path, entry) in overlay.entries() {
            hasher.update(&(path.as_bytes().len() as u64).to_be_bytes());
            hasher.update(path.as_bytes());
            hasher.update(&[entry_tag(entry)]);
            if let Some(id) = entry.content_id() {
                hasher.update(id.as_bytes());
            } else {
                hasher.update(&[0_u8; 32]);
            }
            match entry {
                crate::overlay::OverlayEntry::File { mode, class, .. } => {
                    hasher.update(mode.as_octal_bytes());
                    match class {
                        crate::overlay::EntryClass::Content => hasher.update(&[0]),
                        crate::overlay::EntryClass::Generated { producer } => {
                            hasher.update(&[1]);
                            hasher.update(&(producer.len() as u64).to_be_bytes());
                            hasher.update(producer);
                        }
                    }
                }
                crate::overlay::OverlayEntry::Submodule { commit } => {
                    hasher.update(&(commit.len() as u64).to_be_bytes());
                    hasher.update(commit);
                }
                crate::overlay::OverlayEntry::Conflict { inputs, .. } => {
                    hasher.update(&(inputs.len() as u64).to_be_bytes());
                    for input in inputs {
                        hasher.update(&(input.len() as u64).to_be_bytes());
                        hasher.update(input);
                    }
                }
                crate::overlay::OverlayEntry::Symlink { .. }
                | crate::overlay::OverlayEntry::Directory
                | crate::overlay::OverlayEntry::Whiteout => {}
            }
        }
        let digest = hasher.finish();
        let mut out = [0_u8; 32];
        out.copy_from_slice(digest.as_ref());
        Self(out)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for OverlayRoot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

const fn entry_tag(entry: &crate::overlay::OverlayEntry) -> u8 {
    match entry {
        crate::overlay::OverlayEntry::File { .. } => 1,
        crate::overlay::OverlayEntry::Symlink { .. } => 2,
        crate::overlay::OverlayEntry::Directory => 3,
        crate::overlay::OverlayEntry::Whiteout => 4,
        crate::overlay::OverlayEntry::Submodule { .. } => 5,
        crate::overlay::OverlayEntry::Conflict { .. } => 6,
    }
}

/// An immutable workspace snapshot.
///
/// Every field is read-only after construction. There is no setter and no
/// interior mutability, so a handed-out snapshot cannot change under its
/// holder — the property that lets a tool receive a snapshot receipt instead of
/// a path whose contents may shift invisibly (`docs/GIT_TREE_FS.md` §2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceSnapshotBody<A: GitHashAlgorithm> {
    workspace_id: WorkspaceId,
    repository_id: RepositoryId,
    base_rcr_id: RepositoryCommitId,
    base_commit_oid: GitOid<A>,
    base_tree_oid: GitOid<A>,
    overlay_root: OverlayRoot,
    epochs: EpochSet,
}

impl<A: GitHashAlgorithm> WorkspaceSnapshotBody<A> {
    /// The schema this body encodes under.
    pub const SCHEMA: SchemaId = SchemaId::new(
        SchemaFamily::from_static("frankengit.treefs.snapshot"),
        1,
        0,
    );
    /// The codec version this body encodes under.
    pub const CODEC_VERSION: CodecVersion = CodecVersion::new(1, 0);

    /// Builds a snapshot.
    #[must_use]
    pub const fn new(
        workspace_id: WorkspaceId,
        repository_id: RepositoryId,
        base_rcr_id: RepositoryCommitId,
        base_commit_oid: GitOid<A>,
        base_tree_oid: GitOid<A>,
        overlay_root: OverlayRoot,
        epochs: EpochSet,
    ) -> Self {
        Self {
            workspace_id,
            repository_id,
            base_rcr_id,
            base_commit_oid,
            base_tree_oid,
            overlay_root,
            epochs,
        }
    }

    /// The workspace identity.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// The repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// The canonical RCR this snapshot's base is pinned to.
    #[must_use]
    pub const fn base_rcr_id(&self) -> RepositoryCommitId {
        self.base_rcr_id
    }

    /// The pinned base commit.
    #[must_use]
    pub const fn base_commit_oid(&self) -> &GitOid<A> {
        &self.base_commit_oid
    }

    /// The pinned base tree.
    #[must_use]
    pub const fn base_tree_oid(&self) -> &GitOid<A> {
        &self.base_tree_oid
    }

    /// The overlay root digest.
    #[must_use]
    pub const fn overlay_root(&self) -> OverlayRoot {
        self.overlay_root
    }

    /// The three epochs.
    #[must_use]
    pub const fn epochs(&self) -> EpochSet {
        self.epochs
    }

    /// The canonical bytes a golden is taken over.
    ///
    /// Encoded with `fgit-codec`'s [`Encoder`], not a framing of this crate's
    /// own. ADR-0002 puts canonical encoding under one owner, and a second
    /// hand-rolled framing here would be exactly the divergence that makes two
    /// components disagree about what a snapshot *is* while both look correct.
    /// Every variable-length field goes through a length-prefixing writer, so
    /// the encoding is unambiguous.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CodecRefusal> {
        let mut encoder = Encoder::with_capacity(192);
        encoder.write_schema_id(Self::SCHEMA)?;
        encoder.write_codec_version(Self::CODEC_VERSION);
        encoder.write_opaque_id(self.workspace_id.as_bytes());
        encoder.write_opaque_id(self.repository_id.as_bytes());
        encoder.write_internal_object_id(self.base_rcr_id.as_internal_object_id())?;
        encoder.write_git_oid(&self.base_commit_oid.erase());
        encoder.write_git_oid(&self.base_tree_oid.erase());
        encoder.write_bytes("OverlayRoot", self.overlay_root.as_bytes())?;
        encoder.write_scalar(self.epochs.staged().get());
        encoder.write_scalar(self.epochs.visible().get());
        encoder.write_scalar(self.epochs.durable().get());
        Ok(encoder.into_bytes())
    }

    /// The snapshot's content identity, over [`Self::canonical_bytes`].
    pub fn snapshot_digest(&self) -> Result<[u8; 32], CodecRefusal> {
        let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
        hasher.update(&self.canonical_bytes()?);
        let digest = hasher.finish();
        let mut out = [0_u8; 32];
        out.copy_from_slice(digest.as_ref());
        Ok(out)
    }
}

/// Why a session refused to adopt a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AntiRollbackRefusal {
    /// The proposed snapshot is not strictly newer.
    NotNewer {
        /// The staged epoch the session already holds.
        current_staged: WorkspaceEpoch,
        /// The staged epoch that was proposed.
        proposed_staged: WorkspaceEpoch,
    },
    /// The proposed snapshot belongs to a different workspace.
    WorkspaceMismatch,
    /// The proposed snapshot is pinned to a different base.
    BaseMismatch,
    /// The proposed snapshot violates the epoch invariant.
    Epoch(EpochRefusal),
}

impl Display for AntiRollbackRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNewer {
                current_staged,
                proposed_staged,
            } => write!(
                formatter,
                "refusing rollback: session holds staged {current_staged}, offered {proposed_staged}"
            ),
            Self::WorkspaceMismatch => write!(formatter, "snapshot is for another workspace"),
            Self::BaseMismatch => write!(formatter, "snapshot is pinned to another base"),
            Self::Epoch(inner) => write!(formatter, "{inner}"),
        }
    }
}

impl core::error::Error for AntiRollbackRefusal {}

/// The local anti-rollback authority record for a mutable session.
///
/// Holds the latest adopted snapshot and refuses to move backwards. A snapshot
/// that verifies perfectly but is older is still refused: verification proves
/// integrity, never recency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord<A: GitHashAlgorithm> {
    workspace_id: WorkspaceId,
    latest: WorkspaceSnapshotBody<A>,
    adopted_count: u64,
}

impl<A: GitHashAlgorithm> SessionRecord<A> {
    /// Opens a session at an initial snapshot.
    #[must_use]
    pub const fn open(initial: WorkspaceSnapshotBody<A>) -> Self {
        Self {
            workspace_id: initial.workspace_id,
            latest: initial,
            adopted_count: 1,
        }
    }

    /// The latest adopted snapshot.
    #[must_use]
    pub const fn latest(&self) -> &WorkspaceSnapshotBody<A> {
        &self.latest
    }

    /// How many snapshots this session has adopted.
    #[must_use]
    pub const fn adopted_count(&self) -> u64 {
        self.adopted_count
    }

    /// Adopts a strictly newer snapshot of the same workspace and base.
    pub fn adopt(&mut self, proposed: WorkspaceSnapshotBody<A>) -> Result<(), AntiRollbackRefusal> {
        if proposed.workspace_id != self.workspace_id {
            return Err(AntiRollbackRefusal::WorkspaceMismatch);
        }
        if proposed.base_rcr_id != self.latest.base_rcr_id
            || proposed.base_tree_oid != self.latest.base_tree_oid
        {
            return Err(AntiRollbackRefusal::BaseMismatch);
        }
        if !proposed.epochs.invariant_holds() {
            return Err(AntiRollbackRefusal::Epoch(
                EpochRefusal::VisibleAheadOfStaged {
                    visible: proposed.epochs.visible(),
                    staged: proposed.epochs.staged(),
                },
            ));
        }
        if proposed.epochs.staged().get() <= self.latest.epochs.staged().get() {
            return Err(AntiRollbackRefusal::NotNewer {
                current_staged: self.latest.epochs.staged(),
                proposed_staged: proposed.epochs.staged(),
            });
        }
        self.latest = proposed;
        self.adopted_count = self.adopted_count.saturating_add(1);
        Ok(())
    }
}
