//! The atomic merge path: compute under supervision, refuse when stale, and
//! reduce the whole effect to one commit record.

use fgit_codec::attest::{BodyIdentity, body_id};
use fgit_codec::schema::RepositoryCommitRecord;
use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_diff::{TreeEntry, TreeMergeEntry, TreeMergeOptions, merge_trees};
use fgit_treefs::WorkspaceEpoch;
use fgit_types::{
    Digest, DomainTag, GitOid, PolicyEpoch, PrincipalSnapshotId, RepositoryCommitId, RepositoryId,
    RepositorySequence, SchemaFamily, TxId,
};

use crate::aggregate::PullRequestNumber;
use crate::event::{ForgeEvent, ForgeEventBatch};
use crate::{ForgeRefusal, MergeSide, StaleTips};

/// A conditional ref movement.
///
/// The expected tip is part of the intent rather than a separate check so the
/// condition travels with the effect. An intent that carried only the new tip
/// would be a last-writer-wins ref write wearing a transaction's clothes.
///
/// # Why this is not `fgit-admission`'s `CanonicalRefDelta`
///
/// It used to claim that body's identity, and the two are genuinely different
/// shapes: this is one ref with the tip it is conditional on -- what a merge
/// *requests* -- while a canonical ref delta is the surviving net effect over
/// every ref a transaction moved, which is what a decision *published*. A
/// request that gets refused produces no delta at all.
///
/// Sharing `frankengit/admission-ref-delta/v1` made both decodable in one
/// identity space, so a reader holding a digest could not tell which body shape
/// it named. Section 5.2 requires exactly that case to fail closed, so the
/// intent has its own domain and the delta keeps the original.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefIntent {
    /// Full reference name.
    pub name: Vec<u8>,
    /// Tip this movement is conditional on.
    pub expected_tip: GitOid,
    /// Tip the reference takes if the condition holds.
    pub new_tip: GitOid,
}

impl CanonicalBody for RefIntent {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/forge-ref-intent/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("forge-ref-intent");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_bytes("name", &self.name)?;
        out.write_git_oid(&self.expected_tip);
        out.write_git_oid(&self.new_tip);
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self {
            name: input.read_bytes("name")?.to_vec(),
            expected_tip: input.read_git_oid()?,
            new_tip: input.read_git_oid()?,
        })
    }
}

/// A merge computation pinned to the state it was computed against.
///
/// The workspace epoch is carried because the merge is supervised: the result
/// is only meaningful as a statement about one workspace at one epoch, and a
/// result that cannot name where it was produced cannot be audited later.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeAttempt {
    /// The aggregate being merged.
    pub pull_request: PullRequestNumber,
    /// Branch being merged from.
    pub source_ref: Vec<u8>,
    /// Branch being merged into.
    pub target_ref: Vec<u8>,
    /// Source tip the merge was computed against.
    pub source_tip: GitOid,
    /// Target tip the merge was computed against.
    pub target_tip: GitOid,
    /// Merge base used for the three-way computation.
    pub base_tip: GitOid,
    /// Workspace epoch the computation ran in.
    pub workspace_epoch: WorkspaceEpoch,
}

/// The state actually observed when the effect is about to be admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedTips {
    /// Source tip right now.
    pub source_tip: GitOid,
    /// Target tip right now.
    pub target_tip: GitOid,
    /// Workspace epoch right now.
    pub workspace_epoch: WorkspaceEpoch,
}

impl MergeAttempt {
    /// Refuses when anything the merge was computed against has moved.
    ///
    /// Three axes, checked in a fixed order so the refusal is deterministic
    /// when more than one has moved: source ref, target ref, then the
    /// workspace the computation ran in. A moved source means the merge
    /// produced a tree for content nobody asked to merge; a moved target means
    /// it produced a tree against a base that is no longer the target's state;
    /// a moved workspace means the tree was computed over content the
    /// workspace no longer holds. None is repairable by retrying the admission
    /// with the same result, which is why each is a refusal and not a conflict.
    ///
    /// The workspace axis is what makes the epoch a binding rather than a
    /// label. Recorded and never read, it would be a decorative dependency:
    /// deleting the field would break no test and change no decision.
    ///
    /// # Errors
    ///
    /// [`ForgeRefusal::MergeStale`] naming which ref moved, or
    /// [`ForgeRefusal::WorkspaceMoved`] when the workspace advanced.
    pub fn check_fresh(&self, observed: &ObservedTips) -> Result<(), ForgeRefusal> {
        if observed.source_tip != self.source_tip {
            return Err(ForgeRefusal::MergeStale {
                reference: MergeSide::Source,
                tips: StaleTips {
                    computed_against: self.source_tip,
                    observed: observed.source_tip,
                },
            });
        }
        if observed.target_tip != self.target_tip {
            return Err(ForgeRefusal::MergeStale {
                reference: MergeSide::Target,
                tips: StaleTips {
                    computed_against: self.target_tip,
                    observed: observed.target_tip,
                },
            });
        }
        if observed.workspace_epoch != self.workspace_epoch {
            return Err(ForgeRefusal::WorkspaceMoved {
                computed_in: self.workspace_epoch,
                observed: observed.workspace_epoch,
            });
        }
        Ok(())
    }
}

/// A fully clean merged tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergedTree {
    /// The merged entries, in Git tree order.
    pub entries: Vec<TreeEntry<GitOid>>,
}

/// Runs the three-way tree merge and admits only a fully clean result.
///
/// `fgit-diff` returns clean entries and conflicts together, as proposals with
/// no authority side effect. This is where that proposal becomes a decision:
/// any conflict at all is a typed refusal, because a partially merged tree has
/// no meaning as a commit. Resolving conflicts is a separate act by a principal
/// who can be held to it, not something the merge path may do on their behalf.
///
/// # Errors
///
/// [`ForgeRefusal::MergeConflicted`] when any path conflicts, and
/// [`ForgeRefusal::MergeRefused`] when the engine declines outright.
pub fn merge_pull_request_tree<Base, Ours, Theirs>(
    base: Base,
    ours: Ours,
    theirs: Theirs,
    options: TreeMergeOptions,
) -> Result<MergedTree, ForgeRefusal>
where
    Base: IntoIterator<Item = TreeEntry<GitOid>>,
    Ours: IntoIterator<Item = TreeEntry<GitOid>>,
    Theirs: IntoIterator<Item = TreeEntry<GitOid>>,
{
    let merged = merge_trees(base, ours, theirs, options)
        .map_err(|cause| ForgeRefusal::MergeRefused { cause })?;
    let conflicts = merged
        .entries
        .iter()
        .filter(|entry| matches!(entry, TreeMergeEntry::Conflict(_)))
        .count();
    if conflicts > 0 {
        return Err(ForgeRefusal::MergeConflicted { paths: conflicts });
    }
    let entries = merged
        .entries
        .into_iter()
        .filter_map(|entry| match entry {
            TreeMergeEntry::Clean(clean) => Some(clean),
            TreeMergeEntry::Conflict(_) => None,
        })
        .collect();
    Ok(MergedTree { entries })
}

/// The three things a merge produces, which are admitted together or not at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeEffectPackage {
    /// Objects the merge created, as a closure the admission must already hold.
    pub objects: Vec<GitOid>,
    /// The conditional movement of the target ref.
    pub ref_intent: RefIntent,
    /// The event recording that the merge happened.
    pub event: ForgeEvent,
}

/// The two roots this crate is responsible for producing.
///
/// Both are derived from the package's own bytes, and neither is the RCR's
/// `ref_delta_root`. That field commits to the ref effect a decision published,
/// which only admission can compute, and it arrives on [`RecordFrame`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRoots {
    /// Identity of the conditional ref movement the merge requests.
    ///
    /// Named for the intent rather than the delta because that is the body it
    /// commits to: [`RefIntent`], under `frankengit/forge-ref-intent/v1`. It
    /// belongs to the merge's request identity, not to its published effect.
    pub ref_intent_root: Digest,
    /// Identity of the batch of forge events.
    pub forge_event_batch_root: Digest,
}

/// Everything about a commit record that is admission's to decide, not this
/// crate's.
///
/// Passing these in rather than inventing them is the layer boundary made
/// concrete: an L2 crate that minted a repository sequence or a policy epoch
/// would be deciding something only the authority may decide.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordFrame {
    /// Which repository.
    pub repository_id: RepositoryId,
    /// Position in committed order.
    pub repository_sequence: RepositorySequence,
    /// Predecessor record, absent for the first.
    pub parent_rcr_id: Option<RepositoryCommitId>,
    /// The sealed transaction this record commits.
    pub tx_id: TxId,
    /// Principal snapshot the decision was evaluated under.
    pub principal_snapshot_id: PrincipalSnapshotId,
    /// Digest of the canonical request.
    pub canonical_request_digest: Digest,
    /// Identity of the canonical ref delta this decision publishes.
    ///
    /// Supplied rather than derived here, and that is the layer boundary again:
    /// a canonical ref delta is the surviving net effect over every ref the
    /// transaction moved, which only the admitting crate can fold. This crate
    /// holds one requested movement and could at best restate it, which is how
    /// the RCR field came to carry a [`RefIntent`] identity while every other
    /// admission path computed it from a canonical delta -- one field, two
    /// meanings.
    pub ref_delta_root: Digest,
    /// Ref state after the movement.
    pub resulting_ref_root: Digest,
    /// Closure over the objects the decision needs.
    pub object_closure_root: Digest,
    /// Forge position after the batch.
    pub resulting_forge_position_root: Digest,
    /// Policy epoch in force.
    pub policy_epoch: PolicyEpoch,
    /// Evidence of the policy evaluation.
    pub policy_decision_root: Digest,
    /// Evidence of the invariant checks.
    pub invariant_evidence_root: Digest,
    /// External-effect obligations created.
    pub outbox_effect_root: Digest,
    /// Retention changes created.
    pub retention_delta_root: Digest,
}

fn root_of<B, I>(identity: &I, body: &B, name: &'static str) -> Result<Digest, ForgeRefusal>
where
    B: CanonicalBody,
    I: BodyIdentity + ?Sized,
{
    let object = body_id(identity, body).map_err(|cause| match cause {
        CodecRefusal::IdentityDomainUnregistered { .. } => {
            ForgeRefusal::IdentityUnavailable { body: name }
        }
        cause => ForgeRefusal::BodyUnrepresentable {
            cause: Box::new(cause),
        },
    })?;
    Ok(Digest::new(object.algorithm(), *object.digest()))
}

impl MergeEffectPackage {
    /// Derives both roots from the package's own bytes.
    ///
    /// # Errors
    ///
    /// [`ForgeRefusal::BodyUnrepresentable`] or
    /// [`ForgeRefusal::IdentityUnavailable`].
    pub fn roots<I>(&self, identity: &I) -> Result<EffectRoots, ForgeRefusal>
    where
        I: BodyIdentity + ?Sized,
    {
        let batch = ForgeEventBatch::of_one(self.event.clone());
        Ok(EffectRoots {
            ref_intent_root: root_of(identity, &self.ref_intent, "RefIntent")?,
            forge_event_batch_root: root_of(identity, &batch, "ForgeEventBatch")?,
        })
    }

    /// Reduces the package to ONE commit record carrying both roots.
    ///
    /// This is the acceptance condition in code rather than in prose: the ref
    /// delta and the forge event land on the same record, so there is no
    /// admissible history in which the ref moved and the event did not, or the
    /// reverse. A caller cannot split them, because there is no second record
    /// to put either one on.
    ///
    /// The event root is derived here from the package's own bytes; the ref
    /// delta root is the frame's, because it commits to the folded effect
    /// rather than to the requested movement. Atomicity is unchanged by that
    /// split -- both still land on one record -- and what it buys is that the
    /// field means the same thing on this path as on every other.
    ///
    /// # Errors
    ///
    /// Whatever [`MergeEffectPackage::roots`] refuses.
    pub fn seal_into_record<I>(
        &self,
        identity: &I,
        frame: RecordFrame,
    ) -> Result<RepositoryCommitRecord, ForgeRefusal>
    where
        I: BodyIdentity + ?Sized,
    {
        let roots = self.roots(identity)?;
        Ok(RepositoryCommitRecord {
            repository_id: frame.repository_id,
            repository_sequence: frame.repository_sequence,
            parent_rcr_id: frame.parent_rcr_id,
            tx_id: frame.tx_id,
            principal_snapshot_id: frame.principal_snapshot_id,
            canonical_request_digest: frame.canonical_request_digest,
            ref_delta_root: frame.ref_delta_root,
            resulting_ref_root: frame.resulting_ref_root,
            object_closure_root: frame.object_closure_root,
            forge_event_batch_root: roots.forge_event_batch_root,
            resulting_forge_position_root: frame.resulting_forge_position_root,
            policy_epoch: frame.policy_epoch,
            policy_decision_root: frame.policy_decision_root,
            invariant_evidence_root: frame.invariant_evidence_root,
            outbox_effect_root: frame.outbox_effect_root,
            retention_delta_root: frame.retention_delta_root,
        })
    }
}
