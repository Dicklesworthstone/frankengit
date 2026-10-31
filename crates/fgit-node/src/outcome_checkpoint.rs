//! Trusted-local maintenance of the authority-bound outcome index.
//!
//! Retained leaves are staged in their existing fabric namespace, verified,
//! and selected only by an exact-predecessor authority CAS. This does not
//! prune history, publish a transaction, or constitute a repository backup.

use std::collections::BTreeSet;

use fgit_authority::{
    AsyncAuthorityStore, AuthorityFailure, CumulativeOutcomes, HeadRead, ImmutableRead,
    OutcomeFailure, body_key_for_id, collect_cumulative_outcomes_from_checkpoint_async,
};
use fgit_chronicle::{
    BackupProfile, CapsuleClosure, CapsulePointer, ChronicleRefusal, LiveCapsuleRefusal,
    MAX_CHECKPOINT_PREDECESSORS, OutcomeIndexCheckpointBody, OutcomeIndexCheckpointRefusal,
    OutcomeIndexLeafArchive, RepositoryCapsuleBody, activate_frozen_capsule_async,
    capsule_identity, freeze_capsule_with_outcome_index_checkpoint_async,
    load_verified_outcome_index_checkpoint_async, stage_outcome_index_checkpoint_async,
};
use fgit_codec::{CryptoBodyIdentity, DecodeLimits, decode_body};
use fgit_object_fabric::fabric::{
    ImmutableObjectFabric, PlacementAdmission, PutIfAbsent, StoreRefusal,
};
use fgit_resource::{LeakDisposition, ObligationLedger, RegionId, ResourceError};
use fgit_types::{Digest, HeadGeneration, RepositoryAuthorityHeadId, RepositoryCapsuleId};

use crate::{
    ADMISSION_CLOSURE_KEY_PREFIX, AdmissionMaterializationRefusal, MaterializedAdmission,
    NodeRequestContext, OneNode, PackContextCheckpoint, PermittedObjectClosure,
    admission_immutable_key, authority_head_id, checkpoint_pack_context,
    permitted_object_closure_root, placement_resources,
};

/// Limits for the existing single-manifest retained-leaf profile. Limits may
/// be narrowed; a larger archive needs a separately admitted segmented profile.
#[derive(Clone, Copy, Debug)]
pub struct OutcomeCheckpointLimits {
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub max_decisions: usize,
    pub max_archive_bytes: u64,
}

impl Default for OutcomeCheckpointLimits {
    fn default() -> Self {
        Self {
            expected_head: None,
            max_decisions: 65_536,
            max_archive_bytes: 16 * 1024 * 1024,
        }
    }
}

/// An observed maintenance outcome. `published = false` means the exact
/// selected head already named a verified checkpoint at its decision position.
#[derive(Clone, Debug)]
pub struct OutcomeCheckpointReceipt {
    pub source_head: RepositoryAuthorityHeadId,
    pub published_head: RepositoryAuthorityHeadId,
    pub generation: HeadGeneration,
    pub capsule_id: RepositoryCapsuleId,
    pub checkpoint_root: Digest,
    pub decisions: usize,
    pub leaf_objects: usize,
    pub leaf_bytes: u64,
    pub published: bool,
}

#[derive(Debug)]
pub enum OutcomeCheckpointRefusal {
    InvalidLimits,
    LimitExceeded(&'static str),
    Stopped,
    HeadMoved,
    Selection(Box<AdmissionMaterializationRefusal>),
    Authority(AuthorityFailure),
    Outcomes(OutcomeFailure),
    Checkpoint(Box<OutcomeIndexCheckpointRefusal>),
    Capsule(Box<LiveCapsuleRefusal>),
    CapsuleIdentity(ChronicleRefusal),
    CapsuleUnavailable,
    CapsuleChain,
    Fabric(StoreRefusal),
    Resource(ResourceError),
    Containment,
    /// A failed or cancelled CAS response cannot establish non-publication.
    Activation(Box<LiveCapsuleRefusal>),
    /// Publication succeeded, but its response could not be decoded locally.
    PublishedReceiptInvalid(Box<AdmissionMaterializationRefusal>),
}

impl std::fmt::Display for OutcomeCheckpointRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Self::Activation(error) = self {
            return write!(
                out,
                "checkpoint activation unresolved: {error}; inspect current authority before retrying"
            );
        }
        if let Self::PublishedReceiptInvalid(error) = self {
            return write!(
                out,
                "checkpoint published but its response metadata is invalid: {error}; inspect current authority before retrying"
            );
        }
        write!(out, "outcome checkpoint refused: {self:?}")
    }
}
impl std::error::Error for OutcomeCheckpointRefusal {}

fn live(request: &NodeRequestContext) -> Result<(), OutcomeCheckpointRefusal> {
    match checkpoint_pack_context(request.authority()) {
        PackContextCheckpoint::Live => Ok(()),
        PackContextCheckpoint::Stopped { .. } => Err(OutcomeCheckpointRefusal::Stopped),
    }
}

fn selection(error: AdmissionMaterializationRefusal) -> OutcomeCheckpointRefusal {
    OutcomeCheckpointRefusal::Selection(Box::new(error))
}
fn checkpoint(error: OutcomeIndexCheckpointRefusal) -> OutcomeCheckpointRefusal {
    OutcomeCheckpointRefusal::Checkpoint(Box::new(error))
}

fn retained_bytes(
    mut lengths: impl Iterator<Item = u64>,
    maximum: u64,
) -> Result<u64, OutcomeCheckpointRefusal> {
    lengths.try_fold(0_u64, |sum, length| {
        sum.checked_add(length)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(OutcomeCheckpointRefusal::LimitExceeded(
                "retained leaf bytes",
            ))
    })
}

struct Predecessor {
    pointer: Option<CapsulePointer>,
    current_root: Option<Digest>,
    retained: Option<(Digest, OutcomeIndexCheckpointBody)>,
    outcomes: Option<CumulativeOutcomes>,
}

impl OneNode {
    /// Create a retained-leaf checkpoint for one authenticated decision prefix.
    ///
    /// This is an explicitly trusted local maintenance operation. The caller
    /// owns repository-wide authority access and a finite request context. It
    /// never accepts caller-computed leaves, roots, or a replacement head. The
    /// native Git/forge state and every terminal transaction remain unchanged.
    /// Missing or corrupt newest capsule/checkpoint evidence refuses maintenance;
    /// it is not replaced by an older root. Ordinary admission independently
    /// retains its specified bounded genesis fallback for unavailable leaves.
    pub async fn checkpoint_outcomes_in(
        &self,
        request: &NodeRequestContext,
        limits: OutcomeCheckpointLimits,
    ) -> Result<OutcomeCheckpointReceipt, OutcomeCheckpointRefusal> {
        if limits.max_decisions == 0
            || limits.max_decisions > 65_536
            || limits.max_archive_bytes == 0
            || limits.max_archive_bytes > 16 * 1024 * 1024
        {
            return Err(OutcomeCheckpointRefusal::InvalidLimits);
        }
        live(request)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(selection)?;
        let basis = selected.basis();
        if limits
            .expected_head
            .is_some_and(|expected| expected != basis.id())
        {
            return Err(OutcomeCheckpointRefusal::HeadMoved);
        }
        // Terminal decisions have gap-free sequences starting at one. Refuse
        // an undersized retained-set budget before collecting/encoding leaves.
        if basis
            .body()
            .latest_decision_sequence
            .is_some_and(|sequence| sequence.get() > limits.max_decisions as u64)
        {
            return Err(OutcomeCheckpointRefusal::LimitExceeded(
                "terminal decisions",
            ));
        }
        let mut predecessor = self.checkpoint_predecessor_in(request, &selected).await?;
        live(request)?;
        let outcomes = match predecessor.outcomes.take() {
            Some(outcomes) => outcomes,
            None => crate::outcome_collection::collect(
                &self.authority,
                request.authority(),
                &self.head_key,
                selected.authenticated(),
                Some(&self.outcome_checkpoint_fabric),
            )
            .await
            .map_err(OutcomeCheckpointRefusal::Outcomes)?,
        };
        live(request)?;
        if outcomes.len() > limits.max_decisions {
            return Err(OutcomeCheckpointRefusal::LimitExceeded(
                "terminal decisions",
            ));
        }
        let decisions = outcomes
            .checkpoint_decisions_against(selected.authenticated().receipt().token())
            .map_err(OutcomeCheckpointRefusal::Outcomes)?;
        let exact = predecessor.retained.as_ref().filter(|(_, body)| {
            body.decision_tail_id == basis.body().decision_tail_id
                && body.latest_decision_sequence == basis.body().latest_decision_sequence
        });
        let (archive, leaf_objects, leaf_bytes) = if let Some((_, body)) = exact {
            // A valid existing archive can use smaller chunks than our current
            // writer. Report and bound the actual retained manifest, never a
            // hypothetical repacking that this no-op/rebind would not publish.
            let guarded = crate::outcome_collection::RequestFabric::new(
                &self.outcome_checkpoint_fabric,
                request.authority(),
            );
            let manifest = guarded
                .read_manifest(body.leaf_archive_manifest)
                .map_err(OutcomeCheckpointRefusal::Fabric)?;
            let bytes = retained_bytes(
                manifest
                    .entries()
                    .iter()
                    .map(|entry| entry.payload_length()),
                limits.max_archive_bytes,
            )?;
            (None, manifest.entries().len(), bytes)
        } else {
            // Preparation independently canonicalizes the complete retained
            // set and encodes bounded native chunks before any staging.
            let archive = OutcomeIndexLeafArchive::prepare(
                self.repository_id,
                self.object_format,
                &decisions,
            )
            .map_err(checkpoint)?;
            let bytes = retained_bytes(
                archive
                    .objects()
                    .iter()
                    .map(|object| object.payload().len() as u64),
                limits.max_archive_bytes,
            )?;
            let count = archive.objects().len();
            (Some(archive), count, bytes)
        };
        live(request)?;
        if let Some((root, _)) = exact
            && predecessor.current_root == Some(*root)
        {
            // The predecessor loader verifies the actual retained objects;
            // collector fallback alone would not justify this no-op receipt.
            self.require_checkpoint_head_in(request, &selected).await?;
            let pointer = predecessor
                .pointer
                .ok_or(OutcomeCheckpointRefusal::CapsuleChain)?;
            return Ok(OutcomeCheckpointReceipt {
                source_head: basis.id(),
                published_head: basis.id(),
                generation: basis.generation(),
                capsule_id: pointer.capsule_id(),
                checkpoint_root: *root,
                decisions: decisions.len(),
                leaf_objects,
                leaf_bytes,
                published: false,
            });
        }

        let checkpoint_body = if let Some((_, body)) = exact {
            // A generic intervening capsule can omit the outcome hint. Rebind
            // the already verified checkpoint, without a same-position link.
            body.clone()
        } else {
            let mut previous_root = predecessor.retained.as_ref().map(|(root, _)| *root);
            if previous_root.is_none() && basis.body().latest_decision_sequence.is_some() {
                // §23 permits an absent checkpoint predecessor only at genesis.
                // Establish that empty retained prefix before the first live
                // nonempty checkpoint; it is staged, never separately activated.
                let empty =
                    OutcomeIndexLeafArchive::prepare(self.repository_id, self.object_format, &[])
                        .map_err(checkpoint)?;
                let empty_manifest = self.stage_outcome_archive_in(request, &empty)?;
                let genesis = OutcomeIndexCheckpointBody::new(
                    self.repository_id,
                    None,
                    None,
                    None,
                    empty_manifest,
                )
                .map_err(checkpoint)?;
                previous_root = Some(
                    stage_outcome_index_checkpoint_async(
                        &self.authority,
                        request.authority(),
                        &CryptoBodyIdentity,
                        &genesis,
                    )
                    .await
                    .map_err(checkpoint)?,
                );
                live(request)?;
            }
            let archive = archive
                .as_ref()
                .ok_or(OutcomeCheckpointRefusal::CapsuleChain)?;
            let manifest = self.stage_outcome_archive_in(request, archive)?;
            OutcomeIndexCheckpointBody::new(
                self.repository_id,
                basis.body().decision_tail_id,
                basis.body().latest_decision_sequence,
                previous_root,
                manifest,
            )
            .map_err(checkpoint)?
        };
        live(request)?;
        // This is the exact authority-derived cumulative object union. Staging
        // its body does not select it or grant it retention/disclosure authority.
        let object_root = self
            .admission_materializer
            .stage_permitted_object_closure_in(
                &self.authority,
                request.authority(),
                self.repository_id,
                selected.selected_closure().closure().clone(),
            )
            .await
            .map_err(selection)?;
        live(request)?;
        // Read back the exact cumulative closure before publishing a capsule
        // that names it. Staging success alone is not retained evidence.
        let closure_key = admission_immutable_key(
            ADMISSION_CLOSURE_KEY_PREFIX,
            self.repository_id,
            object_root,
        )
        .map_err(|error| selection(AdmissionMaterializationRefusal::Key(error)))?;
        let closure_read = self
            .authority
            .read_immutable(request.authority(), &closure_key)
            .await
            .map_err(OutcomeCheckpointRefusal::Authority)?;
        live(request)?;
        let ImmutableRead::Present(closure_bytes) = closure_read else {
            return Err(selection(AdmissionMaterializationRefusal::ImmutableAbsent(
                object_root,
            )));
        };
        let closure: PermittedObjectClosure = decode_body(&closure_bytes, DecodeLimits::DEFAULT)
            .map_err(|error| selection(AdmissionMaterializationRefusal::CanonicalFrame(error)))?;
        if permitted_object_closure_root(&closure)
            .map_err(|error| selection(AdmissionMaterializationRefusal::CanonicalRoot(error)))?
            != object_root
            || closure != *selected.selected_closure().closure()
        {
            return Err(selection(
                AdmissionMaterializationRefusal::ImmutableConflict,
            ));
        }
        let manifest_id = checkpoint_body
            .leaf_archive_manifest
            .as_internal_object_id();
        let manifest_root = Digest::new(manifest_id.algorithm(), *manifest_id.digest());
        let guarded = crate::outcome_collection::RequestFabric::new(
            &self.outcome_checkpoint_fabric,
            request.authority(),
        );
        let frozen = freeze_capsule_with_outcome_index_checkpoint_async(
            &self.authority,
            request.authority(),
            &guarded,
            &CryptoBodyIdentity,
            selected.authenticated().receipt(),
            predecessor.pointer.as_ref(),
            CapsuleClosure {
                object_closure_root: object_root,
                segment_manifest_root: manifest_root,
                backup_profile: BackupProfile::DecisionHistoryOnly,
            },
            &checkpoint_body,
        )
        .await
        .map_err(|error| OutcomeCheckpointRefusal::Capsule(Box::new(error)))?;
        live(request)?;
        let root = frozen
            .capsule()
            .outcome_index_checkpoint_root
            .ok_or(OutcomeCheckpointRefusal::CapsuleChain)?;
        let activated = activate_frozen_capsule_async(
            &self.authority,
            request.authority(),
            selected.authenticated().receipt(),
            &frozen,
        )
        .await
        .map_err(|error| OutcomeCheckpointRefusal::Activation(Box::new(error)))?;
        // No cancellation check after a successful CAS may erase visibility.
        // The returned head body was generated and authenticated by activation.
        let published =
            decode_body(activated.head().body(), DecodeLimits::DEFAULT).map_err(|error| {
                OutcomeCheckpointRefusal::PublishedReceiptInvalid(Box::new(
                    AdmissionMaterializationRefusal::CanonicalFrame(error),
                ))
            })?;
        Ok(OutcomeCheckpointReceipt {
            source_head: basis.id(),
            published_head: authority_head_id(&published).map_err(|error| {
                OutcomeCheckpointRefusal::PublishedReceiptInvalid(Box::new(error))
            })?,
            generation: activated.head().generation(),
            capsule_id: activated.pointer().capsule_id(),
            checkpoint_root: root,
            decisions: decisions.len(),
            leaf_objects,
            leaf_bytes,
            published: true,
        })
    }

    async fn require_checkpoint_head_in(
        &self,
        request: &NodeRequestContext,
        selected: &MaterializedAdmission,
    ) -> Result<(), OutcomeCheckpointRefusal> {
        live(request)?;
        let head = self
            .authority
            .read_head(request.authority(), &self.head_key)
            .await
            .map_err(OutcomeCheckpointRefusal::Authority)?;
        live(request)?;
        if !matches!(head, HeadRead::Present(receipt) if receipt == *selected.authenticated().receipt())
        {
            return Err(OutcomeCheckpointRefusal::HeadMoved);
        }
        Ok(())
    }

    async fn checkpoint_predecessor_in(
        &self,
        request: &NodeRequestContext,
        selected: &MaterializedAdmission,
    ) -> Result<Predecessor, OutcomeCheckpointRefusal> {
        let mut id = selected.basis().body().last_checkpoint_id;
        let mut pointer = None;
        let mut current_root = None;
        let mut seen = BTreeSet::new();
        let mut previous_generation = selected.basis().generation();
        while let Some(capsule_id) = id {
            live(request)?;
            if seen.len() >= MAX_CHECKPOINT_PREDECESSORS || !seen.insert(capsule_id) {
                return Err(OutcomeCheckpointRefusal::CapsuleChain);
            }
            let key = body_key_for_id(capsule_id.as_internal_object_id())
                .map_err(OutcomeFailure::from)
                .map_err(OutcomeCheckpointRefusal::Outcomes)?;
            let read = self
                .authority
                .read_immutable(request.authority(), &key)
                .await
                .map_err(OutcomeCheckpointRefusal::Authority)?;
            live(request)?;
            let ImmutableRead::Present(bytes) = read else {
                return Err(OutcomeCheckpointRefusal::CapsuleUnavailable);
            };
            let capsule: RepositoryCapsuleBody = decode_body(&bytes, DecodeLimits::DEFAULT)
                .map_err(|_| OutcomeCheckpointRefusal::CapsuleUnavailable)?;
            if capsule_identity(&CryptoBodyIdentity, &capsule)
                .map_err(OutcomeCheckpointRefusal::CapsuleIdentity)?
                != capsule_id
                || capsule.repository_id != self.repository_id
                || capsule.head_generation >= previous_generation
            {
                return Err(OutcomeCheckpointRefusal::CapsuleChain);
            }
            if pointer.is_none() {
                // Recover the cursor already selected by the authenticated
                // head. This constructor changes no authority and does not
                // discard the capsule's original predecessor. It also works
                // for an explicitly restored namespace with external history.
                pointer = Some(CapsulePointer::restored_root(capsule_id, &capsule));
                current_root = capsule.outcome_index_checkpoint_root;
            }
            if let Some(root) = capsule.outcome_index_checkpoint_root {
                let guarded = crate::outcome_collection::RequestFabric::new(
                    &self.outcome_checkpoint_fabric,
                    request.authority(),
                );
                let (retained, leaves) = load_verified_outcome_index_checkpoint_async(
                    &self.authority,
                    request.authority(),
                    &CryptoBodyIdentity,
                    &guarded,
                    root,
                )
                .await
                .map_err(checkpoint)?;
                live(request)?;
                if retained.repository_id != self.repository_id {
                    return Err(OutcomeCheckpointRefusal::CapsuleChain);
                }
                // Maintenance certifies these exact leaves. Admission may
                // fall back to genesis, which cannot validate a no-op root.
                let outcomes = collect_cumulative_outcomes_from_checkpoint_async(
                    &self.authority,
                    request.authority(),
                    &self.head_key,
                    &leaves,
                    retained.decision_tail_id,
                    retained.latest_decision_sequence,
                )
                .await
                .map_err(OutcomeCheckpointRefusal::Outcomes)?;
                live(request)?;
                if outcomes.observed() != selected.authenticated().receipt().token() {
                    return Err(OutcomeCheckpointRefusal::HeadMoved);
                }
                return Ok(Predecessor {
                    pointer,
                    current_root,
                    retained: Some((root, retained)),
                    outcomes: Some(outcomes),
                });
            }
            previous_generation = capsule.head_generation;
            id = capsule.predecessor_capsule_id;
        }
        Ok(Predecessor {
            pointer,
            current_root,
            retained: None,
            outcomes: None,
        })
    }

    fn stage_outcome_archive_in(
        &self,
        request: &NodeRequestContext,
        archive: &OutcomeIndexLeafArchive,
    ) -> Result<fgit_types::SegmentManifestId, OutcomeCheckpointRefusal> {
        let mut placements = BTreeSet::new();
        for object in archive.objects() {
            live(request)?;
            let resources = placement_resources(object.payload().len() as u64);
            let ledger = ObligationLedger::root(
                RegionId::new(1),
                LeakDisposition::RecordAndContinue,
                resources,
            );
            let grant = ledger
                .grant(resources)
                .map_err(OutcomeCheckpointRefusal::Resource)?;
            let outcome = self
                .outcome_checkpoint_fabric
                .put_if_absent(object.clone(), PlacementAdmission::new(&ledger, grant));
            if !ledger.close().is_quiescent() {
                return Err(OutcomeCheckpointRefusal::Containment);
            }
            let (PutIfAbsent::Created { placement, .. }
            | PutIfAbsent::AlreadyPresent { placement, .. }) =
                outcome.map_err(OutcomeCheckpointRefusal::Fabric)?;
            placements.insert(placement);
            live(request)?;
        }
        let manifest = archive
            .manifest(placements.into_iter().collect())
            .map_err(checkpoint)?;
        live(request)?;
        let root = self
            .outcome_checkpoint_fabric
            .write_manifest(&manifest)
            .map_err(OutcomeCheckpointRefusal::Fabric)?;
        live(request)?;
        Ok(root)
    }
}
