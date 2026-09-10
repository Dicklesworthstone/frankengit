//! Authority-selected cherry-pick/revert preparation. The artifact is a normal
//! single-parent candidate; all mutation remains in workspace admission.
use std::cell::Cell;
use std::collections::BTreeMap;

use fgit_admission::merge::native::objects::{MergeObjectLimits, validate_commit_closure, validate_workspace_objects};
use fgit_admission::ProjectionFailure;
use fgit_forge::preparation::{MergeMetadata, MergeObjectSource, MergeSourceError, PreparationLimits};
use fgit_forge::preparation::replay::{PreparedReplay, ReplayError, ReplayPreparation, ReplayRequest, prepare_replay};
use fgit_git_object::{AcceptanceProfile, ParseLimits};
use fgit_pack::{PackLimits, PackPlanner, PackWriteError, PackWriteProfile, PackWriter, verify_native_object};
use fgit_types::{GitHashAlgorithm, RefName, RepositoryAuthorityHeadId};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_wire::visibility::RefVisibility;

use super::{CandidateSource, SelectedSource};
use crate::{AdmissionMaterializationRefusal, NodeRequestContext, OneNode, VerifiedFabricPackSource};

#[derive(Debug)]
pub struct PreparedReplayBundle {
    pub source_head: RepositoryAuthorityHeadId,
    pub outcome: ReplayPreparation,
    pub bundle: Option<Vec<u8>>,
    pub pack_objects: usize,
    /// Needed native objects borrowed from source history rather than generated.
    pub borrowed_objects: usize,
}

#[derive(Debug)]
pub enum ReplayPreparationRefusal {
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    Preparation(Box<ReplayError>),
    Source(MergeSourceError),
    Validation(ProjectionFailure),
    Pack(Box<PackWriteError>),
    SnapshotMoved,
    RefUnavailable,
    TipMoved,
    InvalidInput(&'static str),
    BudgetExceeded,
}
impl std::fmt::Display for ReplayPreparationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "commit replay preparation refused: {self:?}")
    }
}
impl std::error::Error for ReplayPreparationRefusal {}
impl From<MergeSourceError> for ReplayPreparationRefusal {
    fn from(error: MergeSourceError) -> Self { Self::Source(error) }
}
fn preparation(error: impl Into<ReplayError>) -> ReplayPreparationRefusal {
    ReplayPreparationRefusal::Preparation(Box::new(error.into()))
}

impl OneNode {
    /// Select both branch tips at one authenticated head and replay one exact
    /// historical change. The selected commit must be reachable from the visible
    /// source branch; an arbitrary admitted object ID is not selection authority.
    /// Same-ref operation is allowed for reverting a historical commit.
    ///
    /// The returned pack contains every candidate dependency absent from the
    /// TARGET history, including borrowed source blobs/trees. The source commit
    /// is not a parent, and is never an implicit artifact prerequisite. No seal,
    /// object staging, ref update, forge append or outbox mutation occurs here.
    pub async fn prepare_replay_bundle_in(
        &self, request: &NodeRequestContext, target: &RefName, source_ref: &RefName,
        inputs: ReplayRequest, visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>, metadata: &MergeMetadata,
        limits: PreparationLimits,
    ) -> Result<PreparedReplayBundle, ReplayPreparationRefusal> {
        limits.validate().map_err(preparation)?;
        metadata.validate().map_err(preparation)?;
        if [target, source_ref].iter().any(|name| !name.as_bytes().starts_with(b"refs/heads/"))
            || [inputs.target, inputs.source_tip, inputs.selected_commit].iter()
                .any(|id| id.is_zero() || id.algorithm() != self.object_format)
            || inputs.mainline == Some(0)
        { return Err(ReplayPreparationRefusal::InvalidInput("exact native branch/commit/mainline inputs required")); }
        admits_read(self.cell_state(), ReadMode::Current).map_err(ReplayPreparationRefusal::Cell)?;
        if visibility.hides(target.as_bytes()) || visibility.hides(source_ref.as_bytes()) {
            return Err(ReplayPreparationRefusal::RefUnavailable);
        }
        let selected = self.materialize_admission_in(request).await
            .map_err(|error| ReplayPreparationRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(ReplayPreparationRefusal::SnapshotMoved);
        }
        if selected.snapshot().hidden_refs.hides(target.as_bytes())
            || selected.snapshot().hidden_refs.hides(source_ref.as_bytes())
        { return Err(ReplayPreparationRefusal::RefUnavailable); }
        let actual_target = selected.snapshot().refs.get(target).ok_or(ReplayPreparationRefusal::RefUnavailable)?;
        let actual_source = selected.snapshot().refs.get(source_ref).ok_or(ReplayPreparationRefusal::RefUnavailable)?;
        if *actual_target != inputs.target || *actual_source != inputs.source_tip {
            return Err(ReplayPreparationRefusal::TipMoved);
        }
        let exhaustion = Cell::new(None);
        let max_bytes = usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX).min(32 * 1024 * 1024);
        let original = SelectedSource {
            inner: VerifiedFabricPackSource {
                fabric: &self.fabric, object_format: self.object_format, maximum_object_bytes: max_bytes,
                database_context: request.authority(), database_exhaustion: &exhaustion, session_is_live: None,
            },
            selected: selected.selected_closure(),
            limits: ParseLimits {
                tree_reference_bytes: self.object_format.digest_len(),
                max_tree_entries: limits.max_tree_entries, max_object_bytes: max_bytes,
                // Header syntax and total graph edges are independent budgets.
                ..ParseLimits::default()
            },
            read_bytes: Cell::new(0), budget_failed: Cell::new(false),
        };
        let outcome = prepare_replay(&original, self.object_format, inputs, metadata, limits).map_err(preparation)?;
        let (bundle, pack_objects, borrowed_objects) = match &outcome {
            ReplayPreparation::Clean(plan) => {
                let (bytes, count, borrowed) = replay_bundle(&original, target, plan, limits)?;
                (Some(bytes), count, borrowed)
            }
            ReplayPreparation::Conflicted { .. } | ReplayPreparation::NoChange { .. } => (None, 0, 0),
        };
        original.checkpoint()?;
        Ok(PreparedReplayBundle { source_head: selected.basis().id(), outcome, bundle, pack_objects, borrowed_objects })
    }
}

fn replay_bundle(
    original: &SelectedSource<'_>, reference: &RefName, plan: &PreparedReplay, limits: PreparationLimits,
) -> Result<(Vec<u8>, usize, usize), ReplayPreparationRefusal> {
    let empty = CandidateSource { original, generated: BTreeMap::new() };
    let validation_limits = MergeObjectLimits { max_object_bytes: original.limits.max_object_bytes,
        ..MergeObjectLimits::default() };
    let mut live = || original.checkpoint().is_ok();
    let parent = validate_commit_closure(&empty, plan.coordinates.request.target, validation_limits, &mut live);
    original.checkpoint()?;
    let parent = parent.map_err(ReplayPreparationRefusal::Validation)?;
    let candidate = CandidateSource {
        original, generated: plan.objects.iter().map(|object| (object.id, object)).collect(),
    };
    for object in &plan.objects {
        original.checkpoint()?;
        verify_native_object(original.inner.object_format, object.kind, &object.body, &object.id,
            AcceptanceProfile::StrictCreate, &original.limits)
            .map_err(|_| ReplayPreparationRefusal::InvalidInput("constructed object failed strict validation"))?;
    }
    let verified = validate_workspace_objects(&candidate, plan.commit, plan.coordinates.request.target,
        validation_limits, &mut live);
    original.checkpoint()?;
    let verified = verified.map_err(ReplayPreparationRefusal::Validation)?;
    // A one-parent candidate cannot rely on the selected source commit being
    // fetched. Include the exact closure difference, not just planner output.
    let needed: Vec<_> = verified.objects.difference(&parent.objects).copied().collect();
    if needed.len() > limits.max_objects || !needed.contains(&plan.commit) {
        return Err(ReplayPreparationRefusal::BudgetExceeded);
    }
    let borrowed = needed.iter().filter(|id| !candidate.generated.contains_key(*id)).count();
    let pack_limits = PackLimits { max_entries: u32::try_from(limits.max_objects)
            .map_err(|_| ReplayPreparationRefusal::BudgetExceeded)?,
        max_total_expanded_bytes: limits.max_output_bytes, max_cached_bytes: limits.max_output_bytes,
        ..PackLimits::default() };
    let packed = PackPlanner::new(original.inner.object_format, PackWriteProfile::COMPRESSED_NO_DELTA_V1, pack_limits.clone())
        .plan_selected(&candidate, &needed, &mut live);
    original.checkpoint()?;
    let packed = packed.map_err(|error| ReplayPreparationRefusal::Pack(Box::new(error)))?;
    let packed = PackWriter::new(pack_limits).write(&packed, &mut live);
    original.checkpoint()?;
    let (pack, _) = packed.map_err(|error| ReplayPreparationRefusal::Pack(Box::new(error)))?;
    let mut bundle = match original.inner.object_format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    bundle.extend_from_slice(format!("-{} target\n{} ", plan.coordinates.request.target, plan.commit).as_bytes());
    bundle.extend_from_slice(reference.as_bytes()); bundle.extend_from_slice(b"\n\n");
    bundle.try_reserve(pack.len()).map_err(|_| ReplayPreparationRefusal::BudgetExceeded)?;
    bundle.extend_from_slice(&pack);
    Ok((bundle, needed.len(), borrowed))
}

#[cfg(test)]
mod tests;
