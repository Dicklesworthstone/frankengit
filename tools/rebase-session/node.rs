//! Read-only, exact-snapshot linear rebase and complete onto-only artifacts.
use super::{CandidateSource, SelectedSource};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use fgit_admission::merge::native::objects::{MergeObjectLimits, validate_commit_closure};
use fgit_admission::ProjectionFailure;
use fgit_forge::preparation::{MergeObjectSource, MergeSourceError, PreparationLimits};
use fgit_forge::preparation::rebase::{PreparedRebase, RebaseCommitMetadata, RebaseCommitter,
    RebaseError, RebaseObjectSource, RebasePreparation, RebaseRequest, RebaseStepKind, prepare_rebase};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, parse_object_body};
use fgit_pack::{PackLimits, PackPlanner, PackWriteError, PackWriteProfile, PackWriter, verify_native_object};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_wire::visibility::RefVisibility;
use crate::{AdmissionMaterializationRefusal, NodeRequestContext, OneNode, VerifiedFabricPackSource};

#[derive(Debug)]
pub struct PreparedRebaseBundle {
    pub source_head: RepositoryAuthorityHeadId,
    pub outcome: RebasePreparation,
    pub bundle: Option<Vec<u8>>,
    pub pack_objects: usize,
    pub borrowed_objects: usize,
}
#[derive(Debug)]
pub enum RebasePreparationRefusal {
    Cell(CellRefusal), Authority(Box<AdmissionMaterializationRefusal>),
    Preparation(Box<RebaseError>), Source(MergeSourceError), Validation(ProjectionFailure),
    Pack(Box<PackWriteError>), SnapshotMoved, RefUnavailable, TipMoved,
    InvalidInput(&'static str), BudgetExceeded,
}
impl From<MergeSourceError> for RebasePreparationRefusal {
    fn from(error: MergeSourceError) -> Self { Self::Source(error) }
}
impl std::fmt::Display for RebasePreparationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "rebase preparation refused: {self:?}") }
}
impl std::error::Error for RebasePreparationRefusal {}
fn preparation(error: impl Into<RebaseError>) -> RebasePreparationRefusal {
    RebasePreparationRefusal::Preparation(Box::new(error.into()))
}

impl RebaseObjectSource for SelectedSource<'_> {
    fn rebase_metadata(&self, id: GitOid) -> Result<RebaseCommitMetadata, MergeSourceError> {
        let (_, body) = self.read(id, Some(ObjectType::Commit))?;
        let result = original_metadata(id, &body, &self.limits);
        self.checkpoint()?;
        result
    }
}

fn original_metadata(id: GitOid, body: &[u8], limits: &ParseLimits) -> Result<RebaseCommitMetadata, MergeSourceError> {
    let invalid = || MergeSourceError::InvalidObject(id);
    let ParsedObject::Commit(commit) = parse_object_body(ObjectType::Commit, body,
        AcceptanceProfile::GitCompatibleImport, limits).map_err(|_| invalid())? else { return Err(invalid()); };
    let mut author = None;
    let mut encoding = None;
    let mut committers = 0;
    for header in commit.headers() {
        match header.name.as_slice() {
            b"tree" | b"parent" => {
                if !header.continuations.is_empty() { return Err(invalid()); }
            }
            b"author" => {
                if author.is_some() || !header.continuations.is_empty() { return Err(invalid()); }
                author = Some(header.value.clone());
            }
            b"committer" => {
                committers += 1;
                if committers != 1 || !header.continuations.is_empty() { return Err(invalid()); }
            }
            b"encoding" => {
                if encoding.is_some() || !header.continuations.is_empty() { return Err(invalid()); }
                encoding = Some(header.value.clone());
            }
            // These attest to old bytes, not the newly constructed commit.
            // Unknown extension headers refuse rather than silently losing data.
            b"gpgsig" | b"gpgsig-sha256" => {}
            _ => return Err(invalid()),
        }
    }
    if committers != 1 { return Err(invalid()); }
    Ok(RebaseCommitMetadata { author: author.ok_or_else(invalid)?, encoding, message: commit.message().to_vec() })
}

impl OneNode {
    /// Select source and onto branches from one authenticated current snapshot,
    /// prove the explicit upstream-to-source linear suffix, and construct a
    /// complete candidate chain. Preparation changes no canonical or fabric state.
    /// The artifact advertises the SOURCE branch, with onto as its only external
    /// prerequisite. Publish separately through the existing expected-old receive
    /// gate; the single-parent workspace apply API is deliberately not weakened.
    pub async fn prepare_rebase_bundle_in(
        &self, request: &NodeRequestContext, source_ref: &RefName, onto_ref: &RefName,
        inputs: RebaseRequest, visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>, committer: &RebaseCommitter,
        limits: PreparationLimits,
    ) -> Result<PreparedRebaseBundle, RebasePreparationRefusal> {
        limits.validate().map_err(preparation)?;
        committer.validate().map_err(preparation)?;
        if source_ref == onto_ref || [source_ref, onto_ref].iter().any(|r| !r.as_bytes().starts_with(b"refs/heads/"))
            || [inputs.source_tip, inputs.upstream, inputs.onto].iter().any(|id| id.is_zero() || id.algorithm() != self.object_format) {
            return Err(RebasePreparationRefusal::InvalidInput("two distinct native branches and exact same-format tips required"));
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(RebasePreparationRefusal::Cell)?;
        if visibility.hides(source_ref.as_bytes()) || visibility.hides(onto_ref.as_bytes()) {
            return Err(RebasePreparationRefusal::RefUnavailable);
        }
        let selected = self.materialize_admission_in(request).await
            .map_err(|e| RebasePreparationRefusal::Authority(Box::new(e)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) { return Err(RebasePreparationRefusal::SnapshotMoved); }
        if selected.snapshot().hidden_refs.hides(source_ref.as_bytes()) || selected.snapshot().hidden_refs.hides(onto_ref.as_bytes()) {
            return Err(RebasePreparationRefusal::RefUnavailable);
        }
        let source_tip = selected.snapshot().refs.get(source_ref).ok_or(RebasePreparationRefusal::RefUnavailable)?;
        let onto = selected.snapshot().refs.get(onto_ref).ok_or(RebasePreparationRefusal::RefUnavailable)?;
        if *source_tip != inputs.source_tip || *onto != inputs.onto { return Err(RebasePreparationRefusal::TipMoved); }
        let exhaustion = Cell::new(None);
        let maximum = usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX).min(32*1024*1024);
        let original = SelectedSource {
            inner: VerifiedFabricPackSource { fabric: &self.fabric, object_format: self.object_format,
                maximum_object_bytes: maximum, database_context: request.authority(), database_exhaustion: &exhaustion, session_is_live: None },
            selected: selected.selected_closure(),
            limits: ParseLimits { tree_reference_bytes: self.object_format.digest_len(),
                max_tree_entries: limits.max_tree_entries, max_object_bytes: maximum, ..ParseLimits::default() },
            read_bytes: Cell::new(0), budget_failed: Cell::new(false),
        };
        let outcome = prepare_rebase(&original, self.object_format, inputs, committer, limits).map_err(preparation)?;
        let (bundle, pack_objects, borrowed_objects) = match &outcome {
            RebasePreparation::Clean(plan) => {
                let (bytes, count, borrowed) = rebase_bundle(&original, source_ref, plan, limits)?;
                (Some(bytes), count, borrowed)
            }
            RebasePreparation::Stopped { .. } => (None,0,0),
        };
        original.checkpoint()?;
        Ok(PreparedRebaseBundle { source_head: selected.basis().id(), outcome, bundle, pack_objects, borrowed_objects })
    }
}

/// Check every rewritten parent from native bytes, not caller-declared edges.
/// This is a read-only artifact check; no new publication bypass is created.
fn verify_chain(original: &SelectedSource<'_>, plan: &PreparedRebase) -> Result<(), RebasePreparationRefusal> {
    let invalid = || RebasePreparationRefusal::InvalidInput("rewritten native chain differs from the complete rebase receipt");
    let objects: BTreeMap<_,_> = plan.objects.iter().map(|o| (o.id,o)).collect();
    if objects.len() != plan.objects.len() { return Err(invalid()); }
    let mut parent = plan.request.onto;
    let mut tree = original.commit(parent)?.tree;
    let mut seen = BTreeSet::new();
    for step in &plan.steps {
        original.checkpoint()?;
        if !seen.insert(step.original) { return Err(invalid()); }
        if step.kind == RebaseStepKind::DroppedEmpty {
            if step.rewritten != parent || step.tree != tree { return Err(invalid()); }
            continue;
        }
        let object = objects.get(&step.rewritten).ok_or_else(invalid)?;
        let parsed = verify_native_object(original.inner.object_format, object.kind, &object.body, &object.id,
            AcceptanceProfile::StrictCreate, &original.limits).map_err(|_| invalid())?;
        let ParsedObject::Commit(commit) = parsed else { return Err(invalid()); };
        let parents = commit.parent_references().map(|p| original.oid(p, object.id)).collect::<Result<Vec<_>,_>>()?;
        let actual_tree = original.oid(commit.tree_reference().ok_or_else(invalid)?, object.id)?;
        if parents != [parent] || actual_tree != step.tree { return Err(invalid()); }
        parent = step.rewritten; tree = step.tree;
    }
    if plan.commit != parent || plan.tree != tree
        || plan.steps.last().is_some_and(|s| s.original != plan.request.source_tip)
        || (plan.steps.is_empty() && plan.request.source_tip != plan.request.upstream) { return Err(invalid()); }
    Ok(())
}

fn rebase_bundle(original: &SelectedSource<'_>, reference: &RefName, plan: &PreparedRebase, limits: PreparationLimits)
    -> Result<(Vec<u8>,usize,usize), RebasePreparationRefusal> {
    verify_chain(original, plan)?;
    let candidate = CandidateSource { original, generated: plan.objects.iter().map(|o| (o.id,o)).collect() };
    for object in &plan.objects {
        original.checkpoint()?;
        verify_native_object(original.inner.object_format, object.kind, &object.body, &object.id,
            AcceptanceProfile::StrictCreate, &original.limits)
            .map_err(|_| RebasePreparationRefusal::InvalidInput("constructed object failed strict validation"))?;
    }
    let validation = MergeObjectLimits { max_object_bytes: original.limits.max_object_bytes, ..MergeObjectLimits::default() };
    let empty = CandidateSource { original, generated: BTreeMap::new() };
    let mut live = || original.checkpoint().is_ok();
    let base = validate_commit_closure(&empty, plan.request.onto, validation, &mut live);
    original.checkpoint()?;
    let base = base.map_err(RebasePreparationRefusal::Validation)?;
    let all = validate_commit_closure(&candidate, plan.commit, validation, &mut live);
    original.checkpoint()?;
    let all = all.map_err(RebasePreparationRefusal::Validation)?;
    if !all.objects.contains(&plan.request.onto) { return Err(RebasePreparationRefusal::InvalidInput("onto history absent")); }
    let needed: Vec<_> = all.objects.difference(&base.objects).copied().collect();
    if needed.len() > limits.max_objects { return Err(RebasePreparationRefusal::BudgetExceeded); }
    let borrowed = needed.iter().filter(|id| !candidate.generated.contains_key(*id)).count();
    let pack_limits = PackLimits { max_entries: u32::try_from(limits.max_objects).map_err(|_| RebasePreparationRefusal::BudgetExceeded)?,
        max_total_expanded_bytes: limits.max_output_bytes, max_cached_bytes: limits.max_output_bytes, ..PackLimits::default() };
    let packed = PackPlanner::new(original.inner.object_format, PackWriteProfile::COMPRESSED_NO_DELTA_V1, pack_limits.clone())
        .plan_selected(&candidate, &needed, &mut live);
    original.checkpoint()?;
    let packed = packed.map_err(|e| RebasePreparationRefusal::Pack(Box::new(e)))?;
    let result = PackWriter::new(pack_limits).write(&packed, &mut live);
    original.checkpoint()?;
    let (pack,_) = result.map_err(|e| RebasePreparationRefusal::Pack(Box::new(e)))?;
    let mut bundle = match original.inner.object_format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    bundle.extend_from_slice(format!("-{} onto\n{} ",plan.request.onto,plan.commit).as_bytes());
    bundle.extend_from_slice(reference.as_bytes()); bundle.extend_from_slice(b"\n\n");
    if bundle.len().checked_add(pack.len()).is_none_or(|n| n > limits.max_output_bytes) { return Err(RebasePreparationRefusal::BudgetExceeded); }
    bundle.try_reserve_exact(pack.len()).map_err(|_| RebasePreparationRefusal::BudgetExceeded)?;
    bundle.extend_from_slice(&pack);
    Ok((bundle, needed.len(), borrowed))
}

#[cfg(test)]
#[path = "rebase/tests.rs"]
mod tests;
