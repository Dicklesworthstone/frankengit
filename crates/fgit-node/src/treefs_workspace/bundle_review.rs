//! Read-only inspection of an untrusted candidate's ACTUAL resulting tree.
//! Parent visibility selects the original-object capability before any uploaded
//! REF_DELTA can request bytes. Nothing in this module stages or publishes.

mod pack;
#[cfg(test)]
mod tests;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use fgit_admission::merge::native::objects::{
    MergeObjectLimits, validate_commit_closure, validate_merge_objects, validate_workspace_objects,
};
use fgit_admission::ProjectionFailure;
use fgit_crypto::{git_object_id, sha256_digest};
use fgit_forge::event::NativeMerge;
use fgit_forge::preparation::{CommitInput, MergeEntry, MergeObjectSource, MergeSourceError, PlannedMergeObject};
use fgit_forge::review::{ComparisonMode, ReviewError, ReviewOptions, SourceReview, compare_source};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, parse_object_body};
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackError, PackLimits, PackWriteError};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;

use crate::{AdmissionMaterializationRefusal, NodeRequestContext, OneNode, PackContextCheckpoint,
    VerifiedFabricPackSource, checkpoint_pack_context};
use super::{CandidateEnvelope, MAX_BUNDLE_BYTES, MAX_CANDIDATE_BYTES, MAX_PREREQUISITES};

const MAX_INSPECTION_OBJECTS: u32 = 10_000;
const MAX_EXPANDED_BYTES: usize = 64 * 1024 * 1024;
const MAX_ORIGINAL_READ_BYTES: usize = 128 * 1024 * 1024;

/// A derived, unsigned review result, not an authorization or publication proof.
/// The native candidate may differ from an automatically constructed merge.
/// Its complete commit body is included so authorship, messages and other
/// headers are reviewable alongside the direct target-before -> result diff.
#[derive(Debug)]
pub struct BundleInspection {
    pub review: SourceReview,
    pub bundle_sha256: [u8; 32],
    pub bundle_bytes: usize,
    pub pack_bytes: usize,
    pub pack_objects: usize,
    pub expanded_bytes: usize,
    pub closure_objects: usize,
    pub transport_only_objects: usize,
    pub prerequisites: Vec<GitOid>,
    pub parents: Vec<GitOid>,
    pub merge_base: Option<GitOid>,
    pub candidate_commit_body: Vec<u8>,
}

#[derive(Debug)]
pub enum BundleInspectionRefusal {
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    Envelope(Box<super::NodeWorkspaceRefusal>),
    Pack(Box<PackError>),
    Source(MergeSourceError),
    Validation(ProjectionFailure),
    Review(Box<ReviewError>),
    SnapshotMoved,
    /// Hidden and absent refs intentionally have the same outcome.
    RefUnavailable,
    ParentMoved,
    InvalidCandidate(&'static str),
    BudgetExceeded,
}
impl std::fmt::Display for BundleInspectionRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "candidate inspection refused: {self:?}")
    }
}
impl std::error::Error for BundleInspectionRefusal {}
impl From<PackError> for BundleInspectionRefusal {
    fn from(error: PackError) -> Self { Self::Pack(Box::new(error)) }
}
fn invalid(message: &'static str) -> BundleInspectionRefusal {
    BundleInspectionRefusal::InvalidCandidate(message)
}

impl OneNode {
    /// Inspect a single-parent candidate without importing it into object fabric.
    /// The branch/base/candidate expectations are supplied independently of its
    /// untrusted envelope. Both metadata and content come from verified bytes.
    pub async fn inspect_workspace_bundle_in(
        &self, request: &NodeRequestContext, reference: &RefName,
        expected_base: GitOid, expected_candidate: GitOid, input: &[u8],
        visibility: &RefVisibility, expected_head: Option<RepositoryAuthorityHeadId>,
        options: &ReviewOptions,
    ) -> Result<BundleInspection, BundleInspectionRefusal> {
        self.inspect_bundle_in(request, reference, expected_base, expected_candidate, None,
            input, visibility, expected_head, options).await
    }

    /// Inspect the candidate's resulting tree, NOT the source-side PR diff.
    /// Ordered parents and common-base ancestry use the production validator.
    /// This does not assert that a specific merge algorithm produced the result.
    pub async fn inspect_merge_bundle_in(
        &self, request: &NodeRequestContext, merge: &NativeMerge, input: &[u8],
        visibility: &RefVisibility, expected_head: Option<RepositoryAuthorityHeadId>,
        options: &ReviewOptions,
    ) -> Result<BundleInspection, BundleInspectionRefusal> {
        merge.validate().map_err(|_| invalid("invalid native merge coordinates"))?;
        self.inspect_bundle_in(request, &merge.target_ref, merge.target_tip_before,
            merge.merge_commit, Some(merge), input, visibility, expected_head, options).await
    }

    async fn inspect_bundle_in(
        &self, request: &NodeRequestContext, reference: &RefName,
        expected_base: GitOid, candidate: GitOid, merge: Option<&NativeMerge>,
        input: &[u8], visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>, options: &ReviewOptions,
    ) -> Result<BundleInspection, BundleInspectionRefusal> {
        options.validate().map_err(|error| BundleInspectionRefusal::Review(Box::new(error)))?;
        if options.mode != ComparisonMode::Direct {
            return Err(invalid("candidate inspection requires direct target-to-result comparison"));
        }
        let envelope = CandidateEnvelope::parse_bounded(input, if merge.is_some() { MAX_PREREQUISITES } else { 1 })
            .map_err(|error| BundleInspectionRefusal::Envelope(Box::new(error)))?;
        envelope.bind(self.object_format, reference, expected_base, candidate)
            .map_err(|error| BundleInspectionRefusal::Envelope(Box::new(error)))?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(BundleInspectionRefusal::Cell)?;
        let additional = merge.map(|coordinates| &coordinates.source_ref);
        if visibility.hides(reference.as_bytes()) || additional.is_some_and(|name| visibility.hides(name.as_bytes())) {
            return Err(BundleInspectionRefusal::RefUnavailable);
        }
        let selected = self.materialize_admission_in(request).await
            .map_err(|error| BundleInspectionRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(BundleInspectionRefusal::SnapshotMoved);
        }
        if selected.snapshot().hidden_refs.hides(reference.as_bytes())
            || additional.is_some_and(|name| selected.snapshot().hidden_refs.hides(name.as_bytes()))
        { return Err(BundleInspectionRefusal::RefUnavailable); }
        let current = selected.snapshot().refs.get(reference).ok_or(BundleInspectionRefusal::RefUnavailable)?;
        if *current != expected_base { return Err(BundleInspectionRefusal::ParentMoved); }
        if let Some(coordinates) = merge {
            let current = selected.snapshot().refs.get(&coordinates.source_ref)
                .ok_or(BundleInspectionRefusal::RefUnavailable)?;
            if *current != coordinates.source_tip { return Err(BundleInspectionRefusal::ParentMoved); }
        }
        let exhaustion = Cell::new(None);
        let budget = ReadBudget { bytes: Cell::new(0), exhausted: Cell::new(false) };
        let maximum_object_bytes = usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX).min(32 * 1024 * 1024);
        let limits = MergeObjectLimits { max_object_bytes: maximum_object_bytes, ..MergeObjectLimits::default() };
        let original = OriginalSource {
            inner: VerifiedFabricPackSource {
                fabric: &self.fabric, object_format: self.object_format, maximum_object_bytes,
                database_context: request.authority(), database_exhaustion: &exhaustion, session_is_live: None,
            },
            allowed: selected.selected_closure().closure().objects(), budget: &budget,
        };
        let mut parents = vec![expected_base];
        if let Some(coordinates) = merge { parents.push(coordinates.source_tip); }
        // This traversal is rooted ONLY at the visible, independently selected
        // parents. A thin delta cannot use an unrelated hidden branch's blob
        // merely because the repository's cumulative admitted set contains it.
        let mut parent_objects = BTreeSet::new();
        for parent in &parents {
            let verified = validate_commit_closure(&original, *parent, limits, &mut || original.live().is_ok());
            original.live().map_err(BundleInspectionRefusal::Source)?;
            let verified = verified.map_err(BundleInspectionRefusal::Validation)?;
            parent_objects.extend(verified.objects);
            if parent_objects.len() > limits.max_objects { return Err(BundleInspectionRefusal::BudgetExceeded); }
        }
        let original = OriginalSource { allowed: &parent_objects, ..original };
        for prerequisite in &envelope.prerequisites {
            let object = original.read(*prerequisite).map_err(BundleInspectionRefusal::Source)?;
            if object.0 != ObjectType::Commit { return Err(invalid("prerequisite is not a selected parent-history commit")); }
        }
        let pack_limits = PackLimits {
            max_input_bytes: MAX_BUNDLE_BYTES, max_entries: MAX_INSPECTION_OBJECTS,
            max_object_bytes: maximum_object_bytes, max_total_expanded_bytes: MAX_EXPANDED_BYTES,
            max_cached_bytes: MAX_EXPANDED_BYTES, ..PackLimits::default()
        };
        let unpacked = pack::unpack(envelope.pack, self.object_format, &pack_limits, &original);
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let unpacked = unpacked?;
        let offered = unpacked.objects.get(&candidate).ok_or_else(|| invalid("candidate commit is not in this pack"))?;
        if offered.kind != ObjectType::Commit || offered.body.len() > MAX_CANDIDATE_BYTES {
            return Err(invalid("candidate must be a bounded commit in the uploaded pack"));
        }
        let source = InspectionSource {
            original: &original, objects: &unpacked.objects,
            parse_limits: ParseLimits {
                max_object_bytes: maximum_object_bytes, tree_reference_bytes: self.object_format.digest_len(),
                max_tree_entries: options.limits.max_tree_entries, ..ParseLimits::default()
            },
        };
        let validation = match merge {
            Some(coordinates) => validate_merge_objects(&source, coordinates, limits, &mut || original.live().is_ok()),
            None => validate_workspace_objects(&source, candidate, expected_base, limits, &mut || original.live().is_ok()),
        };
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let validation = validation.map_err(BundleInspectionRefusal::Validation)?;
        let transport_only_objects = unpacked.check_coverage(&validation.objects)?;
        let comparison = compare_source(&source, self.object_format, expected_base, candidate, options);
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let comparison = comparison.map_err(|error| BundleInspectionRefusal::Review(Box::new(error)))?;
        let candidate_commit_body = offered.body.clone();
        let digest = sha256_digest(input);
        original.live().map_err(BundleInspectionRefusal::Source)?;
        Ok(BundleInspection {
            review: SourceReview { repository_id: self.repository_id, source_head: selected.basis().id(),
                before_reference: reference.clone(), after_reference: reference.clone(), pull_request: None, comparison },
            bundle_sha256: digest, bundle_bytes: input.len(), pack_bytes: envelope.pack.len(),
            pack_objects: unpacked.objects.len(), expanded_bytes: unpacked.expanded_bytes,
            closure_objects: validation.objects.len(), transport_only_objects,
            prerequisites: envelope.prerequisites, parents, merge_base: merge.map(|coordinates| coordinates.base_tip),
            candidate_commit_body,
        })
    }
}

struct ReadBudget { bytes: Cell<usize>, exhausted: Cell<bool> }
struct OriginalSource<'a> {
    inner: VerifiedFabricPackSource<'a>,
    allowed: &'a BTreeSet<GitOid>,
    budget: &'a ReadBudget,
}
impl OriginalSource<'_> {
    fn live(&self) -> Result<(), MergeSourceError> {
        if self.budget.exhausted.get() || self.inner.database_exhaustion.get().is_some() {
            return Err(MergeSourceError::BudgetExceeded);
        }
        match checkpoint_pack_context(self.inner.database_context) {
            PackContextCheckpoint::Live => Ok(()),
            PackContextCheckpoint::Stopped { budget_exhaustion: Some(_) } => Err(MergeSourceError::BudgetExceeded),
            PackContextCheckpoint::Stopped { budget_exhaustion: None } => Err(MergeSourceError::Cancelled),
        }
    }
    fn read(&self, id: GitOid) -> Result<(ObjectType, Vec<u8>), MergeSourceError> {
        self.live()?;
        if !self.allowed.contains(&id) { return Err(MergeSourceError::OutsideSelection); }
        let result = self.inner.read_object(&id);
        self.live()?;
        let (kind, body) = result.map_err(|_| MergeSourceError::Unavailable(id))?;
        let total = self.budget.bytes.get().checked_add(body.len()).filter(|bytes| *bytes <= MAX_ORIGINAL_READ_BYTES);
        let Some(total) = total else {
            self.budget.exhausted.set(true); return Err(MergeSourceError::BudgetExceeded);
        };
        self.budget.bytes.set(total);
        if git_object_id(self.inner.object_format, kind, &body) != id {
            return Err(MergeSourceError::InvalidObject(id));
        }
        self.live()?;
        Ok((kind, body))
    }
}
impl CanonicalObjectSource for OriginalSource<'_> {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self.read(*id).map_err(|error| pack_source_error(error, *id))?;
        Ok(CanonicalPackObject::new(*id, kind, body, Vec::new(), 0, 0))
    }
}
fn pack_source_error(error: MergeSourceError, id: GitOid) -> PackWriteError {
    match error {
        MergeSourceError::Cancelled | MergeSourceError::BudgetExceeded => PackError::DeadlineExceeded.into(),
        _ => PackWriteError::MissingCanonicalObject(id),
    }
}
struct InspectionSource<'a, 'b> {
    original: &'a OriginalSource<'b>,
    objects: &'a BTreeMap<GitOid, PlannedMergeObject>,
    parse_limits: ParseLimits,
}
impl InspectionSource<'_, '_> {
    fn read(&self, id: GitOid, expected: Option<ObjectType>) -> Result<(ObjectType, Vec<u8>), MergeSourceError> {
        self.original.live()?;
        let (kind, bytes) = match self.objects.get(&id) {
            Some(object) => (object.kind, object.body.clone()),
            None => self.original.read(id)?,
        };
        if expected.is_some_and(|expected| kind != expected) { return Err(MergeSourceError::InvalidObject(id)); }
        self.original.live()?;
        Ok((kind, bytes))
    }
    fn oid(&self, bytes: &[u8], owner: GitOid) -> Result<GitOid, MergeSourceError> {
        let value = std::str::from_utf8(bytes).map_err(|_| MergeSourceError::InvalidObject(owner))?;
        GitOid::from_hex(self.original.inner.object_format, &value.to_ascii_lowercase())
            .map_err(|_| MergeSourceError::InvalidObject(owner))
    }
}
impl CanonicalObjectSource for InspectionSource<'_, '_> {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self.read(*id, None).map_err(|error| pack_source_error(error, *id))?;
        Ok(CanonicalPackObject::new(*id, kind, body, Vec::new(), 0, 0))
    }
}
impl MergeObjectSource for InspectionSource<'_, '_> {
    fn checkpoint(&self) -> Result<(), MergeSourceError> { self.original.live() }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        let (_, bytes) = self.read(id, Some(ObjectType::Commit))?;
        let ParsedObject::Commit(commit) = parse_object_body(ObjectType::Commit, &bytes,
            AcceptanceProfile::GitCompatibleImport, &self.parse_limits).map_err(|_| MergeSourceError::InvalidObject(id))?
        else { return Err(MergeSourceError::InvalidObject(id)); };
        if commit.headers().iter().filter(|header| header.name == b"tree").count() != 1
            || commit.headers().iter().any(|header| (header.name == b"tree" || header.name == b"parent") && !header.continuations.is_empty())
        { return Err(MergeSourceError::InvalidObject(id)); }
        let tree = self.oid(commit.tree_reference().ok_or(MergeSourceError::InvalidObject(id))?, id)?;
        let parents = commit.parent_references().map(|value| self.oid(value, id)).collect::<Result<Vec<_>, _>>()?;
        self.checkpoint()?;
        Ok(CommitInput { tree, parents })
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        let (_, bytes) = self.read(id, Some(ObjectType::Tree))?;
        let ParsedObject::Tree(entries) = parse_object_body(ObjectType::Tree, &bytes,
            AcceptanceProfile::GitCompatibleImport, &self.parse_limits).map_err(|_| MergeSourceError::InvalidObject(id))?
        else { return Err(MergeSourceError::InvalidObject(id)); };
        let mut result = Vec::with_capacity(entries.len());
        for entry in entries {
            self.checkpoint()?;
            let mode = std::str::from_utf8(&entry.mode).ok().and_then(|value| u32::from_str_radix(value, 8).ok())
                .ok_or(MergeSourceError::InvalidObject(id))?;
            let hex: String = entry.object_id.iter().map(|byte| format!("{byte:02x}")).collect();
            result.push(MergeEntry { name: entry.name, mode, oid: self.oid(hex.as_bytes(), id)? });
        }
        Ok(result)
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.read(id, Some(ObjectType::Blob)).map(|(_, bytes)| bytes)
    }
}
