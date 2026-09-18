//! Verified unpublished candidate inputs for trusted local execution.
//! Pack validation and original-object selection are the existing stage-free
//! inspection engines. A materialization manifest cannot admit its candidate.

use super::*;
use fgit_crypto::{GitHashAlgorithm as Hash, NativeObjectIdentity};
use fgit_treefs::{BaseView, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant,
    SparseCandidateManifest, SparseLimits, TreeCapability, WorkspaceId};
use crate::ClosureSelectionSource;

impl OneNode {
    /// Build capability-scoped inputs from an exact single-parent bundle at one
    /// authenticated base snapshot. No uploaded object is staged or published.
    /// The manifest's BASE RCR and candidate commit/tree are separate values.
    ///
    /// Whole candidate closure and pack coverage are verified before sparse
    /// discovery. Only base-reachable originals can satisfy delta references or
    /// missing candidate dependencies; cumulative admitted objects are not a
    /// substitute for the advertised prerequisite. This method runs no tools.
    pub async fn sparse_candidate_manifest_in<A: Hash>(
        &self, request: &NodeRequestContext, reference: &RefName,
        expected_base: GitOid, candidate: GitOid, input: &[u8],
        visibility: &RefVisibility, expected_head: Option<RepositoryAuthorityHeadId>,
        capability: &mut TreeCapability, now: u64, sparse: SparseLimits,
    ) -> Result<(RepositoryAuthorityHeadId, SparseCandidateManifest<A>, [u8; 32]), BundleInspectionRefusal> {
        if A::DIGEST_LEN != self.object_format.digest_len()
            || capability.repository_id() != self.repository_id
            || sparse.max_entries == 0 || sparse.max_entries > 10_000
            || sparse.max_entry_bytes == 0 || sparse.max_entry_bytes > 16 * 1024 * 1024
            || sparse.max_payload_bytes == 0 || sparse.max_payload_bytes > 64 * 1024 * 1024
            || sparse.max_entry_bytes > sparse.max_payload_bytes
        { return Err(invalid("invalid candidate input scope, format or limits")); }
        capability.authorize_root(now).map_err(|_| invalid("candidate input capability refused"))?;
        let envelope = CandidateEnvelope::parse(input)
            .map_err(|e| BundleInspectionRefusal::Envelope(Box::new(e)))?;
        envelope.bind(self.object_format, reference, expected_base, candidate)
            .map_err(|e| BundleInspectionRefusal::Envelope(Box::new(e)))?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(BundleInspectionRefusal::Cell)?;
        if visibility.hides(reference.as_bytes()) { return Err(BundleInspectionRefusal::RefUnavailable); }
        let selected = self.materialize_admission_in(request).await
            .map_err(|e| BundleInspectionRefusal::Authority(Box::new(e)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(BundleInspectionRefusal::SnapshotMoved);
        }
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(BundleInspectionRefusal::RefUnavailable);
        }
        let actual = selected.snapshot().refs.get(reference).ok_or(BundleInspectionRefusal::RefUnavailable)?;
        if *actual != expected_base { return Err(BundleInspectionRefusal::ParentMoved); }
        let rcr = match selected.selected_closure().source() {
            ClosureSelectionSource::RepositoryCommit(rcr)
            | ClosureSelectionSource::CumulativeHistory { latest: rcr, .. } => rcr,
            ClosureSelectionSource::EmptyGenesis => return Err(BundleInspectionRefusal::RefUnavailable),
        };
        let exhaustion = Cell::new(None);
        let budget = ReadBudget { bytes: Cell::new(0), exhausted: Cell::new(false) };
        let maximum = usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX)
            .min(sparse.max_entry_bytes.max(MAX_CANDIDATE_BYTES));
        let original = OriginalSource {
            inner: VerifiedFabricPackSource { fabric: &self.fabric, object_format: self.object_format,
                maximum_object_bytes: maximum, database_context: request.authority(),
                database_exhaustion: &exhaustion, session_is_live: None },
            allowed: selected.selected_closure().closure().objects(), budget: &budget,
        };
        let limits = MergeObjectLimits { max_object_bytes: maximum, ..Default::default() };
        let base = validate_commit_closure(&original, expected_base, limits, &mut || original.live().is_ok());
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let base = base.map_err(BundleInspectionRefusal::Validation)?;
        let original = OriginalSource { allowed: &base.objects, ..original };
        let pack_limits = PackLimits { max_input_bytes: MAX_BUNDLE_BYTES,
            max_entries: MAX_INSPECTION_OBJECTS, max_object_bytes: maximum,
            max_total_expanded_bytes: MAX_EXPANDED_BYTES, max_cached_bytes: MAX_EXPANDED_BYTES,
            ..Default::default() };
        let unpacked = pack::unpack(envelope.pack, self.object_format, &pack_limits, &original);
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let unpacked = unpacked?;
        let offered = unpacked.objects.get(&candidate).ok_or_else(|| invalid("candidate commit is absent from the pack"))?;
        if offered.kind != ObjectType::Commit || offered.body.len() > MAX_CANDIDATE_BYTES {
            return Err(invalid("candidate is not a bounded uploaded commit"));
        }
        let source = InspectionSource { original: &original, objects: &unpacked.objects,
            parse_limits: ParseLimits { max_object_bytes: maximum,
                tree_reference_bytes: self.object_format.digest_len(), ..Default::default() } };
        let verified = validate_workspace_objects(&source, candidate, expected_base, limits, &mut || original.live().is_ok());
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let verified = verified.map_err(BundleInspectionRefusal::Validation)?;
        unpacked.check_coverage(&verified.objects)?;
        let base_commit = source.commit(expected_base).map_err(BundleInspectionRefusal::Source)?;
        let typed = |id: GitOid| A::parse_hex(&id.to_string()).map_err(|_| invalid("candidate input identity format"));
        let base_view = BaseView::new(self.repository_id, rcr, typed(expected_base)?,
            typed(base_commit.tree)?, source.parse_limits.clone(), PathPolicy::default());
        let tree_source = CandidateTreeSource { source: &source, workspace: capability.workspace_id() };
        let manifest = SparseCandidateManifest::build(&base_view, &tree_source, typed(candidate)?,
            capability, now, source.parse_limits.clone(), sparse);
        // Preserve cancellation/resource cause even when the TreeFS trait's
        // object-source error cannot represent the node's request context.
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let manifest = manifest.map_err(|_| invalid("candidate sparse input discovery refused"))?;
        let digest = sha256_digest(input);
        original.live().map_err(BundleInspectionRefusal::Source)?;
        Ok((selected.basis().id(), manifest, digest))
    }
}

struct CandidateTreeSource<'a, 'b, 'c> {
    source: &'a InspectionSource<'b, 'c>,
    workspace: WorkspaceId,
}
impl<A: Hash> ObjectSource<A> for CandidateTreeSource<'_, '_, '_> {
    fn read_object(&self, oid: &fgit_crypto::GitOid<A>, kind: fgit_crypto::GitObjectKind,
        grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        let refused = |reason: &str| ObjectSourceError::Refused { reason: reason.to_owned() };
        if grant.workspace_id() != self.workspace { return Err(refused("workspace grant mismatch")); }
        let hex: String = oid.digest_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let id = GitOid::from_hex(self.source.original.inner.object_format, &hex)
            .map_err(|_| refused("candidate hash domain mismatch"))?;
        let expected = match kind {
            fgit_crypto::GitObjectKind::Blob => ObjectType::Blob,
            fgit_crypto::GitObjectKind::Tree => ObjectType::Tree,
            fgit_crypto::GitObjectKind::Commit => ObjectType::Commit,
            fgit_crypto::GitObjectKind::Tag => ObjectType::Tag,
        };
        self.source.read(id, Some(expected)).map(|(_, bytes)| bytes)
            .map_err(|_| refused("candidate object unavailable within selected base and upload"))
    }
}
