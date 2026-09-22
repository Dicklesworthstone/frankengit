//! Candidate execution enters the same preflight, journal and job driver as
//! canonical source. Only input provenance and the host plan constructor differ.
mod merge;
use super::*;
use fgit_forge::event::NativeMerge;
use fgit_treefs::{SparseCandidateManifest, SparseEntry};

pub(super) enum WorkflowInputs<A: GitHashAlgorithm> {
    Canonical(Arc<SparseManifest<A>>),
    Candidate {
        manifest: Arc<SparseCandidateManifest<A>>,
        bundle_sha256: [u8; 32],
        merge: Option<NativeMerge>,
    },
}
impl<A: GitHashAlgorithm> WorkflowInputs<A> {
    pub(super) fn entries(&self) -> &[SparseEntry<A>] {
        match self {
            Self::Canonical(m) => m.entries(),
            Self::Candidate { manifest, .. } => manifest.entries(),
        }
    }
    pub(super) fn payload_bytes(&self) -> usize {
        match self {
            Self::Canonical(m) => m.receipt().payload_bytes(),
            Self::Candidate { manifest, .. } => manifest.payload_bytes(),
        }
    }
    pub(super) fn host_plan(
        &self,
        capability: &TreeCapability,
    ) -> Result<SparseWorkspacePlan<A>, HostRefusal> {
        match self {
            Self::Canonical(m) => {
                SparseWorkspacePlan::new(Arc::clone(m), Vec::new(), capability, 0, SOURCE_LIMITS)
            }
            Self::Candidate { manifest, .. } => SparseWorkspacePlan::for_candidate(
                Arc::clone(manifest),
                capability,
                0,
                SOURCE_LIMITS,
            ),
        }
    }
    pub(super) fn merge(&self) -> Option<&NativeMerge> {
        match self {
            Self::Canonical(_) => None,
            Self::Candidate { merge, .. } => merge.as_ref(),
        }
    }
    pub(super) fn coordinates(
        &self,
        format: Format,
    ) -> Result<
        (
            RepositoryCommitId,
            GitOid,
            GitOid,
            Option<TrustedWorkflowCandidate>,
        ),
        TrustedWorkflowFailure,
    > {
        let native = |bytes: &[u8]| {
            GitOid::from_hex(format, &hex(bytes))
                .map_err(|_| TrustedWorkflowFailure::InvalidInput("source identity width"))
        };
        match self {
            Self::Canonical(m) => Ok((
                m.receipt().source_rcr_id(),
                native(m.receipt().source_commit_oid().digest_bytes())?,
                native(m.receipt().source_tree_oid().digest_bytes())?,
                None,
            )),
            Self::Candidate {
                manifest: m,
                bundle_sha256,
                merge,
            } => {
                let base = native(m.base_commit_oid().digest_bytes())?;
                let commit = native(m.candidate_commit_oid().digest_bytes())?;
                let parents = m
                    .parents()
                    .iter()
                    .map(|id| native(id.digest_bytes()))
                    .collect::<Result<Vec<_>, _>>()?;
                match merge {
                    Some(merge)
                        if base == merge.target_tip_before
                            && commit == merge.merge_commit
                            && parents == [merge.target_tip_before, merge.source_tip] => {}
                    None if parents == [base] => {}
                    _ => {
                        return Err(TrustedWorkflowFailure::InvalidInput(
                            "workflow provenance differs from verified native parents",
                        ));
                    }
                }
                Ok((
                    m.base_rcr_id(),
                    base,
                    native(m.base_tree_oid().digest_bytes())?,
                    Some(TrustedWorkflowCandidate {
                        commit,
                        tree: native(m.candidate_tree_oid().digest_bytes())?,
                        bundle_sha256: *bundle_sha256,
                    }),
                ))
            }
        }
    }
}
pub(super) fn merge_json(merge: Option<&NativeMerge>) -> String {
    merge.map_or_else(
        || "null".to_owned(),
        |m| {
            format!(
                concat!(
                    "{{\"target_ref_hex\":\"{}\",\"target_tip\":\"{}\",\"source_ref_hex\":\"{}\",",
                    "\"source_tip\":\"{}\",\"merge_base\":\"{}\",\"candidate_commit\":\"{}\",",
                    "\"parents\":[\"{}\",\"{}\"],\"published\":false,\"approval_created\":false}}"
                ),
                hex(m.target_ref.as_bytes()),
                m.target_tip_before,
                hex(m.source_ref.as_bytes()),
                m.source_tip,
                m.base_tip,
                m.merge_commit,
                m.target_tip_before,
                m.source_tip
            )
        },
    )
}

impl OneNode {
    /// Execute an explicitly trusted unpublished single-parent candidate without
    /// staging objects, updating refs, or creating canonical check evidence.
    /// `coordinates` is (expected canonical base, independently reviewed candidate).
    /// The workflow AND all inputs come from the verified candidate tree. The
    /// local owner must therefore trust candidate scripts, not just base scripts.
    ///
    /// Exact base/ref/head checks and full native bundle validation finish before
    /// any attempt directory or process. All subsequent execution, fresh job
    /// copies, limits, journals, no-replay rules and cleanup use the ordinary
    /// trusted workflow driver. Preparation/validation consumes the run deadline.
    /// This is not a network endpoint or hostile-code sandbox.
    pub async fn run_trusted_candidate_workflow_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        coordinates: (GitOid, GitOid),
        bundle: &[u8],
        workflow_path: &[u8],
        run_id: [u8; 16],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        expected_head: Option<RepositoryAuthorityHeadId>,
        limits: WorkflowLimits,
    ) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
        limits
            .validate()
            .map_err(TrustedWorkflowFailure::Workflow)?;
        let paths = validate_inputs(workflow_path, run_id, parent, read_prefixes)?;
        let started = Instant::now();
        match self.object_format {
            Format::Sha1 => {
                self.run_candidate_format::<Sha1>(
                    request,
                    reference,
                    coordinates,
                    bundle,
                    workflow_path,
                    run_id,
                    parent,
                    paths,
                    expected_head,
                    limits,
                    started,
                )
                .await
            }
            Format::Sha256 => {
                self.run_candidate_format::<Sha256>(
                    request,
                    reference,
                    coordinates,
                    bundle,
                    workflow_path,
                    run_id,
                    parent,
                    paths,
                    expected_head,
                    limits,
                    started,
                )
                .await
            }
        }
    }
    async fn run_candidate_format<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        coordinates: (GitOid, GitOid),
        bundle: &[u8],
        workflow_path: &[u8],
        run_id: [u8; 16],
        parent: &Path,
        paths: Vec<TreePath>,
        expected_head: Option<RepositoryAuthorityHeadId>,
        limits: WorkflowLimits,
        started: Instant,
    ) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
        let bytes = ByteCount::try_new("candidate workflow source", FETCH_BYTES, FETCH_BYTES)
            .map_err(|_| TrustedWorkflowFailure::InvalidInput("source budget"))?;
        let declared = paths
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let mut capability = TreeCapability::new(
            WorkspaceId::from_bytes(run_id),
            self.repository_id(),
            paths,
            Vec::new(),
        )
        .with_fetch_budget(bytes)
        .with_file_budget(FETCH_OBJECTS);
        let (head, manifest, bundle_sha256) = self
            .sparse_candidate_manifest_in::<A>(
                request,
                reference,
                coordinates.0,
                coordinates.1,
                bundle,
                &Default::default(),
                expected_head,
                &mut capability,
                0,
                SOURCE_LIMITS,
            )
            .await
            .map_err(|error| TrustedWorkflowFailure::Candidate(Box::new(error)))?;
        run_inputs(
            self,
            request,
            WorkflowInputs::Candidate {
                manifest: Arc::new(manifest),
                bundle_sha256,
                merge: None,
            },
            &capability,
            head,
            reference,
            workflow_path,
            &declared,
            run_id,
            parent,
            limits,
            started,
        )
    }
}
