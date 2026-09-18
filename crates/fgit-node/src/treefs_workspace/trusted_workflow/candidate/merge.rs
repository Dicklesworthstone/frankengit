//! Explicit trusted execution of the actual reviewed merge result.
use super::*;

impl OneNode {
    /// Run checks on a two-parent candidate WITHOUT publishing it or creating a
    /// temporary canonical ref. The caller is the trusted local operator and
    /// must review the candidate's workflow, not just either parent version.
    ///
    /// Validate both current branch pins at one head, ordered native parents,
    /// common-base ancestry, full object closure and exact prerequisites before
    /// any host attempt. Sparse inputs, graph preflight, fresh job copies,
    /// execution, timeout, no-replay journal and cleanup all use the existing
    /// trusted workflow implementation. Validation consumes the run deadline.
    ///
    /// The persisted attempt/result names target, incoming, common base, actual
    /// candidate and bundle bytes. It is not a PR-version attestation or green
    /// check; later publication must pass its independent current policy/CAS.
    /// No remote endpoint, hostile-code isolation or automatic retry is added.
    pub async fn run_trusted_merge_workflow_in(
        &self, request: &NodeRequestContext, merge: &NativeMerge, bundle: &[u8],
        workflow_path: &[u8], run_id: [u8; 16], parent: &Path, read_prefixes: &[Vec<u8>],
        expected_head: Option<RepositoryAuthorityHeadId>, limits: WorkflowLimits,
    ) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
        limits.validate().map_err(TrustedWorkflowFailure::Workflow)?;
        let paths = validate_inputs(workflow_path, run_id, parent, read_prefixes)?;
        let started = Instant::now();
        match self.object_format {
            Format::Sha1 => self.run_merge_candidate_format::<Sha1>(request, merge, bundle,
                workflow_path, run_id, parent, paths, expected_head, limits, started).await,
            Format::Sha256 => self.run_merge_candidate_format::<Sha256>(request, merge, bundle,
                workflow_path, run_id, parent, paths, expected_head, limits, started).await,
        }
    }

    async fn run_merge_candidate_format<A: GitHashAlgorithm>(
        &self, request: &NodeRequestContext, merge: &NativeMerge, bundle: &[u8],
        workflow_path: &[u8], run_id: [u8; 16], parent: &Path, paths: Vec<TreePath>,
        expected_head: Option<RepositoryAuthorityHeadId>, limits: WorkflowLimits, started: Instant,
    ) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
        let bytes = ByteCount::try_new("merge workflow source", FETCH_BYTES, FETCH_BYTES)
            .map_err(|_| TrustedWorkflowFailure::InvalidInput("source budget"))?;
        let declared = paths.iter().map(|path| path.as_bytes().to_vec()).collect::<Vec<_>>();
        let mut capability = TreeCapability::new(WorkspaceId::from_bytes(run_id), self.repository_id(),
            paths, Vec::new()).with_fetch_budget(bytes).with_file_budget(FETCH_OBJECTS);
        let (head, manifest, bundle_sha256) = self.sparse_merge_candidate_manifest_in::<A>(request,
            merge, bundle, &Default::default(), expected_head, &mut capability, 0, SOURCE_LIMITS).await
            .map_err(|error| TrustedWorkflowFailure::Candidate(Box::new(error)))?;
        run_inputs(self, request, WorkflowInputs::Candidate {
            manifest: Arc::new(manifest), bundle_sha256, merge: Some(merge.clone()),
        }, &capability, head, &merge.target_ref, workflow_path, &declared, run_id, parent, limits, started)
    }
}
