//! Explicit trusted execution of an already prepared complete rebase series.
use super::{
    Arc, ByteCount, FETCH_BYTES, FETCH_OBJECTS, Format, GitHashAlgorithm, GitOid, Instant,
    NativeMerge, NativeObjectIdentity, NodeRequestContext, OneNode, Path,
    RepositoryAuthorityHeadId, SOURCE_LIMITS, Sha1, Sha256, TreeCapability, TreePath,
    TrustedWorkflowArtifactConfig, TrustedWorkflowFailure, TrustedWorkflowRebase,
    TrustedWorkflowRun, WorkflowInputs, WorkflowLimits, WorkspaceId, artifacts, hex, run_inputs,
    validate_inputs, workspace_request_live,
};

impl OneNode {
    /// Execute the final tree and scripts of an explicit unpublished linear
    /// rebase candidate. Validate both current original branch pins, common-base
    /// ancestry, every original and rewritten commit, target-only prerequisites,
    /// complete intermediate object closures and pack coverage before reserving
    /// any execution slot. No merge/squash fallback or automatic preparation.
    ///
    /// This is the existing Linux trusted-local runner: private fresh job copies,
    /// finite budgets, journal custody, no replay and mandatory cleanup remain
    /// unchanged. Input prefixes narrow copied repository files, not host access.
    /// No object, ref, PR version, review or check is published by execution.
    pub async fn run_trusted_rebase_workflow_in(
        &self,
        request: &NodeRequestContext,
        merge: &NativeMerge,
        bundle: &[u8],
        workflow_path: &[u8],
        run_id: [u8; 16],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        expected_head: Option<RepositoryAuthorityHeadId>,
        limits: WorkflowLimits,
        artifacts: Option<&TrustedWorkflowArtifactConfig>,
    ) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
        if artifacts.is_some_and(|config| {
            config
                .selected_workflows()
                .any(|path| path != workflow_path)
        }) {
            return Err(TrustedWorkflowFailure::InvalidInput(
                "single-run artifact selections must name the selected workflow",
            ));
        }
        limits
            .validate()
            .map_err(TrustedWorkflowFailure::Workflow)?;
        let paths = validate_inputs(workflow_path, run_id, parent, read_prefixes)?;
        let started = Instant::now();
        match self.object_format {
            Format::Sha1 => {
                self.run_rebase_candidate_format::<Sha1>(
                    request,
                    merge,
                    bundle,
                    workflow_path,
                    run_id,
                    parent,
                    paths,
                    expected_head,
                    limits,
                    started,
                    artifacts,
                )
                .await
            }
            Format::Sha256 => {
                self.run_rebase_candidate_format::<Sha256>(
                    request,
                    merge,
                    bundle,
                    workflow_path,
                    run_id,
                    parent,
                    paths,
                    expected_head,
                    limits,
                    started,
                    artifacts,
                )
                .await
            }
        }
    }

    async fn run_rebase_candidate_format<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        merge: &NativeMerge,
        bundle: &[u8],
        workflow_path: &[u8],
        run_id: [u8; 16],
        parent: &Path,
        paths: Vec<TreePath>,
        expected_head: Option<RepositoryAuthorityHeadId>,
        limits: WorkflowLimits,
        started: Instant,
        artifacts: Option<&TrustedWorkflowArtifactConfig>,
    ) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
        let bytes = ByteCount::try_new("rebase workflow source", FETCH_BYTES, FETCH_BYTES)
            .map_err(|_| TrustedWorkflowFailure::InvalidInput("source budget"))?;
        let declared = paths
            .iter()
            .map(|path| path.as_bytes().to_vec())
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
            .sparse_rebase_candidate_manifest_in::<A>(
                request,
                merge,
                bundle,
                &Default::default(),
                expected_head,
                &mut capability,
                0,
                SOURCE_LIMITS,
            )
            .await
            .map_err(|error| TrustedWorkflowFailure::Candidate(Box::new(error)))?;
        if !workspace_request_live(request) || started.elapsed() >= limits.run_timeout {
            return Err(TrustedWorkflowFailure::InvalidInput(
                "request stopped before artifact capture setup",
            ));
        }
        let [parent_id] = manifest.parents() else {
            return Err(TrustedWorkflowFailure::InvalidInput(
                "verified rebase final parent missing",
            ));
        };
        let parent_id = GitOid::from_hex(self.object_format, &hex(parent_id.digest_bytes()))
            .map_err(|_| TrustedWorkflowFailure::InvalidInput("rebase parent identity width"))?;
        let artifact_session = artifacts
            .map(|config| artifacts::Session::open(self, config))
            .transpose()?;
        run_inputs(
            self,
            request,
            WorkflowInputs::Rebase {
                manifest: Arc::new(manifest),
                bundle_sha256,
                rebase: TrustedWorkflowRebase {
                    merge: merge.clone(),
                    parent: parent_id,
                },
            },
            &capability,
            head,
            &merge.target_ref,
            workflow_path,
            &declared,
            run_id,
            parent,
            limits,
            started,
            artifact_session.as_ref(),
            None,
            true,
        )
    }
}
