//! All selected definitions run against one verified, unpublished merge tree.
//! No second scheduler, temporary ref, automatic preparation or check grant.
use super::{
    Arc, ByteCount, ComparisonMode, FETCH_BYTES, FETCH_OBJECTS, Format, GitHashAlgorithm, Instant,
    Mutex, NodeRequestContext, NodeWorkspaceRefusal, OneNode, Path, RepositoryAuthorityHeadId,
    SOURCE_LIMITS, Sha1, Sha256, TreeCapability, TreePath, TrustedWorkflowArtifactConfig,
    TrustedWorkflowDispatch, TrustedWorkflowFailure, WorkflowInputs, WorkflowLimits, WorkspaceId,
    dispatch_at, validate_inputs,
};
use fgit_forge::{event::NativeMerge, preparation::MergeCommitStyle};

impl OneNode {
    /// Dispatch direct YAML children of a reviewed merge or squash candidate.
    /// Both branches, ordered parents, prerequisites, ancestry and bundle bytes
    /// are verified before batch reservation. Definitions AND inputs come from
    /// that exact candidate, never from either canonical parent.
    ///
    /// The event is explicit local operator intent, not proof of a PR event.
    /// pull_request branch filters use the verified target branch; path filters
    /// use the complete canonical source change from its unique merge base.
    /// workflow_dispatch ignores push/PR filters. No push event is synthesized.
    ///
    /// Every child shares the existing dispatch deadline, output, artifact and
    /// materialization budgets. Any occupied batch refuses, including after a
    /// crash. Retain its plan and child journals for ordinary check recovery.
    /// Scripts have trusted-host privileges. This does not publish the candidate,
    /// a check or an approval, and does not change source-head watcher semantics.
    pub async fn dispatch_trusted_merge_workflows_in(
        &self,
        request: &NodeRequestContext,
        merge: &NativeMerge,
        bundle: &[u8],
        style: MergeCommitStyle,
        directory: &[u8],
        event: &str,
        run_id: [u8; 16],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        expected_head: Option<RepositoryAuthorityHeadId>,
        limits: WorkflowLimits,
        artifacts: Option<&TrustedWorkflowArtifactConfig>,
    ) -> Result<TrustedWorkflowDispatch, TrustedWorkflowFailure> {
        if !matches!(event, "pull_request" | "workflow_dispatch") {
            return Err(TrustedWorkflowFailure::InvalidInput(
                "merge dispatch requires pull_request or workflow_dispatch",
            ));
        }
        limits
            .validate()
            .map_err(TrustedWorkflowFailure::Workflow)?;
        let paths = validate_inputs(directory, run_id, parent, read_prefixes)?;
        let started = Instant::now();
        match self.object_format {
            Format::Sha1 => {
                self.dispatch_merge_format::<Sha1>(
                    request,
                    merge,
                    bundle,
                    style,
                    directory,
                    event,
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
                self.dispatch_merge_format::<Sha256>(
                    request,
                    merge,
                    bundle,
                    style,
                    directory,
                    event,
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

    async fn dispatch_merge_format<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        merge: &NativeMerge,
        bundle: &[u8],
        style: MergeCommitStyle,
        directory: &[u8],
        event: &str,
        run_id: [u8; 16],
        parent: &Path,
        paths: Vec<TreePath>,
        expected_head: Option<RepositoryAuthorityHeadId>,
        limits: WorkflowLimits,
        started: Instant,
        artifacts: Option<&TrustedWorkflowArtifactConfig>,
    ) -> Result<TrustedWorkflowDispatch, TrustedWorkflowFailure>
    where
        WorkflowInputs<A>: Send,
    {
        let bytes = ByteCount::try_new("merge dispatch source", FETCH_BYTES, FETCH_BYTES)
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
            .sparse_merge_candidate_manifest_with_style_in::<A>(
                request,
                merge,
                bundle,
                &Default::default(),
                expected_head,
                &mut capability,
                0,
                SOURCE_LIMITS,
                style,
            )
            .await
            .map_err(|e| TrustedWorkflowFailure::Candidate(Box::new(e)))?;
        let inputs = WorkflowInputs::Candidate {
            manifest: Arc::new(manifest),
            bundle_sha256,
            merge: Some((merge.clone(), style)),
        };
        let observed = Mutex::new(None);
        // Retain the verified canonical object owner for optional changed-path
        // selection, with the SAME authenticated head as candidate validation.
        // A concurrent source/target/authority change refuses before any script.
        let selected = self
            .with_workspace_snapshot_in::<A, _>(
                request,
                &merge.target_ref,
                &Default::default(),
                &mut capability,
                0,
                Some(head),
                Some(merge.target_tip_before),
                SOURCE_LIMITS.max_entry_bytes,
                |_, source, capability, selected_head, _| {
                    let report = dispatch_at(
                        self,
                        request,
                        inputs,
                        capability,
                        selected_head,
                        &merge.target_ref,
                        directory,
                        event,
                        run_id,
                        parent,
                        &declared,
                        limits,
                        started,
                        artifacts,
                        Some(&merge.target_ref),
                        source,
                        Some((Some(merge.target_tip_before), ComparisonMode::MergeBase)),
                    );
                    *observed
                        .lock()
                        .map_err(|_| NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)? =
                        Some(report);
                    Ok(())
                },
            )
            .await;
        let observed = observed.into_inner().map_err(|_| {
            TrustedWorkflowFailure::InvalidInput("merge dispatch result lock poisoned")
        })?;
        match (selected, observed) {
            (_, Some(Err(error))) => Err(error),
            (Ok(()) | Err(NodeWorkspaceRefusal::Cancelled { .. }), Some(Ok(report))) => Ok(report),
            (Err(error), Some(Ok(report))) => Err(TrustedWorkflowFailure::Journal {
                directory: report.run_directory,
                detail: format!(
                    "merge dispatch source finalization failed after execution: {error}; inspect saved reports, do not replay"
                ),
            }),
            (Err(error), None) => Err(TrustedWorkflowFailure::Source(error)),
            (Ok(()), None) => Err(TrustedWorkflowFailure::InvalidInput(
                "merge dispatch consumer did not complete",
            )),
        }
    }
}
