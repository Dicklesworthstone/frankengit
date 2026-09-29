//! One explicit local dispatch, not an unattended or remotely trusted trigger.
//! All definitions and inputs come from one immutable authenticated snapshot.

use super::super::*;
use fgit_crypto::sha256_digest;
use fgit_runner::workflow::{JobOutcome, MAX_JOBS, MAX_STEPS};

const MAX_WORKFLOWS: usize = 32;
const MAX_WORKFLOW_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
struct Definition {
    path: Vec<u8>,
    blob: GitOid,
    graph: [u8; 32],
    run_id: [u8; 16],
    selected: bool,
}

/// Durable multi-workflow execution observations. No member grants approval.
#[derive(Debug)]
pub struct TrustedWorkflowDispatch {
    /// Exclusive batch directory; retain it even when execution is interrupted.
    pub run_directory: PathBuf,
    identity: String,
    definitions: Vec<Definition>,
    runs: Vec<TrustedWorkflowRun>,
    stop_reason: Option<&'static str>,
}

impl TrustedWorkflowDispatch {
    /// Empty selection is explicitly reported, never turned into a check.
    pub fn succeeded(&self) -> bool {
        self.stop_reason.is_none()
            && self.runs.len() == self.definitions.iter().filter(|d| d.selected).count()
            && self.runs.iter().all(TrustedWorkflowRun::succeeded)
    }

    fn manifest_json(&self) -> String {
        let definitions = self.definitions.iter().map(|d| format!(
            "{{\"path_hex\":\"{}\",\"blob\":\"{}\",\"graph_sha256\":\"{}\",\"run_id\":\"{}\",\"selected\":{}}}",
            hex(&d.path), d.blob, hex(&d.graph), hex(&d.run_id), d.selected,
        )).collect::<Vec<_>>().join(",");
        format!(
            "{{\"type\":\"trusted_workflow_dispatch_plan\",{},\"workflows\":[{definitions}]}}",
            self.identity
        )
    }

    /// Bounded, lossless JSON; all untrusted paths and output remain hexadecimal.
    pub fn to_json(&self) -> String {
        let runs = self
            .runs
            .iter()
            .map(TrustedWorkflowRun::to_json)
            .collect::<Vec<_>>()
            .join(",");
        let reason = self
            .stop_reason
            .map_or_else(|| "null".to_owned(), |s| format!("\"{s}\""));
        format!(
            "{{\"type\":\"trusted_workflow_dispatch\",\"plan\":{},\"matched_count\":{},\"executed_count\":{},\"succeeded\":{},\"stop_reason\":{reason},\"runs\":[{runs}]}}",
            self.manifest_json(),
            self.definitions.iter().filter(|d| d.selected).count(),
            self.runs.len(),
            self.succeeded(),
        )
    }
}

fn event_supported(event: &str) -> bool {
    matches!(event, "push" | "workflow_dispatch")
}

fn workflow_child(path: &[u8], directory: &[u8]) -> bool {
    path.strip_prefix(directory)
        .and_then(|rest| rest.strip_prefix(b"/"))
        .is_some_and(|name| {
            !name.contains(&b'/') && (name.ends_with(b".yml") || name.ends_with(b".yaml"))
        })
}

fn child_id(batch: [u8; 16], event: &str, path: &[u8]) -> [u8; 16] {
    let mut input = b"frankengit/workflow-dispatch-child/v1\0".to_vec();
    input.extend_from_slice(&batch);
    input.extend_from_slice(&(event.len() as u64).to_be_bytes());
    input.extend_from_slice(event.as_bytes());
    input.extend_from_slice(&(path.len() as u64).to_be_bytes());
    input.extend_from_slice(path);
    let mut id = [0; 16];
    id.copy_from_slice(&sha256_digest(&input)[..16]);
    id
}

impl OneNode {
    /// Discover direct YAML children of an explicit workflow directory, select
    /// their declared trigger, and run them against ONE pinned canonical source.
    ///
    /// The operator MUST trust every selected script with host-user privileges.
    /// `event` is an operator-selected matching key, NOT proof of an admitted
    /// push, a webhook signature, or authorization to execute untrusted code.
    /// No remote listener, scheduler retry, or canonical check is introduced.
    /// Every discovered definition is compiled before the exclusive batch is
    /// reserved. Unsupported definitions refuse the entire dispatch preflight.
    ///
    /// Existing workflow attempt fences/journals own each execution. An occupied
    /// batch always refuses, including after a crash before the first child.
    /// `dispatch.json` lists exact child IDs for offline recovery/publication.
    pub async fn dispatch_trusted_workflows_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        directory: &[u8],
        event: &str,
        run_id: [u8; 16],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        expected: (RepositoryAuthorityHeadId, GitOid),
        limits: WorkflowLimits,
    ) -> Result<TrustedWorkflowDispatch, TrustedWorkflowFailure> {
        if !event_supported(event) {
            return Err(TrustedWorkflowFailure::InvalidInput(
                "unsupported dispatch event",
            ));
        }
        limits
            .validate()
            .map_err(TrustedWorkflowFailure::Workflow)?;
        let paths = validate_inputs(directory, run_id, parent, read_prefixes)?;
        let started = Instant::now();
        match self.object_format {
            Format::Sha1 => {
                self.dispatch_workflow_format::<Sha1>(
                    request, reference, directory, event, run_id, parent, paths, expected, limits,
                    started,
                )
                .await
            }
            Format::Sha256 => {
                self.dispatch_workflow_format::<Sha256>(
                    request, reference, directory, event, run_id, parent, paths, expected, limits,
                    started,
                )
                .await
            }
        }
    }

    async fn dispatch_workflow_format<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        directory: &[u8],
        event: &str,
        run_id: [u8; 16],
        parent: &Path,
        paths: Vec<TreePath>,
        expected: (RepositoryAuthorityHeadId, GitOid),
        limits: WorkflowLimits,
        started: Instant,
    ) -> Result<TrustedWorkflowDispatch, TrustedWorkflowFailure> {
        let bytes = ByteCount::try_new("workflow source", FETCH_BYTES, FETCH_BYTES)
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
        let observed = Mutex::new(None);
        let selected = self
            .with_workspace_snapshot_in::<A, _>(
                request,
                reference,
                &Default::default(),
                &mut capability,
                0,
                Some(expected.0),
                Some(expected.1),
                SOURCE_LIMITS.max_entry_bytes,
                |base, source, capability, head, _| {
                    let result = (|| {
                        if !workspace_request_live(request)
                            || started.elapsed() >= limits.run_timeout
                        {
                            return Err(TrustedWorkflowFailure::InvalidInput(
                                "dispatch stopped before discovery",
                            ));
                        }
                        let manifest = Arc::new(
                            SparseManifest::build(base, source, capability, 0, SOURCE_LIMITS)
                                .map_err(|e| {
                                    TrustedWorkflowFailure::Source(NodeWorkspaceRefusal::Manifest(
                                        e,
                                    ))
                                })?,
                        );
                        dispatch_at(
                            self, request, manifest, capability, head, reference, directory, event,
                            run_id, parent, &declared, limits, started,
                        )
                    })();
                    *observed
                        .lock()
                        .map_err(|_| NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)? =
                        Some(result);
                    Ok(())
                },
            )
            .await;
        let observed = observed
            .into_inner()
            .map_err(|_| TrustedWorkflowFailure::InvalidInput("dispatch result lock poisoned"))?;
        match (selected, observed) {
            (_, Some(Err(error))) => Err(error),
            (Ok(()) | Err(NodeWorkspaceRefusal::Cancelled { .. }), Some(Ok(report))) => Ok(report),
            (Err(error), Some(Ok(report))) => Err(TrustedWorkflowFailure::Journal {
                directory: report.run_directory,
                detail: format!(
                    "dispatch source finalization failed after execution: {error}; inspect saved reports, do not replay"
                ),
            }),
            (Err(error), None) => Err(TrustedWorkflowFailure::Source(error)),
            (Ok(()), None) => Err(TrustedWorkflowFailure::InvalidInput(
                "dispatch source consumer did not complete",
            )),
        }
    }
}

fn dispatch_at<A: GitHashAlgorithm>(
    node: &OneNode,
    request: &NodeRequestContext,
    manifest: Arc<SparseManifest<A>>,
    capability: &TreeCapability,
    head: RepositoryAuthorityHeadId,
    reference: &RefName,
    directory: &[u8],
    event: &str,
    run_id: [u8; 16],
    parent: &Path,
    declared: &[Vec<u8>],
    limits: WorkflowLimits,
    started: Instant,
) -> Result<TrustedWorkflowDispatch, TrustedWorkflowFailure> {
    let invalid = TrustedWorkflowFailure::InvalidInput;
    let live = || workspace_request_live(request) && started.elapsed() < limits.run_timeout;
    let inputs = WorkflowInputs::Canonical(Arc::clone(&manifest));
    let mut entries = inputs
        .entries()
        .iter()
        .filter(|e| workflow_child(e.path().as_bytes(), directory))
        .collect::<Vec<_>>();
    if entries.len() > MAX_WORKFLOWS {
        return Err(invalid("dispatch exceeds 32 workflow definitions"));
    }
    entries.sort_by(|a, b| a.path().as_bytes().cmp(b.path().as_bytes()));
    let (source_rcr, source_commit, source_tree, _) = inputs.coordinates(node.object_format)?;
    let mut definitions = Vec::new();
    let mut ids = BTreeSet::new();
    let (mut source_bytes, mut jobs, mut steps) = (0usize, 0usize, 0usize);
    for entry in entries {
        if !live() {
            return Err(invalid("dispatch stopped during definition preflight"));
        }
        let SparseEntryKind::File { body, .. } = entry.kind() else {
            return Err(invalid("dispatch definitions must be regular files"));
        };
        source_bytes = source_bytes
            .checked_add(body.len())
            .filter(|n| *n <= MAX_WORKFLOW_BYTES)
            .ok_or_else(|| invalid("dispatch workflow sources exceed 1 MiB"))?;
        let plan = WorkflowPlan::compile(
            std::str::from_utf8(body).map_err(|_| invalid("workflow is not UTF-8"))?,
        )
        .map_err(TrustedWorkflowFailure::Workflow)?;
        let selected = plan
            .graph()
            .triggers
            .iter()
            .any(|trigger| trigger.name == event);
        if selected {
            jobs += plan.graph().jobs.len();
            steps += plan
                .graph()
                .jobs
                .iter()
                .map(|job| job.steps.len())
                .sum::<usize>();
            if jobs > MAX_JOBS || steps > MAX_STEPS {
                return Err(invalid("dispatch aggregate job or step limit exceeded"));
            }
        }
        let path = entry.path().as_bytes().to_vec();
        let child = child_id(run_id, event, &path);
        if child == [0; 16] || !ids.insert(child) {
            return Err(invalid("dispatch child identity collision"));
        }
        definitions.push(Definition {
            path,
            blob: GitOid::from_hex(node.object_format, &hex(entry.source_oid().digest_bytes()))
                .map_err(|_| invalid("workflow blob identity width"))?,
            graph: sha256_digest(plan.graph().canonical_bytes().as_bytes()),
            run_id: child,
            selected,
        });
    }
    if inputs
        .payload_bytes()
        .checked_mul(jobs)
        .is_none_or(|n| n > MAX_REPLICATED_BYTES)
        || inputs
            .entries()
            .len()
            .checked_mul(jobs)
            .is_none_or(|n| n > MAX_REPLICATED_ENTRIES)
    {
        return Err(invalid(
            "dispatch aggregate workspace materialization exceeds profile",
        ));
    }
    if jobs != 0 {
        inputs
            .host_plan(capability)
            .map_err(TrustedWorkflowFailure::Host)?;
    }
    let run_directory = parent.join(format!("dispatch-{}", hex(&run_id)));
    let prefixes = declared
        .iter()
        .map(|p| format!("\"{}\"", hex(p)))
        .collect::<Vec<_>>()
        .join(",");
    let identity = format!(
        concat!(
            "\"schema_version\":1,\"tenant_id\":\"{}\",\"repository_id\":\"{}\",\"repository_incarnation\":\"{}\",",
            "\"source_head\":\"{}\",\"source_rcr\":\"{}\",\"source_commit\":\"{}\",\"source_tree\":\"{}\",\"object_format\":\"{}\",",
            "\"source_ref_hex\":\"{}\",\"workflow_directory_hex\":\"{}\",\"read_prefixes_hex\":[{}],\"event\":\"{}\",",
            "\"trigger_provenance\":\"explicit_local_operator\",\"run_id\":\"{}\",\"run_directory_hex\":\"{}\",",
            "\"authoritative_check\":false,\"hostile_code_isolated\":false,\"published\":false,\"execution_retried\":false,",
            "\"run_timeout_ms\":{},\"total_output_bytes\":{}"
        ),
        node.tenant_id,
        node.repository_id(),
        node.repository_incarnation_id(),
        head,
        source_rcr,
        source_commit,
        source_tree,
        node.object_format.as_str(),
        hex(reference.as_bytes()),
        hex(directory),
        prefixes,
        event,
        hex(&run_id),
        hex(run_directory.as_os_str().as_bytes()),
        limits.run_timeout.as_millis(),
        limits.total_output_bytes,
    );
    let mut report = TrustedWorkflowDispatch {
        run_directory,
        identity,
        definitions,
        runs: Vec::new(),
        stop_reason: None,
    };
    if !live() {
        return Err(invalid("dispatch stopped before batch reservation"));
    }
    let metadata = fs::symlink_metadata(parent).map_err(|source| TrustedWorkflowFailure::Io {
        operation: "inspect dispatch parent",
        source,
    })?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(invalid(
            "dispatch parent must be a nonsymlink 0700 directory",
        ));
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(&report.run_directory) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(TrustedWorkflowFailure::AttemptExists(report.run_directory));
        }
        Err(source) => {
            return Err(TrustedWorkflowFailure::Io {
                operation: "reserve dispatch batch",
                source,
            });
        }
    }
    let batch_directory = report.run_directory.clone();
    let failed = |detail| TrustedWorkflowFailure::Journal {
        directory: batch_directory.clone(),
        detail,
    };
    let root = File::open(&batch_directory).map_err(|e| failed(e.to_string()))?;
    write_new(
        &batch_directory.join("dispatch.json"),
        report.manifest_json().as_bytes(),
    )
    .and_then(|()| root.sync_all())
    .and_then(|()| File::open(parent)?.sync_all())
    .map_err(|e| {
        failed(format!(
            "dispatch plan durability failed before execution: {e}"
        ))
    })?;
    let mut remaining = limits.total_output_bytes;
    for definition in report.definitions.iter().filter(|d| d.selected) {
        if !live() {
            report.stop_reason = Some("request_stopped");
            break;
        }
        if remaining < 2 {
            report.stop_reason = Some("output_budget_exhausted");
            break;
        }
        let child_limits = WorkflowLimits {
            total_output_bytes: remaining,
            ..limits
        };
        let run = run_inputs(node, request, WorkflowInputs::Canonical(Arc::clone(&manifest)), capability, head, reference,
            &definition.path, declared, definition.run_id, &batch_directory, child_limits, started)
            .map_err(|e| failed(format!("dispatch child {} failed: {e}; retain the batch and inspect its child journals, do not replay", hex(&definition.run_id))))?;
        let captured = run
            .execution
            .jobs
            .iter()
            .flat_map(|job| &job.steps)
            .map(|step| step.observation.stdout.len() + step.observation.stderr.len())
            .sum::<usize>();
        remaining = remaining.checked_sub(captured).ok_or_else(|| {
            failed("dispatch output accounting exceeded its budget; retain all children".into())
        })?;
        report.stop_reason = stop_after(&run);
        report.runs.push(run);
        if report.stop_reason.is_some() {
            break;
        }
    }
    publish_report(&root, &batch_directory, report.to_json().as_bytes()).map_err(|e| {
        failed(format!(
            "dispatch finished but report durability failed: {e}; do not replay"
        ))
    })?;
    Ok(report)
}

fn stop_after(run: &TrustedWorkflowRun) -> Option<&'static str> {
    if !run.workspaces_closed
        || run
            .execution
            .jobs
            .iter()
            .any(|job| job.requires_containment())
    {
        return Some("containment_unproved");
    }
    if run.request_interrupted {
        return Some("request_stopped");
    }
    run.execution.jobs.iter().find_map(|job| match job.outcome {
        JobOutcome::Refused => Some("workflow_refused"),
        JobOutcome::Cancelled => Some("request_stopped"),
        JobOutcome::TimedOut => Some("workflow_timed_out"),
        JobOutcome::OutputLimit => Some("workflow_output_limit"),
        JobOutcome::Succeeded | JobOutcome::Failed | JobOutcome::Skipped => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_is_direct_lossless_and_has_no_prefix_aliases() {
        for name in [
            b".github/workflows/a.yml".as_slice(),
            b".github/workflows/\xff.yaml",
        ] {
            assert!(workflow_child(name, b".github/workflows"));
        }
        for name in [
            b".github/workflows-old/a.yml".as_slice(),
            b".github/workflows/sub/a.yml",
            b".github/workflows/a.yml.txt",
            b".github/workflows",
        ] {
            assert!(!workflow_child(name, b".github/workflows"));
        }
    }

    #[test]
    fn dispatch_identity_binds_every_nonce_bit_event_and_raw_path() {
        let first = child_id([1; 16], "push", b"ci/a.yml");
        assert_eq!(first, child_id([1; 16], "push", b"ci/a.yml"));
        for index in 0..16 {
            let mut different = [1; 16];
            different[index] = 2;
            assert_ne!(first, child_id(different, "push", b"ci/a.yml"));
        }
        assert_ne!(first, child_id([1; 16], "workflow_dispatch", b"ci/a.yml"));
        assert_ne!(first, child_id([1; 16], "push", b"ci/b.yml"));
        assert_ne!(
            child_id([1; 16], "push", b"ci/\xff.yml"),
            child_id([1; 16], "push", b"ci/\xfe.yml")
        );
        assert_ne!(first, [0; 16]);
    }

    #[test]
    fn event_selection_uses_compiled_triggers_not_script_text() {
        let plan = WorkflowPlan::compile("name: dispatch-test\non: workflow_dispatch\njobs:\n  test:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo push\n").unwrap();
        assert!(!plan.graph().triggers.iter().any(|t| t.name == "push"));
        assert!(
            plan.graph()
                .triggers
                .iter()
                .any(|t| t.name == "workflow_dispatch")
        );
        assert!(event_supported("push") && event_supported("workflow_dispatch"));
        for event in ["", "pull_request", "schedule", "Push", "push\n"] {
            assert!(!event_supported(event));
        }
    }
}
