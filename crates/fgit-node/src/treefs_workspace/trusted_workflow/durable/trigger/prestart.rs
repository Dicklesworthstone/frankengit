//! Resume only a durable, versioned merge publication intent whose dispatch
//! never crossed its synchronized start fence. Local custody cannot prove a
//! canonical decision, and an absent response never proves non-commit.

use super::{
    File, GitOid, NodeRequestContext, OneNode, OsStrExt, Path, RefName, RepositoryAuthorityHeadId,
    RepositoryDecisionBatchId, Selected, TrustedRefWorkflowPoll, TrustedWorkflowArtifactConfig,
    TrustedWorkflowFailure, WorkflowLimits, check_directory, commitment, fs, hex, invalid,
    invalid_owned, io, lower_hash, merge_queue, pull_request, pull_request_merge, reporting,
    sha256_digest, workspace_request_live, write_new,
};
use pull_request_merge::{Prepared, PullRequestMergeWatchConfig};

mod configuration;
mod intent;
mod metadata;
use intent::Intent;

/// Shared exact execution configuration binding for durable collection custody.
/// This is a local responsibility identity, never a canonical check receipt.
pub(super) fn execution_identity(
    directory: &[u8],
    inputs: &[Vec<u8>],
    limits: WorkflowLimits,
    artifacts: Option<&TrustedWorkflowArtifactConfig>,
) -> [u8; 32] {
    configuration::identity(directory, inputs, limits, artifacts)
}

type Execution<'a> = (
    &'a [Vec<u8>],
    WorkflowLimits,
    Option<&'a TrustedWorkflowArtifactConfig>,
);

pub(super) struct Pending {
    pub(super) selected: Selected,
    pub(super) prepared: Prepared,
    pub(super) event: String,
    pub(super) event_id: [u8; 32],
    intent: Intent,
}

/// Reporting may defer an intact intent without possessing execution inputs.
/// Only the polling owner checks the exact original execution configuration
/// and performs the first dispatch, after the service's readiness boundary.
pub(super) fn pending(
    node: &OneNode,
    reference: &RefName,
    directory: &[u8],
    path: &Path,
    scope: &[u8; 32],
    key: &str,
    config: &PullRequestMergeWatchConfig,
    execution: Option<Execution<'_>>,
    live: &dyn Fn() -> bool,
) -> Result<bool, TrustedWorkflowFailure> {
    Ok(read(
        node, reference, directory, path, scope, key, config, execution, live,
    )?
    .is_some())
}

/// The caller holds the exclusive watch owner throughout this read and the
/// later admission/dispatch. No public execution handle is produced here.
pub(super) fn read(
    node: &OneNode,
    reference: &RefName,
    directory: &[u8],
    path: &Path,
    scope: &[u8; 32],
    key: &str,
    config: &PullRequestMergeWatchConfig,
    execution: Option<Execution<'_>>,
    live: &dyn Fn() -> bool,
) -> Result<Option<Pending>, TrustedWorkflowFailure> {
    checkpoint(live)?;
    match fs::symlink_metadata(path.join("execution-started")) {
        // Presence, including a partial or malformed fence, proves only that
        // this event cannot resume. Preserve the historical blocked_unresolved
        // poll result for execution custody lacking a complete handoff.
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io(error)),
    }
    if !lower_hash(key) {
        return Err(invalid("invalid prestart event identity"));
    }
    let event_id = metadata::hash(key)?;
    let Some(intent) = Intent::read(path, scope, &event_id, &config.identity(), live)? else {
        // Historical events never claimed this new no-start protocol.
        return Ok(None);
    };
    if execution.is_some_and(|(inputs, limits, artifacts)| {
        intent.execution_config != configuration::identity(directory, inputs, limits, artifacts)
    }) {
        return Err(invalid("prestart execution configuration differs"));
    }
    shape(path, live)?;
    intent.verify_artifacts(path, live)?;
    let pending =
        metadata::reconstruct(node, reference, directory, path, key, config, intent, live)?;
    checkpoint(live)?;
    Ok(Some(pending))
}

impl Pending {
    pub(super) fn load_bundle(
        &mut self,
        path: &Path,
        config: &PullRequestMergeWatchConfig,
        live: &dyn Fn() -> bool,
    ) -> Result<(), TrustedWorkflowFailure> {
        self.prepared.bundle = self.intent.load_bundle(path, live)?;
        // Retain exactly the original CI command. The importer independently
        // verifies its sealed transaction and, for new intake, object closure.
        let mut checkpoint = || live();
        fgit_pack::full_bundle::retarget::RetargetedBundle::parse(
            &self.prepared.bundle,
            config.reference(),
            config.reference(),
            self.prepared.commit,
            Default::default(),
            &mut checkpoint,
        )
        .map_err(|error| invalid_owned(error.to_string()))?;
        Ok(())
    }
}

/// The last durable record enables recovery only after all original bytes
/// reached the event directory's existing durability boundary.
pub(super) fn record(
    path: &Path,
    scope: [u8; 32],
    event_id: [u8; 32],
    event: &str,
    config: &PullRequestMergeWatchConfig,
    prepared: &Prepared,
    directory: &[u8],
    inputs: &[Vec<u8>],
    limits: WorkflowLimits,
    artifacts: Option<&TrustedWorkflowArtifactConfig>,
    live: &dyn Fn() -> bool,
) -> Result<(), TrustedWorkflowFailure> {
    checkpoint(live)?;
    let landing = if prepared.queue.is_some() {
        let mut checkpoint = || live();
        let bundle = prepared.landing_bundle(config, &mut checkpoint)?;
        Some((
            bundle
                .sha256(&mut checkpoint)
                .map_err(|error| invalid_owned(error.to_string()))?,
            bundle.byte_len() as u64,
        ))
    } else {
        None
    };
    Intent::create(
        path,
        &Intent {
            scope,
            event: event_id,
            merge_config: config.identity(),
            execution_config: configuration::identity(directory, inputs, limits, artifacts),
            event_sha256: sha256_digest(event.as_bytes()),
            bundle_sha256: sha256_digest(&prepared.bundle),
            bundle_len: prepared.bundle.len() as u64,
            landing,
        },
        live,
    )?;
    Ok(())
}

/// Reuse the exact original publication and native dispatch: no refreshed
/// lease, key or candidate, and no adoption of an earlier dispatch directory.
pub(super) async fn execute(
    node: &OneNode,
    request: &NodeRequestContext,
    config: &PullRequestMergeWatchConfig,
    selected: &Selected,
    prepared: &Prepared,
    scope: [u8; 32],
    event_id: [u8; 32],
    event: String,
    path: &Path,
    directory: &[u8],
    inputs: &[Vec<u8>],
    limits: WorkflowLimits,
    artifacts: Option<&TrustedWorkflowArtifactConfig>,
    resumed: bool,
) -> Result<TrustedRefWorkflowPoll, TrustedWorkflowFailure> {
    let retained = |error: String| TrustedWorkflowFailure::Journal {
        directory: path.to_path_buf(),
        detail: error,
    };
    let head = node
        .publish_watched_merge_in(request, prepared, config, path)
        .await
        .map_err(|error| retained(format!("{error}; original prestart intent retained")))?;
    let mut run_id = [0; 16];
    run_id.copy_from_slice(&event_id[..16]);
    if run_id == [0; 16] {
        return Err(invalid("invalid prestart dispatch identity"));
    }
    let pull = selected
        .pull
        .as_ref()
        .ok_or_else(|| invalid("prestart PR missing"))?;
    let dispatch = node
        .dispatch_trusted_workflows_with_trigger_branch_in(
            request,
            config.reference(),
            directory,
            "pull_request",
            run_id,
            path,
            inputs,
            (head, prepared.commit),
            limits,
            artifacts,
            Some(pull.target_reference()),
            Some((
                Some(pull.path_comparison_base()),
                fgit_forge::review::ComparisonMode::MergeBase,
                Some(selected.commit),
            )),
            Some(|| started(path, &scope, &event_id, &|| workspace_request_live(request))),
        )
        .await
        .map_err(|error| retained(format!("{error}; original execution custody retained")))?;
    super::finish_dispatch(
        request,
        path,
        scope,
        event_id,
        event,
        prepared.commit,
        dispatch,
        if resumed { "resumed" } else { "dispatched" },
    )
}

fn started(
    path: &Path,
    scope: &[u8; 32],
    event: &[u8; 32],
    live: &dyn Fn() -> bool,
) -> Result<(), TrustedWorkflowFailure> {
    checkpoint(live)?;
    shape(path, live)?;
    let identity = commitment(&[b"frankengit/watch-execution-started/v1", scope, event]);
    // Sync before workflow discovery, child custody, process creation or any
    // execution-side effect. Any interrupted write permanently blocks resume.
    write_new(&path.join("execution-started"), &identity)
        .and_then(|()| File::open(path)?.sync_all())
        .map_err(io)
}

fn shape(path: &Path, live: &dyn Fn() -> bool) -> Result<(), TrustedWorkflowFailure> {
    check_directory(path)?;
    let mut count = 0;
    for entry in fs::read_dir(path).map_err(io)? {
        checkpoint(live)?;
        count += 1;
        if count > 5 {
            return Err(invalid(
                "prestart custody contains execution or extra records",
            ));
        }
        let entry = entry.map_err(io)?;
        if !matches!(
            entry.file_name().to_str(),
            Some(
                "event.json"
                    | "candidate.bundle"
                    | "landing.bundle"
                    | "prestart-intent"
                    | "candidate-publication.json"
            )
        ) {
            return Err(invalid(
                "prestart execution may already have started; retain custody",
            ));
        }
    }
    checkpoint(live)
}

fn checkpoint(live: &dyn Fn() -> bool) -> Result<(), TrustedWorkflowFailure> {
    if live() {
        Ok(())
    } else {
        Err(invalid("prestart recovery cancelled"))
    }
}
