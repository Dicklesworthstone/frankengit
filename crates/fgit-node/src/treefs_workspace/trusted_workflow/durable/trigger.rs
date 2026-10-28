//! Native latest-ref trigger selection and crash-safe execution custody.
//! Canonical history selects work; local records can only suppress execution.
use super::super::{
    DirBuilderExt, File, Format, GitOid, NodeRequestContext, NodeWorkspaceRefusal, OneNode,
    OpenOptions, OpenOptionsExt, OsStrExt, Path, RefName, RepositoryAuthorityHeadId,
    TrustedWorkflowArtifactConfig, TrustedWorkflowFailure, WorkflowLimits, fs, hex,
    validate_inputs, workspace_request_live, write_new,
};
use super::dispatch::TrustedWorkflowDispatch;
use fgit_crypto::sha256_digest;
use fgit_types::RepositoryDecisionBatchId;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

mod cancellation;
mod pull_request;
mod reporting;
pub mod service;

const MAX_EVENTS: usize = 1024;

/// A poll observation is not a green check, a push-protocol receipt or a queue.
#[derive(Debug)]
pub struct TrustedRefWorkflowPoll {
    state: &'static str,
    event: String,
    dispatch: Option<TrustedWorkflowDispatch>,
    execution_settled: bool,
}
impl TrustedRefWorkflowPoll {
    pub const fn state(&self) -> &'static str {
        self.state
    }
    pub const fn dispatch(&self) -> Option<&TrustedWorkflowDispatch> {
        self.dispatch.as_ref()
    }
    /// The request stopped while selecting inputs, before this poll reserved
    /// any event or started execution. Existing custody is never released.
    pub fn stopped_before_reservation(&self) -> bool {
        self.state == "stopped_before_reservation"
    }
    /// The selected event's durable settlement was verified, or its handoff
    /// and settlement marker were written and synced by this poll. Closed
    /// child processes alone do not establish this local recovery boundary.
    pub const fn execution_settled(&self) -> bool {
        self.execution_settled
    }
    pub fn requires_reconciliation(&self) -> bool {
        self.state == "blocked_unresolved"
            || self
                .dispatch
                .as_ref()
                .is_some_and(|run| !self.execution_settled || !closed(run))
    }
    pub fn to_json(&self) -> String {
        format!(
            "{{\"type\":\"workflow_ref_poll\",\"schema_version\":1,\"state\":\"{}\",\"stopped_before_reservation\":{},\"execution_settled\":{},\"event\":{},\"dispatch\":{}}}",
            self.state,
            self.stopped_before_reservation(),
            self.execution_settled,
            self.event,
            self.dispatch
                .as_ref()
                .map_or_else(|| "null".into(), TrustedWorkflowDispatch::to_json)
        )
    }
}

#[derive(Debug)]
struct Selected {
    head: RepositoryAuthorityHeadId,
    commit: GitOid,
    previous_commit: Option<GitOid>,
    batch: RepositoryDecisionBatchId,
    event_head: RepositoryAuthorityHeadId,
    pull: Option<pull_request::PullSelection>,
}

enum Selection {
    Absent,
    ChangedBeforeReservation,
    StoppedBeforeReservation,
    Ready(Selected),
}

fn stopped_poll() -> TrustedRefWorkflowPoll {
    TrustedRefWorkflowPoll {
        state: "stopped_before_reservation",
        event: "null".into(),
        dispatch: None,
        execution_settled: false,
    }
}

impl OneNode {
    /// Observe the latest net change of one visible branch and dispatch its push
    /// definitions once under an exclusive, permanent local custody namespace.
    ///
    /// This is an explicit trusted whole-repository operator API, NOT remote
    /// authentication. Every selected future script must be trusted with host
    /// privileges. Updates through import/merge/receive are all ref-change events;
    /// this does not assert that a wire push occurred. Intermediate tips missed
    /// between polls are coalesced, not silently presented as individually run.
    ///
    /// A canonical check or unrelated forge update does not create a new event.
    /// A->B->A does: identity binds the actual decision batch, not only the tip.
    /// Source selection is rechecked before existing native dispatch admission.
    /// Interrupted custody blocks later events in this watch scope until operator
    /// reconciliation; changing limits or input selectors never releases an ID.
    pub async fn poll_trusted_ref_workflows_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        directory: &[u8],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        limits: WorkflowLimits,
        artifacts: Option<&TrustedWorkflowArtifactConfig>,
    ) -> Result<TrustedRefWorkflowPoll, TrustedWorkflowFailure> {
        self.poll_selected_workflows_in(
            request,
            reference,
            directory,
            parent,
            read_prefixes,
            limits,
            artifacts,
            None,
        )
        .await
    }

    async fn poll_selected_workflows_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        directory: &[u8],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        limits: WorkflowLimits,
        artifacts: Option<&TrustedWorkflowArtifactConfig>,
        pull_number: Option<u64>,
    ) -> Result<TrustedRefWorkflowPoll, TrustedWorkflowFailure> {
        if pull_number == Some(0) {
            return Err(invalid("pull-request number must be positive"));
        }
        limits
            .validate()
            .map_err(TrustedWorkflowFailure::Workflow)?;
        validate_inputs(directory, [1; 16], parent, read_prefixes)?;
        if !reference.as_bytes().starts_with(b"refs/heads/") {
            return Err(invalid("ref watcher requires a branch"));
        }
        if !workspace_request_live(request) {
            return Ok(stopped_poll());
        }
        let selection = match pull_number {
            Some(number) => {
                self.select_pull_request_workflow_event(request, reference, number)
                    .await?
            }
            None => self.select_ref_workflow_event(request, reference).await?,
        };
        let selected = match selection {
            Selection::Absent => None,
            Selection::Ready(selected) => Some(selected),
            Selection::StoppedBeforeReservation => return Ok(stopped_poll()),
            Selection::ChangedBeforeReservation => {
                // No event or execution custody was acquired. Another bounded
                // poll may select again; failures AFTER reservation stay blocked.
                return Ok(TrustedRefWorkflowPoll {
                    state: "source_moved",
                    event: "null".into(),
                    dispatch: None,
                    execution_settled: false,
                });
            }
        };
        let scope = match pull_number {
            Some(number) => pull_request::scope(self, reference, directory, number),
            None => reporting::scope(self, reference, directory),
        };
        check_directory(parent)?;
        let root = parent.join(format!("watch-{}", hex(&scope)));
        let owner = Owner::open(&root)?;
        let entries = reporting::event_entries(&root)?;
        for entry in &entries {
            if entry.file_name() == "owner.lock" {
                continue;
            }
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| invalid("invalid watch custody entry"))?;
            let key = name
                .strip_prefix("event-")
                .filter(|key| lower_hash(key))
                .ok_or_else(|| invalid("unknown watch custody entry"))?;
            check_directory(&entry.path())?;
            if !settled(&entry.path(), key)? {
                return Ok(TrustedRefWorkflowPoll {
                    state: "blocked_unresolved",
                    event: format!(
                        "{{\"custody_directory_hex\":\"{}\"}}",
                        hex(entry.path().as_os_str().as_bytes())
                    ),
                    dispatch: None,
                    execution_settled: false,
                });
            }
        }
        let Some(selected) = selected else {
            return Ok(TrustedRefWorkflowPoll {
                state: if pull_number.is_some() {
                    "pull_request_unavailable"
                } else {
                    "ref_unavailable"
                },
                event: "null".into(),
                dispatch: None,
                execution_settled: false,
            });
        };
        let batch = selected.batch.as_internal_object_id();
        let push_id = commitment(&[
            b"frankengit/ref-workflow-event/v1",
            &scope,
            &batch.algorithm().code_point().to_be_bytes(),
            batch.digest().as_bytes(),
        ]);
        let event_id = selected
            .pull
            .as_ref()
            .map_or(push_id, |pull| pull.event_id(&scope, &selected));
        let key = hex(&event_id);
        let event_directory = root.join(format!("event-{key}"));
        let mut run_id = [0; 16];
        run_id.copy_from_slice(&event_id[..16]);
        if run_id == [0; 16] {
            return Err(invalid("ref workflow execution identity refused"));
        }
        let profile = if selected.pull.is_some() {
            "latest-canonical-pull-request-head-v1"
        } else {
            "latest-canonical-ref-update-v1"
        };
        let mut event = format!(
            concat!(
                "{{\"profile\":\"{}\",\"tenant_id\":\"{}\",",
                "\"repository_id\":\"{}\",\"repository_incarnation\":\"{}\",\"ref_hex\":\"{}\",",
                "\"decision_batch\":\"{}\",\"event_head\":\"{}\",\"observed_head\":\"{}\",",
                "\"commit\":\"{}\",\"workflow_directory_hex\":\"{}\",\"event_id\":\"{}\",",
                "\"dispatch_id\":\"{}\",\"custody_directory_hex\":\"{}\"}}"
            ),
            profile,
            self.tenant_id(),
            self.repository_id(),
            self.repository_incarnation_id(),
            hex(reference.as_bytes()),
            selected.batch,
            selected.event_head,
            selected.head,
            selected.commit,
            hex(directory),
            key,
            hex(&run_id),
            hex(event_directory.as_os_str().as_bytes())
        );
        if let Some(pull) = &selected.pull {
            event.pop();
            event.push_str(&format!(",\"pull_request\":{}}}", pull.to_json()));
        } else {
            let before = selected
                .previous_commit
                .map_or_else(|| "null".to_owned(), |id| format!("\"{id}\""));
            event.pop();
            event.push_str(&format!(",\"previous_commit\":{before}}}"));
        }
        match fs::symlink_metadata(&event_directory) {
            Ok(_) => {
                return Ok(TrustedRefWorkflowPoll {
                    state: "previously_settled",
                    event,
                    dispatch: None,
                    execution_settled: true,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io(error)),
        }
        if entries.len() >= MAX_EVENTS {
            return Err(invalid("ref watcher retained-event limit exceeded"));
        }
        if !workspace_request_live(request) {
            return Ok(stopped_poll());
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&event_directory)
            .map_err(io)?;
        let retained = |error: String| TrustedWorkflowFailure::Journal {
            directory: event_directory.clone(),
            detail: error,
        };
        write_new(&event_directory.join("event.json"), event.as_bytes())
            .and_then(|()| File::open(&event_directory)?.sync_all())
            .and_then(|()| File::open(&root)?.sync_all())
            .map_err(|e| retained(e.to_string()))?;
        let dispatch = self
            .dispatch_trusted_workflows_with_trigger_branch_in(
                request,
                reference,
                directory,
                if selected.pull.is_some() {
                    "pull_request"
                } else {
                    "push"
                },
                run_id,
                &event_directory,
                read_prefixes,
                (selected.head, selected.commit),
                limits,
                artifacts,
                selected.pull.as_ref().map(|pull| pull.target_reference()),
                Some(selected.pull.as_ref().map_or(
                    (
                        selected.previous_commit,
                        fgit_forge::review::ComparisonMode::Direct,
                    ),
                    |pull| {
                        (
                            Some(pull.path_comparison_base()),
                            fgit_forge::review::ComparisonMode::MergeBase,
                        )
                    },
                )),
            )
            .await
            .map_err(|e| {
                retained(format!(
                    "{e}; original event retained; never replay automatically"
                ))
            })?;
        let execution_settled = if closed(&dispatch) && workspace_request_live(request) {
            reporting::capture(
                &event_directory,
                scope,
                event_id,
                selected.commit,
                &dispatch,
                request,
            )?;
            write_new(&event_directory.join("settled"), key.as_bytes())
                .and_then(|()| File::open(&event_directory)?.sync_all())
                .map_err(|e| retained(e.to_string()))?;
            true
        } else {
            false
        };
        drop(owner);
        Ok(TrustedRefWorkflowPoll {
            state: "dispatched",
            event,
            dispatch: Some(dispatch),
            execution_settled,
        })
    }

    async fn select_ref_workflow_event(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
    ) -> Result<Selection, TrustedWorkflowFailure> {
        let state = match self.materialize_admission_in(request).await {
            Ok(state) => state,
            Err(error) if cancellation::materialization(&error) => {
                return Ok(Selection::StoppedBeforeReservation);
            }
            Err(error) => {
                return Err(TrustedWorkflowFailure::Source(
                    NodeWorkspaceRefusal::Authority(Box::new(error)),
                ));
            }
        };
        if state.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Ok(Selection::Absent);
        }
        let Some(commit) = state.snapshot().refs.get(reference).copied() else {
            return Ok(Selection::Absent);
        };
        let head = state.basis().id();
        let history = match self.snapshot_history_in(request).await {
            Ok(history) => history,
            Err(error) if cancellation::materialization(&error) => {
                return Ok(Selection::StoppedBeforeReservation);
            }
            Err(error) => {
                return Err(TrustedWorkflowFailure::Source(
                    NodeWorkspaceRefusal::Authority(Box::new(error)),
                ));
            }
        };
        let after = match self.authenticate_authority_head_in(request).await {
            Ok(after) => after,
            Err(error) if cancellation::node_read(&error) => {
                return Ok(Selection::StoppedBeforeReservation);
            }
            Err(error) => return Err(invalid_owned(error.to_string())),
        };
        if crate::authority_head_id(&after.body().map_err(|e| invalid_owned(e.to_string()))?)
            .map_err(|e| invalid_owned(e.to_string()))?
            != head
        {
            return Ok(Selection::ChangedBeforeReservation);
        }
        // snapshot_history_in authenticates the COMPLETE bounded history to
        // empty genesis, oldest first; it never returns a truncated prefix.
        // The first matching row is this event, the next is its exact old
        // ref value. Preserve a deletion as None: skipping it would reuse a
        // previous branch incarnation. This is neither a Git first parent nor
        // the last tip this particular polling process happened to observe.
        let mut changes = history.iter().rev().filter_map(|batch| {
            batch
                .ref_updates
                .iter()
                .find(|(name, _)| name == reference.as_bytes())
                .map(|(_, value)| (batch, *value))
        });
        let (event, value) = changes
            .next()
            .ok_or_else(|| invalid("current ref has no authenticated change event"))?;
        if value != Some(commit) {
            return Err(invalid("ref event does not match the current branch"));
        }
        let previous_commit = changes.next().and_then(|(_, value)| value);
        if !workspace_request_live(request) {
            return Ok(Selection::StoppedBeforeReservation);
        }
        Ok(Selection::Ready(Selected {
            head,
            commit,
            previous_commit,
            batch: event.batch_id,
            event_head: event.resulting_head_id,
            pull: None,
        }))
    }
}

fn closed(dispatch: &TrustedWorkflowDispatch) -> bool {
    dispatch.runs().iter().all(|run| {
        run.workspaces_closed
            && !run.request_interrupted
            && run
                .execution
                .jobs
                .iter()
                .all(|job| !job.requires_containment())
    })
}
const fn invalid(detail: &'static str) -> TrustedWorkflowFailure {
    TrustedWorkflowFailure::InvalidInput(detail)
}
fn invalid_owned(detail: String) -> TrustedWorkflowFailure {
    TrustedWorkflowFailure::Io {
        operation: "authenticate workflow event",
        source: std::io::Error::other(detail),
    }
}
const fn io(source: std::io::Error) -> TrustedWorkflowFailure {
    TrustedWorkflowFailure::Io {
        operation: "workflow trigger custody",
        source,
    }
}
fn commitment(parts: &[&[u8]]) -> [u8; 32] {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    sha256_digest(&bytes)
}
fn lower_hash(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn check_directory(path: &Path) -> Result<(), TrustedWorkflowFailure> {
    let meta = fs::symlink_metadata(path).map_err(io)?;
    if !meta.is_dir() || meta.mode() & 0o777 != 0o700 {
        return Err(invalid(
            "watch custody requires nonsymlink 0700 directories",
        ));
    }
    Ok(())
}
fn settled(path: &Path, expected: &str) -> Result<bool, TrustedWorkflowFailure> {
    let marker = path.join("settled");
    let meta = match fs::symlink_metadata(&marker) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(io(e)),
        Ok(meta) => meta,
    };
    if !meta.is_file() || meta.mode() & 0o777 != 0o600 || meta.nlink() != 1 || meta.len() != 64 {
        return Err(invalid("invalid watch settlement marker"));
    }
    let file = File::open(&marker).map_err(io)?;
    let actual = file.metadata().map_err(io)?;
    if (meta.dev(), meta.ino()) != (actual.dev(), actual.ino()) {
        return Err(invalid("watch settlement changed during open"));
    }
    let mut bytes = Vec::new();
    (&file).take(65).read_to_end(&mut bytes).map_err(io)?;
    if bytes != expected.as_bytes() {
        return Err(invalid("watch settlement identity mismatch"));
    }
    file.sync_all()
        .and_then(|()| File::open(path)?.sync_all())
        .map_err(io)?;
    Ok(true)
}
struct Owner(File);
impl Owner {
    fn open(root: &Path) -> Result<Self, TrustedWorkflowFailure> {
        match fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io(e)),
        }
        check_directory(root)?;
        let path = root.join("owner.lock");
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = fs::symlink_metadata(&path).map_err(io)?;
                if !meta.is_file() || meta.mode() & 0o777 != 0o600 || meta.nlink() != 1 {
                    return Err(invalid("invalid watch owner file"));
                }
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .map_err(io)?
            }
            Err(e) => return Err(io(e)),
        };
        file.try_lock()
            .map_err(|_| invalid("another workflow watcher owns this scope"))?;
        let actual = file.metadata().map_err(io)?;
        let named = fs::symlink_metadata(&path).map_err(io)?;
        if !actual.is_file()
            || !named.is_file()
            || actual.mode() & 0o777 != 0o600
            || actual.nlink() != 1
            || (actual.dev(), actual.ino()) != (named.dev(), named.ino())
        {
            return Err(invalid("watch ownership changed"));
        }
        file.sync_all()
            .and_then(|()| File::open(root)?.sync_all())
            .and_then(|()| {
                File::open(
                    root.parent()
                        .ok_or_else(|| std::io::Error::other("missing watch parent"))?,
                )?
                .sync_all()
            })
            .map_err(io)?;
        Ok(Self(file))
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
