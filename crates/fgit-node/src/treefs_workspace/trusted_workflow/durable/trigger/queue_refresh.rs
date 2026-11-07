//! Explicit queue metadata authority with complete original-command custody.
//! Refresh changes no Git ref. Current reads can select a new intent only after
//! every retained original outcome and earlier execution have been reconciled.

use super::{
    NodeRequestContext, OneNode, Owner, Path, RefName, TrustedWorkflowFailure,
    check_directory, commitment, fs, hex, invalid, invalid_owned, io, lower_hash,
    merge_queue, pull_request_merge, queue_landing, reporting,
};
use fgit_admission::merge::native::queue::QueueHeadRefreshCommand;
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_types::{DecisionOutcome, PrincipalId, RepositoryAuthorityHeadId};
use std::collections::BTreeSet;

mod custody;
use custody::{Acknowledgement, Attempt};

/// Both modes resolve frozen original commands before any current selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueRefreshMode {
    RecoverOnly,
    RecoverAndSelect,
}

/// Bounded observations, not a check, review, or target-publication permission.
#[derive(Debug, Default)]
pub struct TrustedQueueRefresh {
    pub committed: usize,
    pub refused: usize,
    pub previously_decided: usize,
    pub waiting: usize,
    pub pending: bool,
    pub request_stopped: bool,
    pub error: Option<String>,
}
impl TrustedQueueRefresh {
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"type\":\"workflow_queue_refresh\",\"schema_version\":1,",
                "\"committed\":{},\"refused\":{},\"previously_decided\":{},",
                "\"waiting\":{},\"pending\":{},\"request_stopped\":{},\"error\":{},",
                "\"refs_changed\":false,\"execution_retried\":false}}"
            ),
            self.committed,
            self.refused,
            self.previously_decided,
            self.waiting,
            self.pending,
            self.request_stopped,
            self.error.as_deref().map_or_else(|| "null".into(), reporting::quote),
        )
    }
}

pub(super) enum RefreshSelection {
    Unneeded,
    Waiting,
    Ready {
        basis: RepositoryAuthorityHeadId,
        command: QueueHeadRefreshCommand,
    },
}

struct Retained {
    pending: Option<Attempt>,
    acknowledged: usize,
    refused_semantics: BTreeSet<String>,
}

fn identity(
    scope: &[u8; 32],
    merge: &pull_request_merge::PullRequestMergeWatchConfig,
    principal: PrincipalId,
) -> [u8; 32] {
    commitment(&[
        b"frankengit/queue-watch-refresh-principal/v1",
        scope,
        &merge.identity(),
        principal.as_bytes(),
    ])
}

fn binding(root: &Path) -> Result<Option<[u8; 32]>, TrustedWorkflowFailure> {
    let path = root.join("refresh-principal");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io(error)),
        Ok(_) => reporting::read_private(&path, 32)?
            .try_into()
            .map(Some)
            .map_err(|_| invalid("invalid queue refresh principal binding")),
    }
}

fn scope_inputs(
    target: &RefName,
    number: u64,
    directory: &[u8],
    parent: &Path,
    merge: &pull_request_merge::PullRequestMergeWatchConfig,
) -> Result<(), TrustedWorkflowFailure> {
    merge_queue::validate_selection(target, None, Some(number), Some(merge))?;
    if !target.as_bytes().starts_with(b"refs/heads/")
        || target.as_bytes().len() > 4096
        || directory.is_empty()
        || directory.len() > 4096
        || fgit_treefs::TreePath::parse_default(directory).is_err()
        || !parent.is_absolute()
    {
        return Err(invalid("invalid automatic queue refresh scope"));
    }
    Ok(())
}

/// Validate every retained command before submitting any one of them. A stored
/// principal is used only to verify a historical record; it never grants a
/// submission identity. Unacknowledged work requires the explicit launch grant.
async fn inspect_retained(
    node: &OneNode,
    request: &NodeRequestContext,
    target: &RefName,
    number: u64,
    root: &Path,
    scope: &[u8; 32],
    merge: &pull_request_merge::PullRequestMergeWatchConfig,
    refresher: Option<PrincipalId>,
) -> Result<Retained, TrustedWorkflowFailure> {
    let names = custody::records(root)?;
    let bound = binding(root)?;
    if names.is_empty() {
        if bound.is_some() || fs::symlink_metadata(root.join("queue-refresh")).is_ok() {
            return Err(invalid("queue refresh custody is missing its original intent"));
        }
        return Ok(Retained { pending: None, acknowledged: 0, refused_semantics: BTreeSet::new() });
    }
    // A crash can leave a fully synced first intent before its separate
    // principal marker. Only the independently configured principal can supply
    // the missing expected binding; stored bytes never grant that identity.
    // Startup validates this state without repairing it or submitting work.
    let bound = match bound {
        Some(bound) => bound,
        None => identity(
            scope,
            merge,
            refresher.ok_or_else(|| invalid("queue refresh principal binding is missing"))?,
        ),
    };
    if refresher.is_some_and(|principal| identity(scope, merge, principal) != bound) {
        return Err(invalid("queue refresh principal differs from original custody"));
    }
    let mut retained = Retained { pending: None, acknowledged: 0, refused_semantics: BTreeSet::new() };
    for name in names {
        if !request.checkpoint_is_live() {
            return Err(invalid("queue refresh custody verification stopped"));
        }
        let bytes = custody::read_record(root, &name)?;
        let recorded_principal = custody::record_principal(&bytes)?;
        let expected_identity = identity(scope, merge, recorded_principal);
        if expected_identity != bound {
            return Err(invalid("queue refresh record has a foreign principal or scope"));
        }
        let attempt = Attempt::decode(
            node, recorded_principal, expected_identity, &name, &bytes,
        )?;
        if attempt.command.number.get() != number
            || attempt.command.pull_request.data.target_ref != *target
        {
            return Err(invalid("queue refresh command exceeds its fixed queue target"));
        }
        if let Some((ack, sequence)) = custody::acknowledged(root, &attempt)? {
            let outcome = node.resolve_outcome_checkpointed_in(request, attempt.tx_id)
                .await.map_err(outcome_read_error)?;
            let OutcomeLookup::Decided(terminal) = outcome else {
                return Err(invalid("queue refresh acknowledgement lacks its canonical outcome"));
            };
            if terminal.decision_sequence.get() != sequence
                || matches!(terminal.outcome, DecisionOutcome::Committed { .. })
                    != (ack == Acknowledgement::Committed)
            {
                return Err(invalid("queue refresh acknowledgement differs from native authority"));
            }
            retained.acknowledged += 1;
            if ack == Acknowledgement::Refused {
                retained.refused_semantics.insert(attempt.semantic.clone());
            }
        } else {
            if refresher != Some(recorded_principal) {
                return Err(invalid("pending queue refresh requires its original explicit principal"));
            }
            if retained.pending.replace(attempt).is_some() {
                return Err(invalid("multiple unresolved queue refresh intents"));
            }
        }
    }
    Ok(retained)
}

// Cancellation classification is confined to read-only startup/ACK inspection.
// A corrupt record or unrelated native failure never becomes a clean stop.
fn outcome_read_error(error: fgit_authority::OutcomeFailure) -> TrustedWorkflowFailure {
    let error = crate::NodeRefusal::Authority(Box::new(error));
    if super::cancellation::node_read(&error) {
        invalid("queue refresh custody verification stopped")
    } else {
        invalid_owned(error.to_string())
    }
}

pub(super) async fn validated_pending_in(
    node: &OneNode,
    request: &NodeRequestContext,
    target: &RefName,
    number: u64,
    root: &Path,
    scope: &[u8; 32],
    merge: &pull_request_merge::PullRequestMergeWatchConfig,
    refresher: Option<PrincipalId>,
) -> Result<bool, TrustedWorkflowFailure> {
    Ok(inspect_retained(
        node, request, target, number, root, scope, merge, refresher,
    ).await?.pending.is_some())
}

/// Ordinary polling and landing cannot escape unresolved refresh responsibility
/// by restarting without its grant. Canonical ACK verification performs no write.
pub(super) async fn ensure_resolved_in(
    node: &OneNode,
    request: &NodeRequestContext,
    target: &RefName,
    number: u64,
    root: &Path,
    scope: &[u8; 32],
    merge: &pull_request_merge::PullRequestMergeWatchConfig,
) -> Result<(), TrustedWorkflowFailure> {
    inspect_retained(node, request, target, number, root, scope, merge, None).await?;
    Ok(())
}

impl OneNode {
    /// Read-only validation before listener/foreground readiness. Known local
    /// ACKs must agree with native authority. A configured principal may retain
    /// an undecided original for post-readiness recovery, but this method never
    /// submits it, selects a new intent, or writes a refresh acknowledgement.
    /// Returns true when valid unacknowledged responsibility remains retained.
    pub async fn validate_trusted_queue_head_refresh_custody_in(
        &self,
        request: &NodeRequestContext,
        target: &RefName,
        number: u64,
        directory: &[u8],
        parent: &Path,
        merge: &pull_request_merge::PullRequestMergeWatchConfig,
        refresher: Option<PrincipalId>,
    ) -> Result<bool, TrustedWorkflowFailure> {
        scope_inputs(target, number, directory, parent, merge)?;
        check_directory(parent)?;
        let scope = merge_queue::scope(self, target, directory, number);
        let root = parent.join(format!("watch-{}", hex(&scope)));
        let _owner = Owner::open(&root)?;
        merge.bind(&root)?;
        validated_pending_in(
            self, request, target, number, &root, &scope, merge, refresher,
        ).await
    }

    /// Explicit trusted-operator authority to update only the idle queue head's
    /// recorded target. The separately supplied refresh principal sponsors both
    /// queue management and the PR Update; CI/check/landing identities grant no
    /// implicit metadata authority. Current native visibility and exact guards
    /// remain mandatory. No Git ref, review, check or queue order is changed.
    ///
    /// At most one new command is retained per pass. Every original command is
    /// recovered first. Fresh selection waits for settled execution and verified
    /// canonical landing acknowledgements. The caller must invoke this only
    /// after its readiness callback succeeds.
    pub async fn refresh_trusted_queue_head_merge_workflows_in(
        &self,
        request: &NodeRequestContext,
        target: &RefName,
        number: u64,
        directory: &[u8],
        parent: &Path,
        merge: &pull_request_merge::PullRequestMergeWatchConfig,
        publisher: PrincipalId,
        lander: PrincipalId,
        refresher: PrincipalId,
        mode: QueueRefreshMode,
        mut observe: impl FnMut(&str) -> Result<(), String>,
    ) -> TrustedQueueRefresh {
        let mut result = TrustedQueueRefresh::default();
        let work: Result<(), TrustedWorkflowFailure> = async {
            scope_inputs(target, number, directory, parent, merge)?;
            if stopped(request, &mut result) { return Ok(()); }
            check_directory(parent)?;
            let scope = merge_queue::scope(self, target, directory, number);
            let root = parent.join(format!("watch-{}", hex(&scope)));
            let _owner = Owner::open(&root)?;
            merge.bind(&root)?;
            let mut retained = inspect_retained(
                self, request, target, number, &root, &scope, merge, Some(refresher),
            ).await?;
            result.previously_decided = retained.acknowledged;
            result.pending = retained.pending.is_some();
            if stopped(request, &mut result) { return Ok(()); }
            if retained.acknowledged != 0 || retained.pending.is_some() {
                // Repair the first-reservation crash window only after every
                // record has validated under the explicit launch authority.
                // This pass runs after readiness; startup never repairs it.
                reporting::bind_identity(
                    &root, "refresh-principal", &identity(&scope, merge, refresher),
                )?;
            }
            if let Some(attempt) = retained.pending.take() {
                let refused = result.refused;
                self.finish_queue_watch_refresh(
                    request, &root, &attempt, &mut result, &mut observe,
                ).await?;
                if result.refused != refused {
                    retained.refused_semantics.insert(attempt.semantic.clone());
                }
            }
            if mode == QueueRefreshMode::RecoverOnly || stopped(request, &mut result) {
                return Ok(());
            }
            if !queue_landing::settled_for_refresh_in(
                self, request, target, directory, &root, &scope, merge, publisher, lander,
            ).await? {
                result.waiting += 1;
                return Ok(());
            }
            // A verified never-started candidate is still an earlier execution
            // obligation. Let the ordinary poll resume it; a new PR Update must
            // not invalidate it or bypass its canonical publication recovery.
            let mut settled = true;
            for entry in reporting::event_entries(&root)? {
                if stopped(request, &mut result) { return Ok(()); }
                check_directory(&entry.path())?;
                let name = entry.file_name();
                let key = name.to_str().and_then(|name| name.strip_prefix("event-"))
                    .filter(|key| lower_hash(key))
                    .ok_or_else(|| invalid("invalid queue refresh event custody"))?;
                settled &= reporting::recover_settlement(
                    self, merge.reference(), directory, &entry.path(), &scope, key,
                    &|| request.checkpoint_is_live(),
                )?;
            }
            if !settled {
                result.waiting += 1;
                return Ok(());
            }
            if stopped(request, &mut result) { return Ok(()); }
            let (basis, command) = match self
                .select_queue_target_refresh_in(request, target, number).await?
            {
                RefreshSelection::Unneeded => return Ok(()),
                RefreshSelection::Waiting => {
                    result.waiting += 1;
                    return Ok(());
                }
                RefreshSelection::Ready { basis, command } => (basis, command),
            };
            let expected_identity = identity(&scope, merge, refresher);
            let attempt = Attempt::new(self, refresher, &command, expected_identity, basis)?;
            // Our own refused decision advances the authority head. A new basis
            // alone must not manufacture another identical semantic attempt.
            // Only changed command guards/content may select a new retry key.
            if retained.refused_semantics.contains(&attempt.semantic) {
                result.waiting += 1;
                return Ok(());
            }
            // Failed readiness observation or cancellation reserves no intent.
            observe(&format!(
                concat!(
                    "{{\"type\":\"workflow_queue_refresh_ready\",",
                    "\"queue_number\":\"{}\",\"pull_request\":\"{}\",",
                    "\"transaction_id\":{},\"old_target\":\"{}\",\"new_target\":\"{}\"}}"
                ),
                command.number.get(), command.pull_request.number.get(),
                reporting::quote(&attempt.tx_id.to_string()),
                command.expected_recorded_target_tip, command.pull_request.data.target_tip,
            )).map_err(invalid_owned)?;
            if stopped(request, &mut result) { return Ok(()); }
            custody::retain(&root, &attempt)?;
            result.pending = true;
            reporting::bind_identity(&root, "refresh-principal", &expected_identity)?;
            // From this point, interruption retains an original complete command
            // and blocks later work until it has a known canonical outcome.
            self.finish_queue_watch_refresh(
                request, &root, &attempt, &mut result, &mut observe,
            ).await?;
            Ok(())
        }.await;
        if let Err(error) = work {
            result.request_stopped = !request.checkpoint_is_live();
            result.error = Some(format!("{error}; retain original queue refresh custody"));
        }
        result
    }

    async fn finish_queue_watch_refresh(
        &self,
        request: &NodeRequestContext,
        root: &Path,
        attempt: &Attempt,
        result: &mut TrustedQueueRefresh,
        observe: &mut impl FnMut(&str) -> Result<(), String>,
    ) -> Result<(), TrustedWorkflowFailure> {
        if !request.checkpoint_is_live() {
            return Err(invalid("queue refresh stopped with original intent retained"));
        }
        let terminal = match self.resolve_outcome_checkpointed_in(request, attempt.tx_id)
            .await.map_err(|error| invalid_owned(error.to_string()))?
        {
            OutcomeLookup::Decided(terminal) => terminal,
            OutcomeLookup::Undecided => {
                let (tx, terminal) = self.refresh_queue_head_durable_in(
                    request, &attempt.session(), &attempt.command, Default::default(),
                ).await.map_err(|error| invalid_owned(error.to_string()))?;
                if tx != attempt.tx_id {
                    return Err(invalid("queue refresh returned a different original transaction"));
                }
                terminal
            }
        };
        if matches!(terminal.outcome, DecisionOutcome::Committed { .. }) {
            result.committed += 1;
        } else {
            result.refused += 1;
        }
        observe(&decision_json(attempt, &terminal)).map_err(invalid_owned)?;
        custody::acknowledge(root, attempt, &terminal)?;
        result.pending = false;
        Ok(())
    }
}

fn stopped(request: &NodeRequestContext, result: &mut TrustedQueueRefresh) -> bool {
    if request.checkpoint_is_live() { return false; }
    result.request_stopped = true;
    true
}

fn decision_json(attempt: &Attempt, terminal: &TerminalOutcome) -> String {
    let (committed, repository_commit, refusal) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => (
            true, reporting::quote(&repository_commit_id.to_string()), "null".into(),
        ),
        DecisionOutcome::Refused { code, .. } => (
            false, "null".into(), reporting::quote(&format!("{code:?}")),
        ),
    };
    format!(
        concat!(
            "{{\"type\":\"workflow_queue_refresh_decision\",\"queue_number\":\"{}\",",
            "\"pull_request\":\"{}\",\"transaction_id\":{},\"decision_sequence\":\"{}\",",
            "\"committed\":{},\"repository_commit_id\":{},\"refusal_code\":{},",
            "\"historical_outcome\":true,\"refs_changed\":false,\"execution_retried\":false}}"
        ),
        attempt.command.number.get(), attempt.command.pull_request.number.get(),
        reporting::quote(&attempt.tx_id.to_string()), terminal.decision_sequence.get(),
        committed, repository_commit, refusal,
    )
}
