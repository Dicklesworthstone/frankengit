//! Explicit trusted-operator queue landing after complete candidate execution.
//! Local custody owns retries; current native admission owns every publication.

use super::{
    File, NodeRequestContext, OneNode, Owner, Path, RefName, Selection, TrustedWorkflowFailure,
    check_directory, commitment, fs, hex, invalid, invalid_owned, io, lower_hash, merge_queue,
    prestart, pull_request_merge, reporting, write_new,
};
use fgit_admission::merge::native::queue::QueueCandidateLandingCommand;
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_forge::event::NativeMerge;
use fgit_types::{DecisionOutcome, PrincipalId, RefusalCode};
use std::collections::BTreeSet;

mod custody;
use custody::{Acknowledgement, Attempt};

const MAX_SCOPE_ATTEMPTS: usize = 1024;

/// Observations from one bounded landing pass. Waiting and stale candidates
/// cause no canonical write. Previously decided counts describe local retry
/// suppression, not a fresh canonical success. Errors retain original custody.
#[derive(Debug, Default)]
pub struct TrustedQueueLanding {
    pub committed: usize,
    pub refused: usize,
    pub previously_decided: usize,
    pub waiting: usize,
    pub stale: usize,
    pub request_stopped: bool,
    pub error: Option<String>,
}

impl TrustedQueueLanding {
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"type\":\"workflow_queue_landing\",\"schema_version\":1,",
                "\"committed\":{},\"refused\":{},\"previously_decided\":{},",
                "\"waiting\":{},\"stale\":{},\"request_stopped\":{},\"error\":{},",
                "\"execution_retried\":false}}"
            ),
            self.committed,
            self.refused,
            self.previously_decided,
            self.waiting,
            self.stale,
            self.request_stopped,
            self.error
                .as_deref()
                .map_or_else(|| "null".into(), reporting::quote),
        )
    }
}

impl OneNode {
    /// Land at most one newly eligible queue head using its original tested
    /// candidate. The operator separately authorizes the landing principal;
    /// workflow text, queue membership and successful execution grant no write.
    ///
    /// Recover every outstanding original landing before selecting new work.
    /// A complete successful execution and committed original checks are required
    /// even when branch policy has no required checks. Native admission also
    /// revalidates current reviews, policy, queue/PR versions, refs and objects.
    /// Missing evidence waits without sealing a terminal refusal. An actual
    /// raced refusal remains immutable; a later readiness observation may create
    /// a distinct bounded attempt only after the old outcome is known.
    ///
    /// This is the existing Linux trusted-host profile, not remote credentials,
    /// hostile-code isolation, a speculative train or a protection exemption.
    pub async fn land_trusted_queue_head_merge_workflows_in(
        &self,
        request: &NodeRequestContext,
        target: &RefName,
        number: u64,
        directory: &[u8],
        parent: &Path,
        publisher: PrincipalId,
        merge: &pull_request_merge::PullRequestMergeWatchConfig,
        lander: PrincipalId,
        mut observe: impl FnMut(&str) -> Result<(), String>,
    ) -> TrustedQueueLanding {
        let mut result = TrustedQueueLanding::default();
        let work: Result<(), TrustedWorkflowFailure> = async {
            merge_queue::validate_selection(target, None, Some(number), Some(merge))?;
            if !target.as_bytes().starts_with(b"refs/heads/")
                || target.as_bytes().len() > 4096
                || directory.is_empty() || directory.len() > 4096
                || fgit_treefs::TreePath::parse_default(directory).is_err()
                || !parent.is_absolute()
            {
                return Err(invalid("invalid automatic queue landing scope"));
            }
            if stopped(request, &mut result) { return Ok(()); }
            check_directory(parent)?;
            let scope = merge_queue::scope(self, target, directory, number);
            let root = parent.join(format!("watch-{}", hex(&scope)));
            let _owner = Owner::open(&root)?;
            merge.bind(&root)?;
            super::queue_refresh::ensure_resolved_in(
                self, request, target, number, &root, &scope, merge,
            ).await?;
            let reporter = commitment(&[
                b"frankengit/watch-reporter/v1", &scope, publisher.as_bytes(),
            ]);
            reporting::bind_identity(&root, "publisher", &reporter)?;
            let identity = commitment(&[
                b"frankengit/queue-watch-lander/v1", &scope, &merge.identity(),
                publisher.as_bytes(), lander.as_bytes(),
            ]);
            reporting::bind_identity(&root, "landing-principal", &identity)?;

            // Scan all retained custody first. A moved or hidden current queue
            // never erases responsibility for an earlier submitted transaction.
            let mut scope_attempts = 0usize;
            let mut committed_events = BTreeSet::new();
            for entry in reporting::event_entries(&root)? {
                if stopped(request, &mut result) { return Ok(()); }
                let path = entry.path();
                check_directory(&path)?;
                let name = entry.file_name();
                let key = name.to_str().and_then(|name| name.strip_prefix("event-"))
                    .filter(|key| lower_hash(key))
                    .ok_or_else(|| invalid("invalid queue landing event custody"))?;
                let records = custody::records(&path)?;
                scope_attempts = scope_attempts.checked_add(records.len())
                    .filter(|count| *count <= MAX_SCOPE_ATTEMPTS)
                    .ok_or_else(|| invalid("automatic queue landing scope attempt bound exceeded"))?;
                if records.is_empty() { continue; }
                let original = prestart::read_landing(
                    self, target, directory, &path, &scope, key, merge,
                    &|| request.checkpoint_is_live(),
                )?;
                let command = command(&original)?;
                for (name, bytes) in records {
                    if stopped(request, &mut result) { return Ok(()); }
                    let attempt = Attempt::decode(self, lander, &command, identity,
                        original.event_id, &name, &bytes)?;
                    if let Some((ack, sequence)) = custody::acknowledged(&path, &attempt)? {
                        // The local receipt suppresses duplicate output only.
                        // Authenticate its claimed terminal result before it
                        // can discharge custody or skip an execution fence.
                        let outcome = self
                            .resolve_outcome_checkpointed_in(request, attempt.tx_id)
                            .await
                            .map_err(|error| invalid_owned(error.to_string()))?;
                        let OutcomeLookup::Decided(terminal) = outcome else {
                            return Err(invalid(
                                "queue landing acknowledgement lacks its canonical outcome",
                            ));
                        };
                        let committed = matches!(
                            terminal.outcome,
                            DecisionOutcome::Committed { .. }
                        );
                        if terminal.decision_sequence.get() != sequence
                            || committed != (ack == Acknowledgement::Committed)
                        {
                            return Err(invalid(
                                "queue landing acknowledgement differs from its canonical outcome",
                            ));
                        }
                        result.previously_decided += 1;
                        if committed {
                            committed_events.insert(path.clone());
                        }
                        continue;
                    }
                    if self.finish_queue_watch_landing(
                        request, &path, &original, &command, &attempt,
                        &mut result, &mut observe,
                    ).await? {
                        committed_events.insert(path.clone());
                    }
                    if result.request_stopped { return Ok(()); }
                }
            }

            // Resolve earlier landing responsibility before checking execution
            // custody: decided retries do not depend on retained run files.
            // Before any new landing, however, every scope event must have a
            // verified closed handoff or an intact never-started intent.
            for entry in reporting::event_entries(&root)? {
                if stopped(request, &mut result) { return Ok(()); }
                let path = entry.path();
                if committed_events.contains(&path) { continue; }
                check_directory(&path)?;
                let name = entry.file_name();
                let key = name.to_str().and_then(|name| name.strip_prefix("event-"))
                    .filter(|key| lower_hash(key))
                    .ok_or_else(|| invalid("invalid queue landing event custody"))?;
                if !reporting::recover_settlement(
                    self, merge.reference(), directory, &path, &scope, key,
                    &|| request.checkpoint_is_live(),
                )? && !prestart::pending(
                    self, target, directory, &path, &scope, key, merge, None,
                    &|| request.checkpoint_is_live(),
                )? {
                    return Err(invalid(
                        "watch event unresolved; automatic queue landing blocked",
                    ));
                }
            }

            if stopped(request, &mut result) { return Ok(()); }
            let selected = match self.select_queue_workflow_event(request, target, number).await? {
                Selection::Absent | Selection::Idle(_) => return Ok(()),
                Selection::ChangedBeforeReservation => {
                    result.stale += 1;
                    return Ok(());
                }
                Selection::StoppedBeforeReservation => {
                    result.request_stopped = true;
                    return Ok(());
                }
                Selection::Ready(selected) => selected,
            };
            let event_id = selected.queue.as_ref()
                .ok_or_else(|| invalid("queue landing selection lacks queue coordinates"))?
                .event_id(&scope, &selected)?;
            let key = hex(&event_id);
            let path = root.join(format!("event-{key}"));
            if committed_events.contains(&path) { return Ok(()); }
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    result.waiting += 1;
                    return Ok(());
                }
                Err(error) => return Err(io(error)),
                Ok(_) => check_directory(&path)?,
            }
            // The full execution verifier deliberately bypasses the settlement
            // marker shortcut. It never restarts or adopts an unfinished run.
            if !reporting::verify_complete(self, merge.reference(), directory,
                &path, &scope, &key, &|| request.checkpoint_is_live())?
            {
                result.waiting += 1;
                return Ok(());
            }
            let original = prestart::read_landing(
                self, target, directory, &path, &scope, &key, merge,
                &|| request.checkpoint_is_live(),
            )?;
            if !self.queue_watch_checks_ready(request, &path, &scope, &key,
                publisher, merge.reference(), original.prepared.commit).await?
            {
                result.waiting += 1;
                return Ok(());
            }
            let command = command(&original)?;
            let attempt = Attempt::new(self, lander, &command, identity, event_id, selected.head)?;
            let readiness = self.inspect_queue_head_candidate_in(
                request, &attempt.session(), &command,
            ).await.map_err(TrustedWorkflowFailure::Source)?;
            if readiness.basis != selected.head {
                result.stale += 1;
                return Ok(());
            }
            if let Some(code) = readiness.refusal {
                if matches!(code, RefusalCode::EvidenceStale | RefusalCode::TargetRefMoved
                    | RefusalCode::HiddenRefUnauthorized)
                {
                    result.stale += 1;
                } else {
                    result.waiting += 1;
                }
                observe(&format!(
                    "{{\"type\":\"workflow_queue_landing_wait\",\"event_id\":\"{key}\",\"basis\":{},\"refusal_code\":{}}}",
                    reporting::quote(&readiness.basis.to_string()),
                    reporting::quote(&format!("{code:?}")),
                )).map_err(invalid_owned)?;
                return Ok(());
            }
            if readiness.tx_id != attempt.tx_id {
                return Err(invalid("queue landing readiness changed its original transaction"));
            }
            if scope_attempts >= MAX_SCOPE_ATTEMPTS {
                return Err(invalid("automatic queue landing scope attempt bound exceeded"));
            }
            if stopped(request, &mut result) { return Ok(()); }
            // Emit the immutable intent before submission. A failed consumer
            // creates no new landing; an observer race still faces admission.
            observe(&format!(
                "{{\"type\":\"workflow_queue_landing_ready\",\"event_id\":\"{key}\",\"transaction_id\":{},\"candidate\":\"{}\"}}",
                reporting::quote(&attempt.tx_id.to_string()), command.merge.merge_commit,
            )).map_err(invalid_owned)?;
            if stopped(request, &mut result) { return Ok(()); }
            custody::retain(&path, &attempt)?;
            self.finish_queue_watch_landing(
                request, &path, &original, &command, &attempt, &mut result, &mut observe,
            ).await?;
            Ok(())
        }.await;
        if let Err(error) = work {
            result.request_stopped = !request.checkpoint_is_live();
            result.error = Some(format!("{error}; retain original queue landing custody"));
        }
        result
    }

    async fn queue_watch_checks_ready(
        &self,
        request: &NodeRequestContext,
        path: &Path,
        scope: &[u8; 32],
        key: &str,
        publisher: PrincipalId,
        reference: &RefName,
        candidate: fgit_types::GitOid,
    ) -> Result<bool, TrustedWorkflowFailure> {
        let sources = reporting::Sources::read(path, scope, key)?;
        if sources.commit != candidate || sources.terminal.is_some() || sources.runs.is_empty() {
            return Ok(false);
        }
        let (mut jobs, mut bytes) = (128usize, 16 * 1024 * 1024usize);
        for source in &sources.runs {
            if !request.checkpoint_is_live() {
                return Err(invalid("queue landing check verification stopped"));
            }
            let child = path
                .join(format!("dispatch-{}", &key[..32]))
                .join(format!("workflow-{}", hex(&source.run)));
            let set = self.prepare_trusted_workflow_check_set(
                request,
                &child,
                reporting::digest(source.journal)?,
                (source.bytes, reporting::digest(source.tail)?),
                publisher,
                reference.clone(),
                (jobs.max(1), bytes.max(1)),
            )?;
            jobs = jobs
                .checked_sub(set.len())
                .ok_or_else(|| invalid("queue landing job bound exceeded"))?;
            bytes = bytes
                .checked_sub(set.evidence_bytes())
                .ok_or_else(|| invalid("queue landing evidence bound exceeded"))?;
            if !set.targets_commit(candidate)
                || !set.all_succeeded()
                || !self
                    .trusted_workflow_check_set_committed_in(request, &set)
                    .await?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn finish_queue_watch_landing(
        &self,
        request: &NodeRequestContext,
        path: &Path,
        original: &prestart::Pending,
        command: &QueueCandidateLandingCommand,
        attempt: &Attempt,
        result: &mut TrustedQueueLanding,
        observe: &mut impl FnMut(&str) -> Result<(), String>,
    ) -> Result<bool, TrustedWorkflowFailure> {
        if stopped(request, result) {
            return Ok(false);
        }
        let terminal = match self
            .resolve_outcome_checkpointed_in(request, attempt.tx_id)
            .await
            .map_err(|error| invalid_owned(error.to_string()))?
        {
            OutcomeLookup::Decided(terminal) => terminal,
            OutcomeLookup::Undecided => {
                let bundle =
                    original.load_landing_bundle(path, &|| request.checkpoint_is_live())?;
                if stopped(request, result) {
                    return Ok(false);
                }
                let (tx, terminal) = self
                    .land_queue_head_bundle_durable_in(
                        request,
                        &attempt.session(),
                        command,
                        &bundle,
                        Default::default(),
                    )
                    .await
                    .map_err(TrustedWorkflowFailure::Source)?;
                if tx != attempt.tx_id {
                    return Err(invalid("queue landing returned a different transaction"));
                }
                terminal
            }
        };
        let committed = matches!(terminal.outcome, DecisionOutcome::Committed { .. });
        if committed {
            result.committed += 1;
        } else {
            result.refused += 1;
        }
        // Output failure leaves the pre-submission record unresolved locally.
        // Its next pass recovers this same canonical outcome, even if the
        // bundle, CI branch, queue head or current permissions have changed.
        observe(&decision_json(original.event_id, attempt, &terminal)).map_err(invalid_owned)?;
        custody::acknowledge(path, attempt, &terminal)?;
        Ok(committed)
    }
}

/// Read-only prerequisite for a fresh metadata refresh. Existing landing
/// records are decoded under their explicitly configured publisher and lander;
/// a local ACK alone cannot discharge a pending code-publication obligation.
pub(super) async fn settled_for_refresh_in(
    node: &OneNode,
    request: &NodeRequestContext,
    target: &RefName,
    directory: &[u8],
    root: &Path,
    scope: &[u8; 32],
    merge: &pull_request_merge::PullRequestMergeWatchConfig,
    publisher: PrincipalId,
    lander: PrincipalId,
) -> Result<bool, TrustedWorkflowFailure> {
    let identity = commitment(&[
        b"frankengit/queue-watch-lander/v1", scope, &merge.identity(),
        publisher.as_bytes(), lander.as_bytes(),
    ]);
    let reporter = commitment(&[
        b"frankengit/watch-reporter/v1", scope, publisher.as_bytes(),
    ]);
    let mut attempts = 0usize;
    let mut settled = true;
    for entry in reporting::event_entries(root)? {
        if !request.checkpoint_is_live() {
            return Err(invalid("queue refresh landing verification stopped"));
        }
        let path = entry.path();
        check_directory(&path)?;
        let name = entry.file_name();
        let key = name.to_str().and_then(|name| name.strip_prefix("event-"))
            .filter(|key| lower_hash(key))
            .ok_or_else(|| invalid("invalid queue landing event custody"))?;
        let records = custody::records(&path)?;
        attempts = attempts.checked_add(records.len())
            .filter(|count| *count <= MAX_SCOPE_ATTEMPTS)
            .ok_or_else(|| invalid("automatic queue landing scope attempt bound exceeded"))?;
        if records.is_empty() { continue; }
        if reporting::read_private(&root.join("publisher"), 32)? != reporter
            || reporting::read_private(&root.join("landing-principal"), 32)? != identity
        {
            return Err(invalid("queue refresh cannot adopt another landing identity"));
        }
        let original = prestart::read_landing(
            node, target, directory, &path, scope, key, merge,
            &|| request.checkpoint_is_live(),
        )?;
        let command = command(&original)?;
        for (name, bytes) in records {
            if !request.checkpoint_is_live() {
                return Err(invalid("queue refresh landing verification stopped"));
            }
            let attempt = Attempt::decode(
                node, lander, &command, identity, original.event_id, &name, &bytes,
            )?;
            let Some((ack, sequence)) = custody::acknowledged(&path, &attempt)? else {
                settled = false;
                continue;
            };
            let outcome = node.resolve_outcome_checkpointed_in(request, attempt.tx_id)
                .await.map_err(|error| invalid_owned(error.to_string()))?;
            let OutcomeLookup::Decided(terminal) = outcome else {
                return Err(invalid("queue landing acknowledgement lacks its canonical outcome"));
            };
            if terminal.decision_sequence.get() != sequence
                || matches!(terminal.outcome, DecisionOutcome::Committed { .. })
                    != (ack == Acknowledgement::Committed)
            {
                return Err(invalid("queue landing acknowledgement differs from its canonical outcome"));
            }
        }
    }
    Ok(settled)
}

fn command(
    original: &prestart::Pending,
) -> Result<QueueCandidateLandingCommand, TrustedWorkflowFailure> {
    let prepared = &original.prepared;
    let queue = prepared
        .queue
        .as_ref()
        .ok_or_else(|| invalid("original candidate is not queue-bound"))?;
    let subject = &prepared.subject;
    Ok(QueueCandidateLandingCommand {
        number: queue.number,
        expected_version: queue.version,
        expected_policy_epoch: subject.policy_epoch,
        pull_request: subject.pull_request,
        expected_pull_request_version: subject.pull_request_version,
        merge: NativeMerge {
            source_ref: subject.source_ref.clone(),
            source_tip: subject.source_tip,
            target_ref: subject.target_ref.clone(),
            target_tip_before: subject.target_tip,
            base_tip: prepared.base,
            merge_commit: prepared.commit,
        },
    })
}

fn stopped(request: &NodeRequestContext, result: &mut TrustedQueueLanding) -> bool {
    if request.checkpoint_is_live() {
        return false;
    }
    result.request_stopped = true;
    true
}

fn decision_json(event: [u8; 32], attempt: &Attempt, terminal: &TerminalOutcome) -> String {
    let (committed, repository_commit, refusal) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            true,
            reporting::quote(&repository_commit_id.to_string()),
            "null".into(),
        ),
        DecisionOutcome::Refused { code, .. } => {
            (false, "null".into(), reporting::quote(&format!("{code:?}")))
        }
    };
    format!(
        concat!(
            "{{\"type\":\"workflow_queue_landing_decision\",\"event_id\":\"{}\",",
            "\"transaction_id\":{},\"decision_sequence\":\"{}\",\"committed\":{},",
            "\"repository_commit_id\":{},\"refusal_code\":{},\"historical_outcome\":true,",
            "\"execution_retried\":false}}"
        ),
        hex(&event),
        reporting::quote(&attempt.tx_id.to_string()),
        terminal.decision_sequence.get(),
        committed,
        repository_commit,
        refusal,
    )
}
