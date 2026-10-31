//! Authentication precedes rank; rank precedes eligibility and payload I/O.
//! Native work consumes the exact captured winner, never a reopened control.

use fgit_crypto::{DigestHasher, Sha256Hasher};

use super::super::super::{hex, quote};
use super::super::approval::AuthenticatedApprovalObservation;
use super::super::approval::witness::WitnessGuard;
use super::super::input::PinnedArchive;
use super::super::profile::Deadline;
use super::separation::Separation;
use super::{Candidate, Operation, Options, Receipt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Checkpoint {
    ApprovalObserved,
    AllApprovalsAuthenticated,
    WinnerSelected,
    BeforeNative,
    NativeCompleted,
}

#[derive(Default)]
struct Progress {
    native_started: bool,
    native_completed: bool,
}

pub(super) fn execute_with_checkpoints(
    options: &Options,
    deadline: Deadline,
    mut checkpoint: impl FnMut(Checkpoint) -> Result<(), String>,
) -> Result<Receipt, String> {
    let mut progress = Progress::default();
    let result = execute_inner(options, deadline, &mut checkpoint, &mut progress);
    result.map_err(|error| {
        if options.resume && !progress.native_started {
            format!("selected resume refused before destination publication state was established; a prior attempt may already have published authority; {error}")
        } else {
            error
        }
    })
}

fn execute_inner(
    options: &Options,
    deadline: Deadline,
    checkpoint: &mut impl FnMut(Checkpoint) -> Result<(), String>,
    progress: &mut Progress,
) -> Result<Receipt, String> {
    deadline.check()?;
    options.profile.transfer.validate()?;
    if options.candidates.is_empty() || options.candidates.len() > super::MAX_CANDIDATES {
        return Err("selected recovery requires 1..64 explicit candidate pairs".into());
    }
    let trust = options.trust.load(deadline)?;
    let mut witness = options
        .witness
        .as_ref()
        .map(|path| WitnessGuard::open(path, &trust, deadline))
        .transpose()?;
    // No early return after acquiring the lease may guess that native work has
    // settled. Explicit progress governs the one finalization path below.
    let result = (|| {
        let mut inspected = Vec::with_capacity(options.candidates.len());
        for candidate in &options.candidates {
            deadline.check()?;
            let observation = trust.inspect_path(&candidate.approval)?;
            // Authentication creates a retention obligation before any observer,
            // next candidate, lifetime/eligibility gate or archive operation.
            if let Some(witness) = witness.as_mut() {
                witness.observe(&observation)?;
            }
            inspected.push(observation);
            checkpoint(Checkpoint::ApprovalObserved)?;
        }
        checkpoint(Checkpoint::AllApprovalsAuthenticated)?;
        deadline.check()?;
        let selected = highest(&inspected)?;
        let winner = &inspected[selected];
        if let Some(witness) = witness.as_mut() {
            witness.require(winner)?;
        }
        let separation = witness
            .as_ref()
            .map(|witness| Separation::capture(options, witness.directory(), deadline))
            .transpose()?;
        let aliases = inspected
            .iter()
            .filter(|observation| observation.same_statement(winner))
            .count();
        let selection = selection_json(
            &options.candidates,
            &inspected,
            selected,
            aliases,
            witness.as_ref().map(WitnessGuard::snapshot_json),
        );
        checkpoint(Checkpoint::WinnerSelected)?;
        deadline.check()?;
        let observation = inspected
            .into_iter()
            .nth(selected)
            .ok_or("selected recovery internal candidate mismatch")?;
        // Only a selected, currently eligible observation can become the evidence
        // type the native verify/restore engines accept. Lower paths remain unopened.
        let approval = observation
            .into_verified(options.expected, options.profile.transfer.max_archive_bytes)?;
        let archive = PinnedArchive::open(
            &options.candidates[selected].input,
            options.expected,
            options.profile.transfer,
            deadline,
        )?;
        approval.match_archive(archive.header(), archive.seal())?;
        checkpoint(Checkpoint::BeforeNative)?;
        approval.check_current()?;
        deadline.check()?;
        let mut guard = || {
            if let Some(witness) = witness.as_ref() {
                witness.check_selected()?;
            }
            if let Some(separation) = separation.as_ref() {
                separation.check(deadline)?;
            }
            Ok(())
        };
        progress.native_started = true;
        let native = match (options.operation, witness.is_some()) {
            (Operation::Verify, false) => super::super::restore::verify::execute_selected_in(
                archive,
                approval,
                &options.destination,
                options.instance,
                options.profile,
                deadline,
            )?
            .json()
            .to_owned(),
            (Operation::Recover, false) => super::super::restore::execute_selected_in(
                archive,
                approval,
                &options.destination,
                options.instance,
                options.profile,
                options.resume,
                deadline,
            )?
            .json()
            .to_owned(),
            (Operation::Verify, true) => {
                super::super::restore::verify::execute_selected_guarded_in(
                    archive,
                    approval,
                    &options.destination,
                    options.instance,
                    options.profile,
                    deadline,
                    &mut guard,
                )?
                .json()
                .to_owned()
            }
            (Operation::Recover, true) => super::super::restore::execute_selected_guarded_in(
                archive,
                approval,
                &options.destination,
                options.instance,
                options.profile,
                options.resume,
                deadline,
                &mut guard,
            )?
            .json()
            .to_owned(),
        };
        progress.native_completed = true;
        // Completion is monotonic. A failed observer/output after the native engine
        // returns may report incomplete delivery, never non-publication or rollback.
        checkpoint(Checkpoint::NativeCompleted).map_err(|error| format!(
        "selected recovery native_operation_complete=true; preserve completed result and destination; {error}"
    ))?;
        Ok(Receipt {
            json: format!(
                "{{\"type\":{},\"schema_version\":1,\"complete\":true,\"selection\":{},\"native\":{}}}",
                quote(match options.operation {
                    Operation::Verify => "repository_source_backup_selected_verify",
                    Operation::Recover => "repository_source_backup_recover",
                }),
                selection,
                native,
            ),
        })
    })();
    finish_witness(witness, result, progress)
}

fn finish_witness(
    witness: Option<WitnessGuard<'_>>,
    result: Result<Receipt, String>,
    progress: &Progress,
) -> Result<Receipt, String> {
    let Some(witness) = witness else {
        return result;
    };
    if progress.native_started && !progress.native_completed {
        let error = result
            .err()
            .unwrap_or_else(|| "selected recovery native completion was not established".into());
        return Err(witness.retain(&error));
    }
    match witness.finish() {
        Ok(()) => result,
        Err(cleanup) => {
            let error = match result {
                Ok(_) => format!("witness finalization failed: {cleanup}"),
                Err(error) => format!("{error}; witness finalization failed: {cleanup}"),
            };
            if progress.native_completed {
                Err(format!(
                    "selected recovery native_operation_complete=true; preserve completed result and destination; {error}"
                ))
            } else {
                Err(error)
            }
        }
    }
}

pub(super) fn highest(observations: &[AuthenticatedApprovalObservation]) -> Result<usize, String> {
    let mut selected = 0;
    for (index, observation) in observations.iter().enumerate() {
        if observation.generation() > observations[selected].generation() {
            selected = index;
        }
    }
    let winner = observations
        .get(selected)
        .ok_or("no authenticated backup checkpoint")?;
    if observations.iter().any(|observation| {
        observation.generation() == winner.generation() && !observation.same_statement(winner)
    }) {
        return Err("highest signed backup generation has conflicting canonical statements; recovery refused without changing destination state".into());
    }
    Ok(selected)
}

fn selection_json(
    candidates: &[Candidate],
    observations: &[AuthenticatedApprovalObservation],
    selected: usize,
    aliases: usize,
    witness: Option<String>,
) -> String {
    let mut digest = Sha256Hasher::new();
    digest.update(b"frankengit/native-backup-candidate-observations/v1\0");
    digest.update(&(candidates.len() as u32).to_be_bytes());
    let rows = candidates.iter().zip(observations).map(|(candidate, observation)| {
        for path in [&candidate.input, &candidate.approval] {
            let bytes = path.as_os_str().as_encoded_bytes();
            digest.update(&(bytes.len() as u32).to_be_bytes());
            digest.update(bytes);
        }
        digest.update(&observation.approval_digest());
        digest.update(&observation.statement_digest());
        format!(
            "{{\"archive\":{},\"approval\":{},\"head_generation\":{},\"approval_sha256\":{},\"statement_sha256\":{}}}",
            quote(&candidate.input.display().to_string()), quote(&candidate.approval.display().to_string()),
            quote(&observation.generation().to_string()), quote(&hex(&observation.approval_digest())),
            quote(&hex(&observation.statement_digest())),
        )
    }).collect::<Vec<_>>().join(",");
    let winner = &observations[selected];
    format!(
        concat!(
            "{{\"type\":\"repository_backup_checkpoint_selection\",\"schema_version\":1,",
            "\"all_supplied_approvals_authenticated\":true,\"highest_supplied_generation_selected\":true,",
            "\"selected_index\":{},\"selected_head_generation\":{},\"candidates_authenticated\":{},",
            "\"same_statement_replicas\":{},\"replica_failover\":false,",
            "\"candidate_set_sha256\":{},\"trusted_key_id\":{},\"approval_sha256\":{},",
            "\"statement\":{},\"candidates\":[{}],\"payloads_read_during_selection\":false,",
            "\"persistent_high_water_enforced\":{}{},\"newest_checkpoint_verified\":false,",
            "\"candidate_set_completeness_verified\":false}}"
        ),
        selected,
        quote(&winner.generation().to_string()),
        candidates.len(),
        aliases,
        quote(&hex(&digest.finish())),
        quote(winner.trusted_key_id()),
        quote(&hex(&winner.approval_digest())),
        winner.statement_json(),
        rows,
        witness.is_some(),
        witness.map_or_else(String::new, |json| format!(",\"recovery_witness\":{json}")),
    )
}
