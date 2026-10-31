//! Authentication precedes rank; rank precedes eligibility and payload I/O.
//! Native work consumes the exact captured winner, never a reopened control.

use fgit_crypto::{DigestHasher, Sha256Hasher};

use super::super::super::{hex, quote};
use super::super::approval::AuthenticatedApprovalObservation;
use super::super::input::PinnedArchive;
use super::super::profile::Deadline;
use super::{Candidate, Operation, Options, Receipt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Checkpoint {
    AllApprovalsAuthenticated,
    WinnerSelected,
    BeforeNative,
    NativeCompleted,
}

pub(super) fn execute_with_checkpoints(
    options: &Options,
    deadline: Deadline,
    mut checkpoint: impl FnMut(Checkpoint) -> Result<(), String>,
) -> Result<Receipt, String> {
    let mut native_started = false;
    let result = execute_inner(options, deadline, &mut checkpoint, &mut native_started);
    result.map_err(|error| {
        if options.resume && !native_started {
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
    native_started: &mut bool,
) -> Result<Receipt, String> {
    deadline.check()?;
    options.profile.transfer.validate()?;
    if options.candidates.is_empty() || options.candidates.len() > super::MAX_CANDIDATES {
        return Err("selected recovery requires 1..64 explicit candidate pairs".into());
    }
    let trust = options.trust.load(deadline)?;
    let mut inspected = Vec::with_capacity(options.candidates.len());
    for candidate in &options.candidates {
        deadline.check()?;
        inspected.push(trust.inspect_path(&candidate.approval)?);
    }
    checkpoint(Checkpoint::AllApprovalsAuthenticated)?;
    deadline.check()?;
    let selected = highest(&inspected)?;
    let winner = &inspected[selected];
    let aliases = inspected
        .iter()
        .filter(|observation| observation.same_statement(winner))
        .count();
    let selection = selection_json(&options.candidates, &inspected, selected, aliases);
    checkpoint(Checkpoint::WinnerSelected)?;
    deadline.check()?;
    let observation = inspected
        .into_iter()
        .nth(selected)
        .ok_or("selected recovery internal candidate mismatch")?;
    // Only a selected, currently eligible observation can become the evidence
    // type the native verify/restore engines accept. Lower paths remain unopened.
    let approval =
        observation.into_verified(options.expected, options.profile.transfer.max_archive_bytes)?;
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
    *native_started = true;
    let native = match options.operation {
        Operation::Verify => super::super::restore::verify::execute_selected_in(
            archive,
            approval,
            &options.destination,
            options.instance,
            options.profile,
            deadline,
        )?
        .json()
        .to_owned(),
        Operation::Recover => super::super::restore::execute_selected_in(
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
    };
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
            "\"persistent_high_water_enforced\":false,\"newest_checkpoint_verified\":false,",
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
    )
}
