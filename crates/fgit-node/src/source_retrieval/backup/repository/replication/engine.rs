//! One original selected approval owns native preflight and approval-last
//! replica publication. Returned JSON renders typed outcomes only.

use super::super::profile::Deadline;
use super::{Options, Receipt};
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Checkpoint {
    ApprovalObserved,
    AllApprovalsAuthenticated,
    WinnerSelected,
    BeforeReplicaAttempt,
    ReplicaUnavailable,
    PayloadRead { bytes: usize, total: u64 },
    BeforeNative,
    NativeCompleted,
    DestinationChecked,
    ArchiveStaged,
    ArchiveVisible,
    ArchiveDurable,
    ApprovalVisible,
    Completed,
}

pub(super) fn execute_with_checkpoints(
    options: &Options,
    deadline: Deadline,
    checkpoint: impl FnMut(Checkpoint) -> Result<(), String>,
) -> Result<Receipt, String> {
    #[cfg(unix)]
    {
        use super::super::approval::witness::WitnessGuard;
        use super::super::recovery_io::{Checkpoint as IoCheckpoint, Control, SourceFailure};
        use super::super::restore::verify::{verification_receipt, verify_selected_pinned_in};
        use super::super::selection::intake::{CapturedSelection, inspect};
        use super::super::selection::replicas::{Acquired, acquire};
        use super::super::selection::separation::Separation;
        use super::filesystem::{PublicationCheckpoint, publish_verified};

        deadline.check()?;
        let selected = &options.selection;
        selected.profile.transfer.validate()?;
        if options.max_read_bytes == 0 || options.max_read_bytes > super::MAX_READ_BYTES {
            return Err("replica payload-read allowance is outside its finite profile".into());
        }
        if selected.operation != super::super::selection::Operation::Verify
            || selected.resume
            || selected.reconstruction.is_some()
        {
            return Err(
                "replica publication requires the native verification acquisition profile".into(),
            );
        }
        let checkpoint = RefCell::new(checkpoint);
        let trust = selected.trust.load(deadline)?;
        let mut witness = selected
            .witness
            .as_deref()
            .map(|path| WitnessGuard::open(path, &trust, deadline))
            .transpose()?;
        let mut native_started = false;
        let mut native_settled = false;
        let mut publication_attempted = false;
        let mut completed: Option<Receipt> = None;
        let result = (|| {
            let inspected = inspect(selected, &trust, &mut witness, deadline, |event| {
                selection_checkpoint(event, &checkpoint)
            })?;
            let separation = Separation::capture_for_output(
                selected,
                witness.as_ref().map(WitnessGuard::directory),
                &options.directory,
                deadline,
            )?;
            let CapturedSelection {
                approval,
                envelope,
                selected: index,
                aliases,
                json: selection,
            } = inspected.capture(
                selected,
                witness.as_ref().map(WitnessGuard::snapshot_json),
                deadline,
                |event| selection_checkpoint(event, &checkpoint),
            )?;
            let attempts = if selected.replica_failover.is_some() {
                aliases
            } else {
                vec![index]
            };
            let mut io_checkpoint = |event| match event {
                IoCheckpoint::PayloadRead { bytes, total } => {
                    checkpoint.borrow_mut()(Checkpoint::PayloadRead { bytes, total })
                }
                _ => Ok(()),
            };
            let control = Control::new(
                &approval,
                deadline,
                options.max_read_bytes,
                &mut io_checkpoint,
            );
            let mut guard = || {
                control.check()?;
                if let Some(witness) = witness.as_ref() {
                    witness.check_selected()?;
                }
                separation.check(deadline)?;
                control.check()
            };
            guard()?;
            let Acquired {
                archive,
                mut source,
                report,
            } = acquire(
                selected,
                &attempts,
                approval.artifact_seal(),
                &control,
                deadline,
                |event| {
                    selection_checkpoint(event, &checkpoint)?;
                    guard()
                },
            )?;
            checkpoint.borrow_mut()(Checkpoint::BeforeNative)?;
            control.check()?;
            native_started = true;
            let verified = verify_selected_pinned_in(
                archive,
                &approval,
                &selected.destination,
                selected.instance,
                selected.profile,
                deadline,
                &mut || {
                    source.check().map_err(SourceFailure::message)?;
                    guard()
                },
            )?;
            native_settled = true;
            checkpoint.borrow_mut()(Checkpoint::NativeCompleted)?;
            guard()?;
            let native = verification_receipt(&verified, selected.instance, Some(&approval));
            let mut publication_checkpoint = |event| {
                let event = match event {
                    PublicationCheckpoint::DestinationChecked => Checkpoint::DestinationChecked,
                    PublicationCheckpoint::ArchiveStaged => Checkpoint::ArchiveStaged,
                    PublicationCheckpoint::ArchiveVisible => Checkpoint::ArchiveVisible,
                    PublicationCheckpoint::ArchiveDurable => Checkpoint::ArchiveDurable,
                    PublicationCheckpoint::ApprovalVisible => Checkpoint::ApprovalVisible,
                    PublicationCheckpoint::Completed => Checkpoint::Completed,
                };
                checkpoint.borrow_mut()(event)
            };
            publication_attempted = true;
            let published = publish_verified(
                &options.directory,
                &mut source,
                &envelope,
                &approval,
                &control,
                deadline,
                &mut guard,
                &mut publication_checkpoint,
            );
            let receipt = |published: &super::filesystem::PublishedReplica| Receipt {
                json: format!(
                    concat!(
                        "{{\"type\":\"repository_backup_replica_published\",\"schema_version\":1,\"complete\":true,{},",
                        "\"selection\":{},\"native\":{},\"acquisition\":{},",
                        "\"payload_bytes_read\":{},\"payload_read_calls\":{},\"max_read_bytes\":{},",
                        "\"read_budget_scope\":\"all_archive_passes\",\"new_signature_created\":false,",
                        "\"destination_authority_published\":false,\"routing_published\":false,\"complete_capsule_verified\":false}}"
                    ),
                    published.json_fields(),
                    selection,
                    native.json(),
                    report.json(&control, options.max_read_bytes),
                    control.bytes_read(),
                    control.read_calls(),
                    options.max_read_bytes
                ),
            };
            match published {
                Ok(published) => {
                    let receipt = receipt(&published);
                    completed = Some(receipt.clone());
                    Ok(receipt)
                }
                Err(failure) => {
                    if let Some(published) = failure.completed.as_ref() {
                        completed = Some(receipt(published));
                    }
                    Err(failure.message())
                }
            }
        })();
        // A returned synchronous publisher has no background transfer work.
        // Uncertainty about file visibility remains in its typed publication
        // failure; it cannot erase the durable witness observation. A native
        // preflight error still lacks quiescence evidence and retains its lease.
        let result = if let Some(witness) = witness {
            if native_started && !native_settled {
                let error = result
                    .err()
                    .unwrap_or_else(|| "native verification completion was not established".into());
                Err(witness.retain(&error))
            } else {
                match witness.finish() {
                    Ok(()) => result,
                    Err(error) => Err(match result {
                        Ok(_) => format!("replica witness finalization failed: {error}"),
                        Err(original) => {
                            format!("{original}; replica witness finalization failed: {error}")
                        }
                    }),
                }
            }
        } else {
            result
        };
        result.map_err(|error| {
            if let Some(receipt) = completed {
                format!("replica publication complete=true; publication_state=durable; preserve completed replica; {error}; completed_result={}", receipt.json())
            } else if !publication_attempted {
                format!("replica publication_state=not_started; native_verification_complete={native_settled}; {error}")
            } else { error }
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (options, deadline, checkpoint);
        Err("native replica publication requires Unix pinned private filesystem custody".into())
    }
}

#[cfg(unix)]
fn selection_checkpoint(
    event: super::super::selection::engine::Checkpoint,
    checkpoint: &RefCell<impl FnMut(Checkpoint) -> Result<(), String>>,
) -> Result<(), String> {
    use super::super::selection::engine::Checkpoint as Selected;
    let event = match event {
        Selected::ApprovalObserved => Checkpoint::ApprovalObserved,
        Selected::AllApprovalsAuthenticated => Checkpoint::AllApprovalsAuthenticated,
        Selected::WinnerSelected => Checkpoint::WinnerSelected,
        Selected::BeforeReplicaAttempt => Checkpoint::BeforeReplicaAttempt,
        Selected::ReplicaUnavailable => Checkpoint::ReplicaUnavailable,
        _ => return Err("unexpected replica acquisition checkpoint".into()),
    };
    checkpoint.borrow_mut()(event)
}
