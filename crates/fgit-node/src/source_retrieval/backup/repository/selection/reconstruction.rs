//! Assemble selected same-statement ranges into one owned private pinned input.
//! The existing native driver owns semantic verification and publication; this
//! composition retains its original approval, witness and read ledger throughout.

use std::cell::RefCell;

use super::super::approval::VerifiedApproval;
use super::super::profile::Deadline;
use super::Options;
use super::engine::{Checkpoint, Progress};

pub(super) fn execute(
    options: &Options,
    aliases: &[usize],
    approval: &VerifiedApproval,
    deadline: Deadline,
    checkpoint: &RefCell<impl FnMut(Checkpoint) -> Result<(), String>>,
    progress: &mut Progress,
    guard: &mut impl FnMut() -> Result<(), String>,
) -> Result<(String, Option<String>), String> {
    #[cfg(unix)]
    {
        use super::super::reconstruct::private::{PreparedReconstruction, prepare_pinned_in};
        use super::super::recovery_io::{Checkpoint as IoCheckpoint, Control};
        use super::Operation;
        use super::engine::execute_native;

        let reconstruction = options
            .reconstruction
            .as_ref()
            .ok_or("selected direct reconstruction options are absent")?;
        let mut replicas = Vec::with_capacity(aliases.len());
        for &index in aliases {
            let candidate = options
                .candidates
                .get(index)
                .ok_or("selected reconstruction internal candidate mismatch")?;
            replicas.push(candidate.input.clone());
        }
        let after_assembly_reads = approval
            .artifact_seal()
            .bytes
            .checked_mul(match options.operation {
                Operation::Verify => 3,
                // Two pinned admission scans, separate Install validation and
                // placement scans, quarantine readback and final destination readback.
                Operation::Recover => 6,
            })
            .ok_or("selected reconstruction native read reservation overflow")?;
        let mut io_checkpoint = |event| match event {
            IoCheckpoint::PayloadRead { bytes, total } => {
                checkpoint.borrow_mut()(Checkpoint::ReconstructionPayloadRead { bytes, total })
            }
            IoCheckpoint::ChunkAccepted { chunk, replica } => {
                checkpoint.borrow_mut()(Checkpoint::ReconstructionChunkAccepted { chunk, replica })
            }
            _ => Ok(()),
        };
        let control = Control::new(
            approval,
            deadline,
            reconstruction.max_read_bytes,
            &mut io_checkpoint,
        );
        control.check()?;
        checkpoint.borrow_mut()(Checkpoint::BeforeReconstruction)?;
        control.check()?;
        // Parent aliases and witness state were captured before selection.
        // Recheck them after observers and before catalog/source admission or
        // private-root creation can acquire any filesystem responsibility.
        guard()?;
        control.check()?;
        let PreparedReconstruction {
            archive,
            owner,
            report,
        } = prepare_pinned_in(
            &reconstruction.catalog,
            &replicas,
            &reconstruction.root,
            approval,
            options.profile.transfer,
            &control,
            after_assembly_reads,
            deadline,
        )?;
        let native = (|| {
            checkpoint.borrow_mut()(Checkpoint::ReconstructionPrepared)?;
            let mut constrained = || {
                control.check()?;
                owner.check_frozen()?;
                guard()?;
                control.check()
            };
            // Refuse preparation/custody changes before declaring native entry.
            // Later native boundaries repeat this same frozen-content guard.
            constrained()?;
            execute_native(
                options,
                archive,
                approval,
                deadline,
                checkpoint,
                progress,
                &mut constrained,
            )
        })();
        if progress.native_started && !progress.native_completed {
            let error = native.err().unwrap_or_else(|| {
                "selected reconstruction native completion was not established".into()
            });
            return Err(owner.retain(&error));
        }
        if !progress.native_completed {
            let error = native
                .err()
                .unwrap_or_else(|| "selected reconstruction did not enter native work".into());
            return Err(owner.failure(error));
        }
        // Native completion is settled even if its final observer failed. Only
        // exact owned cleanup may remove this private input; no late time gate
        // may turn completed publication into an unstarted operation.
        if let Err(cleanup) = owner.finish() {
            let error = match native {
                Ok(_) => format!("private reconstruction cleanup failed: {cleanup}"),
                Err(error) => format!("{error}; private reconstruction cleanup failed: {cleanup}"),
            };
            return Err(format!(
                "selected recovery native_operation_complete=true; preserve completed result and destination; {error}"
            ));
        }
        let native = native?;
        let indices = aliases
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let acquisition = format!(
            "{{{},\"candidate_indices\":[{}],\"root_removed\":true,\"intermediate_archive_published\":false}}",
            report.json_fields(&control, reconstruction.max_read_bytes),
            indices,
        );
        Ok((native, Some(acquisition)))
    }
    #[cfg(not(unix))]
    {
        let _ = (
            options, aliases, approval, deadline, checkpoint, progress, guard,
        );
        Err("selected reconstruction requires Unix private staging and pinned sources".into())
    }
}
