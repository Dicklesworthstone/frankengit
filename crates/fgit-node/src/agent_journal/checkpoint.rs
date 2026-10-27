//! Immutable original-run recovery inputs. These files are not authority.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use fgit_agent::{
    RunId,
    run_checkpoint::{MAX_RUN_CHECKPOINT_BYTES, RunCheckpoint},
};

use super::file::{AgentJournalHostRefusal, checked_directory};

pub(super) fn create(
    directory: &Path,
    run: &RunCheckpoint,
    check: &dyn Fn() -> Result<(), AgentJournalHostRefusal>,
) -> Result<(), AgentJournalHostRefusal> {
    check()?;
    let bytes = run
        .encode()
        .map_err(AgentJournalHostRefusal::RunCheckpoint)?;
    let directory = checked_directory(directory)?;
    let directory_handle = File::open(&directory).map_err(|_| AgentJournalHostRefusal::Path)?;
    directory_handle
        .sync_all()
        .map_err(|_| AgentJournalHostRefusal::OutcomeUnknown)?;
    check()?;
    let path = directory.join(format!("{:032x}.fg-agent-run", run.run_id().value()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            AgentJournalHostRefusal::Exists
        } else {
            AgentJournalHostRefusal::OutcomeUnknown
        }
    })?;
    file.try_lock().map_err(|_| AgentJournalHostRefusal::Busy)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| directory_handle.sync_all())
        .map_err(|_| AgentJournalHostRefusal::OutcomeUnknown)?;
    check()
}

pub(super) fn read(
    directory: &Path,
    run_id: RunId,
    expected_run: &[u8; 32],
    check: &dyn Fn() -> Result<(), AgentJournalHostRefusal>,
) -> Result<RunCheckpoint, AgentJournalHostRefusal> {
    check()?;
    let directory = checked_directory(directory)?;
    let path = directory.join(format!("{:032x}.fg-agent-run", run_id.value()));
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| AgentJournalHostRefusal::Read)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AgentJournalHostRefusal::Path);
    }
    let file = File::open(path).map_err(|_| AgentJournalHostRefusal::Read)?;
    file.try_lock().map_err(|_| AgentJournalHostRefusal::Busy)?;
    let length = file
        .metadata()
        .map_err(|_| AgentJournalHostRefusal::Read)?
        .len();
    if length > MAX_RUN_CHECKPOINT_BYTES as u64 {
        return Err(AgentJournalHostRefusal::Limit);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    let mut bounded = (&file).take(MAX_RUN_CHECKPOINT_BYTES as u64 + 1);
    let mut buffer = [0; 8192];
    loop {
        check()?;
        let n = bounded
            .read(&mut buffer)
            .map_err(|_| AgentJournalHostRefusal::Read)?;
        if n == 0 {
            break;
        }
        if bytes.len() + n > MAX_RUN_CHECKPOINT_BYTES {
            return Err(AgentJournalHostRefusal::Limit);
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    if bytes.len() as u64 != length
        || file
            .metadata()
            .map_err(|_| AgentJournalHostRefusal::Read)?
            .len()
            != length
    {
        return Err(AgentJournalHostRefusal::Binding);
    }
    let checkpoint =
        RunCheckpoint::decode(&bytes).map_err(AgentJournalHostRefusal::RunCheckpoint)?;
    if checkpoint.run_id() != run_id || checkpoint.claimed_run_commitment() != expected_run {
        return Err(AgentJournalHostRefusal::Binding);
    }
    check()?;
    Ok(checkpoint)
}
