//! Reopen saved node job evidence without reading source or executing a plan.
use super::*;
use crate::OneNode;
use fgit_runner::coordinator::delivery::journal::CheckJournalPin;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;

// The node bounds input-prefix bytes to 64 KiB before hex rendering. This
// independent read bound also covers paths, native identities and the empty
// execution envelope, without ever reading a potentially large final report.
const MAX_MARKER_BYTES: u64 = 512 * 1024;

impl TrustedWorkflowRun {
    /// Retain this exact local custody scope independently of the run directory
    /// for later reopening. It identifies the immutable attempt marker; it is
    /// neither a canonical check receipt nor authorization to execute again.
    pub fn check_journal_scope(&self) -> CheckJournalScope {
        scope(self)
    }

    /// Open this run's persisted proposal/evidence stream after its producer has
    /// released the lock. No current ref lookup, source recompilation or script
    /// execution occurs. A trusted minimum pin detects rollback past that pin.
    pub fn open_check_journal(
        &self,
        minimum: Option<CheckJournalPin>,
        live: &dyn Fn() -> bool,
    ) -> Result<FileCheckJournal, TrustedWorkflowFailure> {
        OneNode::open_trusted_workflow_journal(
            &self.run_directory,
            self.check_journal_scope(),
            minimum,
            live,
        )
    }
}

impl OneNode {
    /// Reopen one explicitly selected trusted-local attempt's check proposals
    /// and exact evidence, without requiring a running node or a final report.
    /// This associated function does NOT authenticate canonical repository
    /// authority, declare the workflow complete, or permit replay of user code.
    ///
    /// The operator must supply the retained exact scope, including the original
    /// attempt-marker commitment. A digest read from the same untrusted storage
    /// is not independent rollback evidence. Pass a separately retained journal
    /// pin to detect rollback of an otherwise valid proposal prefix.
    ///
    /// The parent paths must be stable, private and operator-owned, as required
    /// by FileCheckJournal. Same-UID hostile replacement is outside this trusted
    /// profile. Missing/corrupt markers, journals and torn tails fail closed:
    /// nothing is recreated, repaired, deleted, rescheduled, or upgraded here.
    /// Verified partial custody is useful after an uncertain execution, but it
    /// never substitutes for execution.owner or host-process reconciliation.
    pub fn open_trusted_workflow_journal(
        directory: &Path,
        expected: CheckJournalScope,
        minimum: Option<CheckJournalPin>,
        live: &dyn Fn() -> bool,
    ) -> Result<FileCheckJournal, TrustedWorkflowFailure> {
        let refused = |detail| TrustedWorkflowFailure::Journal {
            directory: directory.to_path_buf(),
            detail,
        };
        if !live() {
            return Err(refused("workflow custody read cancelled".to_owned()));
        }
        if !directory.is_absolute() {
            return Err(refused(
                "workflow custody requires an absolute private directory".to_owned(),
            ));
        }
        let metadata = fs::symlink_metadata(directory)
            .map_err(|e| refused(format!("inspect workflow custody directory: {e}")))?;
        if !metadata.is_dir() || metadata.mode() & 0o777 != 0o700 {
            return Err(refused(
                "workflow custody directory must be nonsymlink and 0700".to_owned(),
            ));
        }
        let marker_path = directory.join("attempt.json");
        let selected = fs::symlink_metadata(&marker_path)
            .map_err(|e| refused(format!("inspect original workflow marker: {e}")))?;
        if !selected.is_file()
            || selected.mode() & 0o777 != 0o600
            || selected.nlink() != 1
            || selected.len() == 0
            || selected.len() > MAX_MARKER_BYTES
        {
            return Err(refused(
                "original workflow marker must be a bounded private regular file".to_owned(),
            ));
        }
        if !live() {
            return Err(refused("workflow custody read cancelled".to_owned()));
        }
        let mut file = File::open(&marker_path)
            .map_err(|e| refused(format!("open original workflow marker: {e}")))?;
        let opened = file
            .metadata()
            .map_err(|e| refused(format!("inspect opened workflow marker: {e}")))?;
        if opened.dev() != selected.dev()
            || opened.ino() != selected.ino()
            || opened.len() != selected.len()
            || !opened.is_file()
            || opened.mode() & 0o777 != 0o600
            || opened.nlink() != 1
        {
            return Err(refused(
                "original workflow marker changed while opening".to_owned(),
            ));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_MARKER_BYTES as usize + 1)
            .map_err(|_| refused("workflow marker allocation refused".to_owned()))?;
        file.by_ref()
            .take(MAX_MARKER_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| refused(format!("read original workflow marker: {e}")))?;
        if bytes.len() as u64 != selected.len()
            || bytes.len() as u64 > MAX_MARKER_BYTES
            || Commitment::of_bytes(&bytes) != expected.journal_id
        {
            return Err(refused(
                "original workflow marker does not match the retained custody scope".to_owned(),
            ));
        }
        if !live() {
            return Err(refused("workflow custody read cancelled".to_owned()));
        }
        FileCheckJournal::open(
            &directory.join(JOURNAL_FILE),
            expected,
            Default::default(),
            minimum,
            live,
        )
        .map_err(|e| refused(format!("reopen workflow proposal custody: {e}")))
    }
}

#[cfg(test)]
mod tests;

// Read-only node API for CLI/agent recovery without execution capabilities.
mod inspect;
