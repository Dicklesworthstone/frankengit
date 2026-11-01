//! Complete only a missing watch settlement after the producer's closed-run
//! handoff is durable. No script, CI publication, check submission or execution
//! fence is created here. A generic completed check prefix is insufficient.

use super::sources::Run;
use super::{
    File, GitOid, MetadataExt, OneNode, Path, RefName, Sources, TrustedWorkflowFailure, digest, fs,
    hex, invalid, io, lower_hash, read_private, settled, write_new,
};
use fgit_runner::Commitment;
use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

mod journal;
mod metadata;

struct Budget {
    jobs: usize,
    receipts: usize,
    evidence: usize,
    metadata: usize,
    journal_bytes: u64,
    batches: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            jobs: 128,
            receipts: 16 * 1024 * 1024,
            evidence: 16 * 1024 * 1024,
            metadata: 8 * 1024 * 1024,
            journal_bytes: 32 * 1024 * 1024,
            batches: 1024,
        }
    }
}

/// Call only while the watch scope's original exclusive Owner is held. The
/// `check-sources` handoff is written only after closed(dispatch),
/// including workspace/cache drain. It therefore anchors a stronger boundary
/// than arbitrary completed job proposals. Every listed execution is still
/// independently checked before reconstructing the missing acknowledgement.
pub(in super::super) fn recover(
    node: &OneNode,
    reference: &RefName,
    workflow_directory: &[u8],
    path: &Path,
    scope: &[u8; 32],
    key: &str,
    live: &dyn Fn() -> bool,
) -> Result<bool, TrustedWorkflowFailure> {
    checkpoint(live)?;
    if settled(path, key)? {
        return Ok(true);
    }
    if !lower_hash(key) {
        return Err(invalid("invalid watch settlement identity"));
    }
    match fs::symlink_metadata(path.join("check-sources")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io(error)),
        Ok(_) => {}
    }
    let event_directory = PrivateDirectory::open(path)?;
    let sources = Sources::read(path, scope, key)?;
    if sources.commit.algorithm() != node.object_format() {
        return Err(invalid("watch settlement native format differs"));
    }
    let mut budget = Budget::default();
    let dispatch = metadata::dispatch(
        node,
        reference,
        workflow_directory,
        path,
        key,
        &sources,
        &mut budget,
        live,
    )?;
    let selected = dispatch
        .definitions
        .iter()
        .filter(|definition| definition.selected)
        .collect::<Vec<_>>();
    sources.verify_selection(selected.len(), dispatch.identity)?;
    if sources
        .runs
        .iter()
        .zip(&selected)
        .any(|(run, definition)| run.run != definition.run)
    {
        return Err(invalid(
            "watch handoff does not match its original selected child prefix",
        ));
    }
    // A closed failed or explicitly stopped prefix may precede later definitions.
    // Retain precisely that observed prefix, never pretend those jobs ran.
    verify_children(&dispatch.directory.path, &sources, live)?;
    for (run, definition) in sources.runs.iter().zip(selected) {
        checkpoint(live)?;
        let child = dispatch
            .directory
            .path
            .join(format!("workflow-{}", hex(&run.run)));
        let child_directory = PrivateDirectory::open(&child)?;
        let marker = metadata::marker(
            node,
            reference,
            &child,
            &dispatch,
            definition,
            run,
            sources.commit,
            &mut budget,
            live,
        )?;
        journal::verify(
            node,
            &child,
            &marker,
            definition,
            run,
            sources.commit,
            sources.terminal.is_some(),
            &mut budget,
            live,
        )?;
        child_directory.verify()?;
    }
    checkpoint(live)?;
    if Sources::read(path, scope, key)?.identity != sources.identity {
        return Err(invalid("watch handoff changed during settlement recovery"));
    }
    verify_children(&dispatch.directory.path, &sources, live)?;
    dispatch.directory.verify()?;
    event_directory.verify()?;
    checkpoint(live)?;
    // Create-only: a corrupt/partial existing marker is never replaced. Once
    // this write begins, finish its sync independently of a later cancellation.
    write_new(&path.join("settled"), key.as_bytes())
        .and_then(|()| event_directory.file.sync_all())
        .map_err(io)?;
    event_directory.verify()?;
    settled(path, key)
}

fn checkpoint(live: &dyn Fn() -> bool) -> Result<(), TrustedWorkflowFailure> {
    if live() {
        Ok(())
    } else {
        Err(invalid("watch settlement recovery cancelled"))
    }
}

fn verify_children(
    path: &Path,
    sources: &Sources,
    live: &dyn Fn() -> bool,
) -> Result<(), TrustedWorkflowFailure> {
    let expected = sources
        .runs
        .iter()
        .map(|run| format!("workflow-{}", hex(&run.run)))
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let mut count = 0usize;
    for entry in fs::read_dir(path).map_err(io)? {
        checkpoint(live)?;
        count += 1;
        if count > 35 {
            return Err(invalid("watch dispatch custody entry limit exceeded"));
        }
        let entry = entry.map_err(io)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| invalid("invalid watch dispatch custody entry"))?;
        if name.starts_with("workflow-") {
            if !expected.contains(name) || !actual.insert(name.to_owned()) {
                return Err(invalid("watch dispatch contains an unrecorded child"));
            }
        } else if !matches!(name, "dispatch.json" | "report.json" | ".report.pending") {
            return Err(invalid("unknown watch dispatch custody entry"));
        }
    }
    if actual != expected {
        return Err(invalid("watch dispatch is missing an original child"));
    }
    Ok(())
}

struct PrivateDirectory {
    path: PathBuf,
    file: File,
    device: u64,
    inode: u64,
}

impl PrivateDirectory {
    fn open(path: &Path) -> Result<Self, TrustedWorkflowFailure> {
        let named = fs::symlink_metadata(path).map_err(io)?;
        if !named.is_dir() || named.mode() & 0o777 != 0o700 {
            return Err(invalid(
                "watch recovery requires a private nonsymlink directory",
            ));
        }
        let file = File::open(path).map_err(io)?;
        let result = Self {
            path: path.to_path_buf(),
            file,
            device: named.dev(),
            inode: named.ino(),
        };
        result.verify()?;
        Ok(result)
    }
    fn verify(&self) -> Result<(), TrustedWorkflowFailure> {
        for metadata in [
            fs::symlink_metadata(&self.path).map_err(io)?,
            self.file.metadata().map_err(io)?,
        ] {
            if !metadata.is_dir()
                || metadata.mode() & 0o777 != 0o700
                || (metadata.dev(), metadata.ino()) != (self.device, self.inode)
            {
                return Err(invalid("watch recovery directory identity changed"));
            }
        }
        Ok(())
    }
}

fn root(bytes: [u8; 32]) -> Result<Commitment, TrustedWorkflowFailure> {
    Commitment::try_from_digest(digest(bytes)?)
        .map_err(|_| invalid("invalid watch settlement root"))
}
