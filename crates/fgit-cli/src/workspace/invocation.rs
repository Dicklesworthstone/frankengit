//! Local execution custody, never repository authority or an agent credential.
//! The operator must keep this node root stable and retain its invocation records.
mod recovery;
mod saved;
pub(super) use recovery::recover;

use super::Options;
use fgit_crypto::sha256_digest;
use fgit_node::{NodeRequestContext, OneNode};
use fgit_types::{GitOid, RepositoryAuthorityHeadId};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
};
use std::path::{Path, PathBuf};

const MAX_REQUEST: usize = 4 * 1024 * 1024;
const REQUEST_MAGIC: &[u8; 8] = b"FGWIR001";

#[derive(Debug)]
pub(super) enum Refusal {
    AlreadyReserved(PathBuf),
    InvalidStorage,
    Limit,
    Io(io::Error),
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyReserved(path) => write!(
                f,
                "workspace invocation already reserved at {}; execution may have occurred, do not change its ID to retry",
                path.display()
            ),
            Self::InvalidStorage => {
                f.write_str("workspace invocation storage must be private, regular and stable")
            }
            Self::Limit => f.write_str("workspace invocation metadata exceeds its finite limit"),
            Self::Io(error) => write!(f, "workspace invocation I/O: {error}"),
        }
    }
}
impl std::error::Error for Refusal {}
impl From<io::Error> for Refusal {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// An irreversible execution claim. Dropping it NEVER makes execution retryable.
#[derive(Debug)]
pub(super) struct Invocation {
    pub(super) directory: PathBuf,
    pub(super) request_id: [u8; 32],
}
impl Invocation {
    fn create(root: &Path, key: &str, request: &[u8]) -> Result<Self, Refusal> {
        if request.len() > MAX_REQUEST {
            return Err(Refusal::Limit);
        }
        private_directory(root)?;
        let directory = root.join(key);
        match DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(Refusal::AlreadyReserved(directory));
            }
            Err(error) => return Err(error.into()),
        }
        // A crash anywhere after mkdir leaves an occupied claim. Never reclaim
        // an empty or incomplete directory as evidence that execution did not run.
        File::open(root)?.sync_all()?;
        let bytes = frame(REQUEST_MAGIC, request);
        let request_id = sha256_digest(&bytes);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("request"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(&directory)?.sync_all()?;
        Ok(Self {
            directory,
            request_id,
        })
    }
}

/// Select once, then require the SAME source again at the existing tool boundary.
/// A stale caller pin refuses before an execution claim or workspace is created.
pub(super) fn reserve(
    node: &OneNode,
    request: &NodeRequestContext,
    options: &Options,
) -> Result<(Invocation, RepositoryAuthorityHeadId, GitOid), String> {
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(request))
        .map_err(|error| error.to_string())?;
    if selected
        .snapshot()
        .hidden_refs
        .hides(options.reference.as_bytes())
    {
        return Err("workspace source RefUnavailable".into());
    }
    let commit = *selected
        .snapshot()
        .refs
        .get(&options.reference)
        .ok_or("workspace source RefUnavailable")?;
    let head = selected.basis().id();
    if options
        .expected_head
        .is_some_and(|expected| expected != head)
    {
        return Err("SnapshotMoved: workspace source head changed before execution".into());
    }
    if options
        .expected_commit
        .is_some_and(|expected| expected != commit)
    {
        return Err("CommitMoved: workspace source commit changed before execution".into());
    }
    let scope = scope(node);
    let key = format!("{}-{}", super::hex(&scope), super::hex(&options.workspace));
    let mut fields = Fields::default();
    for value in [
        b"trusted-workspace-execution-v1".as_slice(),
        &scope,
        &options.workspace,
        options.reference.as_bytes(),
        head.to_string().as_bytes(),
        commit.to_string().as_bytes(),
    ] {
        fields.push(value).map_err(|e| e.to_string())?;
    }
    for path in [&options.storage, &options.parent] {
        fields
            .push(
                fs::canonicalize(path)
                    .map_err(|e| e.to_string())?
                    .as_os_str()
                    .as_bytes(),
            )
            .map_err(|e| e.to_string())?;
    }
    fields
        .push(
            options
                .destination
                .file_name()
                .ok_or("missing bundle filename")?
                .as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    fields
        .push(options.program.as_bytes())
        .map_err(|e| e.to_string())?;
    fields
        .list(options.arguments.iter().map(String::as_bytes))
        .map_err(|e| e.to_string())?;
    fields
        .list(options.reads.iter().map(Vec::as_slice))
        .map_err(|e| e.to_string())?;
    fields
        .list(options.writes.iter().map(Vec::as_slice))
        .map_err(|e| e.to_string())?;
    for value in [
        options.author.as_bytes(),
        &options.timestamp.to_be_bytes(),
        options.message.as_bytes(),
        &options.timeout.as_nanos().to_be_bytes(),
        &fgit_cli::command_timeout_duration()
            .as_nanos()
            .to_be_bytes(),
        b"env-cleared;PATH=/usr/bin:/bin;trusted-host;candidate-only",
    ] {
        fields.push(value).map_err(|e| e.to_string())?;
    }
    let invocation = Invocation::create(
        &node.storage_root().join("workspace-invocations"),
        &key,
        &fields.0,
    )
    .map_err(|e| e.to_string())?;
    eprintln!(
        "workspace invocation reserved: {}; request_sha256={}",
        invocation.directory.display(),
        super::hex(&invocation.request_id)
    );
    Ok((invocation, head, commit))
}

fn scope(node: &OneNode) -> [u8; 32] {
    sha256_digest(
        &[
            b"fg-workspace-scope-v1\0".as_slice(),
            node.tenant_id().as_bytes(),
            node.repository_id().as_bytes(),
            node.repository_incarnation_id().as_bytes(),
        ]
        .concat(),
    )
}
fn private_directory(path: &Path) -> Result<(), Refusal> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => File::open(path.parent().ok_or(Refusal::InvalidStorage)?)?.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(Refusal::InvalidStorage);
    }
    // Establish our own directory durability even if a concurrent creator has
    // not completed its fence. This is a stable operator-owned filesystem.
    File::open(path)?.sync_all()?;
    File::open(path.parent().ok_or(Refusal::InvalidStorage)?)?.sync_all()?;
    Ok(())
}
fn frame(magic: &[u8; 8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(payload.len() + 48);
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(payload);
    let digest = sha256_digest(&bytes);
    bytes.extend_from_slice(&digest);
    bytes
}
#[derive(Default)]
struct Fields(Vec<u8>);
impl Fields {
    fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if bytes
            .len()
            .checked_add(self.0.len())
            .and_then(|n| n.checked_add(8))
            .is_none_or(|n| n > MAX_REQUEST)
        {
            return Err(Refusal::Limit);
        }
        self.0
            .extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn list<'a>(&mut self, values: impl ExactSizeIterator<Item = &'a [u8]>) -> Result<(), Refusal> {
        self.push(&(values.len() as u64).to_be_bytes())?;
        for value in values {
            self.push(value)?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;
