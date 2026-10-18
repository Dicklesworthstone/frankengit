use super::{
    options::{Options, Selection},
    output,
};
use fgit_object_fabric::artifact::storage::{
    ArtifactOperation, ArtifactPut, ArtifactScope, ArtifactStorageError, LocalArtifactStore,
};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

pub(super) fn run(
    options: &Options,
    timeout: Duration,
    live: &dyn Fn() -> bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    match perform(options, timeout, live) {
        Ok(receipt) => output::completed(out, err, &receipt),
        Err(error) => {
            let uncertain = matches!(error, ArtifactStorageError::PublicationUncertain { .. });
            let id = match &options.selection {
                Selection::Put { identity, .. } => identity.artifact_id(),
                Selection::Inspect { id } | Selection::Export { id, .. } => id,
            };
            output::error(
                err,
                if uncertain {
                    "publication_uncertain"
                } else {
                    "refused"
                },
                &format!("{error}; original artifact ID {}", output::hash(id)),
                if uncertain { 3 } else { 2 },
            )
        }
    }
}
fn perform(
    options: &Options,
    timeout: Duration,
    live: &dyn Fn() -> bool,
) -> Result<String, ArtifactStorageError> {
    // The one absolute deadline starts BEFORE selecting/opening any storage.
    let operation = ArtifactOperation::new(options.maximum, timeout, live)?;
    if !live() {
        return Err(ArtifactStorageError::Cancelled);
    }
    let scope = ArtifactScope::new(
        options.tenant,
        options.repository,
        options.incarnation,
        &options.trust,
    )?;
    let store = LocalArtifactStore::open(&options.root, scope)?;
    let (identity, action, disposition) = match &options.selection {
        Selection::Put { source, identity } => {
            let mut source = source_file(source)?;
            let disposition = match store.put(identity, &mut source, &operation)? {
                ArtifactPut::Created => "created",
                ArtifactPut::AlreadyPresent => "already_present",
            };
            (identity.clone(), "put", disposition)
        }
        Selection::Inspect { id } => (store.inspect(id, &operation)?, "inspect", "verified"),
        Selection::Export { id, output } => {
            (store.export(id, output, &operation)?, "export", "created")
        }
    };
    // Do not reinterpret a late stop/output failure as rollback of a durable link.
    Ok(output::receipt(
        options,
        &store.scope().commitment(),
        &identity,
        action,
        disposition,
    ))
}
fn io_error(error: io::Error) -> ArtifactStorageError {
    ArtifactStorageError::Io {
        operation: "open explicit artifact input",
        kind: error.kind(),
    }
}
fn source_file(path: &Path) -> Result<File, ArtifactStorageError> {
    // Matches the store's trusted stable-directory profile. These checks are not
    // a sandbox against concurrent same-UID replacement of directory components.
    let mut prefix = std::path::PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        let metadata = fs::symlink_metadata(&prefix).map_err(io_error)?;
        if metadata.file_type().is_symlink() || (prefix != path && !metadata.is_dir()) {
            return Err(ArtifactStorageError::UnsafePath);
        }
    }
    let before = fs::symlink_metadata(path).map_err(io_error)?;
    if !before.is_file() {
        return Err(ArtifactStorageError::UnsafePath);
    }
    let file = File::open(path).map_err(io_error)?;
    let after = file.metadata().map_err(io_error)?;
    if !after.is_file()
        || (before.dev(), before.ino(), before.len()) != (after.dev(), after.ino(), after.len())
    {
        return Err(ArtifactStorageError::UnsafePath);
    }
    Ok(file)
}
