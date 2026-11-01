//! Private range assembly for selected native verification and recovery. The
//! original approval remains authoritative; no intermediate archive is published.

use std::fs::{self, DirBuilder, File, Metadata};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use super::super::super::{quote, require_absent};
use super::super::approval::VerifiedApproval;
use super::super::archive::stream::TransferLimits;
use super::super::attest::filesystem::Stage;
use super::super::input::PinnedArchive;
use super::super::profile::Deadline;
use super::catalog::{CHUNK_BYTES, Catalog};
use super::io::{Checkpoint, Control, Metered};
use super::ranges::{self, DuplicateSources, Replica};

pub(in super::super) struct PreparedReconstruction<'control, 'scope> {
    pub(in super::super) archive: PinnedArchive<Metered<'control, 'scope, File>>,
    pub(in super::super) owner: PrivateReconstruction,
    pub(in super::super) report: RangeReport,
}

/// Assemble and admit the exact original bytes once. The caller supplies the
/// complete subsequent input-read reservation, including these two admission
/// passes and its one verification or four fresh-recovery native passes.
pub(in super::super) fn prepare_pinned_in<'control, 'scope>(
    catalog: &Path,
    replicas: &[PathBuf],
    root: &Path,
    approval: &VerifiedApproval,
    limits: TransferLimits,
    control: &'control Control<'scope>,
    after_assembly_reads: u64,
    deadline: Deadline,
) -> Result<PreparedReconstruction<'control, 'scope>, String> {
    deadline.check()?;
    limits.validate()?;
    control.check()?;
    approval.check_current()?;
    let original = approval.artifact_seal();
    if original.bytes == 0 || original.bytes > limits.max_archive_bytes {
        return Err("selected reconstructed archive exceeds its approved resource profile".into());
    }
    let minimum = original
        .bytes
        .checked_mul(3)
        .ok_or("backup native read reservation overflow")?;
    if after_assembly_reads < minimum {
        return Err(
            "private reconstruction must reserve all subsequent native archive passes".into(),
        );
    }
    let initial = original
        .bytes
        .checked_add(after_assembly_reads)
        .ok_or("backup aggregate read reservation overflow")?;
    control.reserve(initial)?;
    // Hints and source custody are inspected before reserving a private root.
    let catalog = ranges::read_catalog(catalog, original, control)?;
    let mut replicas = ranges::open_replicas(replicas, original, control, DuplicateSources::Skip)?;
    let mut owner = PrivateReconstruction::reserve(root, deadline)?;
    let result = (|| {
        ranges::copy_ranges(
            &catalog,
            &mut replicas,
            owner.stage.file(),
            control,
            after_assembly_reads,
        )?;
        owner.stage.synchronize_content(original.bytes, deadline)?;
        owner.check_frozen()?;
        control.checkpoint(Checkpoint::BeforeVerification)?;
        let file = owner
            .stage
            .file()
            .try_clone()
            .map_err(|error| format!("private reconstruction descriptor clone: {error}"))?;
        let archive = PinnedArchive::from_reader(
            Metered {
                input: file,
                control,
            },
            original.digest,
            limits,
            deadline,
        )?;
        approval.match_archive(archive.header(), archive.seal())?;
        owner.check_frozen()?;
        control.check()?;
        Ok((archive, RangeReport::new(&catalog, &replicas)))
    })();
    match result {
        Ok((archive, report)) => Ok(PreparedReconstruction {
            archive,
            owner,
            report,
        }),
        Err(error) => Err(owner.failure(error)),
    }
}

struct Directory {
    path: PathBuf,
    file: File,
    identity: Metadata,
}

impl Directory {
    fn open(path: &Path) -> Result<Self, String> {
        let file = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| format!("private reconstruction directory open: {error}"))?;
        let identity = file.metadata().map_err(|error| error.to_string())?;
        let directory = Self {
            path: path.to_path_buf(),
            file,
            identity,
        };
        directory.check()?;
        Ok(directory)
    }

    fn check(&self) -> Result<(), String> {
        let opened = self.file.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
        let same = |right: &Metadata| {
            right.is_dir()
                && right.mode() & 0o077 == 0
                && self.identity.dev() == right.dev()
                && self.identity.ino() == right.ino()
                && self.identity.uid() == right.uid()
                && self.identity.mode() == right.mode()
        };
        if !same(&opened) || !same(&named) {
            return Err("private reconstruction directory identity or ownership changed".into());
        }
        Ok(())
    }

    fn sync(&self) -> Result<(), String> {
        self.file
            .sync_all()
            .map_err(|error| format!("private reconstruction directory synchronization: {error}"))
    }
}

/// Owns the original private root and frozen Stage. There is deliberately no
/// Drop cleanup: only an explicit settled finish or a contained pre-native abort
/// can delete files. Unknown native completion retains this evidence.
pub(in super::super) struct PrivateReconstruction {
    parent: Directory,
    root: Directory,
    stage: Stage,
    root_removed: bool,
}

impl PrivateReconstruction {
    fn reserve(path: &Path, deadline: Deadline) -> Result<Self, String> {
        deadline.check()?;
        let name = path
            .file_name()
            .ok_or("private reconstruction requires a named new root")?;
        let supplied_parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent_path = fs::canonicalize(supplied_parent)
            .map_err(|error| format!("private reconstruction parent: {error}"))?;
        let parent = Directory::open(&parent_path)?;
        let path = parent_path.join(name);
        require_absent(&path)?;
        parent.check()?;
        deadline.check()?;
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| format!("private reconstruction root reservation: {error}"))?;
        let retained = |error: String| {
            format!(
                "{error}; private_reconstruction_retained=true; reconstruction_root={}",
                path.display()
            )
        };
        let root = Directory::open(&path).map_err(&retained)?;
        if root.identity.uid() != parent.identity.uid() {
            return Err(retained(
                "private reconstruction parent must be owned by this invocation's filesystem user"
                    .into(),
            ));
        }
        if let Err(error) = parent.sync() {
            return Err(cleanup_setup_failure(error, &parent, &root));
        }
        let stage = match Stage::reserve(&path.join("archive.fgit"), deadline) {
            Ok(stage) => stage,
            Err(error) => return Err(cleanup_setup_failure(error, &parent, &root)),
        };
        let owner = Self {
            parent,
            root,
            stage,
            root_removed: false,
        };
        if let Err(error) = owner.check_root().and_then(|()| deadline.check()) {
            return Err(owner.failure(error));
        }
        Ok(owner)
    }

    fn check_root(&self) -> Result<(), String> {
        self.parent.check()?;
        self.root.check()
    }

    pub(in super::super) fn check_frozen(&self) -> Result<(), String> {
        self.check_root()?;
        self.stage.check_frozen_content()
    }

    fn cleanup(&mut self, before_native: bool) -> Result<(), String> {
        self.check_root()?;
        if before_native {
            self.stage.abort_unverified()?;
        } else {
            self.stage.check_frozen_content()?;
            self.stage.discard()?;
        }
        remove_empty_root(&self.parent, &self.root, &mut self.root_removed)
    }

    /// Native completion is monotonic. These explicit custody and directory
    /// synchronization checks do not reconsider a late deadline or expiry.
    pub(in super::super) fn finish(mut self) -> Result<(), String> {
        self.cleanup(false).map_err(|error| {
            self.retained(&format!(
                "private reconstruction cleanup incomplete: {error}"
            ))
        })
    }

    pub(in super::super) fn failure(mut self, error: String) -> String {
        match self.cleanup(true) {
            Ok(()) => format!("{error}; private_reconstruction_removed=true"),
            Err(cleanup) => self.retained(&format!(
                "{error}; private reconstruction cleanup refused: {cleanup}"
            )),
        }
    }

    pub(in super::super) fn retain(self, error: &str) -> String {
        self.retained(error)
    }

    fn retained(&self, error: &str) -> String {
        cleanup_state(error, &self.root.path, self.root_removed)
    }
}

fn remove_empty_root(
    parent: &Directory,
    root: &Directory,
    removed: &mut bool,
) -> Result<(), String> {
    parent.check()?;
    root.check()?;
    // A foreign file or directory makes this refuse; never recursively delete.
    fs::remove_dir(&root.path)
        .map_err(|error| format!("private reconstruction empty-root removal: {error}"))?;
    // This fact is monotonic even if the following durability checks fail.
    *removed = true;
    parent.check()?;
    parent.sync()
}

fn cleanup_state(error: &str, path: &Path, removed: bool) -> String {
    if removed {
        format!(
            "{error}; private_reconstruction_removed=true; reconstruction_root_removal_durability=uncertain; reconstruction_root={}",
            path.display()
        )
    } else {
        format!(
            "{error}; private_reconstruction_retained=true; reconstruction_root={}",
            path.display()
        )
    }
}

fn cleanup_setup_failure(error: String, parent: &Directory, root: &Directory) -> String {
    let mut removed = false;
    match remove_empty_root(parent, root, &mut removed) {
        Ok(()) => format!("{error}; private_reconstruction_removed=true"),
        Err(cleanup) => cleanup_state(
            &format!("{error}; setup cleanup refused: {cleanup}"),
            &root.path,
            removed,
        ),
    }
}

struct ReplicaReport {
    chunks_used: usize,
    chunks_rejected: usize,
    unavailable: Option<String>,
    duplicate_of: Option<usize>,
}

pub(in super::super) struct RangeReport {
    chunks: usize,
    replicas: Vec<ReplicaReport>,
}

impl RangeReport {
    fn new(catalog: &Catalog, replicas: &[Replica]) -> Self {
        Self {
            chunks: catalog.count(),
            replicas: replicas
                .iter()
                .map(|replica| ReplicaReport {
                    chunks_used: replica.chunks_used,
                    chunks_rejected: replica.chunks_rejected,
                    unavailable: replica.unavailable.clone(),
                    duplicate_of: replica.duplicate_of,
                })
                .collect(),
        }
    }

    pub(in super::super) fn json_fields(&self, control: &Control<'_>, maximum: u64) -> String {
        let sources = self.replicas.iter().enumerate().map(|(index, replica)| format!(
            "{{\"replica_index\":{index},\"chunks_used\":{},\"chunks_rejected\":{},\"unavailable\":{},\"duplicate_of\":{}}}",
            replica.chunks_used, replica.chunks_rejected,
            replica.unavailable.as_deref().map_or_else(|| "null".into(), quote),
            replica.duplicate_of.map_or_else(|| "null".into(), |value| value.to_string()),
        )).collect::<Vec<_>>().join(",");
        format!(
            concat!(
                "\"method\":\"reconstructed_ranges\",\"chunk_bytes\":{},\"chunks\":{},",
                "\"duplicate_sources_skipped\":{},\"payload_bytes_read\":{},\"payload_read_calls\":{},",
                "\"max_read_bytes\":{},\"read_budget_scope\":\"all_archive_passes\",\"replicas\":[{}]"
            ),
            CHUNK_BYTES,
            self.chunks,
            self.replicas
                .iter()
                .filter(|replica| replica.duplicate_of.is_some())
                .count(),
            control.bytes_read(),
            control.read_calls(),
            maximum,
            sources
        )
    }
}

#[cfg(test)]
mod tests;
