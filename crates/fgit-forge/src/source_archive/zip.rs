//! Source-path policy around TreeFS's shared deterministic stored-ZIP encoder.
use super::{AssemblyRefusal, MAX_ARCHIVE_BYTES, MAX_DEPTH, SourceArchiveFormat, tar};
use crate::source_browse::SourceEntryKind;
use fgit_treefs::archive::{ArchiveRefusal, StoredZipBuilder, ZipEntryKind, ZipLimits};
use fgit_treefs::path::{PathPolicy, TreePath};

pub(super) struct Zip(StoredZipBuilder);

impl Zip {
    pub(super) fn new(max_bytes: usize) -> Result<Self, AssemblyRefusal> {
        let output = Self(StoredZipBuilder::new(ZipLimits {
            max_entries: SourceArchiveFormat::Zip.max_entries(),
            max_entry_bytes: max_bytes.min(MAX_ARCHIVE_BYTES),
            max_output_bytes: max_bytes.min(MAX_ARCHIVE_BYTES),
        }));
        // A complete archive always includes source/. Refuse impossible framing
        // before the caller performs its first authenticated source read.
        output.remaining_payload(b"source", SourceEntryKind::Directory)?;
        Ok(output)
    }

    pub(super) fn remaining_payload(
        &self,
        path: &[u8],
        kind: SourceEntryKind,
    ) -> Result<usize, AssemblyRefusal> {
        let remaining = self
            .0
            .remaining_payload(&member_path(path)?, member_kind(kind).0)
            .map_err(refusal)?;
        Ok(if kind == SourceEntryKind::Symlink {
            remaining.min(SourceArchiveFormat::Zip.max_link_bytes() as usize)
        } else {
            remaining
        })
    }

    pub(super) fn append(
        &mut self,
        path: &[u8],
        kind: SourceEntryKind,
        payload: &[u8],
    ) -> Result<(), AssemblyRefusal> {
        if kind == SourceEntryKind::Symlink {
            tar::validate_link(payload, SourceArchiveFormat::Zip.max_link_bytes() as usize)?;
        }
        let (kind, mode) = member_kind(kind);
        self.0
            .append(&member_path(path)?, kind, mode, payload)
            .map_err(refusal)
    }

    pub(super) fn finish(self) -> Result<Vec<u8>, AssemblyRefusal> {
        self.0.finish().map_err(refusal)
    }
}

fn member_path(path: &[u8]) -> Result<TreePath, AssemblyRefusal> {
    for component in path.split(|byte| *byte == b'/') {
        tar::validate_component(component)?;
    }
    TreePath::parse(
        path,
        &PathPolicy {
            // The archive prefix adds one component to the source depth.
            max_components: MAX_DEPTH + 1,
            ..PathPolicy::default()
        },
    )
    .map_err(|_| AssemblyRefusal::Invalid("source ZIP path exceeds the exact safe path profile"))
}

const fn member_kind(kind: SourceEntryKind) -> (ZipEntryKind, u64) {
    match kind {
        SourceEntryKind::File => (ZipEntryKind::File, 0o644),
        SourceEntryKind::Executable => (ZipEntryKind::File, 0o755),
        SourceEntryKind::Directory | SourceEntryKind::Gitlink => (ZipEntryKind::Directory, 0o755),
        SourceEntryKind::Symlink => (ZipEntryKind::Symlink, 0o777),
    }
}

fn refusal(error: ArchiveRefusal) -> AssemblyRefusal {
    match error {
        ArchiveRefusal::EntryLimitExceeded { .. }
        | ArchiveRefusal::EntryBytesExceeded { .. }
        | ArchiveRefusal::OutputBytesExceeded { .. }
        | ArchiveRefusal::OutputSizeOverflow
        | ArchiveRefusal::AllocationFailed { .. } => {
            AssemblyRefusal::Budget("source ZIP exceeds its complete byte, entry or memory limit")
        }
        ArchiveRefusal::ZipPathNotUtf8 { .. } => {
            AssemblyRefusal::Invalid("source ZIP requires exact UTF-8 member names")
        }
        ArchiveRefusal::ZipFieldOverflow { .. } => {
            AssemblyRefusal::Invalid("source ZIP cannot represent a field without extensions")
        }
        _ => AssemblyRefusal::Invalid("source ZIP member violates the stored archive profile"),
    }
}
