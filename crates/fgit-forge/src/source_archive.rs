//! Deterministic source archives assembled from verified, ref-selected reads.
//!
//! The host owns authentication, canonical visibility, one finite request context
//! and cancellation for the entire traversal. Every report must come from that
//! existing source-read boundary. The collector pins every page to the first
//! report, preserves exact native bytes and withholds all output on failure.
//! These bytes are a derived export, never a capsule or publication authority.

mod tar;
mod zip;
use crate::source_browse::{
    SourceBrowseAction, SourceBrowseContent, SourceBrowseQuery, SourceBrowseReport, SourceEntryKind,
};
use fgit_types::{
    GitHashAlgorithm, GitOid, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId,
};

/// Existing callers retain the default ustar profile.
pub const PROFILE: &str = "ustar-source-v1";

/// Explicit source archive encoding; extensions never select this profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SourceArchiveFormat {
    /// Exact POSIX ustar fields and the existing raw-byte path profile.
    #[default]
    Tar,
    /// Deterministic stored ZIP with exact UTF-8 names and Unix metadata.
    Zip,
}

impl SourceArchiveFormat {
    /// Stable receipt profile for the selected encoding.
    #[must_use]
    pub const fn profile(self) -> &'static str {
        match self {
            Self::Tar => PROFILE,
            Self::Zip => "zip-store-source-v1",
        }
    }

    const fn max_entries(self) -> usize {
        match self {
            Self::Tar => MAX_ENTRIES,
            Self::Zip => u16::MAX as usize,
        }
    }

    const fn max_path_bytes(self) -> usize {
        match self {
            Self::Tar => 256,
            Self::Zip => 4096,
        }
    }

    const fn max_link_bytes(self) -> u64 {
        match self {
            Self::Tar => 100,
            Self::Zip => 4096,
        }
    }
}

pub const MAX_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;
pub const MIN_ARCHIVE_BYTES: usize = 3 * 512;
pub const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_FILE_READS: usize = 4096;

/// A caller's original read failure remains distinct from malformed reports,
/// unsafe archive paths and finite profile limits.
#[derive(Debug, Eq, PartialEq)]
pub enum SourceArchiveError<E> {
    Read(E),
    Invalid(&'static str),
    Budget(&'static str),
}
impl<E> From<&'static str> for SourceArchiveError<E> {
    fn from(message: &'static str) -> Self {
        Self::Invalid(message)
    }
}
impl<E: core::fmt::Display> core::fmt::Display for SourceArchiveError<E> {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read(error) => error.fmt(out),
            Self::Invalid(message) | Self::Budget(message) => out.write_str(message),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for SourceArchiveError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::Invalid(_) | Self::Budget(_) => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum AssemblyRefusal {
    Invalid(&'static str),
    Budget(&'static str),
}
impl From<&'static str> for AssemblyRefusal {
    fn from(message: &'static str) -> Self {
        Self::Invalid(message)
    }
}
impl<E> From<AssemblyRefusal> for SourceArchiveError<E> {
    fn from(error: AssemblyRefusal) -> Self {
        match error {
            AssemblyRefusal::Invalid(message) => Self::Invalid(message),
            AssemblyRefusal::Budget(message) => Self::Budget(message),
        }
    }
}

struct SelectionQuery<'a> {
    repository: RepositoryId,
    format: GitHashAlgorithm,
    query: &'a SourceBrowseQuery,
}

/// Validate a whole-directory request before any source I/O.
pub fn validate_query(
    format: GitHashAlgorithm,
    query: &SourceBrowseQuery,
) -> Result<(), &'static str> {
    query.validate(format).map_err(|error| match error {
        crate::source_browse::SourceBrowseError::InvalidRequest(message) => message,
        _ => "invalid source archive query",
    })?;
    match query.action {
        SourceBrowseAction::List { after: None, limit } if (1..=1000).contains(&limit) => Ok(()),
        _ => Err("source archive requires a complete directory without a cursor"),
    }
}

/// Collect a complete deterministic ustar archive within the fixed profile.
/// The reader must retain one request context and enforce current source access
/// and cancellation before each response. No bytes escape until all reads pass.
pub fn collect<E>(
    repository: RepositoryId,
    format: GitHashAlgorithm,
    query: &SourceBrowseQuery,
    reader: impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, E>,
) -> Result<SourceArchive, SourceArchiveError<E>> {
    collect_with_limit(repository, format, query, MAX_ARCHIVE_BYTES, reader)
}

/// Narrow the archive byte ceiling for a transport's complete-response budget.
/// Limits above the fixed profile are capped; limits too small even for the
/// prefix and end blocks refuse before source I/O. Entry/path/read bounds are
/// unchanged. Framing and payload bytes both count against this ceiling.
pub fn collect_with_limit<E>(
    repository: RepositoryId,
    format: GitHashAlgorithm,
    query: &SourceBrowseQuery,
    max_bytes: usize,
    reader: impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, E>,
) -> Result<SourceArchive, SourceArchiveError<E>> {
    let options = SelectionQuery {
        repository,
        format,
        query,
    };
    collect_inner(
        &options,
        SourceArchiveFormat::Tar,
        max_bytes.min(MAX_ARCHIVE_BYTES),
        reader,
    )
}

/// Collect a complete source archive in an explicitly selected format.
/// The verified-read and request-lifetime obligations are identical to `collect`.
pub fn collect_with_format<E>(
    repository: RepositoryId,
    format: GitHashAlgorithm,
    query: &SourceBrowseQuery,
    archive_format: SourceArchiveFormat,
    reader: impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, E>,
) -> Result<SourceArchive, SourceArchiveError<E>> {
    collect_with_format_and_limit(
        repository,
        format,
        query,
        archive_format,
        MAX_ARCHIVE_BYTES,
        reader,
    )
}

/// Apply a transport's complete-response ceiling to either encoding.
/// All local records, names, payloads and end records count against the limit.
/// Impossible prefix/framing limits refuse before any verified source read.
pub fn collect_with_format_and_limit<E>(
    repository: RepositoryId,
    format: GitHashAlgorithm,
    query: &SourceBrowseQuery,
    archive_format: SourceArchiveFormat,
    max_bytes: usize,
    reader: impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, E>,
) -> Result<SourceArchive, SourceArchiveError<E>> {
    let options = SelectionQuery {
        repository,
        format,
        query,
    };
    collect_inner(
        &options,
        archive_format,
        max_bytes.min(MAX_ARCHIVE_BYTES),
        reader,
    )
}

enum Encoder {
    Tar(tar::Tar),
    Zip(zip::Zip),
}

impl Encoder {
    fn new(format: SourceArchiveFormat, max_bytes: usize) -> Result<Self, AssemblyRefusal> {
        match format {
            SourceArchiveFormat::Tar => tar::Tar::new(max_bytes).map(Self::Tar),
            SourceArchiveFormat::Zip => zip::Zip::new(max_bytes).map(Self::Zip),
        }
    }

    fn remaining_payload(
        &self,
        path: &[u8],
        kind: SourceEntryKind,
    ) -> Result<usize, AssemblyRefusal> {
        match self {
            Self::Tar(output) => output.remaining_payload(kind),
            Self::Zip(output) => output.remaining_payload(path, kind),
        }
    }

    fn append(
        &mut self,
        path: &[u8],
        kind: SourceEntryKind,
        payload: &[u8],
    ) -> Result<(), AssemblyRefusal> {
        match self {
            Self::Tar(output) => output.append(path, kind, payload),
            Self::Zip(output) => output.append(path, kind, payload),
        }
    }

    fn finish(self) -> Result<Vec<u8>, AssemblyRefusal> {
        match self {
            Self::Tar(output) => output.finish(),
            Self::Zip(output) => output.finish(),
        }
    }
}

const MAX_ENTRIES: usize = 100_000;
const MAX_READS: usize = 200_000;
const MAX_DEPTH: usize = 64;
const MAX_PATH_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceArchivePin {
    pub head: RepositoryAuthorityHeadId,
    pub rcr: RepositoryCommitId,
    pub commit: GitOid,
    pub tree: GitOid,
}

struct Selection {
    pin: Option<SourceArchivePin>,
    root: Option<GitOid>,
    reads: usize,
}
impl Selection {
    fn query(
        &self,
        options: &SelectionQuery,
        path: Option<Vec<u8>>,
        action: SourceBrowseAction,
    ) -> SourceBrowseQuery {
        SourceBrowseQuery {
            path,
            expected_head: self.pin.map(|pin| pin.head).or(options.query.expected_head),
            expected_commit: self
                .pin
                .map(|pin| pin.commit)
                .or(options.query.expected_commit),
            action,
        }
    }

    fn read<E>(
        &mut self,
        options: &SelectionQuery,
        query: &SourceBrowseQuery,
        expected_object: Option<GitOid>,
        reader: &mut impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, E>,
    ) -> Result<SourceBrowseReport, SourceArchiveError<E>> {
        if self.reads >= MAX_READS {
            return Err(SourceArchiveError::Budget(
                "source archive exceeds the total read budget",
            ));
        }
        self.reads += 1;
        let report = reader(query).map_err(SourceArchiveError::Read)?;
        let observed = SourceArchivePin {
            head: report.source_head,
            rcr: report.source_rcr,
            commit: report.source_commit,
            tree: report.root_tree,
        };
        if report.repository_id != options.repository
            || report.path != query.path
            || self.pin.is_some_and(|pin| pin != observed)
            || query
                .expected_head
                .is_some_and(|head| head != report.source_head)
            || query
                .expected_commit
                .is_some_and(|commit| commit != report.source_commit)
            || expected_object.is_some_and(|object| object != report.object_id)
            || [report.source_commit, report.root_tree, report.object_id]
                .iter()
                .any(|oid| oid.is_zero() || oid.algorithm() != options.format)
            || (query.path.is_none() && report.object_id != report.root_tree)
        {
            return Err("source archive snapshot, path or parent-selected object changed".into());
        }
        if self.pin.is_none() {
            self.pin = Some(observed);
            self.root = Some(report.object_id);
        }
        Ok(report)
    }
}

struct Task {
    source: Option<Vec<u8>>,
    path: Vec<u8>,
    object: Option<GitOid>,
    kind: SourceEntryKind,
    depth: usize,
}

#[derive(Debug)]
pub struct SourceArchive {
    pub pin: SourceArchivePin,
    pub root: GitOid,
    pub bytes: Vec<u8>,
    pub entries: usize,
    pub gitlinks: usize,
    pub reads: usize,
}

fn complete_query(options: &SelectionQuery) -> Result<u16, &'static str> {
    validate_query(options.format, options.query)?;
    match &options.query.action {
        SourceBrowseAction::List { after: None, limit } if (1..=1000).contains(limit) => Ok(*limit),
        _ => Err("source archive requires a complete directory without a cursor"),
    }
}

fn collect_inner<E>(
    options: &SelectionQuery,
    archive_format: SourceArchiveFormat,
    max_bytes: usize,
    mut reader: impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, E>,
) -> Result<SourceArchive, SourceArchiveError<E>> {
    let limit = complete_query(options)?;
    let mut selection = Selection {
        pin: None,
        root: None,
        reads: 0,
    };
    let mut stack = vec![Task {
        source: options.query.path.clone(),
        path: b"source".to_vec(),
        object: None,
        kind: SourceEntryKind::Directory,
        depth: 0,
    }];
    let mut output = Encoder::new(archive_format, max_bytes)?;
    let mut entries = 1_usize;
    let mut path_bytes = 0_usize;
    let mut gitlinks = 0_usize;
    while let Some(task) = stack.pop() {
        match task.kind {
            SourceEntryKind::Directory => {
                let mut after = None;
                let mut object = task.object;
                let mut children = Vec::new();
                loop {
                    let query = selection.query(
                        options,
                        task.source.clone(),
                        SourceBrowseAction::List {
                            after: after.clone(),
                            limit,
                        },
                    );
                    let report = selection.read(options, &query, object, &mut reader)?;
                    object = Some(report.object_id);
                    let SourceBrowseContent::Directory {
                        entries: page,
                        next_after,
                    } = report.content
                    else {
                        return Err(
                            "source archive expected a directory selected by its parent".into()
                        );
                    };
                    if page.len() > usize::from(limit) {
                        return Err(
                            "source archive directory exceeded its requested page size".into()
                        );
                    }
                    let mut previous = after.clone();
                    for child in page.iter() {
                        tar::validate_component(&child.name)?;
                        if previous.as_ref().is_some_and(|name| *name >= child.name)
                            || child.oid.is_zero()
                            || child.oid.algorithm() != options.format
                        {
                            return Err(
                                "source archive directory is unordered or has invalid identities"
                                    .into(),
                            );
                        }
                        previous = Some(child.name.clone());
                        let mut path = task.path.clone();
                        path.push(b'/');
                        path.extend_from_slice(&child.name);
                        let mut source = task.source.clone().unwrap_or_default();
                        if !source.is_empty() {
                            source.push(b'/');
                        }
                        source.extend_from_slice(&child.name);
                        if path.len() > archive_format.max_path_bytes()
                            || source.len() > 4096
                            || task.depth >= MAX_DEPTH
                        {
                            return Err(SourceArchiveError::Budget(
                                "source archive path or depth exceeds the bounded profile",
                            ));
                        }
                        entries = entries
                            .checked_add(1)
                            .filter(|count| *count <= archive_format.max_entries())
                            .ok_or(SourceArchiveError::Budget(match archive_format {
                                SourceArchiveFormat::Tar => "source archive exceeds 100000 entries",
                                SourceArchiveFormat::Zip => "source archive exceeds 65535 entries",
                            }))?;
                        path_bytes = path_bytes
                            .checked_add(path.len())
                            .and_then(|n| n.checked_add(source.len()))
                            .filter(|n| *n <= MAX_PATH_BYTES)
                            .ok_or(SourceArchiveError::Budget(
                                "source archive exceeds its path-byte budget",
                            ))?;
                        children.try_reserve(1).map_err(|_| {
                            SourceArchiveError::Budget("cannot allocate archive traversal")
                        })?;
                        children.push(Task {
                            source: Some(source),
                            path,
                            object: Some(child.oid),
                            kind: child.kind,
                            depth: task.depth + 1,
                        });
                    }
                    if let Some(next) = next_after {
                        if page.len() != usize::from(limit)
                            || previous.as_ref() != Some(&next)
                            || after.as_ref().is_some_and(|old| *old >= next)
                        {
                            return Err(
                                "source archive directory cursor did not advance exactly".into()
                            );
                        }
                        after = Some(next);
                    } else {
                        break;
                    }
                }
                output.append(&task.path, task.kind, b"")?;
                // Depth-first order is independent of directory page size. Each
                // directory precedes its children; raw names retain byte order.
                stack
                    .try_reserve(children.len())
                    .map_err(|_| SourceArchiveError::Budget("cannot allocate archive traversal"))?;
                stack.extend(children.into_iter().rev());
            }
            SourceEntryKind::Gitlink => {
                // A gitlink belongs to another repository. Do not clone, fetch,
                // reinterpret its OID as a blob, or delegate our credentials.
                output.append(&task.path, task.kind, b"")?;
                gitlinks += 1;
            }
            kind => {
                let remaining = output.remaining_payload(&task.path, kind)? as u64;
                let query = selection.query(
                    options,
                    task.source,
                    SourceBrowseAction::Read {
                        offset: 0,
                        limit: remaining.clamp(1, 1024 * 1024) as u32,
                    },
                );
                let file_options = SelectionQuery {
                    repository: options.repository,
                    format: options.format,
                    query: &query,
                };
                let file = collect_file_inner(&file_options, |query| {
                    let report = selection.read(options, query, task.object, &mut reader)?;
                    match &report.content {
                        SourceBrowseContent::Blob {
                            kind: observed,
                            total_bytes,
                            ..
                        } if *observed == kind => {
                            if kind == SourceEntryKind::Symlink
                                && *total_bytes > archive_format.max_link_bytes()
                            {
                                return Err(SourceArchiveError::Invalid(match archive_format {
                                    SourceArchiveFormat::Tar => {
                                        "ustar symlink requires at most 100 relative bytes without parent traversal"
                                    }
                                    SourceArchiveFormat::Zip => {
                                        "ZIP symlink requires at most 4096 relative bytes without parent traversal"
                                    }
                                }));
                            }
                            if *total_bytes > remaining {
                                return Err(SourceArchiveError::Budget(
                                    "source archive payload exceeds the remaining byte budget",
                                ));
                            }
                        }
                        _ => return Err("source archive file kind changed".into()),
                    }
                    Ok(report)
                })?;
                output.append(&task.path, kind, &file.bytes)?;
            }
        }
    }
    Ok(SourceArchive {
        pin: selection
            .pin
            .ok_or("source archive has no authenticated source")?,
        root: selection
            .root
            .ok_or("source archive has no selected tree")?,
        bytes: output.finish()?,
        entries,
        gitlinks,
        reads: selection.reads,
    })
}

/// Assemble a complete file from the same verified range contract used by
/// source archives. The caller owns the read authorization and finite lifetime.
pub fn collect_file<E>(
    repository: RepositoryId,
    format: GitHashAlgorithm,
    query: &SourceBrowseQuery,
    mut reader: impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, E>,
) -> Result<SourceFileExport, SourceArchiveError<E>> {
    query.validate(format).map_err(|error| match error {
        crate::source_browse::SourceBrowseError::InvalidRequest(message) => {
            SourceArchiveError::Invalid(message)
        }
        _ => SourceArchiveError::Invalid("invalid source file query"),
    })?;
    let options = SelectionQuery {
        repository,
        format,
        query,
    };
    collect_file_inner(&options, |query| {
        reader(query).map_err(SourceArchiveError::Read)
    })
}

/// Exact complete source bytes and the immutable first-page receipt.
#[derive(Debug)]
pub struct SourceFileExport {
    pub first: SourceBrowseReport,
    pub bytes: Vec<u8>,
    pub pages: usize,
}

/// Pages come only from the node's verified source-read boundary in production.
/// The injected reader lets adversarial tests exercise the same assembly logic.
fn collect_file_inner<E>(
    options: &SelectionQuery,
    mut read: impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, SourceArchiveError<E>>,
) -> Result<SourceFileExport, SourceArchiveError<E>> {
    let SourceBrowseAction::Read { offset: 0, limit } = options.query.action else {
        return Err("complete file export requires a file read at offset zero".into());
    };
    let mut query = (*options.query).clone();
    let mut first: Option<SourceBrowseReport> = None;
    let mut output = Vec::new();
    for pages in 1..=MAX_FILE_READS {
        let report = read(&query)?;
        if report.repository_id != options.repository
            || report.path != query.path
            || [report.source_commit, report.root_tree, report.object_id]
                .iter()
                .any(|oid| oid.is_zero() || oid.algorithm() != options.format)
            || query
                .expected_head
                .is_some_and(|head| head != report.source_head)
            || query
                .expected_commit
                .is_some_and(|commit| commit != report.source_commit)
        {
            return Err("source export snapshot or path changed".into());
        }
        let SourceBrowseContent::Blob {
            kind,
            bytes,
            total_bytes,
            offset,
            next_offset,
        } = &report.content
        else {
            return Err("source export requires a file or symlink payload".into());
        };
        if !matches!(
            kind,
            SourceEntryKind::File | SourceEntryKind::Executable | SourceEntryKind::Symlink
        ) {
            return Err("unsupported source export entry kind".into());
        }
        if *total_bytes > MAX_FILE_BYTES {
            return Err(SourceArchiveError::Budget(
                "source export exceeds the 128 MiB byte limit",
            ));
        }
        if let Some(initial) = &first {
            let SourceBrowseContent::Blob {
                kind: original_kind,
                total_bytes: original_size,
                ..
            } = &initial.content
            else {
                return Err("source export lost its initial file identity".into());
            };
            if report.source_head != initial.source_head
                || report.source_commit != initial.source_commit
                || report.source_rcr != initial.source_rcr
                || report.root_tree != initial.root_tree
                || report.object_id != initial.object_id
                || kind != original_kind
                || total_bytes != original_size
            {
                return Err("source export object identity or size changed".into());
            }
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or("source export byte offset overflow")?;
        if *offset != output.len() as u64
            || bytes.len() > limit as usize
            || end > *total_bytes
            || match next_offset {
                Some(next) => bytes.is_empty() || *next != end || end >= *total_bytes,
                None => end != *total_bytes,
            }
        {
            return Err("incomplete or inconsistent source export range".into());
        }
        output
            .try_reserve(bytes.len())
            .map_err(|_| SourceArchiveError::Budget("cannot allocate bounded source export"))?;
        output.extend_from_slice(bytes);
        let next = *next_offset;
        query.expected_head = Some(report.source_head);
        query.expected_commit = Some(report.source_commit);
        if first.is_none() {
            first = Some(report);
        }
        if let Some(offset) = next {
            query.action = SourceBrowseAction::Read { offset, limit };
        } else {
            return Ok(SourceFileExport {
                first: first.ok_or("source export has no verified first page")?,
                bytes: output,
                pages,
            });
        }
    }
    Err(SourceArchiveError::Budget(
        "source export exceeds the 4096-read limit; increase --max-bytes",
    ))
}

#[cfg(test)]
mod tests;
