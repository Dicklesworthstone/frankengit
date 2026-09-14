//! Immutable source-browsing requests and receipts. No storage or authority effects.
use fgit_treefs::{BaseError, TreePath};
use fgit_types::{GitHashAlgorithm as Format, GitOid as Oid, RepositoryAuthorityHeadId,
    RepositoryCommitId, RepositoryId};
pub const MAX_SOURCE_PAGE_BYTES: u32 = 1024 * 1024;

/// One level of a tree, or one exact byte range of a file/link payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceBrowseAction {
    List { after: Option<Vec<u8>>, limit: u16 },
    Read { offset: u64, limit: u32 },
}

/// Continuations require the authority identity returned on the first page.
/// `path: None` is the root, never an empty or synthetic repository path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceBrowseQuery {
    pub path: Option<Vec<u8>>,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub expected_commit: Option<Oid>,
    pub action: SourceBrowseAction,
}
impl SourceBrowseQuery {
    pub fn validate(&self, format: Format) -> Result<Option<TreePath>, SourceBrowseError> {
        if self.expected_commit.is_some_and(|id| id.algorithm() != format || id.is_zero()) {
            return Err(SourceBrowseError::InvalidRequest("invalid expected commit domain"));
        }
        let path = self.path.as_deref().map(TreePath::parse_default).transpose()
            .map_err(|_| SourceBrowseError::InvalidRequest("invalid repository path"))?;
        match &self.action {
            SourceBrowseAction::List { after, limit } => {
                if !(1..=1000).contains(limit) {
                    return Err(SourceBrowseError::InvalidRequest("directory page limit must be 1..1000"));
                }
                if let Some(name) = after {
                    let cursor = TreePath::parse_default(name)
                        .map_err(|_| SourceBrowseError::InvalidRequest("invalid child cursor"))?;
                    if cursor.components().count() != 1 {
                        return Err(SourceBrowseError::InvalidRequest("cursor must name one immediate child"));
                    }
                    if self.expected_head.is_none() {
                        return Err(SourceBrowseError::InvalidRequest("continuation requires source head"));
                    }
                }
            }
            SourceBrowseAction::Read { offset, limit } => {
                if path.is_none() || *limit == 0 || *limit > MAX_SOURCE_PAGE_BYTES {
                    return Err(SourceBrowseError::InvalidRequest("file path and byte limit 1..1048576 required"));
                }
                if *offset != 0 && self.expected_head.is_none() {
                    return Err(SourceBrowseError::InvalidRequest("range continuation requires source head"));
                }
            }
        }
        Ok(path)
    }
}

#[derive(Debug)]
pub enum SourceBrowseError {
    InvalidRequest(&'static str),
    SnapshotMoved,
    CommitMoved,
    ExpectedFile,
    RangeOutsideFile,
    UnsupportedFileMode,
    Budget(&'static str),
    Base(Box<BaseError>),
}
impl std::fmt::Display for SourceBrowseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source browse refused: {self:?}")
    }
}
impl std::error::Error for SourceBrowseError {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceEntryKind { File, Executable, Directory, Symlink, Gitlink }
impl SourceEntryKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self { Self::File => "file", Self::Executable => "executable",
            Self::Directory => "directory", Self::Symlink => "symlink", Self::Gitlink => "gitlink" }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceDirectoryEntry {
    pub name: Vec<u8>,
    pub oid: Oid,
    pub kind: SourceEntryKind,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceBrowseContent {
    Directory { entries: Vec<SourceDirectoryEntry>, next_after: Option<Vec<u8>> },
    /// Symlink bytes are data, never followed. Gitlinks cannot be read as files.
    Blob { kind: SourceEntryKind, bytes: Vec<u8>, total_bytes: u64,
        offset: u64, next_offset: Option<u64> },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceBrowseReport {
    pub repository_id: RepositoryId,
    pub source_head: RepositoryAuthorityHeadId,
    pub source_rcr: RepositoryCommitId,
    pub source_commit: Oid,
    pub root_tree: Oid,
    pub object_id: Oid,
    pub path: Option<Vec<u8>>,
    pub content: SourceBrowseContent,
}
