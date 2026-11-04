//! Verified, selected native-object reads shared by the pure planners.

use fgit_types::GitOid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitInput {
    pub tree: GitOid,
    pub parents: Vec<GitOid>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeEntry {
    pub name: Vec<u8>,
    pub mode: u32,
    pub oid: GitOid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeSourceError {
    Cancelled,
    BudgetExceeded,
    Unavailable(GitOid),
    InvalidObject(GitOid),
    OutsideSelection,
}

/// Implementations must bound reads before allocation, verify the requested
/// native identity and kind, and refuse objects outside their selected source.
/// The pure planner cannot grant those capabilities to an object adapter.
pub trait MergeObjectSource {
    fn checkpoint(&self) -> Result<(), MergeSourceError>;
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError>;
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError>;
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError>;

    /// The commit plus its committer date in seconds, when one is usable. The
    /// date only orders merge-base traversal, later dates first: a wrong or
    /// missing date can cost work, never select a different base. The default
    /// supplies none.
    fn commit_with_date(&self, id: GitOid) -> Result<(CommitInput, Option<i64>), MergeSourceError> {
        Ok((self.commit(id)?, None))
    }
}
