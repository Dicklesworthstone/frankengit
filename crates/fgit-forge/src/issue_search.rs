//! Bounded issue search over authority-selected pages, never a second index.
//! The reader owns authorization, retained-head lookup and cancellation. Each
//! call must return a complete ascending page at the supplied head (or refuse),
//! and checkpoint its caller's runtime context before doing storage work.

use crate::event::issue::{CompiledIssueQuery, IssueSnapshot};
use fgit_codec::CodecRefusal;
use fgit_types::RepositoryAuthorityHeadId;
use std::fmt::{self, Display, Formatter};

pub const MAX_SCAN: u16 = 1000;
pub const MAX_RESULTS: u16 = 100;

/// Continuations retain the same predicate and exact snapshot token. Changing
/// the predicate intentionally starts a different query over the suffix.
#[derive(Clone, Copy, Debug)]
pub struct SearchRequest {
    pub after: u64,
    pub limit: u16,
    pub max_scan: u16,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
}

/// Adapter input from the existing authority-backed issue reader. `next_after`
/// denotes more candidates, not more matches. It must name the last item of a
/// full page. An empty page cannot carry a continuation.
#[derive(Clone, Debug)]
pub struct SourcePage {
    pub source_head: RepositoryAuthorityHeadId,
    pub issues: Vec<IssueSnapshot>,
    pub next_after: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchStop {
    Exhausted,
    ResultLimit,
    ScanLimit,
}
impl SearchStop {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exhausted => "exhausted",
            Self::ResultLimit => "result_limit",
            Self::ScanLimit => "scan_limit",
        }
    }
}

/// The cursor advances through examined candidates, including nonmatches. A
/// nonempty continuation never asserts that another matching issue exists.
#[derive(Clone, Debug)]
pub struct SearchPage {
    pub source_head: RepositoryAuthorityHeadId,
    pub issues: Vec<IssueSnapshot>,
    pub scanned: u16,
    pub next_after: Option<u64>,
    pub stop: SearchStop,
}

#[derive(Debug)]
pub enum SearchError<E> {
    InvalidLimits,
    SnapshotRequired,
    SnapshotMoved,
    InvalidSourcePage,
    InvalidSnapshot(CodecRefusal),
    Allocation,
    Source(E),
}
impl<E: Display> Display for SearchError<E> {
    fn fmt(&self, out: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => {
                out.write_str("issue search requires limit 1..100 and max_scan 1..1000")
            }
            Self::SnapshotRequired => {
                out.write_str("issue search continuation requires its original snapshot token")
            }
            Self::SnapshotMoved => out.write_str("issue search reader changed the pinned snapshot"),
            Self::InvalidSourcePage => {
                out.write_str("issue search reader violated its pagination contract")
            }
            Self::InvalidSnapshot(error) => write!(out, "issue search invalid snapshot: {error}"),
            Self::Allocation => out.write_str("issue search allocation refused"),
            Self::Source(error) => write!(out, "issue search source: {error}"),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for SearchError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSnapshot(error) => Some(error),
            Self::Source(error) => Some(error),
            _ => None,
        }
    }
}

/// Query a bounded suffix from ONE immutable authority-selected issue view.
///
/// The callback is invoked at most ten times. It must enforce caller disclosure
/// and runtime cancellation/deadline/budget checks on each call. No aggregate
/// count, cache, object listing, mutable index or latest-head refresh is used.
/// A source failure discards the accumulated output rather than returning an
/// apparently complete empty/partial search. At most 100 matches are retained.
///
/// # Errors
/// Invalid bounds or an unpinned continuation refuse before reading. Foreign
/// heads, malformed pages and corrupt scanned snapshots refuse before a result
/// is exposed. Source errors preserve the adapter's original error value.
pub fn search<E>(
    query: &CompiledIssueQuery,
    request: SearchRequest,
    mut read: impl FnMut(u64, u16, Option<RepositoryAuthorityHeadId>) -> Result<SourcePage, E>,
) -> Result<SearchPage, SearchError<E>> {
    if !(1..=MAX_RESULTS).contains(&request.limit) || !(1..=MAX_SCAN).contains(&request.max_scan) {
        return Err(SearchError::InvalidLimits);
    }
    if request.after != 0 && request.expected_head.is_none() {
        return Err(SearchError::SnapshotRequired);
    }
    let mut issues = Vec::new();
    issues
        .try_reserve(usize::from(request.limit))
        .map_err(|_| SearchError::Allocation)?;
    let mut after = request.after;
    let mut selected = request.expected_head;
    let mut scanned = 0;
    loop {
        let batch = MAX_RESULTS.min(request.max_scan - scanned);
        let page = read(after, batch, selected).map_err(SearchError::Source)?;
        if selected.is_some_and(|head| head != page.source_head) {
            return Err(SearchError::SnapshotMoved);
        }
        selected = Some(page.source_head);
        if page.issues.len() > usize::from(batch)
            || page.issues.iter().any(|issue| issue.number.get() <= after)
            || page
                .issues
                .windows(2)
                .any(|pair| pair[0].number >= pair[1].number)
            || page.next_after.is_some_and(|next| {
                next == u64::MAX
                    || page.issues.len() != usize::from(batch)
                    || page.issues.last().map(|issue| issue.number.get()) != Some(next)
            })
        {
            return Err(SearchError::InvalidSourcePage);
        }
        let count = page.issues.len();
        for (index, issue) in page.issues.into_iter().enumerate() {
            scanned += 1;
            after = issue.number.get();
            if query
                .matches(&issue)
                .map_err(SearchError::InvalidSnapshot)?
            {
                issues.push(issue);
            }
            let more = index + 1 < count || page.next_after.is_some();
            let stop = if !more {
                Some(SearchStop::Exhausted)
            } else if issues.len() == usize::from(request.limit) {
                Some(SearchStop::ResultLimit)
            } else if scanned == request.max_scan {
                Some(SearchStop::ScanLimit)
            } else {
                None
            };
            if let Some(stop) = stop {
                return Ok(SearchPage {
                    source_head: page.source_head,
                    issues,
                    scanned,
                    next_after: more.then_some(after),
                    stop,
                });
            }
        }
        if page.next_after.is_none() {
            return Ok(SearchPage {
                source_head: page.source_head,
                issues,
                scanned,
                next_after: None,
                stop: SearchStop::Exhausted,
            });
        }
    }
}

#[cfg(test)]
mod tests;
