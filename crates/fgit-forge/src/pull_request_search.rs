//! Bounded pull-request search over one authenticated, disclosure-filtered
//! authority view. The reader supplies native views; no mutable search index,
//! extra publication schema, or dependency on admission is introduced here.

use crate::aggregate::{AggregateId, PullRequestNumber};
use crate::event::pull_request::{PullRequestAction, PullRequestData};
use crate::event::{ForgeEvent, ForgeEventPayload};
use fgit_codec::CodecRefusal;
use fgit_types::{PrincipalId, RefName, RepositoryAuthorityHeadId};
use std::fmt::{self, Display, Formatter};
use std::future::Future;

pub const MAX_QUERY_BYTES: usize = 256;
pub const MAX_SCAN: u16 = 1000;
pub const MAX_RESULTS: u16 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PullRequestState {
    Open,
    Closed,
    Merged,
}
impl PullRequestState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Merged => "merged",
        }
    }
}

/// A conjunction over the current native PR metadata at a selected head.
/// Branch filters are exact canonical `refs/heads/*` names. Text matches
/// either title or body, never their concatenation or comments/reviews. ASCII
/// case folding is the default; other UTF-8 bytes remain exact.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PullRequestQuery {
    pub state: Option<PullRequestState>,
    pub opened_by: Option<PrincipalId>,
    pub source_ref: Option<RefName>,
    pub target_ref: Option<RefName>,
    pub text: Option<String>,
    pub case_sensitive: bool,
}
impl PullRequestQuery {
    /// Validate the predicate and compile a linear-time literal matcher.
    /// Absence of text means no text restriction, including merge-only rows.
    pub fn compile(self) -> Result<CompiledPullRequestQuery, CodecRefusal> {
        if (self.case_sensitive && self.text.is_none())
            || self.text.as_ref().is_some_and(|text| {
                text.is_empty() || text.len() > MAX_QUERY_BYTES || text.contains('\0')
            })
            || [&self.source_ref, &self.target_ref]
                .into_iter()
                .flatten()
                .any(|reference| !reference.as_bytes().starts_with(b"refs/heads/"))
        {
            return Err(invalid("pull_request.query"));
        }
        let needle: Vec<u8> = self
            .text
            .as_deref()
            .unwrap_or_default()
            .bytes()
            .map(|byte| {
                if self.case_sensitive {
                    byte
                } else {
                    byte.to_ascii_lowercase()
                }
            })
            .collect();
        let mut failure = vec![0; needle.len()];
        let mut matched = 0;
        for index in 1..needle.len() {
            while matched > 0 && needle[index] != needle[matched] {
                matched = failure[matched - 1];
            }
            if needle[index] == needle[matched] {
                matched += 1;
            }
            failure[index] = matched;
        }
        Ok(CompiledPullRequestQuery {
            query: self,
            needle,
            failure,
        })
    }
}

/// Borrowed facets of an authenticated native PR view. Adapters retain their
/// original row type, including merge receipts and metadata provenance.
#[derive(Clone, Copy, Debug)]
pub struct SearchDocument<'a> {
    pub number: PullRequestNumber,
    pub event: &'a ForgeEvent,
    pub data: Option<&'a PullRequestData>,
    pub opened_by: Option<PrincipalId>,
    pub last_metadata_actor: Option<PrincipalId>,
}
impl<'a> SearchDocument<'a> {
    fn validate(self) -> Result<(PullRequestState, &'a RefName, &'a RefName), CodecRefusal> {
        if self.event.aggregate != AggregateId::PullRequest(self.number) {
            return Err(invalid("pull_request.search.aggregate"));
        }
        if let Some(data) = self.data {
            data.validate()?;
        }
        match &self.event.payload {
            ForgeEventPayload::PullRequestChangedNative(change) => {
                change.data.validate()?;
                if self.data != Some(&change.data)
                    || self.opened_by.is_none()
                    || self.last_metadata_actor != Some(change.actor)
                    || (change.action == PullRequestAction::Open
                        && self.opened_by != Some(change.actor))
                {
                    return Err(invalid("pull_request.search.metadata"));
                }
                Ok((
                    if change.action == PullRequestAction::Close {
                        PullRequestState::Closed
                    } else {
                        PullRequestState::Open
                    },
                    &change.data.source_ref,
                    &change.data.target_ref,
                ))
            }
            ForgeEventPayload::MergeCommittedNative(merge) => {
                merge.validate()?;
                if self.data.is_some_and(|data| !data.matches_merge(merge))
                    || self.data.is_some() != self.opened_by.is_some()
                    || self.data.is_some() != self.last_metadata_actor.is_some()
                {
                    return Err(invalid("pull_request.search.merge_metadata"));
                }
                Ok((
                    PullRequestState::Merged,
                    &merge.source_ref,
                    &merge.target_ref,
                ))
            }
            _ => Err(invalid("pull_request.search.event_kind")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledPullRequestQuery {
    query: PullRequestQuery,
    needle: Vec<u8>,
    failure: Vec<usize>,
}
impl CompiledPullRequestQuery {
    #[must_use]
    pub const fn query(&self) -> &PullRequestQuery {
        &self.query
    }

    /// Validate before filtering: malformed evidence is never a nonmatch.
    /// Merge-only receipts cannot match absent title/body or opener metadata.
    pub fn matches(&self, document: SearchDocument<'_>) -> Result<bool, CodecRefusal> {
        let (state, source, target) = document.validate()?;
        if self.query.state.is_some_and(|wanted| state != wanted)
            || self
                .query
                .opened_by
                .is_some_and(|wanted| document.opened_by != Some(wanted))
            || self
                .query
                .source_ref
                .as_ref()
                .is_some_and(|wanted| source != wanted)
            || self
                .query
                .target_ref
                .as_ref()
                .is_some_and(|wanted| target != wanted)
        {
            return Ok(false);
        }
        Ok(self.needle.is_empty()
            || document.data.is_some_and(|data| {
                self.contains(data.title.as_bytes()) || self.contains(data.body.as_bytes())
            }))
    }

    fn contains(&self, bytes: &[u8]) -> bool {
        if self.needle.is_empty() {
            return true;
        }
        let mut matched = 0;
        for &byte in bytes {
            let byte = if self.query.case_sensitive {
                byte
            } else {
                byte.to_ascii_lowercase()
            };
            while matched > 0 && byte != self.needle[matched] {
                matched = self.failure[matched - 1];
            }
            if byte == self.needle[matched] {
                matched += 1;
            }
            if matched == self.needle.len() {
                return true;
            }
        }
        false
    }
}

const fn invalid(field: &'static str) -> CodecRefusal {
    CodecRefusal::ValueUnrepresentable {
        field,
        observed: 0,
        limit: 1,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchRequest {
    pub after: u64,
    pub limit: u16,
    pub max_scan: u16,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
}
impl SearchRequest {
    /// Adapters call this before selecting authority or reading storage.
    pub fn validate<E>(&self) -> Result<(), SearchError<E>> {
        if !(1..=MAX_RESULTS).contains(&self.limit) || !(1..=MAX_SCAN).contains(&self.max_scan) {
            return Err(SearchError::InvalidLimits);
        }
        if self.after != 0 && self.expected_head.is_none() {
            return Err(SearchError::SnapshotRequired);
        }
        Ok(())
    }
}

/// An ascending page of already authorized native views. A continuation names
/// the last row of a full page and means more visible candidates, not matches.
#[derive(Clone, Debug)]
pub struct SourcePage<T> {
    pub source_head: RepositoryAuthorityHeadId,
    pub pull_requests: Vec<T>,
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
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Exhausted)
    }
}

/// `scanned` counts only disclosed candidates. A continuation advances after
/// the last examined row, including nonmatches; it does not imply another hit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchPage<T> {
    pub source_head: RepositoryAuthorityHeadId,
    pub pull_requests: Vec<T>,
    pub scanned: u16,
    pub next_after: Option<u64>,
    pub stop: SearchStop,
}
impl<T> SearchPage<T> {
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.stop.is_complete()
    }
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
                out.write_str("pull-request search requires limit 1..100 and max_scan 1..1000")
            }
            Self::SnapshotRequired => out
                .write_str("pull-request search continuation requires its original snapshot token"),
            Self::SnapshotMoved => {
                out.write_str("pull-request search reader changed the pinned snapshot")
            }
            Self::InvalidSourcePage => {
                out.write_str("pull-request search reader violated its pagination contract")
            }
            Self::InvalidSnapshot(error) => {
                write!(out, "pull-request search invalid snapshot: {error}")
            }
            Self::Allocation => out.write_str("pull-request search allocation refused"),
            Self::Source(error) => write!(out, "pull-request search source: {error}"),
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

/// Search at most ten bounded source pages from one immutable authority head.
/// The async reader owns authorization and cancellation/deadline/budget checks
/// on every call. Source failures discard accumulated matches and retain the
/// original typed error. No text copy or extra candidate index is retained.
///
/// Continuations must keep the query and returned `source_head`; intentionally
/// changing the query starts a different search over the remaining suffix.
pub async fn search<T, E, F, Fut>(
    query: &CompiledPullRequestQuery,
    request: SearchRequest,
    mut read: F,
    describe: impl for<'a> Fn(&'a T) -> SearchDocument<'a>,
) -> Result<SearchPage<T>, SearchError<E>>
where
    F: FnMut(u64, u16, Option<RepositoryAuthorityHeadId>) -> Fut,
    Fut: Future<Output = Result<SourcePage<T>, E>>,
{
    request.validate()?;
    let mut pull_requests = Vec::new();
    pull_requests
        .try_reserve(usize::from(request.limit))
        .map_err(|_| SearchError::Allocation)?;
    let mut after = request.after;
    let mut selected = request.expected_head;
    let mut scanned = 0;
    loop {
        let batch = MAX_RESULTS.min(request.max_scan - scanned);
        let page = read(after, batch, selected)
            .await
            .map_err(SearchError::Source)?;
        if selected.is_some_and(|head| head != page.source_head) {
            return Err(SearchError::SnapshotMoved);
        }
        selected = Some(page.source_head);
        if page.pull_requests.len() > usize::from(batch)
            || page
                .pull_requests
                .iter()
                .any(|row| describe(row).number.get() <= after)
            || page
                .pull_requests
                .windows(2)
                .any(|pair| describe(&pair[0]).number >= describe(&pair[1]).number)
            || page.next_after.is_some_and(|next| {
                next == u64::MAX
                    || page.pull_requests.len() != usize::from(batch)
                    || page
                        .pull_requests
                        .last()
                        .map(|row| describe(row).number.get())
                        != Some(next)
            })
        {
            return Err(SearchError::InvalidSourcePage);
        }
        let count = page.pull_requests.len();
        for (index, row) in page.pull_requests.into_iter().enumerate() {
            scanned += 1;
            let document = describe(&row);
            after = document.number.get();
            if query
                .matches(document)
                .map_err(SearchError::InvalidSnapshot)?
            {
                pull_requests.push(row);
            }
            let more = index + 1 < count || page.next_after.is_some();
            let stop = if !more {
                Some(SearchStop::Exhausted)
            } else if pull_requests.len() == usize::from(request.limit) {
                Some(SearchStop::ResultLimit)
            } else if scanned == request.max_scan {
                Some(SearchStop::ScanLimit)
            } else {
                None
            };
            if let Some(stop) = stop {
                return Ok(SearchPage {
                    source_head: page.source_head,
                    pull_requests,
                    scanned,
                    next_after: more.then_some(after),
                    stop,
                });
            }
        }
        if page.next_after.is_none() {
            return Ok(SearchPage {
                source_head: page.source_head,
                pull_requests,
                scanned,
                next_after: None,
                stop: SearchStop::Exhausted,
            });
        }
    }
}

#[cfg(test)]
mod tests;
