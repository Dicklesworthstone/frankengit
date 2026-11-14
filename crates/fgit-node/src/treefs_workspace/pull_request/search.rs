//! Native PR search pins one authenticated authority basis and the caller's
//! current disclosure policy before scanning bounded existing PR pages.

use super::{PullRequestReadRefusal, snapshots};
use crate::{NodeRequestContext, OneNode};
use fgit_admission::merge::native::pull_request::{self, PullRequestView};
use fgit_forge::pull_request_search::{
    self, CompiledPullRequestQuery, SearchDocument, SearchError, SearchPage, SearchRequest,
    SourcePage,
};
use fgit_types::RefName;
use fgit_types::cell::{ReadMode, admits_read};
use fgit_wire::visibility::RefVisibility;

pub type PullRequestSearchPage = SearchPage<PullRequestView>;
pub type PullRequestSearchRefusal = SearchError<PullRequestReadRefusal>;

impl OneNode {
    /// Search authorized native PR metadata without creating a search index.
    /// Every batch uses the same selected current or retained authority head,
    /// the same current hidden-ref policy, and the same request resource scope.
    /// An `after` continuation must name its original `expected_head`.
    ///
    /// Counts and cursors cover only rows visible through BOTH source/target
    /// refs. Retained tokens are neither credentials nor historical-policy
    /// bypasses. A typed source refusal cannot become a partial success.
    pub async fn search_pull_requests_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        query: &CompiledPullRequestQuery,
        search_request: SearchRequest,
    ) -> Result<PullRequestSearchPage, PullRequestSearchRefusal> {
        search_request.validate()?;
        admits_read(self.cell_state(), ReadMode::Current)
            .map_err(PullRequestReadRefusal::Cell)
            .map_err(SearchError::Source)?;
        let current = self
            .event_read_basis_in(request, None)
            .await
            .map_err(|error| {
                SearchError::Source(PullRequestReadRefusal::Selection(Box::new(error)))
            })?;
        let cancelled = || !super::super::workspace_request_live(request);
        let selected = snapshots::select(
            &self.authority,
            request.authority(),
            &current.basis,
            search_request.expected_head,
            &cancelled,
        )
        .await
        .map_err(|error| {
            SearchError::Source(match error {
                snapshots::SnapshotReadRefusal::Unavailable => {
                    PullRequestReadRefusal::SnapshotMoved
                }
                snapshots::SnapshotReadRefusal::Admission(error) => {
                    PullRequestReadRefusal::Admission(error)
                }
            })
        })?;
        let visible = |source: &RefName, target: &RefName| {
            [source, target].iter().all(|reference| {
                !visibility.hides(reference.as_bytes())
                    && !current.hidden_refs.hides(reference.as_bytes())
            })
        };
        pull_request_search::search(
            query,
            search_request,
            |after, limit, _expected_head| {
                let selected = &selected;
                let visible = &visible;
                let cancelled = &cancelled;
                async move {
                    let page = pull_request::read_page_at(
                        &self.authority,
                        request.authority(),
                        selected,
                        after,
                        limit,
                        visible,
                        cancelled,
                    )
                    .await
                    .map_err(|error| PullRequestReadRefusal::Admission(Box::new(error)))?;
                    Ok(SourcePage {
                        source_head: page.source_head,
                        pull_requests: page.pull_requests,
                        next_after: page.next_after,
                    })
                }
            },
            describe,
        )
        .await
    }
}

fn describe(view: &PullRequestView) -> SearchDocument<'_> {
    SearchDocument {
        number: view.number,
        event: &view.event,
        data: view.data.as_ref(),
        opened_by: view.opened_by,
        last_metadata_actor: view.last_metadata_actor,
    }
}
