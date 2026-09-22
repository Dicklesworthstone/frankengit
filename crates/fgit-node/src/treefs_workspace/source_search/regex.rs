//! Regex dispatch shares the single authority selection used by literal/batch
//! search. Changing a matcher never grants a path or selects another snapshot.
use super::*;
use fgit_forge::source_search::regex::{RegexQuery, RegexSearchReport, search_source_regex};

impl LocalSearch for RegexQuery {
    type Report = RegexSearchReport;
    fn scope(&self) -> &SourceQuery {
        self.source_scope()
    }
    fn empty(&self, source: SourceSearchReport) -> Self::Report {
        RegexSearchReport {
            source,
            program_states: self.state_count(),
            steps: 0,
            lines_searched: 0,
        }
    }
    fn run<A: GitHashAlgorithm, S: ObjectSource<A>>(
        &self,
        base: &BaseView<A>,
        source: &S,
        capability: &mut TreeCapability,
        now: u64,
        limits: SearchLimits,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self::Report, SearchError> {
        search_source_regex(base, source, capability, now, self, limits, cancelled)
    }
}
impl OneNode {
    /// Search one authority-selected immutable source under an existing caller
    /// capability. Visibility and query paths can only narrow that capability.
    pub async fn search_source_regex_in<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        visibility: &RefVisibility,
        capability: &mut TreeCapability,
        now: u64,
        query: &RegexQuery,
        limits: SearchLimits,
    ) -> Result<RegexSearchReport, NodeWorkspaceRefusal> {
        limits.validate().map_err(search_error)?;
        self.with_workspace_base_in::<A, _>(
            request,
            reference,
            visibility,
            capability,
            now,
            |base, original, capability| {
                let source = bounded_source(original, request, limits);
                search_source_regex(base, &source, capability, now, query, limits, &|| {
                    !workspace_request_live(request)
                })
                .map_err(search_error)
            },
        )
        .await
    }

    /// Whole-repository regex read for an independently authorized transport or
    /// local operator. Head/commit pins are tested inside the SAME selection
    /// used for every source byte. This method is not a credential service.
    pub async fn search_source_regex_snapshot_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        query: &RegexQuery,
        limits: SearchLimits,
    ) -> Result<(RepositoryAuthorityHeadId, RegexSearchReport), NodeWorkspaceRefusal> {
        if expected_commit.is_some_and(|id| id.is_zero() || id.algorithm() != self.object_format) {
            return Err(search_error(SearchError::InvalidObjectFormat));
        }
        match self.object_format {
            Format::Sha1 => {
                self.search_local_format::<Sha1, _>(
                    request,
                    reference,
                    expected_head,
                    expected_commit,
                    query,
                    limits,
                )
                .await
            }
            Format::Sha256 => {
                self.search_local_format::<Sha256, _>(
                    request,
                    reference,
                    expected_head,
                    expected_commit,
                    query,
                    limits,
                )
                .await
            }
        }
    }
}
