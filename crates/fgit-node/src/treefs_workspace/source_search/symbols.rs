//! Rust declaration retrieval shares the existing single native source
//! selection. Neither an error nor the language profile mints a read grant.
mod indexed;
use super::*;
use fgit_forge::source_symbols::{SymbolQuery, SymbolReadError, SymbolSearchReport, search_source_symbols};

impl LocalSearch for SymbolQuery {
    type Report = Result<SymbolSearchReport, SymbolReadError<SearchError>>;
    fn scope(&self) -> &SourceQuery { self.source_scope() }
    fn empty(&self, source: SourceSearchReport) -> Self::Report { Ok(SymbolSearchReport::empty(source)) }
    fn run<A: GitHashAlgorithm, S: ObjectSource<A>>(&self,
        base: &BaseView<A>, source: &S, capability: &mut TreeCapability, now: u64,
        limits: SearchLimits, cancelled: &dyn Fn() -> bool,
    ) -> Result<Self::Report, SearchError> {
        // Keep the typed lexical error without changing other matchers' errors.
        Ok(search_source_symbols(base, source, capability, now, self, limits, cancelled))
    }
}
impl OneNode {
    /// Caller-owned sparse capability and explicit visibility can only narrow
    /// canonical source. The name/kind/language filters confer no authority.
    #[expect(clippy::too_many_arguments, reason = "caller capability, visibility and source budgets are independent")]
    pub async fn search_source_symbols_in<A: GitHashAlgorithm>(
        &self, request: &NodeRequestContext, reference: &RefName,
        visibility: &RefVisibility, capability: &mut TreeCapability, now: u64,
        query: &SymbolQuery, limits: SearchLimits,
    ) -> Result<SymbolSearchReport, SymbolReadError<NodeWorkspaceRefusal>> {
        limits.validate().map_err(search_error).map_err(SymbolReadError::Source)?;
        let result = self.with_workspace_base_in::<A, _>(request, reference, visibility, capability, now,
            |base, original, capability| {
                let source = bounded_source(original, request, limits);
                Ok(search_source_symbols(base, &source, capability, now, query, limits,
                    &|| !workspace_request_live(request)))
            }).await.map_err(SymbolReadError::Source)?;
        result.map_err(|error| error.map_source(search_error))
    }

    /// Whole-repository read for an independently authorized local operator or
    /// transport. Source pins are checked in the SAME selection used by every
    /// file read. No index building, workspace, transaction or repository write.
    pub async fn search_source_symbols_snapshot_local_in(
        &self, request: &NodeRequestContext, reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>, expected_commit: Option<GitOid>,
        query: &SymbolQuery, limits: SearchLimits,
    ) -> Result<(RepositoryAuthorityHeadId, SymbolSearchReport), SymbolReadError<NodeWorkspaceRefusal>> {
        if expected_commit.is_some_and(|id| id.is_zero() || id.algorithm() != self.object_format) {
            return Err(SymbolReadError::Source(search_error(SearchError::InvalidObjectFormat)));
        }
        let (head, result) = match self.object_format {
            Format::Sha1 => self.search_local_format::<Sha1, _>(request, reference, expected_head, expected_commit, query, limits).await,
            Format::Sha256 => self.search_local_format::<Sha256, _>(request, reference, expected_head, expected_commit, query, limits).await,
        }.map_err(SymbolReadError::Source)?;
        result.map(|report| (head, report)).map_err(|error| error.map_source(search_error))
    }
}
