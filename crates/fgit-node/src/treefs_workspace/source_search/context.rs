//! Hydrate only retrieval-selected exact paths under ONE current native source
//! selection. The private TreeFS source prevents object-ID read substitution.
use super::{
    BaseView, Format, GitHashAlgorithm, GitObjectKind, GitOid, LocalSearch, NodeRequestContext,
    ObjectSource, OneNode, SearchError, SearchLimits, Sha1, Sha256, SourceQuery,
    SourceSearchReport, TreeCapability, TreePath, search_error, workspace_request_live,
};
use crate::source_retrieval::authorization::SourceReadContext;
use crate::source_retrieval::context::ranked::RankedContext;
use crate::source_retrieval::context::{Assembly, ContextLimits, InitialContext, Plan};
use crate::source_retrieval::{InitialReport, RetrievalError};
use fgit_forge::source_search::SearchCase;
use fgit_treefs::BaseEntry;

struct Hydrate<'a> {
    initial: &'a InitialReport,
    plan: &'a Plan,
    scope: SourceQuery,
    limits: ContextLimits,
}
fn failure(error: SearchError) -> RetrievalError {
    RetrievalError::Source(search_error(error))
}
impl LocalSearch for Hydrate<'_> {
    type Report = Result<Assembly, RetrievalError>;
    fn scope(&self) -> &SourceQuery {
        &self.scope
    }
    fn empty(&self, selected: SourceSearchReport) -> Self::Report {
        let expected = self.initial.source();
        if !self.plan.files.is_empty()
            || selected.repository != expected.namespace.repository
            || selected.source_rcr != expected.source_rcr
            || selected.source_commit != expected.commit
            || selected.source_tree != expected.tree
        {
            return Err(RetrievalError::MixedSource);
        }
        Ok(Assembly::default())
    }
    fn run<A: GitHashAlgorithm, S: ObjectSource<A>>(
        &self,
        base: &BaseView<A>,
        source: &S,
        capability: &mut TreeCapability,
        now: u64,
        _limits: SearchLimits,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self::Report, SearchError> {
        Ok((|| {
            let expected = self.initial.source();
            let parse = |oid: GitOid| {
                A::parse_hex(&oid.to_string()).map_err(|_| RetrievalError::MixedSource)
            };
            if base.repository_id() != expected.namespace.repository
                || base.base_rcr_id() != expected.source_rcr
                || *base.base_commit_oid() != parse(expected.commit)?
                || *base.base_tree_oid() != parse(expected.tree)?
            {
                return Err(RetrievalError::MixedSource);
            }
            let mut assembled = Assembly::default();
            for file in &self.plan.files {
                if cancelled() {
                    return Err(failure(SearchError::Cancelled));
                }
                let path = TreePath::parse_default(&file.path)
                    .map_err(|_| RetrievalError::Invalid("context path"))?;
                let entry = base
                    .resolve(source, capability, &path, now)
                    .map_err(|e| failure(SearchError::Base(Box::new(e))))?;
                // A source index cannot turn a symlink or gitlink into readable
                // context. Authorize the current exact path, not its old blob.
                if !matches!(&entry, BaseEntry::File { mode, .. } if mode == b"100644" || mode == b"100755")
                    || *entry.oid() != parse(file.blob)?
                {
                    return Err(RetrievalError::MixedSource);
                }
                let grant = capability
                    .authorize_read(&path, now)
                    .map_err(|e| failure(SearchError::Capability(e)))?;
                let bytes = base
                    .read_object(source, entry.oid(), GitObjectKind::Blob, &grant)
                    .map_err(|e| failure(SearchError::Source(Box::new(e))))?;
                capability
                    .charge_fetch(bytes.len() as u64)
                    .map_err(|e| failure(SearchError::Capability(e)))?;
                // The shared native reader verifies each full blob. Each path
                // is decoded once, however many channels or excerpts reference it.
                assembled.observe(file, &bytes, self.limits, cancelled)?;
            }
            Ok(assembled)
        })())
    }
}
impl OneNode {
    /// Turn a joined Initial response into exact source excerpts. A report is
    /// not permission: the embedding must still authorize whole-repository
    /// reads, and current canonical visibility and exact source pins are checked
    /// again. No new index generation, fallback source, filesystem checkout,
    /// arbitrary OID read, or automatic retrieval retry is permitted.
    ///
    /// max_files selects a raw-path prefix of the distinct retrieved files and
    /// explicitly counts omitted paths. Every selected file must be verified;
    /// cancellation, missing backing, bad spans or byte limits fail the entire
    /// response rather than exposing the successful prefix of hydration.
    pub async fn hydrate_source_initial_local_in(
        &self,
        request: &NodeRequestContext,
        read: &SourceReadContext,
        initial: InitialReport,
        limits: ContextLimits,
    ) -> Result<InitialContext, RetrievalError> {
        read.check_node(self)?;
        initial.validate_authorization(read, &mut || crate::source_retrieval::live(request))?;
        let plan = Plan::new(&initial, limits, &|| !workspace_request_live(request))?;
        self.hydrate_source_initial_plan_local_in(request, initial, limits, &plan)
            .await
    }

    /// Explicit weighted document fusion, not semantic ranking or authorization.
    /// The receipt records distinct-path channel ranks and fixed-point scores;
    /// the original source/generation/coverage evidence is preserved unchanged.
    /// Native traversal and returned files stay in raw-path order. Selected
    /// oversized/missing files fail, rather than being replaced by lower ranks.
    pub async fn hydrate_source_initial_ranked_local_in(
        &self,
        request: &NodeRequestContext,
        read: &SourceReadContext,
        initial: InitialReport,
        limits: ContextLimits,
    ) -> Result<RankedContext, RetrievalError> {
        read.check_node(self)?;
        initial.validate_authorization(read, &mut || crate::source_retrieval::live(request))?;
        let (plan, ranking) = Plan::ranked(&initial, limits, &|| !workspace_request_live(request))?;
        let context = self
            .hydrate_source_initial_plan_local_in(request, initial, limits, &plan)
            .await?;
        RankedContext::finish(context, ranking)
    }

    async fn hydrate_source_initial_plan_local_in(
        &self,
        request: &NodeRequestContext,
        initial: InitialReport,
        limits: ContextLimits,
        plan: &Plan,
    ) -> Result<InitialContext, RetrievalError> {
        if !workspace_request_live(request) {
            return Err(failure(SearchError::Cancelled));
        }
        // Reserve all newly retained lineage before any native source I/O;
        // the original Initial result-byte allowance remains the sole limit.
        initial.check_context_metadata(plan.lineage_metadata_bytes()?)?;
        let expected = initial.source();
        if expected.namespace.tenant != self.tenant_id
            || expected.namespace.repository != self.repository_id
            || expected.namespace.incarnation != self.repository_incarnation_id()
            || expected.namespace.object_format != self.object_format
        {
            return Err(RetrievalError::MixedSource);
        }
        let file_limit = limits.file_limit(plan.files.len())?;
        let paths: Vec<_> = plan.files.iter().map(|file| file.path.clone()).collect();
        let query = Hydrate {
            initial: &initial,
            plan,
            limits,
            scope: SourceQuery::new(b"context", SearchCase::Exact, &paths).map_err(failure)?,
        };
        let reads = SearchLimits {
            max_file_bytes: file_limit,
            max_total_bytes: limits.max_source_bytes,
            ..Default::default()
        };
        let (head, forge, assembled) = match self.object_format {
            Format::Sha1 => {
                self.select_source_local_format::<Sha1, _>(
                    request,
                    &expected.reference,
                    Some(expected.source_head),
                    Some(expected.commit),
                    &query,
                    reads,
                )
                .await
            }
            Format::Sha256 => {
                self.select_source_local_format::<Sha256, _>(
                    request,
                    &expected.reference,
                    Some(expected.source_head),
                    Some(expected.commit),
                    &query,
                    reads,
                )
                .await
            }
        }
        .map_err(RetrievalError::Source)?;
        if head != expected.source_head || forge != expected.forge_position_root {
            return Err(RetrievalError::MixedSource);
        }
        if !workspace_request_live(request) {
            return Err(failure(SearchError::Cancelled));
        }
        InitialContext::finish(initial, plan, assembled?, file_limit, &mut || {
            crate::source_retrieval::live(request)
        })
    }
}
