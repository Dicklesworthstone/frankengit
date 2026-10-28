//! Explicit ranked retrieval over a revalidated, immutable lexical generation.
use super::*;

/// Current authority and original index provenance remain distinct. Statistics
/// and scores cannot widen the caller's independently granted read authority.
#[derive(Clone, Debug)]
pub struct RevalidatedRankedIndexReport {
    current_source: LexicalSource,
    ranking: RankedLexicalReport,
}
impl RevalidatedRankedIndexReport {
    #[must_use]
    pub const fn current_source(&self) -> &LexicalSource {
        &self.current_source
    }
    #[must_use]
    pub const fn ranking(&self) -> &RankedLexicalReport {
        &self.ranking
    }
}

impl OneNode {
    /// ANY-term ranked search for a trusted local or independently authorized
    /// full-repository reader. The source and generation checks are identical
    /// to the ordinary revalidated index reader. The complete indexed corpus
    /// in the query's scope is scanned under finite work/read/memory limits
    /// before the selected top-k is returned. No source blobs are read.
    ///
    /// `after` is refused: document-ID pagination cannot continue a relevance
    /// order. Source/generation pins still select an exact repeatable query.
    pub async fn search_source_index_ranked_revalidated_local_in(
        &self,
        request: &NodeRequestContext,
        query: RevalidatedIndexRequest<'_>,
    ) -> Result<RevalidatedRankedIndexReport, NodeWorkspaceRefusal> {
        live(request)?;
        if query.after.is_some() {
            return Err(index_error(LexicalError::Invalid(
                "ranked search has no document-ID continuation",
            )));
        }
        let (current_source, selection) = self
            .select_current_lexical_index_in(request, &query)
            .await?;
        let store = LexicalIndexStore::new(
            &self.authority,
            current_source.namespace,
            query.reference.clone(),
        )
        .map_err(index_error)?;
        let mut request_live = || live(request).is_ok();
        let ranking = store
            .search_ranked_async(
                request.authority(),
                &selection,
                query.query,
                query.read_limits,
                query.query_limits,
                &mut request_live,
            )
            .await
            .map_err(index_error)?;
        live(request)?;
        Ok(RevalidatedRankedIndexReport {
            current_source,
            ranking,
        })
    }
}
