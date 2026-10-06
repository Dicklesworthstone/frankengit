#![forbid(unsafe_code)]
//! Model-free retrieval after metadata-only changes. Each index keeps its
//! original provenance; all disclosure is joined to ONE current native source.
use super::{
    IndexedLexicalReport, LexicalQueryLimits, LexicalReadLimits, LexicalSource,
    RevalidatedIndexReport, RevalidatedIndexRequest,
};
use crate::source_retrieval::{
    Checkpoints, GenerationVector, InitialLimits, InitialQuery, RetrievalError, SymbolChannel,
    add_result, check_lexical_join, check_symbol_join, lexical_result_bytes, live, share,
    symbol_unavailable,
};
use crate::{NodeRequestContext, OneNode};
use fgit_forge::source_search::SearchLimits;
use fgit_forge::source_symbols::SymbolQuery;
use fgit_graph::{GenerationActivation, GraphGenerationId};
use fgit_types::{GitOid, HeadGeneration, RefName, RepositoryAuthorityHeadId};

pub const PROFILE: &str = "source-initial-revalidated-v1";

/// Constructed only after current-source and immutable-generation joins pass.
/// `current_source` is disclosure evidence, NOT replacement index provenance.
/// An unavailable optional channel is explicitly incomplete, never zero hits.
#[derive(Clone, Debug)]
pub struct RevalidatedInitialReport {
    current_source: LexicalSource,
    content: IndexedLexicalReport,
    path: IndexedLexicalReport,
    symbols: SymbolChannel,
    vector: GenerationVector,
    result_bytes: usize,
}
impl RevalidatedInitialReport {
    #[must_use]
    pub const fn current_source(&self) -> &LexicalSource {
        &self.current_source
    }
    #[must_use]
    pub const fn content(&self) -> &IndexedLexicalReport {
        &self.content
    }
    #[must_use]
    pub const fn path(&self) -> &IndexedLexicalReport {
        &self.path
    }
    #[must_use]
    pub const fn symbols(&self) -> &SymbolChannel {
        &self.symbols
    }
    #[must_use]
    pub const fn generations(&self) -> &GenerationVector {
        &self.vector
    }
    #[must_use]
    pub const fn result_bytes(&self) -> usize {
        self.result_bytes
    }
    #[must_use]
    pub fn complete(&self) -> bool {
        self.content.results.complete
            && self.path.results.complete
            && match &self.symbols {
                SymbolChannel::NotRequested => true,
                SymbolChannel::Unavailable(_) => false,
                SymbolChannel::Available(report) => report.complete,
            }
    }
    /// Successful-channel receipts, not total physical I/O. An unavailable
    /// channel may have spent its preassigned allowance before refusing.
    #[must_use]
    pub fn completed_payload_bytes_read(&self) -> usize {
        self.content.payload_bytes_read
            + self.path.payload_bytes_read
            + match &self.symbols {
                SymbolChannel::Available(report) => report.payload_bytes_read,
                _ => 0,
            }
    }
    #[must_use]
    pub fn completed_work_units(&self) -> u64 {
        self.content.results.work_units
            + self.path.results.work_units
            + match &self.symbols {
                SymbolChannel::Available(report) => report.work_units,
                _ => 0,
            }
    }
}

fn join_current(left: &LexicalSource, right: &LexicalSource) -> Result<(), RetrievalError> {
    if left == right {
        Ok(())
    } else {
        Err(RetrievalError::MixedSource)
    }
}

impl OneNode {
    /// Read existing content/path/symbol indexes for one currently authorized
    /// native commit/tree, even if unrelated repository metadata has advanced.
    ///
    /// The content read selects current source and lexical generation. Path
    /// repeats BOTH exactly; symbols revalidate against that same current head
    /// and commit while retaining their own original index provenance. Code,
    /// visibility or head movement during the invocation refuses, never retries.
    /// Original lexical and symbol index heads need not equal each other.
    ///
    /// Use only behind an independent whole-repository source-read grant.
    /// This does not create an IntentRun, retention pin or publication right.
    /// All phases share the request context. Work/payload allowances are split
    /// before I/O, including optional failures, and never borrowed or renewed.
    /// The existing exact-source Initial reader remains unchanged.
    #[expect(
        clippy::too_many_arguments,
        reason = "source pins, independent index floors and shared budgets are distinct"
    )]
    pub async fn search_source_initial_revalidated_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        checkpoints: &Checkpoints,
        query: &InitialQuery,
        limits: InitialLimits,
    ) -> Result<RevalidatedInitialReport, RetrievalError> {
        live(request)?;
        limits.validate(query)?;
        if query.symbols().is_none() && checkpoints.symbols.is_some() {
            return Err(RetrievalError::Invalid("symbol checkpoint without symbol query"));
        }
        let count = query.channels();
        let work = |ordinal| share(limits.max_work, count, ordinal);
        let payload = |ordinal| share(limits.max_payload_bytes as u64, count, ordinal) as usize;
        let read_limits = |ordinal| LexicalReadLimits {
            max_payload_bytes: payload(ordinal),
            ..Default::default()
        };
        let query_limits = |ordinal| LexicalQueryLimits {
            max_results: limits.max_results_per_channel,
            max_work: work(ordinal),
        };
        let RevalidatedIndexReport { current_source, index: content } = self
            .search_source_index_revalidated_local_in(request, RevalidatedIndexRequest {
                reference, expected_head, expected_commit,
                generation: None, minimum: checkpoints.lexical.as_ref(),
                query: query.content(), after: None,
                query_limits: query_limits(0), read_limits: read_limits(0),
            })
            .await
            .map_err(RetrievalError::Source)?;
        live(request)?;
        let mut result_bytes = 0;
        lexical_result_bytes(&content, &mut result_bytes, limits.max_result_bytes)?;
        let RevalidatedIndexReport { current_source: path_source, index: path } = self
            .search_source_index_revalidated_local_in(request, RevalidatedIndexRequest {
                reference,
                expected_head: Some(current_source.source_head),
                expected_commit: Some(current_source.commit),
                generation: Some(&content.generation), minimum: checkpoints.lexical.as_ref(),
                query: query.path(), after: None,
                query_limits: query_limits(1), read_limits: read_limits(1),
            })
            .await
            .map_err(RetrievalError::Source)?;
        join_current(&current_source, &path_source)?;
        check_lexical_join(&content, &path)?;
        live(request)?;
        lexical_result_bytes(&path, &mut result_bytes, limits.max_result_bytes)?;
        let symbols = if let Some((symbol, policy)) = query.symbols() {
            let bounded = SymbolQuery::new(
                symbol.name(), symbol.mode(), symbol.kinds(), query.content().prefixes(), work(2),
            ).map_err(|_| RetrievalError::Invalid("symbol work limit"))?;
            match self.search_source_symbols_index_revalidated_local_in(
                request, reference, Some(current_source.source_head), Some(current_source.commit),
                checkpoints.symbols.as_ref(), &bounded,
                SearchLimits { max_matches: limits.max_results_per_channel, ..Default::default() },
                payload(2),
            ).await {
                Ok((symbol_current, report)) => {
                    // This compares CURRENT observations, never rewrites the
                    // symbol report's independently verified original source.
                    check_symbol_join(&current_source, &symbol_current)?;
                    for row in &report.matches {
                        live(request)?;
                        add_result(&mut result_bytes,
                            row.location.path.len() + row.name.len() + row.location.excerpt.len() + 96,
                            limits.max_result_bytes)?;
                    }
                    SymbolChannel::Available(Box::new(report))
                }
                Err(error) => SymbolChannel::Unavailable(symbol_unavailable(
                    error, policy, checkpoints.symbols.is_some(),
                )?),
            }
        } else {
            SymbolChannel::NotRequested
        };
        let symbol_generation = match &symbols {
            SymbolChannel::Available(report) => Some(GenerationActivation {
                generation_id: GraphGenerationId::from_internal_object_id(report.generation)
                    .map_err(|_| RetrievalError::MixedGeneration)?,
                authority_generation: HeadGeneration::try_new(report.generation_number)
                    .map_err(|_| RetrievalError::MixedGeneration)?,
            }),
            _ => None,
        };
        live(request)?;
        Ok(RevalidatedInitialReport {
            vector: GenerationVector { lexical: content.generation.clone(), symbols: symbol_generation },
            current_source, content, path, symbols, result_bytes,
        })
    }
}

#[cfg(test)]
mod tests;
