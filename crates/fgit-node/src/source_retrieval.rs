#![forbid(unsafe_code)]
//! Model-free Initial retrieval across persisted content, path and symbol
//! channels. One exact canonical source and one immutable generation vector
//! bind the response; a channel never silently selects a different snapshot.
//!
//! This is an authorized local read, not index maintenance or a retention pin.
//! Channel semantics remain separate: lexical spans address complete folded
//! tokens, while symbol spans address source-level declaration names.
use crate::{
    NodeRequestContext, NodeWorkspaceRefusal, OneNode, PackContextCheckpoint,
    checkpoint_pack_context,
};
use fgit_forge::source_search::SearchLimits;
use fgit_forge::source_symbols::index as symbols;
use fgit_forge::source_symbols::{SymbolKind, SymbolMatchMode, SymbolQuery};
use fgit_graph::lexical::{
    self, IndexedLexicalReport, LexicalChannel, LexicalQuery, LexicalQueryLimits,
    LexicalReadLimits, LexicalSource,
};
use fgit_graph::{GenerationActivation, GenerationAuthorityError, GraphGenerationId};
use fgit_types::{GitOid, HeadGeneration, RefName, RepositoryAuthorityHeadId};

pub const PROFILE: &str = "source-initial-retrieval-v1";
const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 2 * 1024 * 1024;

/// Optional means ONLY uninitialized/stale symbol indexes may be omitted.
/// Corruption, cancellation, source movement and checkpoint failures are errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolPolicy {
    Optional,
    Required,
}

#[derive(Clone, Debug)]
pub struct InitialQuery {
    content: LexicalQuery,
    path: LexicalQuery,
    symbol: Option<(SymbolQuery, SymbolPolicy)>,
}
impl InitialQuery {
    /// AND of complete tokens in each lexical channel. Both use the same
    /// canonicalized path scope. Tokens are not a regex or a natural-language
    /// tokenizer; the existing lexical profile owns normalization and limits.
    pub fn new(terms: &[Vec<u8>], prefixes: &[Vec<u8>]) -> Result<Self, RetrievalError> {
        Ok(Self {
            content: LexicalQuery::new(LexicalChannel::Content, terms, prefixes)
                .map_err(|_| RetrievalError::Invalid("lexical query"))?,
            path: LexicalQuery::new(LexicalChannel::Path, terms, prefixes)
                .map_err(|_| RetrievalError::Invalid("lexical query"))?,
            symbol: None,
        })
    }
    /// Symbol name/mode are explicit: lexical case folding must never silently
    /// alter a case-sensitive declaration query. Its path scope cannot widen.
    pub fn with_symbols(
        mut self,
        name: &[u8],
        mode: SymbolMatchMode,
        kinds: &[SymbolKind],
        policy: SymbolPolicy,
    ) -> Result<Self, RetrievalError> {
        let query = SymbolQuery::new(
            name,
            mode,
            kinds,
            self.content.prefixes(),
            lexical::MAX_WORK,
        )
        .map_err(|_| RetrievalError::Invalid("symbol query"))?;
        self.symbol = Some((query, policy));
        Ok(self)
    }
    #[must_use]
    pub const fn content(&self) -> &LexicalQuery {
        &self.content
    }
    #[must_use]
    pub const fn path(&self) -> &LexicalQuery {
        &self.path
    }
    #[must_use]
    pub fn symbols(&self) -> Option<(&SymbolQuery, SymbolPolicy)> {
        self.symbol.as_ref().map(|(query, policy)| (query, *policy))
    }
    pub(crate) fn channels(&self) -> usize {
        2 + usize::from(self.symbol.is_some())
    }
}

/// Immutable generation floors retained independently by the caller. A symbol
/// floor requires a symbol query and cannot be discarded by optional mode.
#[derive(Clone, Debug, Default)]
pub struct Checkpoints {
    pub lexical: Option<GenerationActivation>,
    pub symbols: Option<GenerationActivation>,
}

/// Fixed pre-I/O partitioning bounds aggregate channel payload and lookup
/// allowances, including failed optional channels whose partial work is not
/// returned by their native owner. Authority/ancestry budgets remain separate.
/// Unused channel allowances are NOT borrowed or retried on a wider budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialLimits {
    pub max_results_per_channel: usize,
    pub max_work: u64,
    pub max_payload_bytes: usize,
    pub max_result_bytes: usize,
}
impl Default for InitialLimits {
    fn default() -> Self {
        Self {
            max_results_per_channel: 100,
            max_work: lexical::MAX_WORK,
            max_payload_bytes: MAX_PAYLOAD_BYTES,
            max_result_bytes: MAX_RESULT_BYTES,
        }
    }
}
impl InitialLimits {
    pub fn validate(self, query: &InitialQuery) -> Result<(), RetrievalError> {
        let channels = query.channels();
        if self.max_results_per_channel == 0
            || self.max_results_per_channel > 1024
            || self.max_work < channels as u64
            || self.max_work > lexical::MAX_WORK
            || self.max_payload_bytes < channels
            || self.max_payload_bytes > MAX_PAYLOAD_BYTES
            || self.max_result_bytes == 0
            || self.max_result_bytes > MAX_RESULT_BYTES
        {
            return Err(RetrievalError::Invalid("initial retrieval limits"));
        }
        Ok(())
    }
}
pub(crate) fn share(total: u64, count: usize, ordinal: usize) -> u64 {
    total / count as u64 + u64::from((ordinal as u64) < total % count as u64)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolUnavailable {
    Uninitialized,
    Stale,
}
#[derive(Clone, Debug)]
pub enum SymbolChannel {
    NotRequested,
    Unavailable(SymbolUnavailable),
    Available(Box<symbols::Report>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationVector {
    pub lexical: GenerationActivation,
    pub symbols: Option<GenerationActivation>,
}

/// Constructed only after all source/generation joins have been checked.
/// No raw result is exposed before the complete invocation is accepted.
#[derive(Clone, Debug)]
pub struct InitialReport {
    content: IndexedLexicalReport,
    path: IndexedLexicalReport,
    symbols: SymbolChannel,
    vector: GenerationVector,
    result_bytes: usize,
}
impl InitialReport {
    #[must_use]
    pub const fn source(&self) -> &LexicalSource {
        &self.content.source
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
    /// True only if every requested channel was available and untruncated.
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
    /// Successful-channel receipts only. An unavailable channel may have read
    /// metadata before refusing; this is NOT a total physical-I/O measurement.
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

type SymbolError = symbols::AccessError<NodeWorkspaceRefusal, GenerationAuthorityError>;
#[derive(Debug)]
pub enum RetrievalError {
    Source(NodeWorkspaceRefusal),
    Symbols(SymbolError),
    Invalid(&'static str),
    Limit(&'static str),
    MixedSource,
    MixedGeneration,
}
impl std::fmt::Display for RetrievalError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "initial source retrieval refused: {self:?}")
    }
}
impl std::error::Error for RetrievalError {}
fn live(request: &NodeRequestContext) -> Result<(), RetrievalError> {
    match checkpoint_pack_context(request.authority()) {
        PackContextCheckpoint::Stopped { budget_exhaustion } => {
            Err(RetrievalError::Source(NodeWorkspaceRefusal::Cancelled {
                exhaustion: budget_exhaustion,
            }))
        }
        _ => Ok(()),
    }
}
fn add_result(total: &mut usize, amount: usize, maximum: usize) -> Result<(), RetrievalError> {
    *total = total
        .checked_add(amount)
        .filter(|n| *n <= maximum)
        .ok_or(RetrievalError::Limit("retained result bytes"))?;
    Ok(())
}
fn lexical_result_bytes(
    report: &IndexedLexicalReport,
    total: &mut usize,
    maximum: usize,
) -> Result<(), RetrievalError> {
    for hit in &report.results.hits {
        add_result(total, hit.path.len() + hit.spans.len() * 24 + 64, maximum)?;
    }
    Ok(())
}
fn check_lexical_join(
    content: &IndexedLexicalReport,
    path: &IndexedLexicalReport,
) -> Result<(), RetrievalError> {
    if content.source != path.source {
        return Err(RetrievalError::MixedSource);
    }
    if content.generation != path.generation {
        return Err(RetrievalError::MixedGeneration);
    }
    Ok(())
}
fn check_symbol_join(
    source: &LexicalSource,
    symbol: &symbols::Source,
) -> Result<(), RetrievalError> {
    if source.namespace.tenant != symbol.tenant
        || source.namespace.repository != symbol.repository
        || source.namespace.incarnation != symbol.incarnation
        || source.namespace.object_format != symbol.format
        || source.reference != symbol.reference
        || source.source_head != symbol.head
        || source.source_rcr != symbol.rcr
        || source.forge_position_root != symbol.forge
        || source.commit != symbol.commit
        || source.tree != symbol.tree
    {
        return Err(RetrievalError::MixedSource);
    }
    Ok(())
}

impl OneNode {
    /// Retrieve useful model-free Initial channels without mixing canonical
    /// observations or lexical generations. The host must already authorize
    /// whole-repository reads; query prefixes only narrow that authorization.
    ///
    /// Content selects one exact source and lexical generation. Path repeats
    /// that exact generation, even if maintenance publishes a successor. The
    /// symbol reader must select the SAME source head/commit and its own exact
    /// generation. Any source movement refuses the attempt, without retry.
    ///
    /// Optional unbuilt/stale symbols leave lexical results useful and carry a
    /// typed unavailable status, never a successful empty symbol result. All
    /// other failures abort the response. No channel builds or scans source.
    #[expect(
        clippy::too_many_arguments,
        reason = "source pins, independent generation floors and shared read budgets are distinct"
    )]
    pub async fn search_source_initial_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        checkpoints: &Checkpoints,
        query: &InitialQuery,
        limits: InitialLimits,
    ) -> Result<InitialReport, RetrievalError> {
        live(request)?;
        limits.validate(query)?;
        if query.symbol.is_none() && checkpoints.symbols.is_some() {
            return Err(RetrievalError::Invalid(
                "symbol checkpoint without symbol query",
            ));
        }
        let count = query.channels();
        let work = |ordinal| share(limits.max_work, count, ordinal);
        let payload = |ordinal| share(limits.max_payload_bytes as u64, count, ordinal) as usize;
        let lexical_limits = |ordinal| LexicalQueryLimits {
            max_results: limits.max_results_per_channel,
            max_work: work(ordinal),
        };
        let read_limits = |ordinal| LexicalReadLimits {
            max_payload_bytes: payload(ordinal),
            ..Default::default()
        };
        let content = self
            .search_source_index_local_in(
                request,
                reference,
                expected_head,
                expected_commit,
                None,
                checkpoints.lexical.as_ref(),
                &query.content,
                None,
                lexical_limits(0),
                read_limits(0),
            )
            .await
            .map_err(RetrievalError::Source)?;
        live(request)?;
        let mut result_bytes = 0;
        lexical_result_bytes(&content, &mut result_bytes, limits.max_result_bytes)?;
        let path = self
            .search_source_index_local_in(
                request,
                reference,
                Some(content.source.source_head),
                Some(content.source.commit),
                Some(&content.generation),
                checkpoints.lexical.as_ref(),
                &query.path,
                None,
                lexical_limits(1),
                read_limits(1),
            )
            .await
            .map_err(RetrievalError::Source)?;
        check_lexical_join(&content, &path)?;
        live(request)?;
        lexical_result_bytes(&path, &mut result_bytes, limits.max_result_bytes)?;
        let channel = if let Some((symbol, policy)) = &query.symbol {
            let bounded = SymbolQuery::new(
                symbol.name(),
                symbol.mode(),
                symbol.kinds(),
                query.content.prefixes(),
                work(2),
            )
            .map_err(|_| RetrievalError::Invalid("symbol work limit"))?;
            match self
                .search_source_symbols_index_snapshot_local_in(
                    request,
                    reference,
                    Some(content.source.source_head),
                    Some(content.source.commit),
                    checkpoints.symbols.as_ref(),
                    &bounded,
                    SearchLimits {
                        max_matches: limits.max_results_per_channel,
                        ..Default::default()
                    },
                    payload(2),
                )
                .await
            {
                Ok(report) => {
                    check_symbol_join(&content.source, &report.source)?;
                    for row in &report.matches {
                        live(request)?;
                        add_result(
                            &mut result_bytes,
                            row.location.path.len()
                                + row.name.len()
                                + row.location.excerpt.len()
                                + 96,
                            limits.max_result_bytes,
                        )?;
                    }
                    SymbolChannel::Available(Box::new(report))
                }
                Err(error) => SymbolChannel::Unavailable(symbol_unavailable(
                    error,
                    *policy,
                    checkpoints.symbols.is_some(),
                )?),
            }
        } else {
            SymbolChannel::NotRequested
        };
        let symbol_generation = match &channel {
            SymbolChannel::Available(report) => Some(GenerationActivation {
                generation_id: GraphGenerationId::from_internal_object_id(report.generation)
                    .map_err(|_| RetrievalError::MixedGeneration)?,
                authority_generation: HeadGeneration::try_new(report.generation_number)
                    .map_err(|_| RetrievalError::MixedGeneration)?,
            }),
            _ => None,
        };
        live(request)?;
        Ok(InitialReport {
            vector: GenerationVector {
                lexical: content.generation.clone(),
                symbols: symbol_generation,
            },
            content,
            path,
            symbols: channel,
            result_bytes,
        })
    }
}
fn symbol_unavailable(
    error: SymbolError,
    policy: SymbolPolicy,
    has_floor: bool,
) -> Result<SymbolUnavailable, RetrievalError> {
    if policy == SymbolPolicy::Optional && !has_floor {
        match error {
            symbols::AccessError::Uninitialized => return Ok(SymbolUnavailable::Uninitialized),
            symbols::AccessError::Stale => return Ok(SymbolUnavailable::Stale),
            other => return Err(RetrievalError::Symbols(other)),
        }
    }
    Err(RetrievalError::Symbols(error))
}

#[cfg(test)]
mod tests;

/// Complete authority-selected native graph inspection under a node request.
pub mod integrity;
