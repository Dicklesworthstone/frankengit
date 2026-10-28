//! Complete, snapshot-coherent ANY-term retrieval over the existing postings.
//!
//! Coverage sorts first, then the sum of fixed-point inverse document
//! frequencies, then raw path. This is not BM25: the existing format retains
//! first occurrences, not term frequencies or token counts. All selected
//! segments are authenticated and the complete scoped corpus is counted before
//! top-k selection. Neither a late read failure nor a work refusal can return a
//! successful prefix. Corpus statistics are derived, never authorization.

use super::*;
use crate::lexical::{LexicalSpan, lower_bound, under};
use std::cmp::Ordering;
use std::collections::BinaryHeap;

pub const RANKED_PROFILE: &str = "source-lexical-coverage-rarity-v1";
pub const RARITY_SCALE: u64 = 65_536;
const MAX_CANDIDATE_BYTES: usize = 32 * 1024 * 1024;

/// Score evidence in exactly the same order as the report's selected hits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RankedLexicalScore {
    pub matched_terms: usize,
    /// Sum over matched terms of floor((N + 1) * 65536 / (df + 1)). N and df
    /// count indexed documents inside the query's path scope, not the page.
    pub rarity_q16: u64,
}

/// An explicit alternative query profile. `index.results.hits` are ranked,
/// ANY-term results rather than the ordinary reader's path-ordered AND page.
/// There is deliberately no document-ID continuation for a relevance order.
/// Omission evidence remains intact: ranking a complete indexed corpus does
/// not claim that files omitted during index construction were searched.
#[derive(Clone, Debug)]
pub struct RankedLexicalReport {
    pub index: IndexedLexicalReport,
    pub scores: Vec<RankedLexicalScore>,
    pub scoped_documents: usize,
    pub matched_documents: usize,
    /// One frequency per normalized query term, including zero for absent terms.
    pub term_document_frequencies: Vec<usize>,
}

struct RankedScan {
    scan: Scan,
    corpus: usize,
    frequencies: Vec<usize>,
    candidates: Vec<LexicalHit>,
    candidate_bytes: usize,
    max_path_bytes: usize,
}

impl RankedScan {
    fn new(
        selection: &LexicalSelection,
        query: &LexicalQuery,
        read_limits: LexicalReadLimits,
        query_limits: LexicalQueryLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, IndexError> {
        let mut scan = Scan::new(selection, read_limits, query_limits, live)?;
        bounded_add(
            &mut scan.budget.result_bytes,
            128 + query.terms.len() * 8,
            MAX_RESULT_BYTES,
            "ranked result metadata",
        )?;
        Ok(Self {
            scan,
            corpus: 0,
            frequencies: vec![0; query.terms.len()],
            candidates: Vec::new(),
            candidate_bytes: 0,
            max_path_bytes: 0,
        })
    }

    fn observe(
        &mut self,
        reference: &SegmentRef,
        bytes: &[u8],
        namespace: LexicalNamespace,
        omissions: &[LexicalOmission],
        query: &LexicalQuery,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), IndexError> {
        let segment = LexicalSegment::decode(bytes, reference.root, namespace, live)?;
        if SegmentRef::new(&segment, reference.root, bytes.len())? != *reference {
            return Err(LexicalError::CommitmentMismatch.into());
        }
        omissions::disjoint(omissions, segment.documents(), live)?;
        let mut lists = Vec::with_capacity(query.terms.len());
        for term in &query.terms {
            self.scan.budget.charge(1 + term.len() as u64, live)?;
            lists.push(segment.terms.get(&Term {
                channel: query.channel,
                bytes: term.clone(),
            }));
        }
        for document in segment.documents() {
            self.scan.budget.charge(1, live)?;
            let mut included = query.prefixes.is_empty();
            for prefix in &query.prefixes {
                self.scan.budget.charge(1 + prefix.len() as u64, live)?;
                if under(&document.path, prefix) {
                    included = true;
                    break;
                }
            }
            if !included {
                continue;
            }
            bounded_add(&mut self.corpus, 1, MAX_INDEX_DOCUMENTS, "ranked corpus")?;
            let mut spans = Vec::new();
            for (query_index, list) in lists.iter().enumerate() {
                self.scan.budget.charge(1, live)?;
                let Some(list) = list else { continue };
                let at = lower_bound(&list.documents, document.id, &mut self.scan.budget, live)?;
                if list.documents.get(at) == Some(&document.id) {
                    self.frequencies[query_index] += 1;
                    spans.push(LexicalSpan {
                        query_index,
                        byte_offset: list.offsets[at],
                        byte_length: query.terms[query_index].len() as u16,
                    });
                }
            }
            if spans.is_empty() {
                continue;
            }
            // The complete candidate census is bounded independently of the
            // selected output. No file contents or full decoded segments are
            // retained. Refuse before copying paths or extending the census.
            bounded_add(
                &mut self.candidate_bytes,
                document.path.len() + spans.len() * 24 + 128,
                MAX_CANDIDATE_BYTES,
                "ranked candidate bytes",
            )?;
            self.scan
                .budget
                .charge(document.path.len() as u64 + spans.len() as u64, live)?;
            self.max_path_bytes = self.max_path_bytes.max(document.path.len());
            self.candidates.push(LexicalHit {
                document_id: document.id,
                path: document.path.clone(),
                blob: document.blob,
                content_bytes: document.content_bytes,
                spans,
            });
        }
        check(live)?;
        Ok(())
    }

    fn finish(
        mut self,
        selection: &LexicalSelection,
        query: &LexicalQuery,
        live: &mut impl FnMut() -> bool,
    ) -> Result<RankedLexicalReport, IndexError> {
        let matched_documents = self.candidates.len();
        let maximum = self.scan.budget.limits.max_results;
        let weights: Vec<_> = self
            .frequencies
            .iter()
            .map(|frequency| (self.corpus as u64 + 1) * RARITY_SCALE / (*frequency as u64 + 1))
            .collect();
        let mut selected: BinaryHeap<HeapHit> = BinaryHeap::new();
        // Precharge comparisons AND their worst-case raw-path byte scans.
        // Equal coverage/rarity may force a complete common-prefix comparison;
        // a long path must not turn one work unit into thousands of byte reads.
        let heap_work = 2
            * (usize::BITS - maximum.leading_zeros() + 1) as u64
            * (self.max_path_bytes as u64 + 1);
        for hit in self.candidates {
            self.scan
                .budget
                .charge(heap_work + hit.spans.len() as u64, live)?;
            let score = RankedLexicalScore {
                matched_terms: hit.spans.len(),
                rarity_q16: hit.spans.iter().map(|span| weights[span.query_index]).sum(),
            };
            let candidate = HeapHit { hit, score };
            if selected.len() < maximum {
                selected.push(candidate);
            } else if selected.peek().is_some_and(|worst| candidate < *worst) {
                selected.pop();
                selected.push(candidate);
            }
        }
        self.scan
            .budget
            .charge(heap_work * selected.len() as u64, live)?;
        let mut selected = selected.into_vec();
        selected.sort();
        check(live)?;
        let mut scores = Vec::with_capacity(selected.len());
        for value in selected {
            self.scan.budget.charge(1, live)?;
            bounded_add(
                &mut self.scan.budget.result_bytes,
                value.hit.path.len() + value.hit.spans.len() * 24 + 96,
                MAX_RESULT_BYTES,
                "result bytes",
            )?;
            scores.push(value.score);
            self.scan.hits.push(value.hit);
        }
        self.scan.more = matched_documents > self.scan.hits.len();
        let mut index = self.scan.finish(selection, query);
        index.results.next_after = None;
        check(live)?;
        Ok(RankedLexicalReport {
            index,
            scores,
            scoped_documents: self.corpus,
            matched_documents,
            term_document_frequencies: self.frequencies,
        })
    }
}

struct HeapHit {
    hit: LexicalHit,
    score: RankedLexicalScore,
}
impl Ord for HeapHit {
    // The maximum is the WORST retained item, making replacement O(log k).
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .matched_terms
            .cmp(&self.score.matched_terms)
            .then_with(|| other.score.rarity_q16.cmp(&self.score.rarity_q16))
            .then_with(|| self.hit.path.cmp(&other.hit.path))
    }
}
impl PartialOrd for HeapHit {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for HeapHit {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for HeapHit {}

impl<S: AuthorityStore> LexicalIndexStore<'_, S> {
    /// Rank ANY-term matches in one selected generation. Path scopes narrow the
    /// corpus used both for matches and document frequencies; they grant no
    /// permission. All segments are verified even after top-k is attainable.
    pub fn search_ranked(
        &self,
        selection: &LexicalSelection,
        query: &LexicalQuery,
        read_limits: LexicalReadLimits,
        query_limits: LexicalQueryLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<RankedLexicalReport, IndexError> {
        let mut scan = RankedScan::new(selection, query, read_limits, query_limits, live)?;
        self.check_source(selection.source())?;
        if selection.store_instance != self.store.instance_id() {
            return Err(IndexError::SourceMismatch);
        }
        for reference in &selection.manifest.segments {
            scan.scan.before(reference, read_limits, live)?;
            let bytes = payload(
                self.store.read_immutable(&payload_key(
                    self.namespace,
                    "segment",
                    reference.root,
                )?)?,
                reference.root,
                &mut scan.scan.bytes,
                read_limits,
            )?;
            scan.observe(
                reference,
                &bytes,
                self.namespace,
                &selection.manifest.omissions,
                query,
                live,
            )?;
        }
        scan.finish(selection, query, live)
    }
}

impl<S: AsyncAuthorityStore> LexicalIndexStore<'_, S> {
    /// Context-retaining async equivalent of `search_ranked`; cancellation or
    /// any late source/integrity failure discards the entire candidate census.
    pub async fn search_ranked_async(
        &self,
        cx: &S::Context,
        selection: &LexicalSelection,
        query: &LexicalQuery,
        read_limits: LexicalReadLimits,
        query_limits: LexicalQueryLimits,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<RankedLexicalReport, IndexError> {
        let mut scan = RankedScan::new(selection, query, read_limits, query_limits, live)?;
        self.check_source(selection.source())?;
        if selection.store_instance != self.store.instance_id() {
            return Err(IndexError::SourceMismatch);
        }
        for reference in &selection.manifest.segments {
            scan.scan.before(reference, read_limits, live)?;
            let bytes = payload(
                self.store
                    .read_immutable(cx, &payload_key(self.namespace, "segment", reference.root)?)
                    .await?,
                reference.root,
                &mut scan.scan.bytes,
                read_limits,
            )?;
            scan.observe(
                reference,
                &bytes,
                self.namespace,
                &selection.manifest.omissions,
                query,
                live,
            )?;
        }
        scan.finish(selection, query, live)
    }
}
