//! Same-snapshot, single-pass literal retrieval for Context Packet consumers.
//!
//! This is the model-free scan profile, not a persistent search generation.
//! One bounded Aho-Corasick machine handles all needles; traversal, verified
//! object reads and capability charges are shared, never repeated per query.
//! Result order is input-query order, then raw path bytes, then byte offset.

use std::collections::{BTreeMap, VecDeque};

use super::*;

pub const MAX_BATCH_QUERIES: usize = 32;
const MAX_RETAINED_MATCHES: usize = 4096;
const MAX_RETAINED_BYTES: usize = 2 * 1024 * 1024;

/// An ordered, nonempty batch sharing one case policy and path scope.
/// Duplicate needles are intentional: every input keeps its own result slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceQueryBatch {
    queries: Vec<SourceQuery>,
}
impl SourceQueryBatch {
    pub fn new(
        needles: &[Vec<u8>],
        case: SearchCase,
        prefixes: &[Vec<u8>],
    ) -> Result<Self, SearchError> {
        if needles.is_empty() || needles.len() > MAX_BATCH_QUERIES {
            return Err(SearchError::InvalidQuery);
        }
        let queries = needles
            .iter()
            .map(|needle| SourceQuery::new(needle, case, prefixes))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { queries })
    }

    #[must_use]
    pub fn queries(&self) -> &[SourceQuery] {
        &self.queries
    }

    /// Every query has this same validated disclosure-narrowing scope.
    #[must_use]
    pub fn scope(&self) -> &SourceQuery {
        &self.queries[0]
    }

    /// Construct an empty answer AFTER the caller verifies an empty selection.
    /// These coordinates are descriptive and never establish read authority.
    #[must_use]
    pub fn empty_report(
        &self,
        repository: RepositoryId,
        source_rcr: RepositoryCommitId,
        source_commit: GitOid,
        source_tree: GitOid,
    ) -> SourceSearchBatchReport {
        SourceSearchBatchReport {
            repository,
            source_rcr,
            source_commit,
            source_tree,
            results: self
                .queries
                .iter()
                .map(|query| SourceQueryResult {
                    needle: query.needle().to_vec(),
                    matches: Vec::new(),
                    completion: SearchCompletion::Complete,
                })
                .collect(),
            files_selected: 0,
            files_read: 0,
            bytes_read: 0,
            bytes_searched: 0,
            non_regular_entries: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceQueryResult {
    pub needle: Vec<u8>,
    pub matches: Vec<SourceMatch>,
    /// A limit is reported only after observing an additional match for THIS
    /// query. An absent query is not made partial by another query's limit.
    pub completion: SearchCompletion,
}

/// Every result shares these exact immutable source coordinates. Work counters
/// are batch totals, not multiplied by the number of matching needles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSearchBatchReport {
    pub repository: RepositoryId,
    pub source_rcr: RepositoryCommitId,
    pub source_commit: GitOid,
    pub source_tree: GitOid,
    pub results: Vec<SourceQueryResult>,
    pub files_selected: usize,
    pub files_read: usize,
    pub bytes_read: usize,
    pub bytes_searched: usize,
    pub non_regular_entries: usize,
}

/// Search one verified immutable tree for up to 32 literals in one pass.
///
/// `max_matches` applies independently to each needle. The batch additionally
/// retains at most 4096 matches and 2 MiB of path/excerpt bytes. Exceeding either
/// aggregate ceiling refuses the WHOLE read, never returns incomplete success.
/// Capability, source, budget and cancellation failures likewise return no
/// answer. Persistent indexing and semantic/rerank generations are not claimed.
pub fn search_source_batch<A: GitHashAlgorithm, S: ObjectSource<A>>(
    base: &BaseView<A>,
    source: &S,
    capability: &mut TreeCapability,
    now: u64,
    queries: &SourceQueryBatch,
    limits: SearchLimits,
    cancelled: &dyn Fn() -> bool,
) -> Result<SourceSearchBatchReport, SearchError> {
    limits.validate()?;
    checkpoint(cancelled)?;
    capability
        .authorize_root(now)
        .map_err(SearchError::Capability)?;
    let machine = Matcher::new(queries, cancelled)?;
    let mut discovery = Discovery {
        files: BTreeMap::new(),
        entries: 0,
        excluded: 0,
    };
    let mut ctx = DiscoveryContext {
        base,
        source,
        capability,
        now,
        query: queries.scope(),
        limits,
        cancelled,
    };
    discover(&mut ctx, None, 0, &mut discovery)?;
    let mut report = queries.empty_report(
        base.repository_id(),
        base.base_rcr_id(),
        oid::<A>(base.base_commit_oid())?,
        oid::<A>(base.base_tree_oid())?,
    );
    report.files_selected = discovery.files.len();
    report.non_regular_entries = discovery.excluded;
    let mut collector = Collector::new(queries, limits.max_matches);
    for (path, blob) in discovery.files {
        checkpoint(cancelled)?;
        let grant = capability
            .authorize_read(&path, now)
            .map_err(SearchError::Capability)?;
        let body = base
            .read_object(source, &blob, GitObjectKind::Blob, &grant)
            .map_err(|error| SearchError::Source(Box::new(error)))?;
        capability
            .charge_fetch(body.len() as u64)
            .map_err(SearchError::Capability)?;
        checkpoint(cancelled)?;
        if body.len() > limits.max_file_bytes {
            return Err(SearchError::Budget("file bytes"));
        }
        report.bytes_read = report
            .bytes_read
            .checked_add(body.len())
            .filter(|bytes| *bytes <= limits.max_total_bytes)
            .ok_or(SearchError::Budget("total bytes"))?;
        report.files_read += 1;
        report.bytes_searched += collector.scan_file(
            &machine,
            path.as_bytes(),
            oid::<A>(&blob)?,
            &body,
            cancelled,
        )?;
        if collector.unfinished == 0 {
            break;
        }
    }
    checkpoint(cancelled)?;
    report.results = collector.results;
    Ok(report)
}

#[derive(Default)]
struct State {
    edges: BTreeMap<u8, usize>,
    fallback: usize,
    outputs: u32,
}
struct Matcher {
    states: Vec<State>,
    case: SearchCase,
}
impl Matcher {
    fn new(batch: &SourceQueryBatch, cancelled: &dyn Fn() -> bool) -> Result<Self, SearchError> {
        checkpoint(cancelled)?;
        // At most 32 * 256 + 1 states. Edges remain sparse; there is no
        // adversary-sized 256-way transition allocation for every prefix.
        let capacity = 1 + batch
            .queries()
            .iter()
            .map(|query| query.needle().len())
            .sum::<usize>();
        let mut states = Vec::new();
        states
            .try_reserve_exact(capacity)
            .map_err(|_| SearchError::Budget("matcher allocation"))?;
        states.push(State::default());
        let case = batch.scope().case();
        for (index, query) in batch.queries().iter().enumerate() {
            checkpoint(cancelled)?;
            let mut state = 0;
            for &raw in query.needle() {
                let byte = fold(raw, case);
                let next = if let Some(&next) = states[state].edges.get(&byte) {
                    next
                } else {
                    let next = states.len();
                    states.push(State::default());
                    states[state].edges.insert(byte, next);
                    next
                };
                state = next;
            }
            states[state].outputs |= 1u32 << index;
        }
        let mut queue = VecDeque::new();
        queue
            .try_reserve(states.len())
            .map_err(|_| SearchError::Budget("matcher allocation"))?;
        queue.extend(states[0].edges.values().copied());
        while let Some(parent) = queue.pop_front() {
            checkpoint(cancelled)?;
            let edges: Vec<_> = states[parent]
                .edges
                .iter()
                .map(|(&byte, &child)| (byte, child))
                .collect();
            for (byte, child) in edges {
                let mut fallback = states[parent].fallback;
                while fallback != 0 && !states[fallback].edges.contains_key(&byte) {
                    fallback = states[fallback].fallback;
                }
                fallback = states[fallback].edges.get(&byte).copied().unwrap_or(0);
                states[child].fallback = fallback;
                let inherited = states[fallback].outputs;
                states[child].outputs |= inherited;
                queue.push_back(child);
            }
        }
        checkpoint(cancelled)?;
        Ok(Self { states, case })
    }

    fn scan(
        &self,
        bytes: &[u8],
        cancelled: &dyn Fn() -> bool,
        mut found: impl FnMut(usize, usize, usize, u32) -> Result<bool, SearchError>,
    ) -> Result<usize, SearchError> {
        let (mut state, mut line, mut line_start) = (0, 1, 0);
        for (offset, &raw) in bytes.iter().enumerate() {
            if offset % 4096 == 0 {
                checkpoint(cancelled)?;
            }
            let byte = fold(raw, self.case);
            while state != 0 && !self.states[state].edges.contains_key(&byte) {
                state = self.states[state].fallback;
            }
            state = self.states[state].edges.get(&byte).copied().unwrap_or(0);
            let outputs = self.states[state].outputs;
            if outputs != 0 && !found(offset + 1, line, line_start, outputs)? {
                return Ok(offset + 1);
            }
            if raw == b'\n' {
                line += 1;
                line_start = offset + 1;
            }
        }
        checkpoint(cancelled)?;
        Ok(bytes.len())
    }
}

struct Collector {
    results: Vec<SourceQueryResult>,
    per_query_limit: usize,
    unfinished: u32,
    retained_matches: usize,
    retained_bytes: usize,
}
impl Collector {
    fn new(batch: &SourceQueryBatch, per_query_limit: usize) -> Self {
        Self {
            results: batch
                .queries()
                .iter()
                .map(|query| SourceQueryResult {
                    needle: query.needle().to_vec(),
                    matches: Vec::new(),
                    completion: SearchCompletion::Complete,
                })
                .collect(),
            per_query_limit,
            unfinished: u32::MAX >> (32 - batch.queries().len()),
            retained_matches: 0,
            retained_bytes: 0,
        }
    }

    fn scan_file(
        &mut self,
        machine: &Matcher,
        path: &[u8],
        blob: GitOid,
        bytes: &[u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<usize, SearchError> {
        machine.scan(bytes, cancelled, |end, line, line_start, mask| {
            let mut pending = mask & self.unfinished;
            while pending != 0 {
                let index = pending.trailing_zeros() as usize;
                let bit = 1u32 << index;
                pending &= !bit;
                let result = &mut self.results[index];
                if result.matches.len() == self.per_query_limit {
                    result.completion = SearchCompletion::MatchLimit;
                    self.unfinished &= !bit;
                    continue;
                }
                let length = result.needle.len();
                let start = end - length;
                let excerpt_offset = line_start.max(start.saturating_sub(80));
                let upper = bytes.len().min(end.saturating_add(80));
                let excerpt_end = bytes[end..upper]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(upper, |offset| end + offset);
                let charge = path
                    .len()
                    .checked_add(excerpt_end - excerpt_offset)
                    .ok_or(SearchError::Budget("batch result bytes"))?;
                if self.retained_matches == MAX_RETAINED_MATCHES {
                    return Err(SearchError::Budget("batch matches"));
                }
                self.retained_bytes = self
                    .retained_bytes
                    .checked_add(charge)
                    .filter(|bytes| *bytes <= MAX_RETAINED_BYTES)
                    .ok_or(SearchError::Budget("batch result bytes"))?;
                result
                    .matches
                    .try_reserve(1)
                    .map_err(|_| SearchError::Budget("result allocation"))?;
                result.matches.push(SourceMatch {
                    path: path.to_vec(),
                    blob,
                    byte_offset: start,
                    line,
                    byte_column: start - line_start + 1,
                    excerpt: bytes[excerpt_offset..excerpt_end].to_vec(),
                    excerpt_offset,
                    match_length: length,
                });
                self.retained_matches += 1;
            }
            Ok(self.unfinished != 0)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn batch(needles: &[&[u8]], case: SearchCase) -> SourceQueryBatch {
        SourceQueryBatch::new(
            &needles
                .iter()
                .map(|needle| needle.to_vec())
                .collect::<Vec<_>>(),
            case,
            &[],
        )
        .unwrap()
    }
    fn blob() -> GitOid {
        GitOid::from_hex(Format::Sha1, &"1".repeat(40)).unwrap()
    }
    fn collect(
        input: &[u8],
        needles: &[&[u8]],
        case: SearchCase,
        limit: usize,
    ) -> Result<(Collector, usize), SearchError> {
        let query = batch(needles, case);
        let machine = Matcher::new(&query, &|| false)?;
        let mut collector = Collector::new(&query, limit);
        let bytes = collector.scan_file(&machine, b"file", blob(), input, &|| false)?;
        Ok((collector, bytes))
    }

    #[test]
    fn suffix_outputs_overlaps_duplicates_and_query_order_are_preserved() {
        let needles = [b"he".as_slice(), b"she", b"hers", b"his", b"he", b"aa"];
        let (result, read) = collect(b"ushers his aaaa", &needles, SearchCase::Exact, 100).unwrap();
        assert_eq!(read, 15);
        let positions: Vec<Vec<_>> = result
            .results
            .iter()
            .map(|query| query.matches.iter().map(|hit| hit.byte_offset).collect())
            .collect();
        assert_eq!(
            positions,
            vec![
                vec![2],
                vec![1],
                vec![2],
                vec![7],
                vec![2],
                vec![11, 12, 13]
            ]
        );
        assert!(
            result
                .results
                .iter()
                .all(|query| query.completion == SearchCompletion::Complete)
        );
    }

    #[test]
    fn exhaustive_small_corpus_agrees_with_independent_scalar_search() {
        let needles = [b"a".as_slice(), b"B", b"aa", b"ab", b"BaB", b"a", b"bbbb"];
        for length in 0..9 {
            for word in 0..(1usize << length) {
                let bytes: Vec<_> = (0..length)
                    .map(|i| if word & (1 << i) == 0 { b'a' } else { b'B' })
                    .collect();
                for case in [SearchCase::Exact, SearchCase::AsciiInsensitive] {
                    let (actual, consumed) = collect(&bytes, &needles, case, 100).unwrap();
                    assert_eq!(consumed, bytes.len());
                    for (index, needle) in needles.iter().enumerate() {
                        let expected: Vec<_> = bytes
                            .windows(needle.len())
                            .enumerate()
                            .filter(|(_, window)| match case {
                                SearchCase::Exact => *window == *needle,
                                SearchCase::AsciiInsensitive => window.eq_ignore_ascii_case(needle),
                            })
                            .map(|(offset, _)| offset)
                            .collect();
                        assert_eq!(
                            actual.results[index]
                                .matches
                                .iter()
                                .map(|hit| hit.byte_offset)
                                .collect::<Vec<_>>(),
                            expected
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn raw_bytes_crlf_and_final_lines_keep_single_search_coordinates() {
        let bytes = "éX\r\n\0xX".as_bytes();
        let (actual, _) = collect(
            bytes,
            &[b"x", b"\0", "é".as_bytes(), "É".as_bytes()],
            SearchCase::AsciiInsensitive,
            100,
        )
        .unwrap();
        assert_eq!(
            actual.results[0]
                .matches
                .iter()
                .map(|hit| (hit.byte_offset, hit.line, hit.byte_column))
                .collect::<Vec<_>>(),
            vec![(2, 1, 3), (6, 2, 2), (7, 2, 3)]
        );
        assert_eq!(actual.results[1].matches[0].byte_offset, 5);
        assert_eq!(actual.results[2].matches[0].match_length, 2);
        assert!(actual.results[3].matches.is_empty());
    }

    #[test]
    fn every_query_has_independent_lookahead_and_absence_evidence() {
        let (actual, read) =
            collect(b"aaaa", &[b"a", b"aa", b"absent"], SearchCase::Exact, 2).unwrap();
        assert_eq!(read, 4);
        assert_eq!(actual.results[0].completion, SearchCompletion::MatchLimit);
        assert_eq!(actual.results[1].completion, SearchCompletion::MatchLimit);
        assert_eq!(actual.results[2].completion, SearchCompletion::Complete);
        assert!(actual.results[2].matches.is_empty());
        let (exact, _) = collect(b"aa", &[b"a", b"aa"], SearchCase::Exact, 2).unwrap();
        assert!(
            exact
                .results
                .iter()
                .all(|query| query.completion == SearchCompletion::Complete)
        );
        let (early, consumed) =
            collect(b"aaaa-tail", &[b"a", b"aa"], SearchCase::Exact, 1).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(early.unfinished, 0);
    }

    #[test]
    fn file_boundaries_reset_automaton_and_limits_span_files() {
        let query = batch(&[b"ab", b"a"], SearchCase::Exact);
        let machine = Matcher::new(&query, &|| false).unwrap();
        let mut collector = Collector::new(&query, 1);
        collector
            .scan_file(&machine, b"first", blob(), b"a", &|| false)
            .unwrap();
        collector
            .scan_file(&machine, b"second", blob(), b"ba", &|| false)
            .unwrap();
        assert!(collector.results[0].matches.is_empty());
        assert_eq!(collector.results[1].matches[0].path, b"first");
        assert_eq!(
            collector.results[1].completion,
            SearchCompletion::MatchLimit
        );
    }

    #[test]
    fn thirty_two_queries_use_all_mask_bits_and_thirty_three_refuse() {
        let needles = vec![b"a".to_vec(); 32];
        let query = SourceQueryBatch::new(&needles, SearchCase::Exact, &[]).unwrap();
        let machine = Matcher::new(&query, &|| false).unwrap();
        let mut collector = Collector::new(&query, 1);
        assert_eq!(
            collector
                .scan_file(&machine, b"file", blob(), b"aa", &|| false)
                .unwrap(),
            2
        );
        assert_eq!(collector.unfinished, 0);
        assert!(
            collector
                .results
                .iter()
                .all(|query| query.matches.len() == 1
                    && query.completion == SearchCompletion::MatchLimit)
        );
        assert!(SourceQueryBatch::new(&vec![b"a".to_vec(); 33], SearchCase::Exact, &[]).is_err());
        assert!(SourceQueryBatch::new(&[], SearchCase::Exact, &[]).is_err());
    }

    #[test]
    fn invalid_needles_and_prefixes_refuse_before_search() {
        for needle in [b"".to_vec(), b"a\nb".to_vec(), vec![b'a'; 257]] {
            assert!(
                SourceQueryBatch::new(&[b"valid".to_vec(), needle], SearchCase::Exact, &[])
                    .is_err()
            );
        }
        assert!(
            SourceQueryBatch::new(
                &[b"a".to_vec()],
                SearchCase::Exact,
                &[b"../secret".to_vec()]
            )
            .is_err()
        );
        let query = SourceQueryBatch::new(
            &[b"a".to_vec(), b"b".to_vec()],
            SearchCase::Exact,
            &[b"src".to_vec(), b"src".to_vec()],
        )
        .unwrap();
        assert!(
            query
                .queries()
                .iter()
                .all(|item| item.prefixes() == query.scope().prefixes())
        );
    }

    #[test]
    fn aggregate_result_budgets_do_not_turn_into_partial_success() {
        assert!(matches!(
            collect(&vec![b'a'; 2049], &[b"a", b"a"], SearchCase::Exact, 4096),
            Err(SearchError::Budget("batch matches"))
        ));
        let query = batch(&[b"a"], SearchCase::Exact);
        let machine = Matcher::new(&query, &|| false).unwrap();
        let mut collector = Collector::new(&query, 100);
        collector.retained_bytes = MAX_RETAINED_BYTES - 1;
        assert!(matches!(
            collector.scan_file(&machine, b"file", blob(), b"a", &|| false),
            Err(SearchError::Budget("batch result bytes"))
        ));
        assert!(collector.results[0].matches.is_empty());
    }

    #[test]
    fn cancellation_is_checked_during_construction_and_scan() {
        let query = batch(&[b"a", b"aaaaa"], SearchCase::Exact);
        assert!(matches!(
            Matcher::new(&query, &|| true),
            Err(SearchError::Cancelled)
        ));
        let polls = Cell::new(0);
        assert!(matches!(
            Matcher::new(&query, &|| {
                polls.set(polls.get() + 1);
                polls.get() == 4
            }),
            Err(SearchError::Cancelled)
        ));
        let machine = Matcher::new(&query, &|| false).unwrap();
        let polls = Cell::new(0);
        assert!(matches!(
            machine.scan(
                &vec![b'x'; 8192],
                &|| {
                    polls.set(polls.get() + 1);
                    polls.get() == 2
                },
                |_, _, _, _| Ok(true)
            ),
            Err(SearchError::Cancelled)
        ));
    }
}
