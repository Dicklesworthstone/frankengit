//! Model-free, line-oriented byte-regex search over one immutable source tree.
//!
//! The profile returns one leftmost-longest span per matching LF-delimited
//! line. It never crosses LF, follows symlinks, supplies captures, changes
//! authorization, or claims to implement Unicode/PCRE semantics. Pattern and
//! state ceilings, an aggregate VM-work budget, and ordinary source budgets
//! are independent. Any exhaustion refuses the whole read.

mod engine;
pub use engine::{RegexError, RegexErrorKind};

use super::{
    Discovery, DiscoveryContext, SearchCase, SearchCompletion, SearchError, SearchLimits,
    SourceMatch, SourceQuery, SourceSearchReport, checkpoint, discover, oid,
};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind};
use fgit_treefs::{BaseView, ObjectSource, TreeCapability, TreePath};
use std::collections::BTreeMap;

/// The default and maximum VM-work envelope for one entire repository query.
pub const MAX_REGEX_STEPS: u64 = 64 * 1024 * 1024;
/// Maximum combined retained path and excerpt bytes, independent of row count.
const MAX_RESULT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegexQueryError {
    Expression(RegexError),
    InvalidScope,
    InvalidWorkLimit,
}
impl std::fmt::Display for RegexQueryError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "source regex query refused: {self:?}")
    }
}
impl std::error::Error for RegexQueryError {}

/// Immutable compiled query. Neither a regex nor a path prefix is a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegexQuery {
    pattern: Vec<u8>,
    program: engine::Program,
    scope: SourceQuery,
    maximum_steps: u64,
}
impl RegexQuery {
    pub fn new(
        pattern: &[u8],
        case: SearchCase,
        prefixes: &[Vec<u8>],
        maximum_steps: u64,
    ) -> Result<Self, RegexQueryError> {
        if maximum_steps == 0 || maximum_steps > MAX_REGEX_STEPS {
            return Err(RegexQueryError::InvalidWorkLimit);
        }
        let program = engine::Program::compile(pattern, case == SearchCase::AsciiInsensitive)
            .map_err(RegexQueryError::Expression)?;
        // Only the source query's canonical path selection is reused.
        let scope =
            SourceQuery::new(b"\0", case, prefixes).map_err(|_| RegexQueryError::InvalidScope)?;
        Ok(Self {
            pattern: pattern.to_vec(),
            program,
            scope,
            maximum_steps,
        })
    }
    #[must_use]
    pub fn pattern(&self) -> &[u8] {
        &self.pattern
    }
    #[must_use]
    pub const fn case(&self) -> SearchCase {
        self.scope.case()
    }
    #[must_use]
    pub fn prefixes(&self) -> &[TreePath] {
        self.scope.prefixes()
    }
    /// Shared node selection consumes only this query's normalized path scope.
    /// The sentinel needle has no role in regex matching.
    #[must_use]
    pub const fn source_scope(&self) -> &SourceQuery {
        &self.scope
    }
    #[must_use]
    pub const fn maximum_steps(&self) -> u64 {
        self.maximum_steps
    }
    #[must_use]
    pub const fn state_count(&self) -> usize {
        self.program.states()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegexSearchReport {
    /// Source coordinates, byte spans, file counters and honest match ceiling.
    /// `matches` contains at most ONE span per physical line, unlike literals.
    pub source: SourceSearchReport,
    /// Exact size of the bounded Thompson program.
    pub program_states: usize,
    /// Input-position, epsilon-edge and active-byte work charged by the VM.
    pub steps: u64,
    /// Includes the extra matching line that establishes a match-limit result.
    pub lines_searched: usize,
}

const fn scan_error(error: engine::ScanError) -> SearchError {
    match error {
        engine::ScanError::Cancelled => SearchError::Cancelled,
        engine::ScanError::WorkLimit => SearchError::Budget("regex VM work"),
        engine::ScanError::Allocation => SearchError::Budget("regex VM allocation"),
    }
}

/// Compile-independent execution over existing verified and capability-scoped
/// TreeFS reads. The returned positions are all derived from `base`, not from
/// a separately read ref/head. Infrastructure failures never imply no matches.
pub fn search_source_regex<A: GitHashAlgorithm, S: ObjectSource<A>>(
    base: &BaseView<A>,
    source: &S,
    capability: &mut TreeCapability,
    now: u64,
    query: &RegexQuery,
    limits: SearchLimits,
    cancelled: &dyn Fn() -> bool,
) -> Result<RegexSearchReport, SearchError> {
    limits.validate()?;
    checkpoint(cancelled)?;
    capability
        .authorize_root(now)
        .map_err(SearchError::Capability)?;
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
        query: &query.scope,
        limits,
        cancelled,
    };
    discover(&mut ctx, None, 0, &mut discovery)?;
    let mut report = RegexSearchReport {
        source: SourceSearchReport {
            repository: base.repository_id(),
            source_rcr: base.base_rcr_id(),
            source_commit: oid::<A>(base.base_commit_oid())?,
            source_tree: oid::<A>(base.base_tree_oid())?,
            matches: Vec::new(),
            completion: SearchCompletion::Complete,
            files_selected: discovery.files.len(),
            files_read: 0,
            bytes_read: 0,
            bytes_searched: 0,
            non_regular_entries: discovery.excluded,
        },
        program_states: query.state_count(),
        steps: 0,
        lines_searched: 0,
    };
    let mut runner = engine::Runner::new(&query.program).map_err(scan_error)?;
    let mut budget = engine::Budget {
        used: 0,
        maximum: query.maximum_steps,
    };
    let mut result_bytes = 0usize;
    'files: for (path, blob) in discovery.files {
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
        report.source.bytes_read = report
            .source
            .bytes_read
            .checked_add(body.len())
            .filter(|bytes| *bytes <= limits.max_total_bytes)
            .ok_or(SearchError::Budget("total bytes"))?;
        report.source.files_read += 1;
        let blob = oid::<A>(&blob)?;
        let mut line_start = 0usize;
        // split_inclusive does not invent a line for an empty file or after
        // a final LF. CR is source data; $ does not silently strip it.
        for (line_index, record) in body.split_inclusive(|byte| *byte == b'\n').enumerate() {
            checkpoint(cancelled)?;
            let line = record.strip_suffix(b"\n").unwrap_or(record);
            let matched = runner
                .find_line(line, &mut budget, cancelled)
                .map_err(scan_error)?;
            report.lines_searched += 1;
            report.source.bytes_searched += record.len();
            if let Some((start, end)) = matched {
                if report.source.matches.len() == limits.max_matches {
                    report.source.completion = SearchCompletion::MatchLimit;
                    break 'files;
                }
                // A long match is not copied into a huge excerpt. Its full
                // byte span remains exact; the transport labels truncation.
                let excerpt_start = start.saturating_sub(80);
                let excerpt_end = line
                    .len()
                    .min(end.saturating_add(80))
                    .min(excerpt_start + 416);
                result_bytes = result_bytes
                    .checked_add(path.as_bytes().len())
                    .and_then(|n| n.checked_add(excerpt_end - excerpt_start))
                    .filter(|n| *n <= MAX_RESULT_BYTES)
                    .ok_or(SearchError::Budget("regex result bytes"))?;
                report.source.matches.push(SourceMatch {
                    path: path.as_bytes().to_vec(),
                    blob,
                    byte_offset: line_start + start,
                    line: line_index + 1,
                    byte_column: start + 1,
                    match_length: end - start,
                    excerpt: line[excerpt_start..excerpt_end].to_vec(),
                    excerpt_offset: line_start + excerpt_start,
                });
            }
            line_start += record.len();
        }
    }
    checkpoint(cancelled)?;
    report.steps = budget.used;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_limits_and_scope_cannot_disable_or_widen_the_profile() {
        for maximum in [0, MAX_REGEX_STEPS + 1, u64::MAX] {
            assert_eq!(
                RegexQuery::new(b"a", SearchCase::Exact, &[], maximum),
                Err(RegexQueryError::InvalidWorkLimit)
            );
        }
        assert!(RegexQuery::new(b"a", SearchCase::Exact, &[], 1).is_ok());
        assert!(matches!(
            RegexQuery::new(b"(", SearchCase::Exact, &[], MAX_REGEX_STEPS),
            Err(RegexQueryError::Expression(_))
        ));
        assert_eq!(
            RegexQuery::new(
                b"a",
                SearchCase::Exact,
                &[b"../secret".to_vec()],
                MAX_REGEX_STEPS
            ),
            Err(RegexQueryError::InvalidScope)
        );
        let query = RegexQuery::new(
            br"\bThing\b",
            SearchCase::Exact,
            &[b"src".to_vec(), b"src".to_vec()],
            MAX_REGEX_STEPS,
        )
        .unwrap();
        assert_eq!(query.prefixes().len(), 1);
        assert!(
            query
                .source_scope()
                .includes(&TreePath::parse_default(b"src/a").unwrap())
        );
        assert!(
            !query
                .source_scope()
                .includes(&TreePath::parse_default(b"src2/a").unwrap())
        );
        assert_eq!(query.pattern(), br"\bThing\b");
    }
    #[test]
    fn execution_errors_are_distinct_from_empty_success() {
        assert!(matches!(
            scan_error(engine::ScanError::Cancelled),
            SearchError::Cancelled
        ));
        assert!(matches!(
            scan_error(engine::ScanError::WorkLimit),
            SearchError::Budget("regex VM work")
        ));
        assert!(matches!(
            scan_error(engine::ScanError::Allocation),
            SearchError::Budget("regex VM allocation")
        ));
    }
}
