//! Opt-in deterministic document fusion for exact-byte context selection.
//! Channel order is the native reader's raw-path order, NOT a relevance score.
//! Reciprocal-rank fusion rewards cross-channel agreement; it is advisory and
//! never changes the source observation, evidence, visibility or read grants.
use super::{
    ContextChannel, ContextLimits, InitialContext, InitialReport, RetrievalError, SymbolChannel,
    check,
};
use fgit_treefs::TreePath;
use fgit_types::{GitHashAlgorithm, GitOid};
use std::collections::{BTreeMap, BTreeSet};

pub const PROFILE: &str = "context-weighted-rrf-q16-v1";
pub const RANK_CONSTANT: u32 = 60;
pub const SCORE_SCALE: u32 = 65_536;
const MAX_CHANNEL_HITS: usize = 1024;
const MAX_PATH_BYTES: usize = 2 * 1024 * 1024;

/// Fixed v1 weights, not a remotely supplied policy or authorization input.
#[must_use]
pub const fn channel_weight(channel: ContextChannel) -> u32 {
    match channel {
        ContextChannel::Content | ContextChannel::Path => 1,
        ContextChannel::Symbol => 2,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RankContribution {
    channel: ContextChannel,
    document_rank: u32,
    score_q16: u32,
}
impl RankContribution {
    #[must_use]
    pub const fn channel(&self) -> ContextChannel {
        self.channel
    }
    /// One-based rank among DISTINCT returned paths in this channel. Repeated
    /// declarations in a file neither amplify its score nor displace later ranks.
    #[must_use]
    pub const fn document_rank(&self) -> u32 {
        self.document_rank
    }
    #[must_use]
    pub const fn score_q16(&self) -> u32 {
        self.score_q16
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RankedFile {
    path: Vec<u8>,
    blob: GitOid,
    score_q16: u32,
    contributions: Vec<RankContribution>,
}
impl RankedFile {
    #[must_use]
    pub fn path(&self) -> &[u8] {
        &self.path
    }
    #[must_use]
    pub const fn blob(&self) -> GitOid {
        self.blob
    }
    #[must_use]
    pub const fn score_q16(&self) -> u32 {
        self.score_q16
    }
    #[must_use]
    pub fn contributions(&self) -> &[RankContribution] {
        &self.contributions
    }
}

/// A bounded selection receipt, constructed from the actual Initial response.
/// Scores are sum(floor(weight * 65536 / (60 + distinct_document_rank))).
/// Descending score, then ascending raw path, is the complete tie-break rule.
/// Only the selected prefix is retained here; the original channel results in
/// InitialContext preserve the evidence needed to reproduce every candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextRanking {
    candidate_files: usize,
    selected: Vec<RankedFile>,
}
impl ContextRanking {
    #[must_use]
    pub const fn candidate_files(&self) -> usize {
        self.candidate_files
    }
    /// Selection order. Context files themselves stay in raw-path order so
    /// selection cannot change native traversal or excerpt ordering semantics.
    #[must_use]
    pub fn selected(&self) -> &[RankedFile] {
        &self.selected
    }
    pub(crate) fn build(
        report: &InitialReport,
        limits: ContextLimits,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, RetrievalError> {
        limits.validate()?;
        check(cancelled)?;
        let mut accumulator = Accumulator::default();
        let format = report.source().namespace.object_format;
        for (channel, hits) in [
            (ContextChannel::Content, &report.content().results.hits),
            (ContextChannel::Path, &report.path().results.hits),
        ] {
            accumulator.add(
                channel,
                hits.iter().map(|hit| (hit.path.as_slice(), hit.blob)),
                format,
                cancelled,
            )?;
        }
        if let SymbolChannel::Available(symbols) = report.symbols() {
            accumulator.add(
                ContextChannel::Symbol,
                symbols
                    .matches
                    .iter()
                    .map(|hit| (hit.location.path.as_slice(), hit.location.blob)),
                format,
                cancelled,
            )?;
        }
        accumulator.finish(limits.max_files, cancelled)
    }
}

/// Ranked selection and verified context are joined before either is returned.
/// This does not upgrade optional/missing channels or incomplete index coverage.
#[derive(Clone, Debug)]
pub struct RankedContext {
    context: InitialContext,
    ranking: ContextRanking,
}
impl RankedContext {
    #[must_use]
    pub const fn context(&self) -> &InitialContext {
        &self.context
    }
    #[must_use]
    pub const fn ranking(&self) -> &ContextRanking {
        &self.ranking
    }
    #[must_use]
    pub fn into_parts(self) -> (InitialContext, ContextRanking) {
        (self.context, self.ranking)
    }
    pub(crate) fn finish(
        context: InitialContext,
        ranking: ContextRanking,
    ) -> Result<Self, RetrievalError> {
        if context.candidate_files() != ranking.candidate_files
            || context.files().len() != ranking.selected.len()
        {
            return Err(RetrievalError::Invalid("ranked context selection"));
        }
        for selected in &ranking.selected {
            let at = context
                .files()
                .binary_search_by(|file| file.path().cmp(selected.path()))
                .map_err(|_| RetrievalError::Invalid("ranked context path"))?;
            if context.files()[at].blob() != selected.blob {
                return Err(RetrievalError::MixedSource);
            }
        }
        Ok(Self { context, ranking })
    }
}

#[derive(Default)]
struct Accumulator {
    files: BTreeMap<Vec<u8>, RankedFile>,
    channels: BTreeSet<ContextChannel>,
    path_bytes: usize,
}
impl Accumulator {
    /// Any error poisons this local computation: callers propagate it rather
    /// than finalizing a partially accumulated channel as a successful ranking.
    fn add<'a>(
        &mut self,
        channel: ContextChannel,
        hits: impl IntoIterator<Item = (&'a [u8], GitOid)>,
        format: GitHashAlgorithm,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), RetrievalError> {
        check(cancelled)?;
        if !self.channels.insert(channel) {
            return Err(RetrievalError::Invalid("repeated fusion channel"));
        }
        let mut previous: Option<&[u8]> = None;
        let mut rank = 0u32;
        for (ordinal, (path, blob)) in hits.into_iter().enumerate() {
            check(cancelled)?;
            if ordinal >= MAX_CHANNEL_HITS {
                return Err(RetrievalError::Limit("fusion channel hits"));
            }
            if blob.is_zero()
                || blob.algorithm() != format
                || TreePath::parse_default(path).is_err()
                || previous.is_some_and(|prior| prior > path)
            {
                return Err(RetrievalError::Invalid("fusion native identity/order"));
            }
            if self.files.get(path).is_some_and(|file| file.blob != blob) {
                return Err(RetrievalError::MixedSource);
            }
            // Input symbol rows can repeat a path. Check identity BEFORE
            // deduplication; a conflicting repeated blob is not harmless spam.
            if previous == Some(path) {
                continue;
            }
            previous = Some(path);
            rank += 1; // <= MAX_CHANNEL_HITS; denominator and score fit u32.
            let contribution = channel_weight(channel) * SCORE_SCALE / (RANK_CONSTANT + rank);
            if !self.files.contains_key(path) {
                self.path_bytes = self
                    .path_bytes
                    .checked_add(path.len())
                    .filter(|n| *n <= MAX_PATH_BYTES)
                    .ok_or(RetrievalError::Limit("fusion path bytes"))?;
                self.files.insert(
                    path.to_vec(),
                    RankedFile {
                        path: path.to_vec(),
                        blob,
                        score_q16: 0,
                        contributions: Vec::new(),
                    },
                );
            }
            let file = self
                .files
                .get_mut(path)
                .ok_or(RetrievalError::Invalid("fusion document"))?;
            file.score_q16 = file
                .score_q16
                .checked_add(contribution)
                .ok_or(RetrievalError::Limit("fusion score"))?;
            file.contributions.push(RankContribution {
                channel,
                document_rank: rank,
                score_q16: contribution,
            });
        }
        check(cancelled)
    }
    fn finish(
        self,
        maximum: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<ContextRanking, RetrievalError> {
        check(cancelled)?;
        if !(1..=super::MAX_FILES).contains(&maximum) {
            return Err(RetrievalError::Invalid("fusion selection limit"));
        }
        let candidate_files = self.files.len();
        let mut selected: Vec<_> = self.files.into_values().collect();
        for file in &mut selected {
            check(cancelled)?;
            file.contributions.sort_by_key(|value| value.channel);
        }
        selected.sort_by(|left, right| {
            right
                .score_q16
                .cmp(&left.score_q16)
                .then_with(|| left.path.cmp(&right.path))
        });
        check(cancelled)?;
        selected.truncate(maximum);
        Ok(ContextRanking {
            candidate_files,
            selected,
        })
    }
}

#[cfg(test)]
mod tests;
