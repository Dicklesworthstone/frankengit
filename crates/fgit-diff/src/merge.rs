//! Deterministic three-way merge proposals.
//!
//! This module has no authority capability. A clean result is still only a
//! proposed object, and a conflicted result preserves all source evidence for a
//! later `TreeFS` `RecordConflictMarkers` intent. All scratch state is owned by
//! the call stack and therefore drops on cancellation or refusal.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use crate::{
    diff, merge_bases_all, CommitGraph, DiffError, DiffHunk, DiffOptions, DiffProfile, Edit,
    MergeBaseError, MergeBaseLimits, MergeBaseResult, Span, TreeEntry, TreeMode,
};

/// Versioned selection rules for a merge proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MergeProfile {
    pub version: u16,
    pub diff_options: DiffOptions,
    pub conflict_style: ConflictStyle,
    pub virtual_base: VirtualBaseProfile,
}

impl Default for MergeProfile {
    fn default() -> Self {
        Self {
            version: 1,
            diff_options: DiffOptions::myers_lines(crate::DiffLimits::default()),
            conflict_style: ConflictStyle::MarkerV1,
            virtual_base: VirtualBaseProfile::RequireSingle,
        }
    }
}

/// Conflict-marker rendering is observable proposal data, never authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictStyle {
    /// Fixed ASCII labels and newline delimiters: `ours`, `base`, `theirs`.
    MarkerV1,
}

/// Multiple-base behavior. Inputs to `merge_content_many` must be in the
/// canonical ancestor order returned by `merge_bases_all`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBaseProfile {
    RequireSingle,
    /// Fold bases left-to-right using an empty common ancestor. Any divergence
    /// becomes an explicit marker in the virtual base, preserving rather than
    /// guessing at unresolved ancestry.
    RecursiveConflictPreservingV1,
}

/// Bounded resources for content and virtual-base construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentMergeLimits {
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_hunks: usize,
    pub max_conflicts: usize,
    pub max_work_steps: usize,
    pub max_depth: usize,
}

impl Default for ContentMergeLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 32 * 1024 * 1024,
            max_output_bytes: 32 * 1024 * 1024,
            max_hunks: 1_000_000,
            max_conflicts: 100_000,
            max_work_steps: 100_000_000,
            max_depth: 128,
        }
    }
}

/// All content-merge inputs except the byte slices themselves.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ContentMergeOptions {
    pub profile: MergeProfile,
    pub limits: ContentMergeLimits,
}

/// Cooperative cancellation boundary for the synchronous pure merge core.
pub trait MergeCancellation {
    fn is_cancelled(&self) -> bool;
}

/// A cancellation probe for callers that have no cancellation scope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NeverCancelled;

impl MergeCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Exact byte range in one input version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

/// Lossless one-side conflict evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictSideEvidence {
    pub byte_range: ByteRange,
    pub source_span: Option<Span>,
    pub bytes: Vec<u8>,
    pub edits: Vec<Edit>,
}

/// Explicit conflict data retained for review and `TreeFS` intent construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentConflict {
    pub base: ConflictSideEvidence,
    pub ours: ConflictSideEvidence,
    pub theirs: ConflictSideEvidence,
}

/// A content merge result is a proposal, whether clean or conflicted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentMergeOutcome {
    Clean {
        bytes: Vec<u8>,
    },
    Conflicted {
        /// Deterministic marker bytes for human review only.
        marker_bytes: Vec<u8>,
        conflicts: Vec<ContentConflict>,
    },
}

impl ContentMergeOutcome {
    #[must_use]
    pub fn proposed_bytes(&self) -> &[u8] {
        match self {
            Self::Clean { bytes } => bytes,
            Self::Conflicted { marker_bytes, .. } => marker_bytes,
        }
    }

    #[must_use]
    pub const fn is_clean(&self) -> bool {
        matches!(self, Self::Clean { .. })
    }
}

/// A deterministic receipt, carried with a proposal rather than publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentMergeReceipt {
    pub profile_version: u16,
    pub diff_profile: DiffProfile,
    pub conflict_style: ConflictStyle,
    pub virtual_base: VirtualBaseProfile,
    pub base_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentMergeResult {
    pub outcome: ContentMergeOutcome,
    pub receipt: ContentMergeReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentMergeError {
    Diff(DiffError),
    InputBytesExceeded { limit: usize, actual: usize },
    OutputBytesExceeded { limit: usize },
    HunkLimitExceeded { limit: usize },
    ConflictLimitExceeded { limit: usize },
    WorkLimitExceeded { limit: usize },
    DepthLimitExceeded { limit: usize },
    NoMergeBase,
    MultipleBasesRequireVirtualBase,
    Cancelled,
    ArithmeticOverflow,
    MalformedDiffHunk,
}

impl From<DiffError> for ContentMergeError {
    fn from(error: DiffError) -> Self {
        Self::Diff(error)
    }
}

/// Typed bridge from FG-044a's graph result into a merge proposal. A caller
/// supplies content/tree bases only after this selection succeeds.
#[derive(Debug, Eq, PartialEq)]
pub enum MergeBaseSelectionError<CommitId, SourceError> {
    MergeBase(MergeBaseError<CommitId, SourceError>),
    NoCommonAncestor,
}

/// Result type for the merge-base-to-proposal bridge.
pub type MergeBaseSelectionResult<CommitId, SourceError> =
    Result<Vec<CommitId>, MergeBaseSelectionError<CommitId, SourceError>>;

/// Select every best common ancestor in the canonical `CommitId` order used by
/// `merge_content_many`; shallow or malformed ancestry remains a typed error.
pub fn select_merge_bases<Graph>(
    graph: &Graph,
    ours: Graph::CommitId,
    theirs: Graph::CommitId,
    limits: MergeBaseLimits,
) -> MergeBaseSelectionResult<Graph::CommitId, Graph::Error>
where
    Graph: CommitGraph,
{
    match merge_bases_all(graph, ours, theirs, limits)
        .map_err(MergeBaseSelectionError::MergeBase)?
    {
        MergeBaseResult::Bases(bases) => Ok(bases),
        MergeBaseResult::NoCommonAncestor => Err(MergeBaseSelectionError::NoCommonAncestor),
    }
}

/// Merge one known base. This never publishes a ref, tree, or authority event.
pub fn merge_content(
    base: &[u8],
    ours: &[u8],
    theirs: &[u8],
    options: ContentMergeOptions,
) -> Result<ContentMergeResult, ContentMergeError> {
    merge_content_with_cancellation(base, ours, theirs, options, &NeverCancelled)
}

/// Cancellation-aware content merge; cancelling drops all local scratch before
/// returning `Cancelled` and never emits a partial proposal.
pub fn merge_content_with_cancellation<Cancellation>(
    base: &[u8],
    ours: &[u8],
    theirs: &[u8],
    options: ContentMergeOptions,
    cancellation: &Cancellation,
) -> Result<ContentMergeResult, ContentMergeError>
where
    Cancellation: MergeCancellation,
{
    merge_content_with_base_count(base, ours, theirs, options, cancellation, 1)
}

/// Merge a canonically ordered set of best common ancestors. The recursive
/// profile is conflict-preserving: it never silently chooses one divergent
/// ancestor as the virtual base.
pub fn merge_content_many(
    bases: &[&[u8]],
    ours: &[u8],
    theirs: &[u8],
    options: ContentMergeOptions,
) -> Result<ContentMergeResult, ContentMergeError> {
    merge_content_many_with_cancellation(bases, ours, theirs, options, &NeverCancelled)
}

/// Cancellation-aware multiple-base merge.
pub fn merge_content_many_with_cancellation<Cancellation>(
    bases: &[&[u8]],
    ours: &[u8],
    theirs: &[u8],
    options: ContentMergeOptions,
    cancellation: &Cancellation,
) -> Result<ContentMergeResult, ContentMergeError>
where
    Cancellation: MergeCancellation,
{
    if bases.is_empty() {
        return Err(ContentMergeError::NoMergeBase);
    }
    if bases.len() == 1 {
        return merge_content_with_base_count(bases[0], ours, theirs, options, cancellation, 1);
    }
    if options.profile.virtual_base == VirtualBaseProfile::RequireSingle {
        return Err(ContentMergeError::MultipleBasesRequireVirtualBase);
    }
    if bases.len() > options.limits.max_depth {
        return Err(ContentMergeError::DepthLimitExceeded {
            limit: options.limits.max_depth,
        });
    }

    check_cancelled(cancellation)?;
    let mut virtual_base = Vec::new();
    append_bytes(&mut virtual_base, bases[0], options.limits.max_output_bytes)?;
    for base in &bases[1..] {
        check_cancelled(cancellation)?;
        let folded =
            merge_content_with_base_count(b"", &virtual_base, base, options, cancellation, 2)?;
        virtual_base = folded.outcome.proposed_bytes().to_vec();
        if virtual_base.len() > options.limits.max_output_bytes {
            return Err(ContentMergeError::OutputBytesExceeded {
                limit: options.limits.max_output_bytes,
            });
        }
    }
    merge_content_with_base_count(
        &virtual_base,
        ours,
        theirs,
        options,
        cancellation,
        bases.len(),
    )
}

#[derive(Clone, Debug)]
struct Change {
    old: Span,
    new: Span,
    replacement: Vec<u8>,
    edits: Vec<Edit>,
}

struct WorkBudget {
    remaining: usize,
    limit: usize,
}

impl WorkBudget {
    const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            limit,
        }
    }

    fn consume(&mut self, amount: usize) -> Result<(), ContentMergeError> {
        self.remaining = self
            .remaining
            .checked_sub(amount)
            .ok_or(ContentMergeError::WorkLimitExceeded { limit: self.limit })?;
        Ok(())
    }
}

fn merge_content_with_base_count<Cancellation>(
    base: &[u8],
    ours: &[u8],
    theirs: &[u8],
    options: ContentMergeOptions,
    cancellation: &Cancellation,
    base_count: usize,
) -> Result<ContentMergeResult, ContentMergeError>
where
    Cancellation: MergeCancellation,
{
    check_input_bytes(base, ours, theirs, options.limits.max_input_bytes)?;
    check_cancelled(cancellation)?;
    let receipt = ContentMergeReceipt {
        profile_version: options.profile.version,
        diff_profile: options.profile.diff_options.profile,
        conflict_style: options.profile.conflict_style,
        virtual_base: options.profile.virtual_base,
        base_count,
    };
    if ours == theirs {
        return clean_result(ours, options.limits.max_output_bytes, receipt);
    }
    if base == ours {
        return clean_result(theirs, options.limits.max_output_bytes, receipt);
    }
    if base == theirs {
        return clean_result(ours, options.limits.max_output_bytes, receipt);
    }
    if is_binary(base) || is_binary(ours) || is_binary(theirs) {
        return binary_conflict(base, ours, theirs, options, receipt);
    }

    let ours_diff = diff(base, ours, options.profile.diff_options)?;
    check_cancelled(cancellation)?;
    let theirs_diff = diff(base, theirs, options.profile.diff_options)?;
    let ours_changes = changes_from_hunks(ours_diff.hunks(), options.limits.max_hunks)?;
    let theirs_changes = changes_from_hunks(theirs_diff.hunks(), options.limits.max_hunks)?;
    merge_change_lists(
        base,
        &ours_changes,
        &theirs_changes,
        options,
        cancellation,
        receipt,
    )
}

fn clean_result(
    bytes: &[u8],
    max_output_bytes: usize,
    receipt: ContentMergeReceipt,
) -> Result<ContentMergeResult, ContentMergeError> {
    if bytes.len() > max_output_bytes {
        return Err(ContentMergeError::OutputBytesExceeded {
            limit: max_output_bytes,
        });
    }
    Ok(ContentMergeResult {
        outcome: ContentMergeOutcome::Clean {
            bytes: bytes.to_vec(),
        },
        receipt,
    })
}

fn binary_conflict(
    base: &[u8],
    ours: &[u8],
    theirs: &[u8],
    options: ContentMergeOptions,
    receipt: ContentMergeReceipt,
) -> Result<ContentMergeResult, ContentMergeError> {
    if options.limits.max_conflicts == 0 {
        return Err(ContentMergeError::ConflictLimitExceeded {
            limit: options.limits.max_conflicts,
        });
    }
    let conflict = ContentConflict {
        base: whole_evidence(base),
        ours: whole_evidence(ours),
        theirs: whole_evidence(theirs),
    };
    let marker_bytes = render_marker(
        &conflict,
        options.profile.conflict_style,
        options.limits.max_output_bytes,
    )?;
    Ok(ContentMergeResult {
        outcome: ContentMergeOutcome::Conflicted {
            marker_bytes,
            conflicts: vec![conflict],
        },
        receipt,
    })
}

fn merge_change_lists<Cancellation>(
    base: &[u8],
    ours: &[Change],
    theirs: &[Change],
    options: ContentMergeOptions,
    cancellation: &Cancellation,
    receipt: ContentMergeReceipt,
) -> Result<ContentMergeResult, ContentMergeError>
where
    Cancellation: MergeCancellation,
{
    let mut work = WorkBudget::new(options.limits.max_work_steps);
    let mut ours_index = 0;
    let mut theirs_index = 0;
    let mut cursor = 0;
    let mut output = Vec::new();
    let mut conflicts = Vec::new();
    while ours_index < ours.len() || theirs_index < theirs.len() {
        check_cancelled(cancellation)?;
        work.consume(1)?;
        match (ours.get(ours_index), theirs.get(theirs_index)) {
            (Some(ours_change), Some(theirs_change))
                if changes_overlap(ours_change, theirs_change) =>
            {
                let cluster = collect_cluster(ours, theirs, &mut ours_index, &mut theirs_index)?;
                append_base(
                    &mut output,
                    base,
                    cursor,
                    cluster.start,
                    options.limits.max_output_bytes,
                )?;
                let ours_evidence = render_side(base, cluster.start, cluster.end, &cluster.ours)?;
                let theirs_evidence =
                    render_side(base, cluster.start, cluster.end, &cluster.theirs)?;
                if ours_evidence.bytes == theirs_evidence.bytes {
                    append_bytes(
                        &mut output,
                        &ours_evidence.bytes,
                        options.limits.max_output_bytes,
                    )?;
                } else {
                    if conflicts.len() == options.limits.max_conflicts {
                        return Err(ContentMergeError::ConflictLimitExceeded {
                            limit: options.limits.max_conflicts,
                        });
                    }
                    let conflict = ContentConflict {
                        base: ConflictSideEvidence {
                            byte_range: ByteRange {
                                start: cluster.start,
                                end: cluster.end,
                            },
                            source_span: cluster.base_span,
                            bytes: base[cluster.start..cluster.end].to_vec(),
                            edits: Vec::new(),
                        },
                        ours: ours_evidence,
                        theirs: theirs_evidence,
                    };
                    append_bytes(
                        &mut output,
                        &render_marker(
                            &conflict,
                            options.profile.conflict_style,
                            options.limits.max_output_bytes,
                        )?,
                        options.limits.max_output_bytes,
                    )?;
                    conflicts.push(conflict);
                }
                cursor = cluster.end;
            }
            (Some(ours_change), Some(theirs_change)) => {
                let choose_ours = compare_change_position(ours_change, theirs_change).is_lt();
                let selected = if choose_ours {
                    ours_index += 1;
                    ours_change
                } else {
                    theirs_index += 1;
                    theirs_change
                };
                append_base(
                    &mut output,
                    base,
                    cursor,
                    selected.old.byte_start,
                    options.limits.max_output_bytes,
                )?;
                append_bytes(
                    &mut output,
                    &selected.replacement,
                    options.limits.max_output_bytes,
                )?;
                cursor = selected.old.byte_end;
            }
            (Some(change), None) => {
                ours_index += 1;
                append_base(
                    &mut output,
                    base,
                    cursor,
                    change.old.byte_start,
                    options.limits.max_output_bytes,
                )?;
                append_bytes(
                    &mut output,
                    &change.replacement,
                    options.limits.max_output_bytes,
                )?;
                cursor = change.old.byte_end;
            }
            (None, Some(change)) => {
                theirs_index += 1;
                append_base(
                    &mut output,
                    base,
                    cursor,
                    change.old.byte_start,
                    options.limits.max_output_bytes,
                )?;
                append_bytes(
                    &mut output,
                    &change.replacement,
                    options.limits.max_output_bytes,
                )?;
                cursor = change.old.byte_end;
            }
            (None, None) => break,
        }
    }
    append_base(
        &mut output,
        base,
        cursor,
        base.len(),
        options.limits.max_output_bytes,
    )?;
    let outcome = if conflicts.is_empty() {
        ContentMergeOutcome::Clean { bytes: output }
    } else {
        ContentMergeOutcome::Conflicted {
            marker_bytes: output,
            conflicts,
        }
    };
    Ok(ContentMergeResult { outcome, receipt })
}

struct Cluster<'a> {
    start: usize,
    end: usize,
    base_span: Option<Span>,
    ours: Vec<&'a Change>,
    theirs: Vec<&'a Change>,
}

fn collect_cluster<'a>(
    ours: &'a [Change],
    theirs: &'a [Change],
    ours_index: &mut usize,
    theirs_index: &mut usize,
) -> Result<Cluster<'a>, ContentMergeError> {
    let ours_first = ours
        .get(*ours_index)
        .ok_or(ContentMergeError::MalformedDiffHunk)?;
    let theirs_first = theirs
        .get(*theirs_index)
        .ok_or(ContentMergeError::MalformedDiffHunk)?;
    let mut start = ours_first.old.byte_start.min(theirs_first.old.byte_start);
    let mut end = ours_first.old.byte_end.max(theirs_first.old.byte_end);
    let mut ours_cluster = Vec::new();
    let mut theirs_cluster = Vec::new();
    let mut consumed = true;
    while consumed {
        consumed = false;
        while let Some(change) = ours.get(*ours_index) {
            if !change_touches_range(change, start, end) {
                break;
            }
            start = start.min(change.old.byte_start);
            end = end.max(change.old.byte_end);
            ours_cluster.push(change);
            *ours_index += 1;
            consumed = true;
        }
        while let Some(change) = theirs.get(*theirs_index) {
            if !change_touches_range(change, start, end) {
                break;
            }
            start = start.min(change.old.byte_start);
            end = end.max(change.old.byte_end);
            theirs_cluster.push(change);
            *theirs_index += 1;
            consumed = true;
        }
    }
    let base_span = merge_spans(
        ours_cluster
            .iter()
            .chain(&theirs_cluster)
            .map(|change| change.old),
    );
    Ok(Cluster {
        start,
        end,
        base_span,
        ours: ours_cluster,
        theirs: theirs_cluster,
    })
}

fn render_side(
    base: &[u8],
    start: usize,
    end: usize,
    changes: &[&Change],
) -> Result<ConflictSideEvidence, ContentMergeError> {
    let mut cursor = start;
    let mut bytes = Vec::new();
    let mut edits = Vec::new();
    for change in changes {
        if change.old.byte_start < cursor || change.old.byte_end > end {
            return Err(ContentMergeError::MalformedDiffHunk);
        }
        bytes.extend_from_slice(&base[cursor..change.old.byte_start]);
        bytes.extend_from_slice(&change.replacement);
        cursor = change.old.byte_end;
        edits.extend(change.edits.iter().cloned());
    }
    bytes.extend_from_slice(&base[cursor..end]);
    Ok(ConflictSideEvidence {
        byte_range: ByteRange { start, end },
        source_span: merge_spans(changes.iter().map(|change| change.new)),
        bytes,
        edits,
    })
}

fn changes_from_hunks(
    hunks: Vec<DiffHunk>,
    limit: usize,
) -> Result<Vec<Change>, ContentMergeError> {
    if hunks.len() > limit {
        return Err(ContentMergeError::HunkLimitExceeded { limit });
    }
    let mut previous_end = 0;
    let mut changes = Vec::with_capacity(hunks.len());
    for hunk in hunks {
        if hunk.old.byte_start < previous_end || hunk.old.byte_start > hunk.old.byte_end {
            return Err(ContentMergeError::MalformedDiffHunk);
        }
        previous_end = hunk.old.byte_end;
        let mut replacement = Vec::new();
        for edit in &hunk.edits {
            if let Edit::Insert { bytes, .. } = edit {
                replacement.extend_from_slice(bytes);
            }
        }
        changes.push(Change {
            old: hunk.old,
            new: hunk.new,
            replacement,
            edits: hunk.edits,
        });
    }
    Ok(changes)
}

const fn changes_overlap(left: &Change, right: &Change) -> bool {
    change_touches_range(left, right.old.byte_start, right.old.byte_end)
}

const fn change_touches_range(change: &Change, start: usize, end: usize) -> bool {
    if change.old.byte_start == change.old.byte_end {
        start <= change.old.byte_start && change.old.byte_start <= end
    } else {
        change.old.byte_start <= end && start <= change.old.byte_end
    }
}

fn compare_change_position(left: &Change, right: &Change) -> Ordering {
    (left.old.byte_start, left.old.byte_end).cmp(&(right.old.byte_start, right.old.byte_end))
}

fn merge_spans<I>(spans: I) -> Option<Span>
where
    I: IntoIterator<Item = Span>,
{
    let mut spans = spans.into_iter();
    let first = spans.next()?;
    Some(spans.fold(first, |merged, span| Span {
        byte_start: merged.byte_start.min(span.byte_start),
        byte_end: merged.byte_end.max(span.byte_end),
        unit_start: merged.unit_start.min(span.unit_start),
        unit_end: merged.unit_end.max(span.unit_end),
    }))
}

fn append_base(
    output: &mut Vec<u8>,
    base: &[u8],
    start: usize,
    end: usize,
    limit: usize,
) -> Result<(), ContentMergeError> {
    if start > end || end > base.len() {
        return Err(ContentMergeError::MalformedDiffHunk);
    }
    append_bytes(output, &base[start..end], limit)
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), ContentMergeError> {
    let next_len = output
        .len()
        .checked_add(bytes.len())
        .ok_or(ContentMergeError::ArithmeticOverflow)?;
    if next_len > limit {
        return Err(ContentMergeError::OutputBytesExceeded { limit });
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn whole_evidence(bytes: &[u8]) -> ConflictSideEvidence {
    ConflictSideEvidence {
        byte_range: ByteRange {
            start: 0,
            end: bytes.len(),
        },
        source_span: None,
        bytes: bytes.to_vec(),
        edits: Vec::new(),
    }
}

fn render_marker(
    conflict: &ContentConflict,
    style: ConflictStyle,
    max_output_bytes: usize,
) -> Result<Vec<u8>, ContentMergeError> {
    let mut marker = Vec::new();
    match style {
        ConflictStyle::MarkerV1 => {
            for bytes in [
                b"<<<<<<< ours\n".as_slice(),
                conflict.ours.bytes.as_slice(),
                b"||||||| base\n".as_slice(),
                conflict.base.bytes.as_slice(),
                b"=======\n".as_slice(),
                conflict.theirs.bytes.as_slice(),
                b">>>>>>> theirs\n".as_slice(),
            ] {
                append_bytes(&mut marker, bytes, max_output_bytes)?;
            }
        }
    }
    Ok(marker)
}

fn check_input_bytes(
    base: &[u8],
    ours: &[u8],
    theirs: &[u8],
    limit: usize,
) -> Result<(), ContentMergeError> {
    let actual = base
        .len()
        .checked_add(ours.len())
        .and_then(|sum| sum.checked_add(theirs.len()))
        .ok_or(ContentMergeError::ArithmeticOverflow)?;
    if actual > limit {
        return Err(ContentMergeError::InputBytesExceeded { limit, actual });
    }
    Ok(())
}

fn check_cancelled<Cancellation>(cancellation: &Cancellation) -> Result<(), ContentMergeError>
where
    Cancellation: MergeCancellation,
{
    if cancellation.is_cancelled() {
        Err(ContentMergeError::Cancelled)
    } else {
        Ok(())
    }
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

/// Lossless conflict evidence carried into one `TreeFS` marker intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictMarkerInputs {
    pub conflicts: Vec<ContentConflict>,
}

/// A `TreeFS`-facing intent proposal. It is typed merge output only: an authority
/// transaction must separately validate and publish any later tree/ref change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposedTreeIntent<ObjectId> {
    RecordConflictMarkers {
        path: Vec<u8>,
        merge_inputs: ConflictMarkerInputs,
        marker_object: Vec<u8>,
    },
    RecordTreeConflict {
        path: Vec<u8>,
        kind: TreeConflictKind,
        base: Option<TreeEntry<ObjectId>>,
        ours: Option<TreeEntry<ObjectId>>,
        theirs: Option<TreeEntry<ObjectId>>,
    },
}

/// Turn every content conflict into a lossless, non-authoritative `TreeFS`
/// conflict-marker proposal.
#[must_use]
pub fn content_conflict_intents<ObjectId>(
    path: &[u8],
    outcome: &ContentMergeOutcome,
) -> Vec<ProposedTreeIntent<ObjectId>> {
    let ContentMergeOutcome::Conflicted {
        marker_bytes,
        conflicts,
    } = outcome
    else {
        return Vec::new();
    };
    if conflicts.is_empty() {
        Vec::new()
    } else {
        vec![ProposedTreeIntent::RecordConflictMarkers {
            path: path.to_vec(),
            merge_inputs: ConflictMarkerInputs {
                conflicts: conflicts.clone(),
            },
            marker_object: marker_bytes.clone(),
        }]
    }
}

/// Exact tree conflict categories; no variant silently chooses one side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeConflictKind {
    AddAdd,
    ModifyDelete,
    RenameInteraction,
    ModeChange,
    TypeChange,
    Symlink,
    SubmodulePointer,
    Content,
}

/// A conflicted tree path retains all three exact entries for later review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeConflict<ObjectId> {
    pub path: Vec<u8>,
    pub kind: TreeConflictKind,
    pub base: Option<TreeEntry<ObjectId>>,
    pub ours: Option<TreeEntry<ObjectId>>,
    pub theirs: Option<TreeEntry<ObjectId>>,
}

/// One path in an uncommitted tree merge proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeMergeEntry<ObjectId> {
    Clean(TreeEntry<ObjectId>),
    Conflict(TreeConflict<ObjectId>),
}

/// Hard tree-merge bounds, including path-byte allocation and candidate work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeMergeLimits {
    pub max_entries_per_tree: usize,
    pub max_paths: usize,
    pub max_path_bytes: usize,
    pub max_conflicts: usize,
    pub max_work_steps: usize,
}

impl Default for TreeMergeLimits {
    fn default() -> Self {
        Self {
            max_entries_per_tree: 1_000_000,
            max_paths: 2_000_000,
            max_path_bytes: 4 * 1024,
            max_conflicts: 100_000,
            max_work_steps: 20_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TreeMergeOptions {
    pub limits: TreeMergeLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeMergeResult<ObjectId> {
    pub entries: Vec<TreeMergeEntry<ObjectId>>,
    pub proposed_intents: Vec<ProposedTreeIntent<ObjectId>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeMergeError {
    UnsortedOrDuplicatePath,
    EntryLimitExceeded { limit: usize },
    PathLimitExceeded { limit: usize },
    PathBytesExceeded { limit: usize, actual: usize },
    ConflictLimitExceeded { limit: usize },
    WorkLimitExceeded { limit: usize },
    Cancelled,
}

/// Merge three validated, Git-order tree-entry streams. Clean entries and
/// conflicts are both proposals; this function has no authority side effect.
pub fn merge_trees<ObjectId, BaseEntries, OursEntries, TheirsEntries>(
    base_entries: BaseEntries,
    ours_entries: OursEntries,
    theirs_entries: TheirsEntries,
    options: TreeMergeOptions,
) -> Result<TreeMergeResult<ObjectId>, TreeMergeError>
where
    ObjectId: Clone + Eq,
    BaseEntries: IntoIterator<Item = TreeEntry<ObjectId>>,
    OursEntries: IntoIterator<Item = TreeEntry<ObjectId>>,
    TheirsEntries: IntoIterator<Item = TreeEntry<ObjectId>>,
{
    merge_trees_with_cancellation(
        base_entries,
        ours_entries,
        theirs_entries,
        options,
        &NeverCancelled,
    )
}

/// Cancellation-aware tree merge.
pub fn merge_trees_with_cancellation<
    ObjectId,
    BaseEntries,
    OursEntries,
    TheirsEntries,
    Cancellation,
>(
    base_entries: BaseEntries,
    ours_entries: OursEntries,
    theirs_entries: TheirsEntries,
    options: TreeMergeOptions,
    cancellation: &Cancellation,
) -> Result<TreeMergeResult<ObjectId>, TreeMergeError>
where
    ObjectId: Clone + Eq,
    BaseEntries: IntoIterator<Item = TreeEntry<ObjectId>>,
    OursEntries: IntoIterator<Item = TreeEntry<ObjectId>>,
    TheirsEntries: IntoIterator<Item = TreeEntry<ObjectId>>,
    Cancellation: MergeCancellation,
{
    let base = collect_tree(
        base_entries,
        options.limits.max_entries_per_tree,
        options.limits.max_path_bytes,
        cancellation,
    )?;
    let ours = collect_tree(
        ours_entries,
        options.limits.max_entries_per_tree,
        options.limits.max_path_bytes,
        cancellation,
    )?;
    let theirs = collect_tree(
        theirs_entries,
        options.limits.max_entries_per_tree,
        options.limits.max_path_bytes,
        cancellation,
    )?;
    let mut base_index = 0;
    let mut ours_index = 0;
    let mut theirs_index = 0;
    let mut work_remaining = options.limits.max_work_steps;
    let ours_renames = exact_object_renames(
        &base,
        &ours,
        &mut work_remaining,
        options.limits,
        cancellation,
    )?;
    let theirs_renames = exact_object_renames(
        &base,
        &theirs,
        &mut work_remaining,
        options.limits,
        cancellation,
    )?;
    let mut entries = Vec::new();
    let mut proposed_intents = Vec::new();
    while base_index < base.len() || ours_index < ours.len() || theirs_index < theirs.len() {
        if cancellation.is_cancelled() {
            return Err(TreeMergeError::Cancelled);
        }
        work_remaining =
            work_remaining
                .checked_sub(1)
                .ok_or(TreeMergeError::WorkLimitExceeded {
                    limit: options.limits.max_work_steps,
                })?;
        if entries.len() == options.limits.max_paths {
            return Err(TreeMergeError::PathLimitExceeded {
                limit: options.limits.max_paths,
            });
        }
        let path = next_path(
            base.get(base_index),
            ours.get(ours_index),
            theirs.get(theirs_index),
        )
        .ok_or(TreeMergeError::UnsortedOrDuplicatePath)?;
        if path.len() > options.limits.max_path_bytes {
            return Err(TreeMergeError::PathBytesExceeded {
                limit: options.limits.max_path_bytes,
                actual: path.len(),
            });
        }
        let base_entry = take_matching(base.as_slice(), &mut base_index, path);
        let ours_entry = take_matching(ours.as_slice(), &mut ours_index, path);
        let theirs_entry = take_matching(theirs.as_slice(), &mut theirs_index, path);
        let rename_interaction =
            renamed_path(&ours_renames, path) || renamed_path(&theirs_renames, path);
        let force_rename_conflict = conflicting_rename_source(
            &ours_renames,
            &theirs_renames,
            path,
            ours_entry.as_ref(),
            theirs_entry.as_ref(),
        );
        match merge_tree_entry(
            path.to_vec(),
            base_entry,
            ours_entry,
            theirs_entry,
            rename_interaction,
            force_rename_conflict,
        ) {
            Ok(Some(clean)) => entries.push(TreeMergeEntry::Clean(clean)),
            Ok(None) => {}
            Err(conflict) => {
                if proposed_intents.len() == options.limits.max_conflicts {
                    return Err(TreeMergeError::ConflictLimitExceeded {
                        limit: options.limits.max_conflicts,
                    });
                }
                proposed_intents.push(ProposedTreeIntent::RecordTreeConflict {
                    path: conflict.path.clone(),
                    kind: conflict.kind,
                    base: conflict.base.clone(),
                    ours: conflict.ours.clone(),
                    theirs: conflict.theirs.clone(),
                });
                entries.push(TreeMergeEntry::Conflict(conflict));
            }
        }
    }
    Ok(TreeMergeResult {
        entries,
        proposed_intents,
    })
}

fn collect_tree<ObjectId, Entries>(
    entries: Entries,
    limit: usize,
    max_path_bytes: usize,
    cancellation: &impl MergeCancellation,
) -> Result<Vec<TreeEntry<ObjectId>>, TreeMergeError>
where
    Entries: IntoIterator<Item = TreeEntry<ObjectId>>,
{
    let mut collected = Vec::new();
    for entry in entries {
        if cancellation.is_cancelled() {
            return Err(TreeMergeError::Cancelled);
        }
        if collected.len() == limit {
            return Err(TreeMergeError::EntryLimitExceeded { limit });
        }
        if entry.path.len() > max_path_bytes {
            return Err(TreeMergeError::PathBytesExceeded {
                limit: max_path_bytes,
                actual: entry.path.len(),
            });
        }
        if collected
            .last()
            .is_some_and(|previous| !compare_tree_entries(previous, &entry).is_lt())
        {
            return Err(TreeMergeError::UnsortedOrDuplicatePath);
        }
        collected.push(entry);
    }
    Ok(collected)
}

fn next_path<'a, ObjectId>(
    base: Option<&'a TreeEntry<ObjectId>>,
    ours: Option<&'a TreeEntry<ObjectId>>,
    theirs: Option<&'a TreeEntry<ObjectId>>,
) -> Option<&'a [u8]> {
    [base, ours, theirs]
        .into_iter()
        .flatten()
        .min_by(|left, right| compare_tree_entries(left, right))
        .map(|entry| entry.path.as_slice())
}

fn take_matching<ObjectId>(
    entries: &[TreeEntry<ObjectId>],
    index: &mut usize,
    path: &[u8],
) -> Option<TreeEntry<ObjectId>>
where
    ObjectId: Clone,
{
    let entry = entries.get(*index)?;
    if entry.path == path {
        *index += 1;
        Some(entry.clone())
    } else {
        None
    }
}

fn merge_tree_entry<ObjectId>(
    path: Vec<u8>,
    base: Option<TreeEntry<ObjectId>>,
    ours: Option<TreeEntry<ObjectId>>,
    theirs: Option<TreeEntry<ObjectId>>,
    rename_interaction: bool,
    force_rename_conflict: bool,
) -> Result<Option<TreeEntry<ObjectId>>, TreeConflict<ObjectId>>
where
    ObjectId: Clone + Eq,
{
    if force_rename_conflict {
        return Err(TreeConflict {
            path,
            kind: TreeConflictKind::RenameInteraction,
            base,
            ours,
            theirs,
        });
    }
    if ours == theirs {
        return Ok(ours);
    }
    if base == ours {
        return Ok(theirs);
    }
    if base == theirs {
        return Ok(ours);
    }
    let kind = if rename_interaction {
        TreeConflictKind::RenameInteraction
    } else {
        classify_tree_conflict(base.as_ref(), ours.as_ref(), theirs.as_ref())
    };
    Err(TreeConflict {
        path,
        kind,
        base,
        ours,
        theirs,
    })
}

#[derive(Default)]
struct RenamePairs {
    sources: BTreeMap<Vec<u8>, Vec<u8>>,
    destinations: BTreeSet<Vec<u8>>,
}

fn exact_object_renames<ObjectId, Cancellation>(
    base: &[TreeEntry<ObjectId>],
    side: &[TreeEntry<ObjectId>],
    work_remaining: &mut usize,
    limits: TreeMergeLimits,
    cancellation: &Cancellation,
) -> Result<RenamePairs, TreeMergeError>
where
    ObjectId: Eq,
    Cancellation: MergeCancellation,
{
    let mut renames = RenamePairs::default();
    let mut used_additions = BTreeSet::new();
    for before in base {
        if cancellation.is_cancelled() {
            return Err(TreeMergeError::Cancelled);
        }
        let mut exists_in_side = false;
        for entry in side {
            consume_tree_work(work_remaining, limits.max_work_steps)?;
            if entry.path == before.path {
                exists_in_side = true;
                break;
            }
        }
        if exists_in_side {
            continue;
        }
        for (addition_index, after) in side.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Err(TreeMergeError::Cancelled);
            }
            let mut existed_in_base = false;
            for entry in base {
                consume_tree_work(work_remaining, limits.max_work_steps)?;
                if entry.path == after.path {
                    existed_in_base = true;
                    break;
                }
            }
            if existed_in_base || used_additions.contains(&addition_index) {
                continue;
            }
            consume_tree_work(work_remaining, limits.max_work_steps)?;
            if before.object == after.object {
                used_additions.insert(addition_index);
                renames.destinations.insert(after.path.clone());
                renames
                    .sources
                    .insert(before.path.clone(), after.path.clone());
                break;
            }
        }
    }
    Ok(renames)
}

fn renamed_path(renames: &RenamePairs, path: &[u8]) -> bool {
    renames.sources.contains_key(path) || renames.destinations.contains(path)
}

fn conflicting_rename_source<ObjectId>(
    ours_renames: &RenamePairs,
    theirs_renames: &RenamePairs,
    path: &[u8],
    ours: Option<&TreeEntry<ObjectId>>,
    theirs: Option<&TreeEntry<ObjectId>>,
) -> bool {
    let ours_destination = rename_destination(ours_renames, path);
    let theirs_destination = rename_destination(theirs_renames, path);
    match (ours_destination, theirs_destination) {
        (Some(ours), Some(theirs)) => ours != theirs,
        (Some(_), None) => theirs.is_none(),
        (None, Some(_)) => ours.is_none(),
        (None, None) => false,
    }
}

fn rename_destination<'a>(renames: &'a RenamePairs, path: &[u8]) -> Option<&'a [u8]> {
    renames.sources.get(path).map(Vec::as_slice)
}

fn consume_tree_work(work_remaining: &mut usize, limit: usize) -> Result<(), TreeMergeError> {
    *work_remaining = work_remaining
        .checked_sub(1)
        .ok_or(TreeMergeError::WorkLimitExceeded { limit })?;
    Ok(())
}

fn classify_tree_conflict<ObjectId>(
    base: Option<&TreeEntry<ObjectId>>,
    ours: Option<&TreeEntry<ObjectId>>,
    theirs: Option<&TreeEntry<ObjectId>>,
) -> TreeConflictKind {
    match (base, ours, theirs) {
        (None, Some(_), Some(_)) => TreeConflictKind::AddAdd,
        (Some(_), None, Some(_)) | (Some(_), Some(_), None) => TreeConflictKind::ModifyDelete,
        (Some(base), Some(ours), Some(theirs)) => {
            let kinds = [
                entry_kind(base.mode),
                entry_kind(ours.mode),
                entry_kind(theirs.mode),
            ];
            if kinds.contains(&EntryKind::Submodule) {
                TreeConflictKind::SubmodulePointer
            } else if kinds.contains(&EntryKind::Symlink) {
                TreeConflictKind::Symlink
            } else if kinds[1] != kinds[2] || kinds[0] != kinds[1] || kinds[0] != kinds[2] {
                TreeConflictKind::TypeChange
            } else if ours.mode != theirs.mode {
                TreeConflictKind::ModeChange
            } else {
                TreeConflictKind::Content
            }
        }
        _ => TreeConflictKind::Content,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    Tree,
    Regular,
    Symlink,
    Submodule,
    Other,
}

const fn entry_kind(mode: TreeMode) -> EntryKind {
    match mode.0 & 0o170_000 {
        0o040_000 => EntryKind::Tree,
        0o100_000 => EntryKind::Regular,
        0o120_000 => EntryKind::Symlink,
        0o160_000 => EntryKind::Submodule,
        _ => EntryKind::Other,
    }
}

fn compare_tree_entries<ObjectId>(
    left: &TreeEntry<ObjectId>,
    right: &TreeEntry<ObjectId>,
) -> Ordering {
    let shared = left
        .path
        .iter()
        .zip(&right.path)
        .take_while(|(left, right)| left == right)
        .count();
    match (left.path.get(shared), right.path.get(shared)) {
        (Some(left), Some(right)) => left.cmp(right),
        (None, None) => Ordering::Equal,
        (None, Some(right)) => tree_name_terminator(left.mode).cmp(right),
        (Some(left), None) => left.cmp(&tree_name_terminator(right.mode)),
    }
}

const fn tree_name_terminator(mode: TreeMode) -> u8 {
    if mode.0 & 0o170_000 == 0o040_000 {
        b'/'
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn content_options() -> ContentMergeOptions {
        ContentMergeOptions {
            profile: MergeProfile {
                diff_options: DiffOptions::myers_lines(crate::DiffLimits {
                    max_input_bytes: 4096,
                    max_units: 4096,
                    max_work: 100_000,
                    max_trace_cells: 100_000,
                }),
                ..MergeProfile::default()
            },
            limits: ContentMergeLimits {
                max_input_bytes: 4096,
                max_output_bytes: 4096,
                max_hunks: 128,
                max_conflicts: 16,
                max_work_steps: 10_000,
                max_depth: 8,
            },
        }
    }

    fn entry(path: &[u8], mode: u32, object: u8) -> TreeEntry<u8> {
        TreeEntry {
            path: path.to_vec(),
            mode: TreeMode(mode),
            object,
        }
    }

    #[derive(Default)]
    struct Graph {
        parents: BTreeMap<&'static str, crate::ParentSet<&'static str>>,
    }

    impl Graph {
        fn with_edges(edges: &[(&'static str, &[&'static str])]) -> Self {
            let mut graph = Self::default();
            for (commit, parents) in edges {
                graph
                    .parents
                    .insert(*commit, crate::ParentSet::Complete(parents.to_vec()));
            }
            graph
        }
    }

    impl CommitGraph for Graph {
        type CommitId = &'static str;
        type Error = ();

        fn parents_of(
            &self,
            commit: &&'static str,
        ) -> Result<crate::ParentSet<Self::CommitId>, Self::Error> {
            Ok(self
                .parents
                .get(commit)
                .cloned()
                .unwrap_or_else(|| crate::ParentSet::Complete(Vec::new())))
        }
    }

    #[test]
    fn merge_base_selection_preserves_no_base_and_shallow_refusals() {
        let graph = Graph::with_edges(&[("a", &[]), ("b", &["a"]), ("c", &["b"])]);
        assert_eq!(
            select_merge_bases(&graph, "c", "b", MergeBaseLimits::default()),
            Ok(vec!["b"])
        );
        assert_eq!(
            select_merge_bases(&graph, "c", "missing", MergeBaseLimits::default()),
            Err(MergeBaseSelectionError::NoCommonAncestor)
        );
        let mut shallow = Graph::with_edges(&[("a", &[]), ("b", &["a"])]);
        shallow
            .parents
            .insert("a", crate::ParentSet::ShallowBoundary);
        assert!(matches!(
            select_merge_bases(&shallow, "b", "a", MergeBaseLimits::default()),
            Err(MergeBaseSelectionError::MergeBase(
                MergeBaseError::ShallowBoundary { .. }
            ))
        ));
    }

    #[test]
    fn content_merge_cleanly_combines_disjoint_line_changes() {
        let result = merge_content(
            b"a\nb\nc\n",
            b"ours\nb\nc\n",
            b"a\nb\ntheirs\n",
            content_options(),
        )
        .expect("merge");
        assert_eq!(
            result.outcome,
            ContentMergeOutcome::Clean {
                bytes: b"ours\nb\ntheirs\n".to_vec(),
            }
        );
        assert_eq!(result.receipt.profile_version, 1);
        assert_eq!(result.receipt.diff_profile, DiffProfile::MyersMinimal);
    }

    #[test]
    fn content_merge_conflict_is_explicit_lossless_and_maps_to_treefs_intent() {
        let result =
            merge_content(b"base\n", b"ours\n", b"theirs\n", content_options()).expect("merge");
        let ContentMergeOutcome::Conflicted {
            marker_bytes,
            conflicts,
        } = &result.outcome
        else {
            panic!("expected explicit conflict");
        };
        assert_eq!(
            marker_bytes,
            b"<<<<<<< ours\nours\n||||||| base\nbase\n=======\ntheirs\n>>>>>>> theirs\n"
        );
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].base.bytes, b"base\n");
        assert_eq!(conflicts[0].ours.bytes, b"ours\n");
        assert_eq!(conflicts[0].theirs.bytes, b"theirs\n");
        assert_ne!(conflicts[0].ours.edits.len(), 0);
        let intents = content_conflict_intents::<u8>(b"src/lib.rs", &result.outcome);
        assert_eq!(intents.len(), 1);
        assert!(matches!(
            intents[0],
            ProposedTreeIntent::RecordConflictMarkers { .. }
        ));
    }

    #[test]
    fn content_merge_is_deterministic_for_every_diff_profile() {
        for profile in [
            DiffProfile::MyersMinimal,
            DiffProfile::Patience,
            DiffProfile::Histogram,
        ] {
            let options = ContentMergeOptions {
                profile: MergeProfile {
                    diff_options: DiffOptions {
                        profile,
                        ..content_options().profile.diff_options
                    },
                    ..content_options().profile
                },
                ..content_options()
            };
            let first = merge_content(
                b"one\ntwo\nthree\n",
                b"ours\ntwo\nthree\n",
                b"one\ntwo\ntheirs\n",
                options,
            )
            .expect("first merge");
            let second = merge_content(
                b"one\ntwo\nthree\n",
                b"ours\ntwo\nthree\n",
                b"one\ntwo\ntheirs\n",
                options,
            )
            .expect("second merge");
            assert_eq!(first, second);
            assert!(first.outcome.is_clean());
        }
    }

    #[test]
    fn content_conflicts_preserve_unchanged_context_metamorphically() {
        let core = merge_content(b"base\n", b"ours\n", b"theirs\n", content_options())
            .expect("core conflict");
        let extended = merge_content(
            b"prefix\nbase\nsuffix\n",
            b"prefix\nours\nsuffix\n",
            b"prefix\ntheirs\nsuffix\n",
            content_options(),
        )
        .expect("extended conflict");
        let mut expected = b"prefix\n".to_vec();
        expected.extend_from_slice(core.outcome.proposed_bytes());
        expected.extend_from_slice(b"suffix\n");
        assert_eq!(extended.outcome.proposed_bytes(), expected);
    }

    #[test]
    fn content_merge_handles_identical_binary_and_budget_refusal_paths() {
        let identical = merge_content(b"\0base", b"\0same", b"\0same", content_options())
            .expect("identical binary sides are clean");
        assert!(identical.outcome.is_clean());

        let binary = merge_content(b"\0base", b"\0ours", b"\0theirs", content_options())
            .expect("binary conflict");
        assert!(matches!(
            binary.outcome,
            ContentMergeOutcome::Conflicted { .. }
        ));

        assert_eq!(
            merge_content(
                b"base",
                b"ours",
                b"theirs",
                ContentMergeOptions {
                    limits: ContentMergeLimits {
                        max_input_bytes: 1,
                        ..content_options().limits
                    },
                    ..content_options()
                },
            ),
            Err(ContentMergeError::InputBytesExceeded {
                limit: 1,
                actual: 14,
            })
        );
        assert_eq!(
            merge_content(
                b"base\n",
                b"ours\n",
                b"theirs\n",
                ContentMergeOptions {
                    limits: ContentMergeLimits {
                        max_output_bytes: 1,
                        ..content_options().limits
                    },
                    ..content_options()
                },
            ),
            Err(ContentMergeError::OutputBytesExceeded { limit: 1 })
        );
        assert_eq!(
            merge_content(
                b"base\n",
                b"ours\n",
                b"theirs\n",
                ContentMergeOptions {
                    limits: ContentMergeLimits {
                        max_conflicts: 0,
                        ..content_options().limits
                    },
                    ..content_options()
                },
            ),
            Err(ContentMergeError::ConflictLimitExceeded { limit: 0 })
        );
    }

    #[test]
    fn content_merge_refuses_hunk_work_and_virtual_depth_bounds() {
        let hunk_limited = ContentMergeOptions {
            limits: ContentMergeLimits {
                max_hunks: 0,
                ..content_options().limits
            },
            ..content_options()
        };
        assert_eq!(
            merge_content(b"base\n", b"ours\n", b"theirs\n", hunk_limited),
            Err(ContentMergeError::HunkLimitExceeded { limit: 0 })
        );

        let work_limited = ContentMergeOptions {
            limits: ContentMergeLimits {
                max_work_steps: 0,
                ..content_options().limits
            },
            ..content_options()
        };
        assert_eq!(
            merge_content(b"base\n", b"ours\n", b"theirs\n", work_limited),
            Err(ContentMergeError::WorkLimitExceeded { limit: 0 })
        );

        let bases = [b"left\n".as_slice(), b"right\n".as_slice()];
        let depth_limited = ContentMergeOptions {
            profile: MergeProfile {
                virtual_base: VirtualBaseProfile::RecursiveConflictPreservingV1,
                ..content_options().profile
            },
            limits: ContentMergeLimits {
                max_depth: 1,
                ..content_options().limits
            },
        };
        assert_eq!(
            merge_content_many(&bases, b"ours\n", b"theirs\n", depth_limited),
            Err(ContentMergeError::DepthLimitExceeded { limit: 1 })
        );
    }

    struct Cancelled;

    impl MergeCancellation for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    #[test]
    fn cancellation_refuses_before_a_content_or_tree_proposal_exists() {
        assert_eq!(
            merge_content_with_cancellation(
                b"base\n",
                b"ours\n",
                b"theirs\n",
                content_options(),
                &Cancelled,
            ),
            Err(ContentMergeError::Cancelled)
        );
        assert_eq!(
            merge_trees_with_cancellation(
                vec![entry(b"a", 0o100_644, 1)],
                vec![entry(b"a", 0o100_644, 2)],
                vec![entry(b"a", 0o100_644, 3)],
                TreeMergeOptions::default(),
                &Cancelled,
            ),
            Err(TreeMergeError::Cancelled)
        );
    }

    #[test]
    fn multiple_base_profile_is_explicit_and_repeatable() {
        let bases = [b"left\n".as_slice(), b"right\n".as_slice()];
        assert_eq!(
            merge_content_many(&bases, b"ours\n", b"theirs\n", content_options()),
            Err(ContentMergeError::MultipleBasesRequireVirtualBase)
        );
        let options = ContentMergeOptions {
            profile: MergeProfile {
                virtual_base: VirtualBaseProfile::RecursiveConflictPreservingV1,
                ..content_options().profile
            },
            ..content_options()
        };
        let first = merge_content_many(&bases, b"ours\n", b"theirs\n", options)
            .expect("recursive virtual base");
        let second =
            merge_content_many(&bases, b"ours\n", b"theirs\n", options).expect("same virtual base");
        assert_eq!(first, second);
        assert_eq!(first.receipt.base_count, 2);
    }

    #[test]
    fn tree_merge_preserves_clean_entries_and_explicit_add_add_conflicts() {
        let clean = merge_trees(
            vec![entry(b"a", 0o100_644, 1)],
            vec![entry(b"a", 0o100_644, 2)],
            vec![entry(b"a", 0o100_644, 1), entry(b"b", 0o100_644, 3)],
            TreeMergeOptions::default(),
        )
        .expect("tree merge");
        assert_eq!(
            clean.entries,
            vec![
                TreeMergeEntry::Clean(entry(b"a", 0o100_644, 2)),
                TreeMergeEntry::Clean(entry(b"b", 0o100_644, 3)),
            ]
        );

        let add_add = merge_trees(
            Vec::new(),
            vec![entry(b"new", 0o100_644, 1)],
            vec![entry(b"new", 0o100_644, 2)],
            TreeMergeOptions::default(),
        )
        .expect("tree proposal");
        assert!(matches!(
            add_add.entries[0],
            TreeMergeEntry::Conflict(TreeConflict {
                kind: TreeConflictKind::AddAdd,
                ..
            })
        ));
        assert_eq!(add_add.proposed_intents.len(), 1);
    }

    #[test]
    fn tree_merge_classifies_delete_mode_type_symlink_submodule_and_rename_conflicts() {
        let modify_delete = merge_trees(
            vec![entry(b"a", 0o100_644, 1)],
            Vec::new(),
            vec![entry(b"a", 0o100_644, 2)],
            TreeMergeOptions::default(),
        )
        .expect("tree proposal");
        assert_tree_conflict(&modify_delete, TreeConflictKind::ModifyDelete);

        let mode = merge_trees(
            vec![entry(b"a", 0o100_644, 1)],
            vec![entry(b"a", 0o100_755, 2)],
            vec![entry(b"a", 0o100_644, 3)],
            TreeMergeOptions::default(),
        )
        .expect("tree proposal");
        assert_tree_conflict(&mode, TreeConflictKind::ModeChange);

        let symlink = merge_trees(
            vec![entry(b"link", 0o120_000, 1)],
            vec![entry(b"link", 0o120_000, 2)],
            vec![entry(b"link", 0o120_000, 3)],
            TreeMergeOptions::default(),
        )
        .expect("tree proposal");
        assert_tree_conflict(&symlink, TreeConflictKind::Symlink);

        let type_change = merge_trees(
            vec![entry(b"node", 0o100_644, 1)],
            vec![entry(b"node", 0o040_000, 2)],
            vec![entry(b"node", 0o100_644, 3)],
            TreeMergeOptions::default(),
        )
        .expect("tree proposal");
        assert_tree_conflict(&type_change, TreeConflictKind::TypeChange);

        let submodule = merge_trees(
            vec![entry(b"sub", 0o160_000, 1)],
            vec![entry(b"sub", 0o160_000, 2)],
            vec![entry(b"sub", 0o160_000, 3)],
            TreeMergeOptions::default(),
        )
        .expect("tree proposal");
        assert_tree_conflict(&submodule, TreeConflictKind::SubmodulePointer);

        let renamed = merge_trees(
            vec![entry(b"before", 0o100_644, 1)],
            vec![entry(b"after", 0o100_644, 1)],
            vec![entry(b"before", 0o100_644, 2)],
            TreeMergeOptions::default(),
        )
        .expect("tree proposal");
        assert_tree_conflict(&renamed, TreeConflictKind::RenameInteraction);

        let competing_renames = merge_trees(
            vec![entry(b"before", 0o100_644, 1)],
            vec![entry(b"ours", 0o100_644, 1)],
            vec![entry(b"theirs", 0o100_644, 1)],
            TreeMergeOptions::default(),
        )
        .expect("tree proposal");
        assert_tree_conflict(&competing_renames, TreeConflictKind::RenameInteraction);
    }

    #[test]
    fn tree_merge_refuses_path_and_work_bounds() {
        assert_eq!(
            merge_trees(
                Vec::new(),
                vec![entry(b"a", 0o100_644, 1)],
                Vec::new(),
                TreeMergeOptions {
                    limits: TreeMergeLimits {
                        max_paths: 0,
                        ..TreeMergeLimits::default()
                    },
                },
            ),
            Err(TreeMergeError::PathLimitExceeded { limit: 0 })
        );
        assert_eq!(
            merge_trees(
                vec![entry(b"a", 0o100_644, 1)],
                vec![entry(b"a", 0o100_644, 2)],
                vec![entry(b"a", 0o100_644, 3)],
                TreeMergeOptions {
                    limits: TreeMergeLimits {
                        max_work_steps: 0,
                        ..TreeMergeLimits::default()
                    },
                },
            ),
            Err(TreeMergeError::WorkLimitExceeded { limit: 0 })
        );
        assert_eq!(
            merge_trees(
                Vec::new(),
                vec![entry(b"a", 0o100_644, 1)],
                vec![entry(b"a", 0o100_644, 2)],
                TreeMergeOptions {
                    limits: TreeMergeLimits {
                        max_conflicts: 0,
                        ..TreeMergeLimits::default()
                    },
                },
            ),
            Err(TreeMergeError::ConflictLimitExceeded { limit: 0 })
        );
        assert_eq!(
            merge_trees(
                Vec::new(),
                vec![entry(b"oversized", 0o100_644, 1)],
                Vec::new(),
                TreeMergeOptions {
                    limits: TreeMergeLimits {
                        max_path_bytes: 1,
                        ..TreeMergeLimits::default()
                    },
                },
            ),
            Err(TreeMergeError::PathBytesExceeded {
                limit: 1,
                actual: 9,
            })
        );
    }

    #[test]
    fn tree_proposals_are_canonical_deterministic_and_lossless() {
        let base = vec![
            entry(b"a", 0o100_644, 1),
            entry(b"b", 0o100_644, 2),
            entry(b"c", 0o100_644, 3),
        ];
        let ours = vec![
            entry(b"a", 0o100_644, 4),
            entry(b"b", 0o100_644, 2),
            entry(b"c", 0o100_644, 3),
        ];
        let theirs = vec![
            entry(b"a", 0o100_644, 5),
            entry(b"b", 0o100_644, 2),
            entry(b"c", 0o100_755, 3),
        ];
        let first = merge_trees(
            base.clone(),
            ours.clone(),
            theirs.clone(),
            TreeMergeOptions::default(),
        )
        .expect("first tree proposal");
        let second = merge_trees(base, ours, theirs, TreeMergeOptions::default())
            .expect("second tree proposal");
        assert_eq!(first, second);
        assert_eq!(
            first
                .entries
                .iter()
                .map(|entry| match entry {
                    TreeMergeEntry::Clean(entry) => entry.path.as_slice(),
                    TreeMergeEntry::Conflict(conflict) => conflict.path.as_slice(),
                })
                .collect::<Vec<_>>(),
            vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]
        );
        let TreeMergeEntry::Conflict(conflict) = &first.entries[0] else {
            panic!("expected conflict at a");
        };
        assert_eq!(conflict.base, Some(entry(b"a", 0o100_644, 1)));
        assert_eq!(conflict.ours, Some(entry(b"a", 0o100_644, 4)));
        assert_eq!(conflict.theirs, Some(entry(b"a", 0o100_644, 5)));
    }

    fn assert_tree_conflict(result: &TreeMergeResult<u8>, expected: TreeConflictKind) {
        assert!(
            result.entries.iter().any(|entry| {
                matches!(entry, TreeMergeEntry::Conflict(TreeConflict { kind, .. }) if *kind == expected)
            }),
            "missing {expected:?} conflict in {result:?}"
        );
    }
}
