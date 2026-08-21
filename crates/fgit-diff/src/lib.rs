#![forbid(unsafe_code)]
//! Pure, bounded, deterministic diff, tree-diff, and merge-base primitives.
//!
//! `fgit-diff` deliberately has no Git-object parser dependency. Callers supply
//! bytes, sorted tree entries, or a commit-parent graph through the small traits
//! in this crate. A future `fgit-git-object` adapter is therefore mechanical and
//! cannot redefine the ordering or refusal semantics established here.
//!
//! The three text profiles have observable, closed tie rules:
//!
//! * `MyersMinimal` uses Myers' O(ND) frontier rule. At a frontier tie it takes
//!   the deletion/right branch; equal tokens are consumed greedily as a snake.
//!   When retaining the backtracking trace would exceed its declared bound, the
//!   same profile uses a deterministic linear-space LCS refinement. That
//!   refinement chooses the lowest new-side split and then the earliest matching
//!   new-side token.
//! * `Patience` anchors tokens that occur exactly once in each compared region,
//!   chooses the earliest-ending longest increasing sequence of those anchors
//!   (with the earliest predecessor at every equal-length choice), and
//!   recursively applies `MyersMinimal` to unanchored gaps.
//! * `Histogram` chooses an exact matching token with the lowest maximum
//!   occurrence count across the compared regions. Equal rarity chooses the
//!   lowest old-side index, then the lowest new-side index. It recursively
//!   applies the same rule to both gaps and uses `MyersMinimal` where no exact
//!   match exists.
//!
//! The exact selected algorithm is returned with every result. Limits are part
//! of the profile input, so a linear-space refinement is never hidden as the
//! same receipt as a trace-backed Myers execution.

use std::collections::{BTreeMap, BTreeSet};

/// The requested tokenization and deterministic edit-selection profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffProfile {
    MyersMinimal,
    Patience,
    Histogram,
}

/// Whether bytes are compared independently or as newline-inclusive lines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceGranularity {
    Bytes,
    Lines,
}

/// Hard pre-allocation and work limits for sequence diffing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiffLimits {
    pub max_input_bytes: usize,
    pub max_units: usize,
    pub max_work: usize,
    pub max_trace_cells: usize,
}

impl Default for DiffLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024 * 1024,
            max_units: 1_000_000,
            max_work: 100_000_000,
            max_trace_cells: 8_000_000,
        }
    }
}

/// All inputs that determine a sequence-diff result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiffOptions {
    pub profile: DiffProfile,
    pub granularity: SequenceGranularity,
    pub limits: DiffLimits,
}

impl DiffOptions {
    #[must_use]
    pub const fn myers_lines(limits: DiffLimits) -> Self {
        Self {
            profile: DiffProfile::MyersMinimal,
            granularity: SequenceGranularity::Lines,
            limits,
        }
    }

    #[must_use]
    pub const fn patience_lines(limits: DiffLimits) -> Self {
        Self {
            profile: DiffProfile::Patience,
            granularity: SequenceGranularity::Lines,
            limits,
        }
    }

    #[must_use]
    pub const fn histogram_lines(limits: DiffLimits) -> Self {
        Self {
            profile: DiffProfile::Histogram,
            granularity: SequenceGranularity::Lines,
            limits,
        }
    }
}

/// The implementation path used for the returned deterministic profile result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffAlgorithm {
    MyersTrace,
    MyersLinearRefinement,
    PatienceAnchored,
    HistogramAnchored,
}

/// An exact byte and unit interval in one input sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub byte_start: usize,
    pub byte_end: usize,
    pub unit_start: usize,
    pub unit_end: usize,
}

impl Span {
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.byte_start == self.byte_end && self.unit_start == self.unit_end
    }
}

/// One operation in a common span-carrying hunk model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Edit {
    Equal {
        old: Span,
        new: Span,
    },
    Delete {
        old: Span,
        new: Span,
    },
    Insert {
        old: Span,
        new: Span,
        bytes: Vec<u8>,
    },
}

impl Edit {
    #[must_use]
    pub const fn old_span(&self) -> Span {
        match self {
            Self::Equal { old, .. } | Self::Delete { old, .. } | Self::Insert { old, .. } => *old,
        }
    }

    #[must_use]
    pub const fn new_span(&self) -> Span {
        match self {
            Self::Equal { new, .. } | Self::Delete { new, .. } | Self::Insert { new, .. } => *new,
        }
    }

    #[must_use]
    pub const fn is_equal(&self) -> bool {
        matches!(self, Self::Equal { .. })
    }
}

/// A contiguous changed region reconstructed from the canonical edit stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffHunk {
    pub old: Span,
    pub new: Span,
    pub edits: Vec<Edit>,
}

/// A deterministic edit script. `apply_to` is the scalar correctness oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffResult {
    pub profile: DiffProfile,
    pub granularity: SequenceGranularity,
    pub algorithm: DiffAlgorithm,
    pub edits: Vec<Edit>,
}

impl DiffResult {
    /// Reconstruct the new byte sequence and validate the script's old spans.
    pub fn apply_to(&self, old: &[u8]) -> Result<Vec<u8>, DiffError> {
        let mut output = Vec::new();
        let mut cursor = 0;
        for edit in &self.edits {
            let old_span = edit.old_span();
            if old_span.byte_start != cursor || old_span.byte_end > old.len() {
                return Err(DiffError::MalformedScript);
            }
            match edit {
                Edit::Equal { old: span, .. } => {
                    output.extend_from_slice(&old[span.byte_start..span.byte_end]);
                    cursor = span.byte_end;
                }
                Edit::Delete { old: span, .. } => cursor = span.byte_end,
                Edit::Insert { bytes, .. } => output.extend_from_slice(bytes),
            }
        }
        if cursor != old.len() {
            return Err(DiffError::MalformedScript);
        }
        Ok(output)
    }

    /// Group adjacent non-equal operations without changing script semantics.
    #[must_use]
    pub fn hunks(&self) -> Vec<DiffHunk> {
        let mut hunks = Vec::new();
        let mut active: Option<DiffHunk> = None;
        for edit in &self.edits {
            if edit.is_equal() {
                if let Some(hunk) = active.take() {
                    hunks.push(hunk);
                }
                continue;
            }
            let old = edit.old_span();
            let new = edit.new_span();
            if let Some(hunk) = &mut active {
                hunk.old.byte_end = old.byte_end;
                hunk.old.unit_end = old.unit_end;
                hunk.new.byte_end = new.byte_end;
                hunk.new.unit_end = new.unit_end;
                hunk.edits.push(edit.clone());
            } else {
                active = Some(DiffHunk {
                    old,
                    new,
                    edits: vec![edit.clone()],
                });
            }
        }
        if let Some(hunk) = active {
            hunks.push(hunk);
        }
        hunks
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiffError {
    InputBytesExceeded { limit: usize, actual: usize },
    UnitsExceeded { limit: usize, actual: usize },
    WorkExceeded { limit: usize },
    ArithmeticOverflow,
    MalformedScript,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Token {
    byte_start: usize,
    byte_end: usize,
}

struct TokenStream<'a> {
    bytes: &'a [u8],
    tokens: Vec<Token>,
}

impl<'a> TokenStream<'a> {
    fn new(bytes: &'a [u8], granularity: SequenceGranularity) -> Self {
        let tokens = match granularity {
            SequenceGranularity::Bytes => bytes
                .iter()
                .enumerate()
                .map(|(offset, _)| Token {
                    byte_start: offset,
                    byte_end: offset + 1,
                })
                .collect(),
            SequenceGranularity::Lines => line_tokens(bytes),
        };
        Self { bytes, tokens }
    }

    fn equal(&self, left: usize, other: &Self, right: usize) -> bool {
        let left = self.tokens[left];
        let right = other.tokens[right];
        self.bytes[left.byte_start..left.byte_end] == other.bytes[right.byte_start..right.byte_end]
    }

    fn span(&self, start: usize, end: usize) -> Span {
        let byte_start = self.byte_offset_at(start);
        let byte_end = self.byte_offset_at(end);
        Span {
            byte_start,
            byte_end,
            unit_start: start,
            unit_end: end,
        }
    }

    fn bytes_for(&self, start: usize, end: usize) -> Vec<u8> {
        let span = self.span(start, end);
        self.bytes[span.byte_start..span.byte_end].to_vec()
    }

    fn byte_offset_at(&self, unit: usize) -> usize {
        self.tokens
            .get(unit)
            .map_or(self.bytes.len(), |token| token.byte_start)
    }
}

fn unit_count(bytes: &[u8], granularity: SequenceGranularity) -> usize {
    match granularity {
        SequenceGranularity::Bytes => bytes.len(),
        SequenceGranularity::Lines => {
            let newline_count = bytes.iter().filter(|byte| **byte == b'\n').count();
            newline_count + usize::from(bytes.last() != Some(&b'\n') && !bytes.is_empty())
        }
    }
}

fn line_tokens(bytes: &[u8]) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut start = 0;
    for (offset, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            tokens.push(Token {
                byte_start: start,
                byte_end: offset + 1,
            });
            start = offset + 1;
        }
    }
    if start < bytes.len() {
        tokens.push(Token {
            byte_start: start,
            byte_end: bytes.len(),
        });
    }
    tokens
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AtomicEdit {
    Equal { old: usize, new: usize },
    Delete { old: usize },
    Insert { new: usize },
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

    fn consume(&mut self, amount: usize) -> Result<(), DiffError> {
        self.remaining = self
            .remaining
            .checked_sub(amount)
            .ok_or(DiffError::WorkExceeded { limit: self.limit })?;
        Ok(())
    }
}

/// Compute a bounded deterministic diff. No algorithm allocates before its
/// corresponding byte/unit/work limit has been checked.
pub fn diff(old: &[u8], new: &[u8], options: DiffOptions) -> Result<DiffResult, DiffError> {
    let total_bytes = old
        .len()
        .checked_add(new.len())
        .ok_or(DiffError::ArithmeticOverflow)?;
    if total_bytes > options.limits.max_input_bytes {
        return Err(DiffError::InputBytesExceeded {
            limit: options.limits.max_input_bytes,
            actual: total_bytes,
        });
    }
    let total_units = unit_count(old, options.granularity)
        .checked_add(unit_count(new, options.granularity))
        .ok_or(DiffError::ArithmeticOverflow)?;
    if total_units > options.limits.max_units {
        return Err(DiffError::UnitsExceeded {
            limit: options.limits.max_units,
            actual: total_units,
        });
    }
    let old_tokens = TokenStream::new(old, options.granularity);
    let new_tokens = TokenStream::new(new, options.granularity);

    let mut budget = WorkBudget::new(options.limits.max_work);
    let (atoms, algorithm) = match options.profile {
        DiffProfile::MyersMinimal => minimal_atoms(
            &old_tokens,
            0,
            old_tokens.tokens.len(),
            &new_tokens,
            0,
            new_tokens.tokens.len(),
            &options.limits,
            &mut budget,
        )?,
        DiffProfile::Patience => (
            patience_atoms(
                &old_tokens,
                0,
                old_tokens.tokens.len(),
                &new_tokens,
                0,
                new_tokens.tokens.len(),
                &options.limits,
                &mut budget,
            )?,
            DiffAlgorithm::PatienceAnchored,
        ),
        DiffProfile::Histogram => (
            histogram_atoms(
                &old_tokens,
                0,
                old_tokens.tokens.len(),
                &new_tokens,
                0,
                new_tokens.tokens.len(),
                &options.limits,
                &mut budget,
            )?,
            DiffAlgorithm::HistogramAnchored,
        ),
    };
    budget.consume(atoms.len())?;
    Ok(DiffResult {
        profile: options.profile,
        granularity: options.granularity,
        algorithm,
        edits: materialize_edits(&old_tokens, &new_tokens, &atoms)?,
    })
}

fn minimal_atoms(
    old: &TokenStream<'_>,
    old_start: usize,
    old_end: usize,
    new: &TokenStream<'_>,
    new_start: usize,
    new_end: usize,
    limits: &DiffLimits,
    budget: &mut WorkBudget,
) -> Result<(Vec<AtomicEdit>, DiffAlgorithm), DiffError> {
    match myers_trace_atoms(
        old, old_start, old_end, new, new_start, new_end, limits, budget,
    )? {
        Some(atoms) => Ok((atoms, DiffAlgorithm::MyersTrace)),
        None => {
            let mut atoms = Vec::new();
            hirschberg_atoms(
                old, old_start, old_end, new, new_start, new_end, budget, &mut atoms,
            )?;
            Ok((atoms, DiffAlgorithm::MyersLinearRefinement))
        }
    }
}

fn myers_trace_atoms(
    old: &TokenStream<'_>,
    old_start: usize,
    old_end: usize,
    new: &TokenStream<'_>,
    new_start: usize,
    new_end: usize,
    limits: &DiffLimits,
    budget: &mut WorkBudget,
) -> Result<Option<Vec<AtomicEdit>>, DiffError> {
    let old_len = old_end - old_start;
    let new_len = new_end - new_start;
    let max = old_len
        .checked_add(new_len)
        .ok_or(DiffError::ArithmeticOverflow)?;
    let width = max
        .checked_mul(2)
        .and_then(|value| value.checked_add(3))
        .ok_or(DiffError::ArithmeticOverflow)?;
    let offset = isize::try_from(max.checked_add(1).ok_or(DiffError::ArithmeticOverflow)?)
        .map_err(|_| DiffError::ArithmeticOverflow)?;
    if width > limits.max_trace_cells {
        return Ok(None);
    }
    let mut frontier = vec![0_isize; width];
    let mut trace = Vec::new();
    let mut trace_cells = 0_usize;

    for distance in 0..=max {
        let diagonal_count = distance
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or(DiffError::ArithmeticOverflow)?;
        budget.consume(diagonal_count)?;
        let next_trace_cells = trace_cells
            .checked_add(width)
            .ok_or(DiffError::ArithmeticOverflow)?;
        if next_trace_cells > limits.max_trace_cells {
            return Ok(None);
        }
        for diagonal in (-isize::try_from(distance).map_err(|_| DiffError::ArithmeticOverflow)?)
            ..=isize::try_from(distance).map_err(|_| DiffError::ArithmeticOverflow)?
        {
            if (diagonal + isize::try_from(distance).map_err(|_| DiffError::ArithmeticOverflow)?)
                % 2
                != 0
            {
                continue;
            }
            let index =
                usize::try_from(offset + diagonal).map_err(|_| DiffError::ArithmeticOverflow)?;
            let take_insert = diagonal
                == -isize::try_from(distance).map_err(|_| DiffError::ArithmeticOverflow)?
                || (diagonal
                    != isize::try_from(distance).map_err(|_| DiffError::ArithmeticOverflow)?
                    && frontier[index - 1] < frontier[index + 1]);
            let mut old_index = if take_insert {
                frontier[index + 1]
            } else {
                frontier[index - 1] + 1
            };
            let mut new_index = old_index - diagonal;
            while old_index < isize::try_from(old_len).map_err(|_| DiffError::ArithmeticOverflow)?
                && new_index
                    < isize::try_from(new_len).map_err(|_| DiffError::ArithmeticOverflow)?
                && old.equal(
                    old_start
                        + usize::try_from(old_index).map_err(|_| DiffError::ArithmeticOverflow)?,
                    new,
                    new_start
                        + usize::try_from(new_index).map_err(|_| DiffError::ArithmeticOverflow)?,
                )
            {
                budget.consume(1)?;
                old_index += 1;
                new_index += 1;
            }
            frontier[index] = old_index;
            if old_index == isize::try_from(old_len).map_err(|_| DiffError::ArithmeticOverflow)?
                && new_index
                    == isize::try_from(new_len).map_err(|_| DiffError::ArithmeticOverflow)?
            {
                trace.push(frontier.clone());
                return backtrack_myers(
                    &trace, distance, old_start, new_start, old_len, new_len, offset,
                )
                .map(Some);
            }
        }
        trace_cells = next_trace_cells;
        trace.push(frontier.clone());
    }
    Err(DiffError::ArithmeticOverflow)
}

fn backtrack_myers(
    trace: &[Vec<isize>],
    distance: usize,
    old_start: usize,
    new_start: usize,
    old_len: usize,
    new_len: usize,
    offset: isize,
) -> Result<Vec<AtomicEdit>, DiffError> {
    let mut old_index = isize::try_from(old_len).map_err(|_| DiffError::ArithmeticOverflow)?;
    let mut new_index = isize::try_from(new_len).map_err(|_| DiffError::ArithmeticOverflow)?;
    let mut reversed = Vec::new();
    for current_distance in (1..=distance).rev() {
        let previous = &trace[current_distance - 1];
        let current_distance =
            isize::try_from(current_distance).map_err(|_| DiffError::ArithmeticOverflow)?;
        let diagonal = old_index - new_index;
        let index =
            usize::try_from(offset + diagonal).map_err(|_| DiffError::ArithmeticOverflow)?;
        let previous_diagonal = if diagonal == -current_distance
            || (diagonal != current_distance && previous[index - 1] < previous[index + 1])
        {
            diagonal + 1
        } else {
            diagonal - 1
        };
        let previous_old = previous[usize::try_from(offset + previous_diagonal)
            .map_err(|_| DiffError::ArithmeticOverflow)?];
        let previous_new = previous_old - previous_diagonal;
        while old_index > previous_old && new_index > previous_new {
            old_index -= 1;
            new_index -= 1;
            reversed.push(AtomicEdit::Equal {
                old: old_start
                    + usize::try_from(old_index).map_err(|_| DiffError::ArithmeticOverflow)?,
                new: new_start
                    + usize::try_from(new_index).map_err(|_| DiffError::ArithmeticOverflow)?,
            });
        }
        if old_index == previous_old {
            new_index -= 1;
            reversed.push(AtomicEdit::Insert {
                new: new_start
                    + usize::try_from(new_index).map_err(|_| DiffError::ArithmeticOverflow)?,
            });
        } else {
            old_index -= 1;
            reversed.push(AtomicEdit::Delete {
                old: old_start
                    + usize::try_from(old_index).map_err(|_| DiffError::ArithmeticOverflow)?,
            });
        }
    }
    while old_index > 0 && new_index > 0 {
        old_index -= 1;
        new_index -= 1;
        reversed.push(AtomicEdit::Equal {
            old: old_start
                + usize::try_from(old_index).map_err(|_| DiffError::ArithmeticOverflow)?,
            new: new_start
                + usize::try_from(new_index).map_err(|_| DiffError::ArithmeticOverflow)?,
        });
    }
    while old_index > 0 {
        old_index -= 1;
        reversed.push(AtomicEdit::Delete {
            old: old_start
                + usize::try_from(old_index).map_err(|_| DiffError::ArithmeticOverflow)?,
        });
    }
    while new_index > 0 {
        new_index -= 1;
        reversed.push(AtomicEdit::Insert {
            new: new_start
                + usize::try_from(new_index).map_err(|_| DiffError::ArithmeticOverflow)?,
        });
    }
    reversed.reverse();
    Ok(reversed)
}

fn hirschberg_atoms(
    old: &TokenStream<'_>,
    old_start: usize,
    old_end: usize,
    new: &TokenStream<'_>,
    new_start: usize,
    new_end: usize,
    budget: &mut WorkBudget,
    output: &mut Vec<AtomicEdit>,
) -> Result<(), DiffError> {
    if old_start == old_end {
        budget.consume(new_end - new_start)?;
        output.extend((new_start..new_end).map(|index| AtomicEdit::Insert { new: index }));
        return Ok(());
    }
    if new_start == new_end {
        budget.consume(old_end - old_start)?;
        output.extend((old_start..old_end).map(|index| AtomicEdit::Delete { old: index }));
        return Ok(());
    }
    if old_end - old_start == 1 {
        let mut matching = None;
        for new_index in new_start..new_end {
            budget.consume(1)?;
            if old.equal(old_start, new, new_index) {
                matching = Some(new_index);
                break;
            }
        }
        if let Some(matching) = matching {
            budget.consume(new_end - new_start)?;
            output.extend((new_start..matching).map(|index| AtomicEdit::Insert { new: index }));
            output.push(AtomicEdit::Equal {
                old: old_start,
                new: matching,
            });
            output.extend((matching + 1..new_end).map(|index| AtomicEdit::Insert { new: index }));
        } else {
            budget.consume(
                new_end
                    .checked_sub(new_start)
                    .and_then(|length| length.checked_add(1))
                    .ok_or(DiffError::ArithmeticOverflow)?,
            )?;
            output.push(AtomicEdit::Delete { old: old_start });
            output.extend((new_start..new_end).map(|index| AtomicEdit::Insert { new: index }));
        }
        return Ok(());
    }

    let old_middle = old_start + (old_end - old_start) / 2;
    let prefix = lcs_prefix(old, old_start, old_middle, new, new_start, new_end, budget)?;
    let suffix = lcs_suffix(old, old_middle, old_end, new, new_start, new_end, budget)?;
    let mut new_middle = 0;
    let mut best = 0;
    for split in 0..=new_end - new_start {
        let score = prefix[split]
            .checked_add(suffix[split])
            .ok_or(DiffError::ArithmeticOverflow)?;
        if score > best {
            best = score;
            new_middle = split;
        }
    }
    let new_middle = new_start + new_middle;
    hirschberg_atoms(
        old, old_start, old_middle, new, new_start, new_middle, budget, output,
    )?;
    hirschberg_atoms(
        old, old_middle, old_end, new, new_middle, new_end, budget, output,
    )
}

fn lcs_prefix(
    old: &TokenStream<'_>,
    old_start: usize,
    old_end: usize,
    new: &TokenStream<'_>,
    new_start: usize,
    new_end: usize,
    budget: &mut WorkBudget,
) -> Result<Vec<usize>, DiffError> {
    let width = new_end - new_start;
    let storage_len = width.checked_add(1).ok_or(DiffError::ArithmeticOverflow)?;
    let mut previous = vec![0_usize; storage_len];
    for old_index in old_start..old_end {
        let mut current = vec![0_usize; storage_len];
        for new_offset in 0..width {
            budget.consume(1)?;
            let new_index = new_start + new_offset;
            current[new_offset + 1] = if old.equal(old_index, new, new_index) {
                previous[new_offset]
                    .checked_add(1)
                    .ok_or(DiffError::ArithmeticOverflow)?
            } else {
                previous[new_offset + 1].max(current[new_offset])
            };
        }
        previous = current;
    }
    Ok(previous)
}

fn lcs_suffix(
    old: &TokenStream<'_>,
    old_start: usize,
    old_end: usize,
    new: &TokenStream<'_>,
    new_start: usize,
    new_end: usize,
    budget: &mut WorkBudget,
) -> Result<Vec<usize>, DiffError> {
    let width = new_end - new_start;
    let storage_len = width.checked_add(1).ok_or(DiffError::ArithmeticOverflow)?;
    let mut previous = vec![0_usize; storage_len];
    for old_index in (old_start..old_end).rev() {
        let mut current = vec![0_usize; storage_len];
        for new_offset in (0..width).rev() {
            budget.consume(1)?;
            let new_index = new_start + new_offset;
            current[new_offset] = if old.equal(old_index, new, new_index) {
                previous[new_offset + 1]
                    .checked_add(1)
                    .ok_or(DiffError::ArithmeticOverflow)?
            } else {
                previous[new_offset].max(current[new_offset + 1])
            };
        }
        previous = current;
    }
    Ok(previous)
}

fn patience_atoms(
    old: &TokenStream<'_>,
    old_start: usize,
    old_end: usize,
    new: &TokenStream<'_>,
    new_start: usize,
    new_end: usize,
    limits: &DiffLimits,
    budget: &mut WorkBudget,
) -> Result<Vec<AtomicEdit>, DiffError> {
    let anchors = unique_anchors(old, old_start, old_end, new, new_start, new_end, budget)?;
    let anchors = longest_increasing_anchors(&anchors, budget)?;
    if anchors.is_empty() {
        return minimal_atoms(
            old, old_start, old_end, new, new_start, new_end, limits, budget,
        )
        .map(|(atoms, _)| atoms);
    }
    let mut output = Vec::new();
    let mut old_cursor = old_start;
    let mut new_cursor = new_start;
    for (old_anchor, new_anchor) in anchors {
        output.extend(patience_atoms(
            old, old_cursor, old_anchor, new, new_cursor, new_anchor, limits, budget,
        )?);
        output.push(AtomicEdit::Equal {
            old: old_anchor,
            new: new_anchor,
        });
        old_cursor = old_anchor + 1;
        new_cursor = new_anchor + 1;
    }
    output.extend(patience_atoms(
        old, old_cursor, old_end, new, new_cursor, new_end, limits, budget,
    )?);
    Ok(output)
}

fn unique_anchors(
    old: &TokenStream<'_>,
    old_start: usize,
    old_end: usize,
    new: &TokenStream<'_>,
    new_start: usize,
    new_end: usize,
    budget: &mut WorkBudget,
) -> Result<Vec<(usize, usize)>, DiffError> {
    let mut anchors = Vec::new();
    for old_index in old_start..old_end {
        let mut old_count = 0;
        for candidate in old_start..old_end {
            budget.consume(1)?;
            if old.equal(old_index, old, candidate) {
                old_count += 1;
            }
        }
        if old_count != 1 {
            continue;
        }
        let mut matching_new = None;
        let mut new_count = 0;
        for new_index in new_start..new_end {
            budget.consume(1)?;
            if old.equal(old_index, new, new_index) {
                new_count += 1;
                matching_new = Some(new_index);
            }
        }
        if let (1, Some(matching_new)) = (new_count, matching_new) {
            anchors.push((old_index, matching_new));
        }
    }
    Ok(anchors)
}

fn longest_increasing_anchors(
    anchors: &[(usize, usize)],
    budget: &mut WorkBudget,
) -> Result<Vec<(usize, usize)>, DiffError> {
    let mut lengths = vec![1_usize; anchors.len()];
    let mut previous = vec![None; anchors.len()];
    for current in 0..anchors.len() {
        for candidate in 0..current {
            budget.consume(1)?;
            if anchors[candidate].1 < anchors[current].1
                && lengths[candidate]
                    .checked_add(1)
                    .ok_or(DiffError::ArithmeticOverflow)?
                    > lengths[current]
            {
                lengths[current] = lengths[candidate] + 1;
                previous[current] = Some(candidate);
            }
        }
    }
    let mut current = None;
    let mut best_length = 0;
    for (index, length) in lengths.iter().enumerate() {
        if *length > best_length {
            best_length = *length;
            current = Some(index);
        }
    }
    let Some(mut current) = current else {
        return Ok(Vec::new());
    };
    let mut reversed = Vec::new();
    loop {
        reversed.push(anchors[current]);
        let Some(next) = previous[current] else {
            break;
        };
        current = next;
    }
    reversed.reverse();
    Ok(reversed)
}

#[derive(Default)]
struct HistogramRecord {
    old_count: usize,
    new_count: usize,
    first_old: Option<usize>,
    first_new: Option<usize>,
}

fn histogram_atoms(
    old: &TokenStream<'_>,
    old_start: usize,
    old_end: usize,
    new: &TokenStream<'_>,
    new_start: usize,
    new_end: usize,
    limits: &DiffLimits,
    budget: &mut WorkBudget,
) -> Result<Vec<AtomicEdit>, DiffError> {
    let mut prefix = 0;
    while old_start + prefix < old_end
        && new_start + prefix < new_end
        && old.equal(old_start + prefix, new, new_start + prefix)
    {
        budget.consume(1)?;
        prefix += 1;
    }
    let mut old_center_end = old_end;
    let mut new_center_end = new_end;
    while old_center_end > old_start + prefix
        && new_center_end > new_start + prefix
        && old.equal(old_center_end - 1, new, new_center_end - 1)
    {
        budget.consume(1)?;
        old_center_end -= 1;
        new_center_end -= 1;
    }
    if prefix != 0 || old_center_end != old_end {
        let mut output = (0..prefix)
            .map(|offset| AtomicEdit::Equal {
                old: old_start + offset,
                new: new_start + offset,
            })
            .collect::<Vec<_>>();
        output.extend(histogram_atoms(
            old,
            old_start + prefix,
            old_center_end,
            new,
            new_start + prefix,
            new_center_end,
            limits,
            budget,
        )?);
        output.extend(
            (old_center_end..old_end).map(|old_index| AtomicEdit::Equal {
                old: old_index,
                new: new_center_end + (old_index - old_center_end),
            }),
        );
        return Ok(output);
    }
    let Some((old_anchor, new_anchor)) =
        histogram_anchor(old, old_start, old_end, new, new_start, new_end, budget)?
    else {
        return minimal_atoms(
            old, old_start, old_end, new, new_start, new_end, limits, budget,
        )
        .map(|(atoms, _)| atoms);
    };

    let mut output = histogram_atoms(
        old, old_start, old_anchor, new, new_start, new_anchor, limits, budget,
    )?;
    output.push(AtomicEdit::Equal {
        old: old_anchor,
        new: new_anchor,
    });
    output.extend(histogram_atoms(
        old,
        old_anchor + 1,
        old_end,
        new,
        new_anchor + 1,
        new_end,
        limits,
        budget,
    )?);
    Ok(output)
}

fn histogram_anchor(
    old: &TokenStream<'_>,
    old_start: usize,
    old_end: usize,
    new: &TokenStream<'_>,
    new_start: usize,
    new_end: usize,
    budget: &mut WorkBudget,
) -> Result<Option<(usize, usize)>, DiffError> {
    let mut frequencies: BTreeMap<Vec<u8>, HistogramRecord> = BTreeMap::new();
    for old_index in old_start..old_end {
        budget.consume(1)?;
        let record = frequencies
            .entry(old.bytes_for(old_index, old_index + 1))
            .or_default();
        record.old_count = record
            .old_count
            .checked_add(1)
            .ok_or(DiffError::ArithmeticOverflow)?;
        if record.first_old.is_none() {
            record.first_old = Some(old_index);
        }
    }
    for new_index in new_start..new_end {
        budget.consume(1)?;
        let record = frequencies
            .entry(new.bytes_for(new_index, new_index + 1))
            .or_default();
        record.new_count = record
            .new_count
            .checked_add(1)
            .ok_or(DiffError::ArithmeticOverflow)?;
        if record.first_new.is_none() {
            record.first_new = Some(new_index);
        }
    }

    let mut selected = None;
    for record in frequencies.values() {
        let (Some(old_index), Some(new_index)) = (record.first_old, record.first_new) else {
            continue;
        };
        let candidate = (record.old_count.max(record.new_count), old_index, new_index);
        if selected.is_none_or(|current| candidate < current) {
            selected = Some(candidate);
        }
    }
    Ok(selected.map(|(_, old_index, new_index)| (old_index, new_index)))
}

fn materialize_edits(
    old: &TokenStream<'_>,
    new: &TokenStream<'_>,
    atoms: &[AtomicEdit],
) -> Result<Vec<Edit>, DiffError> {
    let mut edits = Vec::with_capacity(atoms.len());
    let mut old_cursor = 0;
    let mut new_cursor = 0;
    for atom in atoms {
        match *atom {
            AtomicEdit::Equal {
                old: old_index,
                new: new_index,
            } => {
                if old_index != old_cursor || new_index != new_cursor {
                    return Err(DiffError::MalformedScript);
                }
                edits.push(Edit::Equal {
                    old: old.span(old_index, old_index + 1),
                    new: new.span(new_index, new_index + 1),
                });
                old_cursor += 1;
                new_cursor += 1;
            }
            AtomicEdit::Delete { old: old_index } => {
                if old_index != old_cursor {
                    return Err(DiffError::MalformedScript);
                }
                edits.push(Edit::Delete {
                    old: old.span(old_index, old_index + 1),
                    new: new.span(new_cursor, new_cursor),
                });
                old_cursor += 1;
            }
            AtomicEdit::Insert { new: new_index } => {
                if new_index != new_cursor {
                    return Err(DiffError::MalformedScript);
                }
                edits.push(Edit::Insert {
                    old: old.span(old_cursor, old_cursor),
                    new: new.span(new_index, new_index + 1),
                    bytes: new.bytes_for(new_index, new_index + 1),
                });
                new_cursor += 1;
            }
        }
    }
    if old_cursor != old.tokens.len() || new_cursor != new.tokens.len() {
        return Err(DiffError::MalformedScript);
    }
    Ok(edits)
}

/// A Git tree mode supplied by the object adapter; this crate never parses one.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TreeMode(pub u32);

/// One already-validated, Git-canonical-tree-sorted entry. `path` is the raw
/// tree-entry name, not a display-normalized filesystem path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntry<ObjectId> {
    pub path: Vec<u8>,
    pub mode: TreeMode,
    pub object: ObjectId,
}

/// Tree-level classification in deterministic Git tree order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeChange<ObjectId> {
    Added(TreeEntry<ObjectId>),
    Deleted(TreeEntry<ObjectId>),
    Modified {
        before: TreeEntry<ObjectId>,
        after: TreeEntry<ObjectId>,
    },
    ModeChanged {
        before: TreeEntry<ObjectId>,
        after: TreeEntry<ObjectId>,
        object_changed: bool,
    },
    Renamed {
        before: TreeEntry<ObjectId>,
        after: TreeEntry<ObjectId>,
        similarity_percent: u8,
    },
}

/// Hard limits on one tree comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeDiffLimits {
    pub max_entries_per_tree: usize,
    pub max_changes: usize,
}

impl Default for TreeDiffLimits {
    fn default() -> Self {
        Self {
            max_entries_per_tree: 1_000_000,
            max_changes: 2_000_000,
        }
    }
}

/// An explicitly selected rename policy. The implemented `ExactObject` profile
/// reports only byte-identical objects as 100 percent similar; it does not
/// fabricate an unverified content-similarity result. It scans deletions in
/// tree-diff order and pairs each with the earliest still-unpaired matching
/// addition; the rename occupies the deletion's original output slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameProfile {
    Disabled,
    ExactObject {
        minimum_similarity_percent: u8,
        max_candidate_pairs: usize,
    },
}

/// Tree-diff behavior and hard bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeDiffOptions {
    pub rename: RenameProfile,
    pub limits: TreeDiffLimits,
}

impl Default for TreeDiffOptions {
    fn default() -> Self {
        Self {
            rename: RenameProfile::Disabled,
            limits: TreeDiffLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeDiff<ObjectId> {
    pub changes: Vec<TreeChange<ObjectId>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeDiffError {
    UnsortedOrDuplicatePath,
    EntryLimitExceeded { limit: usize },
    ChangeLimitExceeded { limit: usize },
    InvalidSimilarityThreshold { requested: u8 },
    UnsupportedSimilarityThreshold { requested: u8 },
    RenameCandidateLimitExceeded { limit: usize },
}

/// Diff two Git-canonical-tree-sorted streams. This pure iterator API is the
/// only surface an `fgit-git-object` adapter needs to implement.
pub fn diff_trees<ObjectId, OldEntries, NewEntries>(
    old_entries: OldEntries,
    new_entries: NewEntries,
    options: TreeDiffOptions,
) -> Result<TreeDiff<ObjectId>, TreeDiffError>
where
    ObjectId: Clone + Eq,
    OldEntries: IntoIterator<Item = TreeEntry<ObjectId>>,
    NewEntries: IntoIterator<Item = TreeEntry<ObjectId>>,
{
    let old = collect_tree_entries(old_entries, options.limits.max_entries_per_tree)?;
    let new = collect_tree_entries(new_entries, options.limits.max_entries_per_tree)?;
    let mut old_index = 0;
    let mut new_index = 0;
    let mut changes = Vec::new();
    while old_index < old.len() || new_index < new.len() {
        match (old.get(old_index), new.get(new_index)) {
            (Some(before), Some(after)) if before.path == after.path => {
                if before.mode != after.mode {
                    push_tree_change(
                        &mut changes,
                        TreeChange::ModeChanged {
                            before: before.clone(),
                            after: after.clone(),
                            object_changed: before.object != after.object,
                        },
                        options.limits.max_changes,
                    )?;
                } else if before.object != after.object {
                    push_tree_change(
                        &mut changes,
                        TreeChange::Modified {
                            before: before.clone(),
                            after: after.clone(),
                        },
                        options.limits.max_changes,
                    )?;
                }
                old_index += 1;
                new_index += 1;
            }
            (Some(before), Some(after)) if compare_tree_entries(before, after).is_lt() => {
                push_tree_change(
                    &mut changes,
                    TreeChange::Deleted(before.clone()),
                    options.limits.max_changes,
                )?;
                old_index += 1;
            }
            (Some(_), Some(after)) => {
                push_tree_change(
                    &mut changes,
                    TreeChange::Added(after.clone()),
                    options.limits.max_changes,
                )?;
                new_index += 1;
            }
            (Some(before), None) => {
                push_tree_change(
                    &mut changes,
                    TreeChange::Deleted(before.clone()),
                    options.limits.max_changes,
                )?;
                old_index += 1;
            }
            (None, Some(after)) => {
                push_tree_change(
                    &mut changes,
                    TreeChange::Added(after.clone()),
                    options.limits.max_changes,
                )?;
                new_index += 1;
            }
            (None, None) => break,
        }
    }
    let changes = match options.rename {
        RenameProfile::Disabled => changes,
        RenameProfile::ExactObject {
            minimum_similarity_percent,
            max_candidate_pairs,
        } => exact_object_renames(changes, minimum_similarity_percent, max_candidate_pairs)?,
    };
    Ok(TreeDiff { changes })
}

fn exact_object_renames<ObjectId>(
    changes: Vec<TreeChange<ObjectId>>,
    minimum_similarity_percent: u8,
    max_candidate_pairs: usize,
) -> Result<Vec<TreeChange<ObjectId>>, TreeDiffError>
where
    ObjectId: Clone + Eq,
{
    if minimum_similarity_percent > 100 {
        return Err(TreeDiffError::InvalidSimilarityThreshold {
            requested: minimum_similarity_percent,
        });
    }
    if minimum_similarity_percent != 100 {
        return Err(TreeDiffError::UnsupportedSimilarityThreshold {
            requested: minimum_similarity_percent,
        });
    }
    let mut candidate_pairs = 0;
    let mut paired_additions = BTreeSet::new();
    let mut replacements = BTreeMap::new();
    for (delete_index, change) in changes.iter().enumerate() {
        let TreeChange::Deleted(before) = change else {
            continue;
        };
        for (addition_index, candidate) in changes.iter().enumerate() {
            let TreeChange::Added(after) = candidate else {
                continue;
            };
            if paired_additions.contains(&addition_index) {
                continue;
            }
            if candidate_pairs == max_candidate_pairs {
                return Err(TreeDiffError::RenameCandidateLimitExceeded {
                    limit: max_candidate_pairs,
                });
            }
            candidate_pairs += 1;
            if before.object == after.object {
                paired_additions.insert(addition_index);
                replacements.insert(
                    delete_index,
                    TreeChange::Renamed {
                        before: before.clone(),
                        after: after.clone(),
                        similarity_percent: 100,
                    },
                );
                break;
            }
        }
    }

    let mut resolved = Vec::with_capacity(changes.len());
    for (index, change) in changes.into_iter().enumerate() {
        if let Some(rename) = replacements.remove(&index) {
            resolved.push(rename);
        } else if !paired_additions.contains(&index) {
            resolved.push(change);
        }
    }
    Ok(resolved)
}

fn collect_tree_entries<ObjectId, Entries>(
    entries: Entries,
    limit: usize,
) -> Result<Vec<TreeEntry<ObjectId>>, TreeDiffError>
where
    Entries: IntoIterator<Item = TreeEntry<ObjectId>>,
{
    let mut collected = Vec::new();
    for entry in entries {
        if collected.len() == limit {
            return Err(TreeDiffError::EntryLimitExceeded { limit });
        }
        if collected
            .last()
            .is_some_and(|previous| !compare_tree_entries(previous, &entry).is_lt())
        {
            return Err(TreeDiffError::UnsortedOrDuplicatePath);
        }
        collected.push(entry);
    }
    Ok(collected)
}

fn push_tree_change<ObjectId>(
    changes: &mut Vec<TreeChange<ObjectId>>,
    change: TreeChange<ObjectId>,
    limit: usize,
) -> Result<(), TreeDiffError> {
    if changes.len() == limit {
        return Err(TreeDiffError::ChangeLimitExceeded { limit });
    }
    changes.push(change);
    Ok(())
}

fn compare_tree_entries<ObjectId>(
    left: &TreeEntry<ObjectId>,
    right: &TreeEntry<ObjectId>,
) -> std::cmp::Ordering {
    let shared = left
        .path
        .iter()
        .zip(&right.path)
        .take_while(|(left, right)| left == right)
        .count();
    match (left.path.get(shared), right.path.get(shared)) {
        (Some(left), Some(right)) => left.cmp(right),
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(right)) => tree_name_terminator(left.mode).cmp(right),
        (Some(left), None) => left.cmp(&tree_name_terminator(right.mode)),
    }
}

const fn tree_name_terminator(mode: TreeMode) -> u8 {
    if mode.0 & 0o170000 == 0o040000 {
        b'/'
    } else {
        0
    }
}

/// The parent relation supplied by a commit-object adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParentSet<CommitId> {
    Complete(Vec<CommitId>),
    ShallowBoundary,
}

/// A graph-only boundary. Commit generations and commit dates are deliberately
/// absent, so neither can influence best-common-ancestor selection.
pub trait CommitGraph {
    type CommitId: Clone + Ord;
    type Error;

    fn parents_of(&self, commit: &Self::CommitId)
    -> Result<ParentSet<Self::CommitId>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MergeBaseLimits {
    pub max_commits: usize,
    pub max_edges: usize,
}

impl Default for MergeBaseLimits {
    fn default() -> Self {
        Self {
            max_commits: 1_000_000,
            max_edges: 4_000_000,
        }
    }
}

/// Equivalent to `git merge-base --all` for a complete commit DAG: every common
/// ancestor that is not itself an ancestor of another common ancestor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeBaseResult<CommitId> {
    Bases(Vec<CommitId>),
    NoCommonAncestor,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MergeBaseError<CommitId, SourceError> {
    Source(SourceError),
    ShallowBoundary { commit: CommitId },
    DuplicateParent { commit: CommitId },
    GraphClosureViolation,
    Cycle,
    CommitLimitExceeded { limit: usize },
    EdgeLimitExceeded { limit: usize },
}

/// Return all best common ancestors in ascending `CommitId` order.
pub fn merge_bases_all<Graph>(
    graph: &Graph,
    left: Graph::CommitId,
    right: Graph::CommitId,
    limits: MergeBaseLimits,
) -> Result<MergeBaseResult<Graph::CommitId>, MergeBaseError<Graph::CommitId, Graph::Error>>
where
    Graph: CommitGraph,
{
    let snapshot = load_graph(graph, [left.clone(), right.clone()], limits)?;
    let descendant_first = descendant_first_topology(&snapshot)?;
    let left_ancestors = ancestors_of(&snapshot, &left)?;
    let right_ancestors = ancestors_of(&snapshot, &right)?;
    let common: BTreeSet<_> = left_ancestors
        .intersection(&right_ancestors)
        .cloned()
        .collect();
    if common.is_empty() {
        return Ok(MergeBaseResult::NoCommonAncestor);
    }

    let mut dominated = BTreeSet::new();
    let mut has_common_descendant = BTreeSet::new();
    for commit in descendant_first {
        let is_common = common.contains(&commit);
        let reaches_common = is_common || has_common_descendant.contains(&commit);
        if is_common && has_common_descendant.contains(&commit) {
            dominated.insert(commit.clone());
        }
        if reaches_common {
            let Some(parents) = snapshot.get(&commit) else {
                return Err(MergeBaseError::GraphClosureViolation);
            };
            has_common_descendant.extend(parents.iter().cloned());
        }
    }
    let bases = common.difference(&dominated).cloned().collect();
    Ok(MergeBaseResult::Bases(bases))
}

fn descendant_first_topology<CommitId, SourceError>(
    snapshot: &BTreeMap<CommitId, Vec<CommitId>>,
) -> Result<Vec<CommitId>, MergeBaseError<CommitId, SourceError>>
where
    CommitId: Clone + Ord,
{
    let mut incoming: BTreeMap<_, usize> =
        snapshot.keys().cloned().map(|commit| (commit, 0)).collect();
    for parents in snapshot.values() {
        for parent in parents {
            let Some(degree) = incoming.get_mut(parent) else {
                return Err(MergeBaseError::GraphClosureViolation);
            };
            *degree = degree
                .checked_add(1)
                .ok_or(MergeBaseError::GraphClosureViolation)?;
        }
    }
    let mut ready: BTreeSet<_> = incoming
        .iter()
        .filter_map(|(commit, degree)| (*degree == 0).then(|| commit.clone()))
        .collect();
    let mut ordered = Vec::with_capacity(snapshot.len());
    while let Some(commit) = ready.iter().next().cloned() {
        ready.remove(&commit);
        ordered.push(commit.clone());
        let Some(parents) = snapshot.get(&commit) else {
            return Err(MergeBaseError::GraphClosureViolation);
        };
        for parent in parents {
            let Some(degree) = incoming.get_mut(parent) else {
                return Err(MergeBaseError::GraphClosureViolation);
            };
            *degree -= 1;
            if *degree == 0 {
                ready.insert(parent.clone());
            }
        }
    }
    if ordered.len() == snapshot.len() {
        Ok(ordered)
    } else {
        Err(MergeBaseError::Cycle)
    }
}

fn load_graph<Graph, Starts>(
    graph: &Graph,
    starts: Starts,
    limits: MergeBaseLimits,
) -> Result<
    BTreeMap<Graph::CommitId, Vec<Graph::CommitId>>,
    MergeBaseError<Graph::CommitId, Graph::Error>,
>
where
    Graph: CommitGraph,
    Starts: IntoIterator<Item = Graph::CommitId>,
{
    let mut pending: BTreeSet<_> = starts.into_iter().collect();
    let mut snapshot = BTreeMap::new();
    let mut edge_count = 0_usize;
    while let Some(commit) = pending.iter().next().cloned() {
        pending.remove(&commit);
        if snapshot.contains_key(&commit) {
            continue;
        }
        if snapshot.len() == limits.max_commits {
            return Err(MergeBaseError::CommitLimitExceeded {
                limit: limits.max_commits,
            });
        }
        let ParentSet::Complete(mut parents) =
            graph.parents_of(&commit).map_err(MergeBaseError::Source)?
        else {
            return Err(MergeBaseError::ShallowBoundary { commit });
        };
        parents.sort();
        if parents.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(MergeBaseError::DuplicateParent { commit });
        }
        edge_count =
            edge_count
                .checked_add(parents.len())
                .ok_or(MergeBaseError::EdgeLimitExceeded {
                    limit: limits.max_edges,
                })?;
        if edge_count > limits.max_edges {
            return Err(MergeBaseError::EdgeLimitExceeded {
                limit: limits.max_edges,
            });
        }
        pending.extend(parents.iter().cloned());
        snapshot.insert(commit, parents);
    }
    Ok(snapshot)
}

fn ancestors_of<CommitId, SourceError>(
    snapshot: &BTreeMap<CommitId, Vec<CommitId>>,
    start: &CommitId,
) -> Result<BTreeSet<CommitId>, MergeBaseError<CommitId, SourceError>>
where
    CommitId: Clone + Ord,
{
    let mut pending = BTreeSet::from([start.clone()]);
    let mut ancestors = BTreeSet::new();
    while let Some(commit) = pending.iter().next().cloned() {
        pending.remove(&commit);
        if !ancestors.insert(commit.clone()) {
            continue;
        }
        let Some(parents) = snapshot.get(&commit) else {
            return Err(MergeBaseError::GraphClosureViolation);
        };
        pending.extend(parents.iter().cloned());
    }
    Ok(ancestors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> DiffLimits {
        DiffLimits {
            max_input_bytes: 1024,
            max_units: 1024,
            max_work: 100_000,
            max_trace_cells: 100_000,
        }
    }

    #[test]
    fn myers_line_script_replays_and_spans_are_exact() {
        let old = b"alpha\nbeta\ngamma\n";
        let new = b"alpha\nbeta\ndelta\ngamma\n";
        let result = diff(old, new, DiffOptions::myers_lines(limits())).expect("diff");
        assert_eq!(result.apply_to(old), Ok(new.to_vec()));
        assert_eq!(result.profile, DiffProfile::MyersMinimal);
        assert!(matches!(result.edits[0], Edit::Equal { .. }));
        assert!(matches!(result.edits[1], Edit::Equal { .. }));
        assert_eq!(
            result.edits[2],
            Edit::Insert {
                old: Span {
                    byte_start: 11,
                    byte_end: 11,
                    unit_start: 2,
                    unit_end: 2,
                },
                new: Span {
                    byte_start: 11,
                    byte_end: 17,
                    unit_start: 2,
                    unit_end: 3,
                },
                bytes: b"delta\n".to_vec(),
            }
        );
        assert!(matches!(result.edits[3], Edit::Equal { .. }));
    }

    #[test]
    fn profile_results_are_deterministic_on_empty_identical_and_disjoint_inputs() {
        for profile in [
            DiffProfile::MyersMinimal,
            DiffProfile::Patience,
            DiffProfile::Histogram,
        ] {
            let options = DiffOptions {
                profile,
                granularity: SequenceGranularity::Bytes,
                limits: limits(),
            };
            for (old, new) in [
                (b"".as_slice(), b"".as_slice()),
                (b"same", b"same"),
                (b"ab", b"XY"),
            ] {
                let first = diff(old, new, options).expect("first diff");
                let second = diff(old, new, options).expect("second diff");
                assert_eq!(first, second);
                assert_eq!(first.edits, second.edits);
                assert_eq!(first.apply_to(old), Ok(new.to_vec()));
            }
        }
    }

    #[test]
    fn patience_anchors_unique_lines_and_replays() {
        let old = b"header\nleft\nanchor\nright\nfooter\n";
        let new = b"header\nleft changed\nanchor\nright\nfooter\n";
        let result = diff(old, new, DiffOptions::patience_lines(limits())).expect("diff");
        assert_eq!(result.algorithm, DiffAlgorithm::PatienceAnchored);
        assert_eq!(result.apply_to(old), Ok(new.to_vec()));
        assert_eq!(result.hunks().len(), 1);
        assert_eq!(
            result
                .edits
                .iter()
                .map(|edit| match edit {
                    Edit::Equal { .. } => "=",
                    Edit::Delete { .. } => "-",
                    Edit::Insert { .. } => "+",
                })
                .collect::<Vec<_>>(),
            vec!["=", "+", "-", "=", "=", "="]
        );
    }

    #[test]
    fn histogram_selects_the_lowest_rarity_anchor_with_a_stable_script() {
        let old = b"header\nleft\nanchor\nright\nfooter\n";
        let new = b"header\nleft changed\nanchor\nright\nfooter\n";
        let result = diff(old, new, DiffOptions::histogram_lines(limits())).expect("diff");
        assert_eq!(result.algorithm, DiffAlgorithm::HistogramAnchored);
        assert_eq!(result.apply_to(old), Ok(new.to_vec()));
        assert_eq!(
            result
                .edits
                .iter()
                .map(|edit| match edit {
                    Edit::Equal { .. } => "=",
                    Edit::Delete { .. } => "-",
                    Edit::Insert { .. } => "+",
                })
                .collect::<Vec<_>>(),
            vec!["=", "+", "-", "=", "=", "="]
        );
    }

    #[test]
    fn input_and_work_limits_refuse_before_unbounded_work() {
        let input_error = diff(
            b"abcd",
            b"efgh",
            DiffOptions::myers_lines(DiffLimits {
                max_input_bytes: 4,
                ..limits()
            }),
        )
        .expect_err("combined bytes exceed bound");
        assert!(matches!(input_error, DiffError::InputBytesExceeded { .. }));

        let units_error = diff(
            b"a",
            b"b",
            DiffOptions {
                profile: DiffProfile::MyersMinimal,
                granularity: SequenceGranularity::Bytes,
                limits: DiffLimits {
                    max_units: 1,
                    ..limits()
                },
            },
        )
        .expect_err("unit count exceeds bound before token allocation");
        assert_eq!(
            units_error,
            DiffError::UnitsExceeded {
                limit: 1,
                actual: 2,
            }
        );

        let work_error = diff(
            b"a\nb\nc\n",
            b"x\ny\nz\n",
            DiffOptions::myers_lines(DiffLimits {
                max_work: 1,
                ..limits()
            }),
        )
        .expect_err("work exceeds bound");
        assert!(matches!(work_error, DiffError::WorkExceeded { .. }));

        let huge = vec![b'x'; 4096];
        assert_eq!(
            diff(
                &huge,
                &huge,
                DiffOptions::myers_lines(DiffLimits {
                    max_input_bytes: 64,
                    ..limits()
                })
            ),
            Err(DiffError::InputBytesExceeded {
                limit: 64,
                actual: 8192,
            })
        );
    }

    #[test]
    fn myers_trace_limit_selects_the_receipted_linear_space_refinement() {
        let result = diff(
            b"left\n",
            b"right\n",
            DiffOptions::myers_lines(DiffLimits {
                max_trace_cells: 1,
                ..limits()
            }),
        )
        .expect("linear-space refinement");
        assert_eq!(result.algorithm, DiffAlgorithm::MyersLinearRefinement);
        assert_eq!(result.apply_to(b"left\n"), Ok(b"right\n".to_vec()));
    }

    #[test]
    fn tree_diff_classifies_add_delete_modify_and_mode_change_in_path_order() {
        let old = vec![
            TreeEntry {
                path: b"a".to_vec(),
                mode: TreeMode(0o100644),
                object: 1_u8,
            },
            TreeEntry {
                path: b"b".to_vec(),
                mode: TreeMode(0o100644),
                object: 2,
            },
            TreeEntry {
                path: b"gone".to_vec(),
                mode: TreeMode(0o100644),
                object: 3,
            },
        ];
        let new = vec![
            TreeEntry {
                path: b"a".to_vec(),
                mode: TreeMode(0o100755),
                object: 1,
            },
            TreeEntry {
                path: b"b".to_vec(),
                mode: TreeMode(0o100644),
                object: 4,
            },
            TreeEntry {
                path: b"new".to_vec(),
                mode: TreeMode(0o100644),
                object: 5,
            },
        ];
        let result = diff_trees(old, new, TreeDiffOptions::default()).expect("tree diff");
        assert!(matches!(result.changes[0], TreeChange::ModeChanged { .. }));
        assert!(matches!(result.changes[1], TreeChange::Modified { .. }));
        assert!(matches!(result.changes[2], TreeChange::Deleted(_)));
        assert!(matches!(result.changes[3], TreeChange::Added(_)));
    }

    #[test]
    fn tree_diff_refuses_unsorted_entries_and_unsupported_rename_similarity() {
        let unsorted = vec![
            TreeEntry {
                path: b"b".to_vec(),
                mode: TreeMode(0o100644),
                object: 1_u8,
            },
            TreeEntry {
                path: b"a".to_vec(),
                mode: TreeMode(0o100644),
                object: 2,
            },
        ];
        assert_eq!(
            diff_trees(unsorted, Vec::new(), TreeDiffOptions::default()),
            Err(TreeDiffError::UnsortedOrDuplicatePath)
        );
        assert_eq!(
            diff_trees::<u8, _, _>(
                Vec::new(),
                Vec::new(),
                TreeDiffOptions {
                    rename: RenameProfile::ExactObject {
                        minimum_similarity_percent: 99,
                        max_candidate_pairs: 1,
                    },
                    ..TreeDiffOptions::default()
                },
            ),
            Err(TreeDiffError::UnsupportedSimilarityThreshold { requested: 99 })
        );

        let one_entry = vec![TreeEntry {
            path: b"a".to_vec(),
            mode: TreeMode(0o100644),
            object: 1_u8,
        }];
        assert_eq!(
            diff_trees(
                one_entry.clone(),
                Vec::new(),
                TreeDiffOptions {
                    limits: TreeDiffLimits {
                        max_entries_per_tree: 0,
                        ..TreeDiffLimits::default()
                    },
                    ..TreeDiffOptions::default()
                },
            ),
            Err(TreeDiffError::EntryLimitExceeded { limit: 0 })
        );
        assert_eq!(
            diff_trees(
                one_entry,
                Vec::new(),
                TreeDiffOptions {
                    limits: TreeDiffLimits {
                        max_changes: 0,
                        ..TreeDiffLimits::default()
                    },
                    ..TreeDiffOptions::default()
                },
            ),
            Err(TreeDiffError::ChangeLimitExceeded { limit: 0 })
        );
    }

    #[test]
    fn tree_diff_accepts_git_directory_sort_order() {
        let entries = vec![
            TreeEntry {
                path: b"foo.bar".to_vec(),
                mode: TreeMode(0o100644),
                object: 1_u8,
            },
            TreeEntry {
                path: b"foo".to_vec(),
                mode: TreeMode(0o040000),
                object: 2,
            },
        ];
        let result = diff_trees(Vec::new(), entries, TreeDiffOptions::default())
            .expect("Git tree order is accepted");
        assert_eq!(result.changes.len(), 2);
    }

    #[test]
    fn exact_object_rename_profile_receipts_a_permitted_rename_deterministically() {
        let old = vec![TreeEntry {
            path: b"before".to_vec(),
            mode: TreeMode(0o100644),
            object: 7_u8,
        }];
        let new = vec![TreeEntry {
            path: b"after".to_vec(),
            mode: TreeMode(0o100644),
            object: 7_u8,
        }];
        let result = diff_trees(
            old,
            new,
            TreeDiffOptions {
                rename: RenameProfile::ExactObject {
                    minimum_similarity_percent: 100,
                    max_candidate_pairs: 1,
                },
                ..TreeDiffOptions::default()
            },
        )
        .expect("exact-object rename");
        assert_eq!(
            result.changes,
            vec![TreeChange::Renamed {
                before: TreeEntry {
                    path: b"before".to_vec(),
                    mode: TreeMode(0o100644),
                    object: 7_u8,
                },
                after: TreeEntry {
                    path: b"after".to_vec(),
                    mode: TreeMode(0o100644),
                    object: 7_u8,
                },
                similarity_percent: 100,
            }]
        );
    }

    #[derive(Default)]
    struct Graph {
        parents: BTreeMap<&'static str, ParentSet<&'static str>>,
    }

    impl Graph {
        fn with_edges(edges: &[(&'static str, &[&'static str])]) -> Self {
            let mut graph = Self::default();
            for (commit, parents) in edges {
                graph
                    .parents
                    .insert(*commit, ParentSet::Complete(parents.to_vec()));
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
        ) -> Result<ParentSet<Self::CommitId>, Self::Error> {
            Ok(self
                .parents
                .get(commit)
                .cloned()
                .unwrap_or_else(|| ParentSet::Complete(Vec::new())))
        }
    }

    #[test]
    fn merge_base_handles_linear_simple_and_disconnected_histories() {
        let graph = Graph::with_edges(&[
            ("a", &[]),
            ("b", &["a"]),
            ("c", &["a"]),
            ("d", &["b"]),
            ("merge", &["b", "c"]),
            ("other", &[]),
        ]);
        assert_eq!(
            merge_bases_all(&graph, "d", "b", MergeBaseLimits::default()),
            Ok(MergeBaseResult::Bases(vec!["b"]))
        );
        assert_eq!(
            merge_bases_all(&graph, "merge", "c", MergeBaseLimits::default()),
            Ok(MergeBaseResult::Bases(vec!["c"]))
        );
        assert_eq!(
            merge_bases_all(&graph, "merge", "other", MergeBaseLimits::default()),
            Ok(MergeBaseResult::NoCommonAncestor)
        );
    }

    #[test]
    fn merge_base_returns_all_criss_cross_and_octopus_best_ancestors() {
        let criss_cross = Graph::with_edges(&[
            ("a", &[]),
            ("b", &["a"]),
            ("c", &["a"]),
            ("d", &["b", "c"]),
            ("e", &["c", "b"]),
        ]);
        assert_eq!(
            merge_bases_all(&criss_cross, "d", "e", MergeBaseLimits::default()),
            Ok(MergeBaseResult::Bases(vec!["b", "c"]))
        );

        let octopus = Graph::with_edges(&[
            ("a", &[]),
            ("b", &["a"]),
            ("c", &["a"]),
            ("d", &["a"]),
            ("x", &["b", "c", "d"]),
            ("y", &["c", "d"]),
        ]);
        assert_eq!(
            merge_bases_all(&octopus, "x", "y", MergeBaseLimits::default()),
            Ok(MergeBaseResult::Bases(vec!["c", "d"]))
        );
    }

    #[test]
    fn merge_base_refuses_shallow_and_cyclic_graphs() {
        let mut shallow = Graph::with_edges(&[("a", &[]), ("b", &["a"])]);
        shallow.parents.insert("a", ParentSet::ShallowBoundary);
        assert!(matches!(
            merge_bases_all(&shallow, "b", "a", MergeBaseLimits::default()),
            Err(MergeBaseError::ShallowBoundary { .. })
        ));

        let cycle = Graph::with_edges(&[("a", &["b"]), ("b", &["a"])]);
        assert!(matches!(
            merge_bases_all(&cycle, "a", "b", MergeBaseLimits::default()),
            Err(MergeBaseError::Cycle)
        ));

        let limited = Graph::with_edges(&[("a", &[]), ("b", &["a"])]);
        assert_eq!(
            merge_bases_all(
                &limited,
                "b",
                "a",
                MergeBaseLimits {
                    max_commits: 1,
                    max_edges: 1,
                },
            ),
            Err(MergeBaseError::CommitLimitExceeded { limit: 1 })
        );
    }
}
