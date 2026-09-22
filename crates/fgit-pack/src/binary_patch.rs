//! Git binary-patch literals and deltas, decoded without a checkout or object
//! lookup. Both native identities and any supplied reverse image are checked.
//! This produces bytes, never a ref update, staging receipt or authorization.

use crate::{Deadline, ObjectId, PackError, PackLimits, apply_delta};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_deflate::{CancellationProbe, InflateLimits, InflateRefusal, Inflater};

mod batch;
pub use batch::{BinaryPatchBatch, BinaryPatchUsage};

const ALPHABET: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
const DECODE: [u8; 256] = {
    let mut table = [u8::MAX; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Narrowable limits on one complete forward/reverse binary patch. Expanded
/// bytes include the source, both inflated members, and reconstructed deltas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryPatchLimits {
    pub max_input_bytes: usize,
    pub max_file_bytes: usize,
    pub max_expanded_bytes: usize,
    pub max_lines: usize,
    pub max_inflate_work: u64,
    pub max_delta_work: usize,
}
impl Default for BinaryPatchLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024 * 1024,
            max_file_bytes: 8 * 1024 * 1024,
            max_expanded_bytes: 32 * 1024 * 1024,
            max_lines: 262_144,
            max_inflate_work: 64 * 1024 * 1024,
            max_delta_work: 64 * 1024 * 1024,
        }
    }
}
impl BinaryPatchLimits {
    pub fn validate(self) -> Result<(), BinaryPatchError> {
        let c = Self::default();
        if self.max_inflate_work < 2
            || self.max_inflate_work > c.max_inflate_work
            || self.max_delta_work < 2
            || self.max_delta_work > c.max_delta_work
        {
            return Err(BinaryPatchError::InvalidLimits);
        }
        for (value, maximum) in [
            (self.max_input_bytes, c.max_input_bytes),
            (self.max_file_bytes, c.max_file_bytes),
            (self.max_expanded_bytes, c.max_expanded_bytes),
            (self.max_lines, c.max_lines),
        ] {
            if value == 0 || value > maximum {
                return Err(BinaryPatchError::InvalidLimits);
            }
        }
        Ok(())
    }
}

/// Diagnostics never contain source bytes, object IDs or repository paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BinaryPatchError {
    InvalidLimits,
    Cancelled,
    Limit(&'static str),
    Invalid(&'static str),
    SourceMismatch,
    TargetMismatch,
    ReverseMismatch,
}
impl std::fmt::Display for BinaryPatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "binary patch refused: {self:?}")
    }
}
impl std::error::Error for BinaryPatchError {}
fn check(deadline: &mut impl Deadline) -> Result<(), BinaryPatchError> {
    if deadline.checkpoint() {
        Ok(())
    } else {
        Err(BinaryPatchError::Cancelled)
    }
}
fn inflate_error(error: InflateRefusal) -> BinaryPatchError {
    match error {
        InflateRefusal::Cancelled => BinaryPatchError::Cancelled,
        InflateRefusal::ResourceLimit { .. } => BinaryPatchError::Limit("inflate"),
        _ => BinaryPatchError::Invalid("zlib member"),
    }
}
fn delta_error(error: PackError) -> BinaryPatchError {
    match error {
        PackError::DeadlineExceeded => BinaryPatchError::Cancelled,
        PackError::InputLimit { .. }
        | PackError::ObjectSizeLimit { .. }
        | PackError::TotalExpandedLimit { .. }
        | PackError::DeltaResultSizeLimit { .. }
        | PackError::DeltaWorkLimit { .. }
        | PackError::AllocationFailed { .. } => BinaryPatchError::Limit("delta"),
        _ => BinaryPatchError::Invalid("delta program"),
    }
}
struct Probe<'a, D>(&'a mut D);
impl<D: Deadline> CancellationProbe for Probe<'_, D> {
    fn is_cancelled(&mut self) -> bool {
        !self.0.checkpoint()
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    at: usize,
    lines: usize,
    remaining: usize,
}
impl<'a> Input<'a> {
    fn line(
        &mut self,
        limits: BinaryPatchLimits,
        deadline: &mut impl Deadline,
    ) -> Result<&'a [u8], BinaryPatchError> {
        check(deadline)?;
        if self.lines == limits.max_lines {
            return Err(BinaryPatchError::Limit("lines"));
        }
        // A Git base85 row holds at most 52 bytes in 65 digits plus its count.
        // Bound the search too: malformed multi-MiB lines do not delay cancel.
        let rest = &self.bytes[self.at..];
        let end =
            rest.iter()
                .take(67)
                .position(|b| *b == b'\n')
                .ok_or(BinaryPatchError::Invalid(
                    "unterminated or oversized record",
                ))?;
        self.at += end + 1;
        self.lines += 1;
        Ok(&rest[..end])
    }
    fn charge(&mut self, bytes: usize) -> Result<(), BinaryPatchError> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(BinaryPatchError::Limit("expanded bytes"))?;
        Ok(())
    }
}
fn decode_row(row: &[u8], output: &mut [u8; 52]) -> Result<usize, BinaryPatchError> {
    let count = match row.first() {
        Some(b'A'..=b'Z') => usize::from(row[0] - b'A') + 1,
        Some(b'a'..=b'z') => usize::from(row[0] - b'a') + 27,
        _ => return Err(BinaryPatchError::Invalid("base85 length")),
    };
    if row.len() != 1 + count.div_ceil(4) * 5 {
        return Err(BinaryPatchError::Invalid("base85 row size"));
    }
    for (i, digits) in row[1..].chunks_exact(5).enumerate() {
        let mut word = 0u32;
        for digit in digits {
            let value = DECODE[usize::from(*digit)];
            if value == u8::MAX {
                return Err(BinaryPatchError::Invalid("base85 digit"));
            }
            word = word
                .checked_mul(85)
                .and_then(|n| n.checked_add(u32::from(value)))
                .ok_or(BinaryPatchError::Invalid("base85 overflow"))?;
        }
        let bytes = word.to_be_bytes();
        let used = 4.min(count - i * 4);
        output[i * 4..i * 4 + used].copy_from_slice(&bytes[..used]);
    }
    Ok(count)
}
fn block(
    input: &mut Input<'_>,
    base: &[u8],
    limits: BinaryPatchLimits,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, BinaryPatchError> {
    let header = input.line(limits, deadline)?;
    let (delta, digits) = if let Some(n) = header.strip_prefix(b"literal ") {
        (false, n)
    } else if let Some(n) = header.strip_prefix(b"delta ") {
        (true, n)
    } else {
        return Err(BinaryPatchError::Invalid("binary hunk header"));
    };
    if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
        return Err(BinaryPatchError::Invalid("binary hunk length"));
    }
    let mut declared = 0usize;
    for digit in digits {
        if !digit.is_ascii_digit() {
            return Err(BinaryPatchError::Invalid("binary hunk length"));
        }
        declared = declared
            .checked_mul(10)
            .and_then(|n| n.checked_add(usize::from(*digit - b'0')))
            .filter(|n| *n <= limits.max_file_bytes)
            .ok_or(BinaryPatchError::Limit("hunk bytes"))?;
    }
    input.charge(declared)?;
    let policy = InflateLimits {
        max_input_bytes: limits.max_input_bytes,
        max_pending_input_bytes: limits.max_input_bytes,
        max_output_bytes: declared.max(1),
        // Reserve half for a reverse member; a one-member patch cannot borrow it.
        max_work_units: limits.max_inflate_work / 2,
        ..InflateLimits::GIT_OBJECT
    };
    let mut inflater = Inflater::new(policy).map_err(inflate_error)?;
    let mut inflated = Vec::new();
    inflated
        .try_reserve_exact(declared)
        .map_err(|_| BinaryPatchError::Limit("allocation"))?;
    let mut rows = 0;
    loop {
        let row = input.line(limits, deadline)?;
        if row.is_empty() {
            break;
        }
        let mut decoded = [0u8; 52];
        let count = decode_row(row, &mut decoded)?;
        inflater
            .push_with_control(&decoded[..count], &mut Probe(deadline))
            .map_err(inflate_error)?;
        let next = inflater.take_output();
        if next.len() > declared.saturating_sub(inflated.len()) {
            return Err(BinaryPatchError::Invalid("inflated hunk length"));
        }
        inflated.extend_from_slice(&next);
        rows += 1;
    }
    if rows == 0 {
        return Err(BinaryPatchError::Invalid("empty encoded member"));
    }
    inflater.finish().map_err(inflate_error)?;
    let next = inflater.take_output();
    if next.len() > declared.saturating_sub(inflated.len()) {
        return Err(BinaryPatchError::Invalid("inflated hunk length"));
    }
    inflated.extend_from_slice(&next);
    if inflated.len() != declared {
        return Err(BinaryPatchError::Invalid("inflated hunk length"));
    }
    check(deadline)?;
    if !delta {
        return Ok(inflated);
    }
    // Delta headers name the inflated PROGRAM length, not the result size.
    // The existing native delta engine checks both embedded sizes before alloc.
    let pack = PackLimits {
        max_input_bytes: limits.max_input_bytes,
        max_object_bytes: limits.max_file_bytes,
        max_total_expanded_bytes: input
            .remaining
            .checked_add(base.len())
            .ok_or(BinaryPatchError::Limit("expanded bytes"))?,
        max_delta_work: limits.max_delta_work / 2,
        ..PackLimits::default()
    };
    let result = apply_delta(base, &inflated, &pack, deadline).map_err(delta_error)?;
    input.charge(result.len())?;
    Ok(result)
}

/// Apply a `GIT binary patch` body with exact full native old/new identities.
/// `None` denotes an absent side, not the ID of an empty blob. A present reverse
/// member is fully decoded and must reproduce the supplied source byte-for-byte.
/// Path, mode, source selection and publication are the caller's responsibilities.
/// No object lookup, already-applied shortcut, fuzzy match or subprocess exists.
pub fn apply_binary_patch(
    bytes: &[u8],
    old: Option<ObjectId>,
    new: Option<ObjectId>,
    base: &[u8],
    limits: BinaryPatchLimits,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, BinaryPatchError> {
    decode(bytes, old, new, base, limits, deadline).map(|(body, _)| body)
}

// Private accounting comes from the actual decoder, not untrusted hunk sizes.
// The batch caller consumes these totals only after every original commitment
// and the optional reverse image have verified.
fn decode(
    bytes: &[u8],
    old: Option<ObjectId>,
    new: Option<ObjectId>,
    base: &[u8],
    limits: BinaryPatchLimits,
    deadline: &mut impl Deadline,
) -> Result<(Vec<u8>, BinaryPatchUsage), BinaryPatchError> {
    limits.validate()?;
    check(deadline)?;
    if bytes.len() > limits.max_input_bytes {
        return Err(BinaryPatchError::Limit("input bytes"));
    }
    if base.len() > limits.max_file_bytes {
        return Err(BinaryPatchError::Limit("source bytes"));
    }
    let format = old
        .or(new)
        .filter(|id| !id.is_zero())
        .ok_or(BinaryPatchError::Invalid("object identities"))?
        .algorithm();
    if [old, new]
        .into_iter()
        .flatten()
        .any(|id| id.is_zero() || id.algorithm() != format)
    {
        return Err(BinaryPatchError::Invalid("object identities"));
    }
    if old.map_or(!base.is_empty(), |id| {
        git_object_id(format, GitObjectKind::Blob, base) != id
    }) {
        return Err(BinaryPatchError::SourceMismatch);
    }
    check(deadline)?;
    let mut input = Input {
        bytes,
        at: 0,
        lines: 0,
        remaining: limits.max_expanded_bytes,
    };
    input.charge(base.len())?;
    if input.line(limits, deadline)? != b"GIT binary patch" {
        return Err(BinaryPatchError::Invalid("binary patch marker"));
    }
    let result = block(&mut input, base, limits, deadline)?;
    if new.map_or(!result.is_empty(), |id| {
        git_object_id(format, GitObjectKind::Blob, &result) != id
    }) {
        return Err(BinaryPatchError::TargetMismatch);
    }
    check(deadline)?;
    if input.at != bytes.len() {
        let reverse = block(&mut input, &result, limits, deadline)?;
        if reverse != base {
            return Err(BinaryPatchError::ReverseMismatch);
        }
    }
    if input.at != bytes.len() {
        return Err(BinaryPatchError::Invalid("trailing binary records"));
    }
    check(deadline)?;
    Ok((
        result,
        BinaryPatchUsage {
            files: 1,
            input_bytes: bytes.len(),
            expanded_bytes: limits.max_expanded_bytes - input.remaining,
            lines: input.lines,
        },
    ))
}

#[cfg(test)]
mod tests;
