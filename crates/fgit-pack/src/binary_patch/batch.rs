//! One nonrenewable decode budget for every compressed file in a patch.
use super::{BinaryPatchError, BinaryPatchLimits, Deadline, ObjectId, decode};

/// Successful native decoding work, not staging or publication evidence.
/// Expanded bytes include original sources, inflated members, and delta results.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BinaryPatchUsage {
    pub files: usize,
    pub input_bytes: usize,
    pub expanded_bytes: usize,
    pub lines: usize,
}

/// Share byte/line ceilings across a known, bounded set of binary files.
///
/// The declared count reserves equal, nontransferable inflate/delta work shares
/// before the first decode. Shares are ceilings, not measured work. Unused work
/// is deliberately not lent to another file; the per-member split in the native
/// decoder is unchanged. The sum of decode-work ceilings stays within one envelope.
/// Source/output sizes and cancellation remain independent bounds.
///
/// Any refusal poisons this attempt, including cancellation or a corrupt reverse
/// image. A caller cannot repeatedly spend an unaccounted failed decode and then
/// continue the batch. Previously returned bytes remain tentative until the
/// caller's complete patch validates; this object has no publication operation.
#[derive(Debug)]
pub struct BinaryPatchBatch {
    limits: BinaryPatchLimits,
    files: usize,
    usage: BinaryPatchUsage,
    poisoned: bool,
}
impl BinaryPatchBatch {
    pub fn new(mut limits: BinaryPatchLimits, files: usize) -> Result<Self, BinaryPatchError> {
        limits.validate()?;
        if files == 0 || files > 1024 { return Err(BinaryPatchError::InvalidLimits); }
        // Reserve the whole work envelope exactly once. Rounding only narrows.
        limits.max_inflate_work /= files as u64;
        limits.max_delta_work /= files;
        limits.validate()?;
        Ok(Self { limits, files, usage: BinaryPatchUsage::default(), poisoned: false })
    }

    #[must_use]
    pub const fn usage(&self) -> BinaryPatchUsage { self.usage }

    pub fn apply(&mut self, bytes: &[u8], old: Option<ObjectId>, new: Option<ObjectId>,
        base: &[u8], deadline: &mut impl Deadline,
    ) -> Result<Vec<u8>, BinaryPatchError> {
        if self.poisoned { return Err(BinaryPatchError::Invalid("binary batch already refused")); }
        self.poisoned = true;
        if self.usage.files == self.files { return Err(BinaryPatchError::Limit("binary files")); }
        let limits = BinaryPatchLimits {
            max_input_bytes: self.limits.max_input_bytes - self.usage.input_bytes,
            max_expanded_bytes: self.limits.max_expanded_bytes - self.usage.expanded_bytes,
            max_lines: self.limits.max_lines - self.usage.lines,
            ..self.limits
        };
        if limits.max_input_bytes == 0 || limits.max_expanded_bytes == 0 || limits.max_lines == 0 {
            return Err(BinaryPatchError::Limit("binary batch exhausted"));
        }
        let (body, used) = decode(bytes, old, new, base, limits, deadline)?;
        // decode enforces every remaining allowance before returning these
        // totals, so none of the additions can exceed the validated envelope.
        self.usage.files += 1;
        self.usage.input_bytes += used.input_bytes;
        self.usage.expanded_bytes += used.expanded_bytes;
        self.usage.lines += used.lines;
        self.poisoned = false;
        Ok(body)
    }
}

#[cfg(test)]
mod tests;
