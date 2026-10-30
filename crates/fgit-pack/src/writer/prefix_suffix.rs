//! Exact sizing before allocating a prefix/suffix delta (frankengit-1tl9).
//! A losing candidate need not copy its whole unmatched target into a program.
//! The frozen profile still compares the same encoded lengths and emits the
//! same instructions; only the winning fallback becomes owned bytes.

use super::{
    PackError, PackWriteError, emit_copy_run, emit_insert_run, encode_delta_varint, insert_run_cost,
};

const MATCH_CHUNK_BYTES: usize = 64;

pub(super) struct PrefixSuffixDelta<'a> {
    base_length: usize,
    target_length: usize,
    prefix: usize,
    middle: &'a [u8],
    suffix_start: usize,
    suffix: usize,
    encoded_length: usize,
}

impl<'a> PrefixSuffixDelta<'a> {
    pub(super) fn new(base: &[u8], target: &'a [u8]) -> Result<Self, PackWriteError> {
        let prefix = common_prefix(base, target);
        let suffix = common_suffix(base, target, prefix);
        let middle_end = target
            .len()
            .checked_sub(suffix)
            .ok_or(PackError::IntegerOverflow {
                context: "delta target middle boundary",
            })?;
        let suffix_start = base
            .len()
            .checked_sub(suffix)
            .ok_or(PackError::IntegerOverflow {
                context: "delta base suffix boundary",
            })?;
        let middle = &target[prefix..middle_end];
        // Copy costs preserve even zero-length runs' offset validation and
        // the final checked offset advance in emit_copy_run.
        let costs = [
            varint_cost(base.len())?,
            varint_cost(target.len())?,
            copy_run_cost(0, prefix)?,
            insert_run_cost(middle.len()),
            copy_run_cost(suffix_start, suffix)?,
        ];
        let encoded_length = costs.into_iter().try_fold(0_usize, |total, cost| {
            total.checked_add(cost).ok_or(PackError::IntegerOverflow {
                context: "delta prefix/suffix program bytes",
            })
        })?;
        Ok(Self {
            base_length: base.len(),
            target_length: target.len(),
            prefix,
            middle,
            suffix_start,
            suffix,
            encoded_length,
        })
    }

    pub(super) const fn len(&self) -> usize {
        self.encoded_length
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, PackWriteError> {
        let mut program = Vec::new();
        program
            .try_reserve_exact(self.encoded_length)
            .map_err(|_| PackError::AllocationFailed {
                requested: self.encoded_length,
            })?;
        encode_delta_varint(self.base_length, &mut program)?;
        encode_delta_varint(self.target_length, &mut program)?;
        emit_copy_run(0, self.prefix, &mut program)?;
        emit_insert_run(self.middle, &mut program)?;
        emit_copy_run(self.suffix_start, self.suffix, &mut program)?;
        Ok(program)
    }
}

fn varint_cost(value: usize) -> Result<usize, PackWriteError> {
    let mut value = u64::try_from(value).map_err(|_| PackError::IntegerOverflow {
        context: "delta size varint",
    })?;
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    Ok(length)
}

fn copy_run_cost(offset: usize, length: usize) -> Result<usize, PackWriteError> {
    let mut offset = u32::try_from(offset).map_err(|_| PackError::IntegerOverflow {
        context: "delta copy offset",
    })?;
    let mut remaining = length;
    let mut cost = 0_usize;
    while remaining != 0 {
        let chunk = remaining.min(0x1_0000);
        let chunk_u32 = u32::try_from(chunk).map_err(|_| PackError::IntegerOverflow {
            context: "delta copy chunk",
        })?;
        let offset_bytes = offset
            .to_le_bytes()
            .iter()
            .filter(|&&byte| byte != 0)
            .count();
        let length_bytes = if chunk == 0x1_0000 {
            0
        } else {
            chunk_u32.to_le_bytes()[..3]
                .iter()
                .filter(|&&byte| byte != 0)
                .count()
        };
        cost = cost.checked_add(1 + offset_bytes + length_bytes).ok_or(
            PackError::IntegerOverflow {
                context: "delta prefix/suffix program bytes",
            },
        )?;
        offset = offset
            .checked_add(chunk_u32)
            .ok_or(PackError::IntegerOverflow {
                context: "delta copy next offset",
            })?;
        remaining -= chunk;
    }
    Ok(cost)
}

/// Compare long equal runs in safe fixed-size chunks, then locate the exact
/// mismatch with the scalar rule. This also serves indexed match extension.
pub(super) fn common_prefix(left: &[u8], right: &[u8]) -> usize {
    let chunks = left
        .as_chunks::<MATCH_CHUNK_BYTES>()
        .0
        .iter()
        .zip(right.as_chunks::<MATCH_CHUNK_BYTES>().0)
        .take_while(|(left, right)| left == right)
        .count();
    let matched = chunks * MATCH_CHUNK_BYTES;
    matched
        + left[matched..]
            .iter()
            .zip(&right[matched..])
            .take_while(|(left, right)| left == right)
            .count()
}

pub(super) fn common_suffix(base: &[u8], target: &[u8], prefix: usize) -> usize {
    let base = &base[prefix..];
    let target = &target[prefix..];
    let chunks = base
        .rchunks_exact(MATCH_CHUNK_BYTES)
        .zip(target.rchunks_exact(MATCH_CHUNK_BYTES))
        .take_while(|(base, target)| base == target)
        .count();
    let matched = chunks * MATCH_CHUNK_BYTES;
    matched
        + base[..base.len() - matched]
            .iter()
            .rev()
            .zip(target[..target.len() - matched].iter().rev())
            .take_while(|(base, target)| base == target)
            .count()
}

/// The eager scalar encoder before frankengit-1tl9, retained independently of
/// both the cost calculation and chunk matching as their output oracle.
#[cfg(test)]
pub(super) fn scalar_program(base: &[u8], target: &[u8]) -> Result<Vec<u8>, PackWriteError> {
    let prefix = scalar_prefix(base, target);
    let suffix = scalar_suffix(base, target, prefix);
    let target_middle_end = target
        .len()
        .checked_sub(suffix)
        .ok_or(PackError::IntegerOverflow {
            context: "delta target middle boundary",
        })?;
    let base_suffix_start = base
        .len()
        .checked_sub(suffix)
        .ok_or(PackError::IntegerOverflow {
            context: "delta base suffix boundary",
        })?;
    let mut program = Vec::new();
    program
        .try_reserve(target.len().saturating_add(16))
        .map_err(|_| PackError::AllocationFailed {
            requested: target.len().saturating_add(16),
        })?;
    encode_delta_varint(base.len(), &mut program)?;
    encode_delta_varint(target.len(), &mut program)?;
    emit_copy_run(0, prefix, &mut program)?;
    emit_insert_run(&target[prefix..target_middle_end], &mut program)?;
    emit_copy_run(base_suffix_start, suffix, &mut program)?;
    Ok(program)
}

#[cfg(test)]
pub(super) fn scalar_prefix(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right)
        .take_while(|(left, right)| left == right)
        .count()
}

#[cfg(test)]
fn scalar_suffix(base: &[u8], target: &[u8], prefix: usize) -> usize {
    base[prefix..]
        .iter()
        .rev()
        .zip(target[prefix..].iter().rev())
        .take_while(|(base, target)| base == target)
        .count()
}

#[cfg(test)]
mod tests;
