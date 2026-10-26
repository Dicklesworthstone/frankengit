//! Bounded delta execution over caller-owned authenticated quarantine storage.
//! The instruction decoder is shared with the buffered scalar oracle.

use std::fmt;

use super::{ResolutionBudget, decode_copy_instruction, read_byte, read_delta_size};
use crate::{Deadline, PackError, PackLimits, checkpoint};

/// Largest base read or output chunk requested by streamed delta execution.
pub const STREAM_DELTA_CHUNK_BYTES: usize = 16 * 1024;

/// Custody of one already charged base and one tentative reconstructed result.
///
/// Authenticate the actual bytes returned by each base read against the private
/// inventory. Verifying a file once and then trusting unchecked random reads
/// does not satisfy this contract. One owner may seek between a base span and
/// an appended result in the same scratch descriptor. Output stays tentative
/// until successful execution and native identity/pack/graph verification.
pub trait DeltaStreamIo {
    type Error;

    /// Starts private result custody after declared sizes and budgets pass.
    /// This is also the place to verify/index the base. One complete base read
    /// has already been charged to the shared work budget before this call.
    fn begin_result(
        &mut self,
        length: usize,
        deadline: &mut impl Deadline,
    ) -> Result<(), Self::Error>;

    /// Reads at the exact base-relative offset. Short positive reads are valid;
    /// zero or an oversized count refuses. Each request is at most 16 KiB.
    ///
    /// Additional physical work, such as reading and verifying a whole scratch
    /// block for a one-byte copy, must be charged to `budget` before that work.
    /// Logical output work and the initial complete base read are charged by
    /// the executor. Retain the selected `PackLimits` for any additional
    /// [`ResolutionBudget::charge_work`] calls.
    fn read_base(
        &mut self,
        offset: usize,
        output: &mut [u8],
        budget: &mut ResolutionBudget,
        deadline: &mut impl Deadline,
    ) -> Result<usize, Self::Error>;

    /// Accepts a complete bounded chunk into private result custody. An error
    /// cannot turn earlier chunks into a successful reconstruction.
    fn write_result(
        &mut self,
        bytes: &[u8],
        deadline: &mut impl Deadline,
    ) -> Result<(), Self::Error>;
}

/// Preserves malformed input, quarantine failures, and broken read contracts.
/// No variant yields a completed result or resets spent work.
#[derive(Debug, PartialEq, Eq)]
pub enum StreamDeltaError<E> {
    Pack(PackError),
    Io(E),
    InvalidBaseRead { requested: usize, received: usize },
}

impl<E: fmt::Display> fmt::Display for StreamDeltaError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pack(error) => write!(f, "streamed delta refused: {error}"),
            Self::Io(error) => write!(f, "streamed delta quarantine: {error}"),
            Self::InvalidBaseRead {
                requested,
                received,
            } => write!(
                f,
                "streamed delta base returned {received} bytes for a {requested}-byte read"
            ),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for StreamDeltaError<E> {}
impl<E> From<PackError> for StreamDeltaError<E> {
    fn from(error: PackError) -> Self {
        Self::Pack(error)
    }
}

/// Reads only the two declared sizes, without validating instructions or
/// authenticating a base. Consumers can select a bounded storage strategy
/// before executing the same program through either scalar or streamed APIs.
pub fn delta_declared_sizes(
    delta: &[u8],
    deadline: &mut impl Deadline,
) -> Result<(usize, usize), PackError> {
    let mut cursor = 0;
    let base = read_delta_size(delta, &mut cursor, "delta base size", deadline)?;
    let result = read_delta_size(delta, &mut cursor, "delta result size", deadline)?;
    Ok((base, result))
}

/// Applies an inflated delta without allocating the base or result body.
///
/// The authenticated base must already have been charged to `budget`, as for
/// [`super::apply_delta_to_charged_base_with_budget`]. Its type and identity are
/// caller responsibilities. `limits.max_object_bytes` bounds both its declared
/// length and the new result; select a separate blob allowance only after
/// authenticating the inherited type. The bounded program stays borrowed and
/// the executor uses one 16 KiB buffer.
///
/// Successful execution has the scalar oracle's bytes and logical work charge.
/// Reserve the result allowance before the first callback, so an interrupted
/// stream cannot reuse that expanded-byte budget. The I/O owner charges extra
/// physical reads through the same budget. Cancellation checks bracket every
/// callback, including the final write. A successful byte count alone is not a
/// native object identity or a publication receipt.
pub fn apply_delta_streamed_to_charged_base_with_budget<I: DeltaStreamIo>(
    base_length: usize,
    delta: &[u8],
    limits: &PackLimits,
    budget: &mut ResolutionBudget,
    io: &mut I,
    deadline: &mut impl Deadline,
) -> Result<usize, StreamDeltaError<I::Error>> {
    checkpoint(deadline)?;
    limits.input(delta.len())?;
    limits.object_size(base_length)?;
    let mut cursor = 0;
    let declared_base = read_delta_size(delta, &mut cursor, "delta base size", deadline)?;
    if declared_base != base_length {
        return Err(PackError::DeltaBaseSizeMismatch {
            declared: declared_base,
            actual: base_length,
        }
        .into());
    }
    let declared_result = read_delta_size(delta, &mut cursor, "delta result size", deadline)?;
    if declared_result > limits.max_object_bytes {
        return Err(PackError::DeltaResultSizeLimit {
            declared: declared_result,
            limit: limits.max_object_bytes,
        }
        .into());
    }
    budget.accounting.ensure_expanded(declared_result, limits)?;
    budget.charge_work(base_length, limits)?;
    budget.charge_expanded(declared_result, limits)?;
    checkpoint(deadline)?;
    let started = io.begin_result(declared_result, deadline);
    checkpoint(deadline)?;
    started.map_err(StreamDeltaError::Io)?;

    let mut written = 0_usize;
    let mut buffer = [0_u8; STREAM_DELTA_CHUNK_BYTES];
    while cursor < delta.len() {
        checkpoint(deadline)?;
        let instruction = read_byte(delta, &mut cursor, "delta instruction", deadline)?;
        if instruction == 0 {
            return Err(PackError::InvalidDeltaInstruction.into());
        }
        let (offset, length, insert) = if instruction & 0x80 == 0 {
            let length = usize::from(instruction);
            let end = cursor
                .checked_add(length)
                .ok_or(PackError::IntegerOverflow {
                    context: "delta insert range",
                })?;
            let bytes = delta.get(cursor..end).ok_or(PackError::Truncated {
                context: "delta insert data",
            })?;
            cursor = end;
            (0, length, Some(bytes))
        } else {
            let (offset, length) =
                decode_copy_instruction(instruction, delta, &mut cursor, deadline)?;
            let end = offset
                .checked_add(length)
                .ok_or(PackError::IntegerOverflow {
                    context: "delta copy range",
                })?;
            if end > base_length {
                return Err(PackError::DeltaCopyOutOfRange {
                    offset,
                    length,
                    base_len: base_length,
                }
                .into());
            }
            (offset, length, None)
        };
        let next = written
            .checked_add(length)
            .ok_or(PackError::IntegerOverflow {
                context: "delta result length",
            })?;
        if next > declared_result {
            return Err(PackError::DeltaResultSizeMismatch {
                declared: declared_result,
                actual: next,
            }
            .into());
        }
        budget.charge_work(length, limits)?;
        if let Some(bytes) = insert {
            // Git inserts are at most 127 bytes, below the chunk bound.
            checkpoint(deadline)?;
            let result = io.write_result(bytes, deadline);
            checkpoint(deadline)?;
            result.map_err(StreamDeltaError::Io)?;
        } else {
            let mut copied = 0;
            while copied < length {
                checkpoint(deadline)?;
                let offered = (length - copied).min(buffer.len());
                let read = io.read_base(offset + copied, &mut buffer[..offered], budget, deadline);
                checkpoint(deadline)?;
                let count = read.map_err(StreamDeltaError::Io)?;
                if count == 0 || count > offered {
                    return Err(StreamDeltaError::InvalidBaseRead {
                        requested: offered,
                        received: count,
                    });
                }
                let result = io.write_result(&buffer[..count], deadline);
                checkpoint(deadline)?;
                result.map_err(StreamDeltaError::Io)?;
                copied += count;
            }
        }
        written = next;
    }
    if written != declared_result {
        return Err(PackError::DeltaResultSizeMismatch {
            declared: declared_result,
            actual: written,
        }
        .into());
    }
    checkpoint(deadline)?;
    Ok(written)
}
