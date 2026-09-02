//! Incremental pack-stream boundary detection for duplex transports.
//!
//! A pack has no outer length framing: its end is knowable only by parsing —
//! the 12-byte header names the object count, every object is a bounded entry
//! header plus one self-delimiting zlib member, and the stream closes with a
//! trailer digest. Upstream Git's `receive-pack` learns the boundary the same
//! way, by letting `index-pack` consume exactly the pack from the socket.
//!
//! [`PackBoundaryScanner`] answers exactly one question for a transport that
//! shares a socket between an incoming pack and a subsequent response (the
//! git-daemon receive-pack service): after how many bytes does the pack end?
//! It enforces the same [`PackLimits`] admission policy as the quarantine
//! parser, discards every inflated byte immediately, and never certifies
//! object contents — full validation stays owned by the quarantine validator,
//! which re-reads the complete buffered pack. A scanner success is therefore a
//! framing fact, not an object-integrity claim.

use fgit_deflate::{Inflater, StreamProgress};

use crate::pack::{
    EntryKind, PackEntryHeader, ParsedDeltaBase, decode_entry_header, parse_delta_base,
    parse_pack_header,
};
use crate::reader::inflate_limits;
use crate::{Deadline, ObjectFormat, PackError, PackLimits, checkpoint};

/// Progress of one incremental scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanStatus {
    /// The supplied bytes end before the pack does.
    NeedInput,
    /// The pack ends exactly `pack_len` bytes into the scanned stream.
    Finished {
        /// Total pack bytes, header through trailer inclusive.
        pack_len: u64,
    },
}

enum ScanPhase {
    Header,
    EntryHeader,
    Body {
        inflater: Box<Inflater>,
        declared_size: usize,
        fed: usize,
        emitted: usize,
    },
    Trailer,
    Finished {
        pack_len: u64,
    },
}

/// Incremental scanner that finds the exact end of one pack stream.
pub struct PackBoundaryScanner {
    format: ObjectFormat,
    limits: PackLimits,
    phase: ScanPhase,
    buffered: Vec<u8>,
    consumed: u64,
    remaining_entries: u32,
    total_inflated: usize,
}

impl PackBoundaryScanner {
    /// Creates a scanner bound to one object format and admission policy.
    #[must_use]
    pub const fn new(format: ObjectFormat, limits: PackLimits) -> Self {
        Self {
            format,
            limits,
            phase: ScanPhase::Header,
            buffered: Vec::new(),
            consumed: 0,
            remaining_entries: 0,
            total_inflated: 0,
        }
    }

    /// Total stream bytes the scanner has accepted so far.
    #[must_use]
    pub const fn accepted_bytes(&self) -> u64 {
        self.consumed
    }

    /// Bytes supplied beyond the finished pack.
    ///
    /// A conforming client sends nothing after the trailer, so the transport
    /// treats a non-empty excess as a protocol violation rather than data.
    #[must_use]
    pub fn excess_bytes(&self) -> &[u8] {
        match self.phase {
            ScanPhase::Finished { .. } => &self.buffered,
            _ => &[],
        }
    }

    /// Accepts the next stream fragment and reports whether the pack ended.
    ///
    /// # Errors
    ///
    /// Every structural refusal of the underlying header, delta-base, and
    /// DEFLATE decoders, plus the scanner's own input, entry-count, object
    /// size, and total-expansion ceilings. After an error the scanner is
    /// poisoned and further pushes keep refusing.
    pub fn push(
        &mut self,
        input: &[u8],
        deadline: &mut impl Deadline,
    ) -> Result<ScanStatus, PackError> {
        if let ScanPhase::Finished { pack_len } = self.phase {
            if !input.is_empty() {
                self.buffered.extend_from_slice(input);
            }
            return Ok(ScanStatus::Finished { pack_len });
        }
        let already = self
            .consumed
            .checked_add(u64::try_from(self.buffered.len()).unwrap_or(u64::MAX))
            .and_then(|value| value.checked_add(u64::try_from(input.len()).unwrap_or(u64::MAX)))
            .ok_or(PackError::IntegerOverflow {
                context: "pack scan stream length",
            })?;
        self.limits
            .input(usize::try_from(already).unwrap_or(usize::MAX))?;
        self.buffered
            .try_reserve(input.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: input.len(),
            })?;
        self.buffered.extend_from_slice(input);
        loop {
            checkpoint(deadline)?;
            match &mut self.phase {
                ScanPhase::Header => {
                    if self.buffered.len() < 12 {
                        return Ok(ScanStatus::NeedInput);
                    }
                    let header = parse_pack_header(&self.buffered[..12], &self.limits)?;
                    self.remaining_entries = header.object_count;
                    self.advance(12)?;
                    self.phase = if self.remaining_entries == 0 {
                        ScanPhase::Trailer
                    } else {
                        ScanPhase::EntryHeader
                    };
                }
                ScanPhase::EntryHeader => {
                    let entry_start = self.consumed;
                    let (header, header_len) =
                        match decode_entry_header(&self.buffered, &self.limits, deadline) {
                            Ok(decoded) => decoded,
                            Err(PackError::Truncated { .. }) => return Ok(ScanStatus::NeedInput),
                            Err(error) => return Err(error),
                        };
                    let base_len = match base_length(
                        &header,
                        entry_start,
                        &self.buffered[header_len..],
                        self.format,
                        deadline,
                    ) {
                        Ok(length) => length,
                        Err(PackError::Truncated { .. }) => return Ok(ScanStatus::NeedInput),
                        Err(error) => return Err(error),
                    };
                    let consumed_header =
                        header_len
                            .checked_add(base_len)
                            .ok_or(PackError::IntegerOverflow {
                                context: "pack scan entry header length",
                            })?;
                    self.total_inflated = self
                        .total_inflated
                        .checked_add(header.declared_size)
                        .ok_or(PackError::IntegerOverflow {
                            context: "pack scan total inflated bytes",
                        })?;
                    if self.total_inflated > self.limits.max_total_expanded_bytes {
                        return Err(PackError::TotalExpandedLimit {
                            actual: self.total_inflated,
                            limit: self.limits.max_total_expanded_bytes,
                        });
                    }
                    let inflater =
                        Inflater::new_framed(inflate_limits(&self.limits, header.declared_size))
                            .map_err(PackError::Inflate)?;
                    self.advance(consumed_header)?;
                    self.phase = ScanPhase::Body {
                        inflater: Box::new(inflater),
                        declared_size: header.declared_size,
                        fed: 0,
                        emitted: 0,
                    };
                }
                ScanPhase::Body {
                    inflater,
                    declared_size,
                    fed,
                    emitted,
                } => {
                    if self.buffered.is_empty() {
                        return Ok(ScanStatus::NeedInput);
                    }
                    let chunk_len = self.buffered.len();
                    *fed = fed
                        .checked_add(chunk_len)
                        .ok_or(PackError::IntegerOverflow {
                            context: "pack scan zlib member length",
                        })?;
                    let progress = inflater.push(&self.buffered).map_err(PackError::Inflate)?;
                    *emitted = emitted.checked_add(inflater.take_output().len()).ok_or(
                        PackError::IntegerOverflow {
                            context: "pack scan inflated bytes",
                        },
                    )?;
                    match progress {
                        StreamProgress::NeedInput => {
                            // The inflater now owns every buffered byte; its
                            // internal pending buffer carries whatever the
                            // decode has not yet bit-consumed.
                            self.consumed = self
                                .consumed
                                .checked_add(u64::try_from(chunk_len).unwrap_or(u64::MAX))
                                .ok_or(PackError::IntegerOverflow {
                                    context: "pack scan consumed bytes",
                                })?;
                            self.buffered.clear();
                            return Ok(ScanStatus::NeedInput);
                        }
                        StreamProgress::Finished => {
                            // The member finished inside this chunk: the
                            // suffix past the zlib trailer still belongs to
                            // the outer pack stream and resumes the scan.
                            let member_len = inflater.consumed_input_bytes();
                            let consumed_from_chunk = member_len
                                .checked_sub(*fed - chunk_len)
                                .ok_or(PackError::IntegerOverflow {
                                    context: "pack scan member boundary",
                                })?;
                            if consumed_from_chunk > chunk_len {
                                return Err(PackError::IntegerOverflow {
                                    context: "pack scan member boundary",
                                });
                            }
                            if *emitted != *declared_size {
                                return Err(PackError::InflatedEntrySizeMismatch {
                                    declared: *declared_size,
                                    actual: *emitted,
                                });
                            }
                            self.buffered.drain(..consumed_from_chunk);
                            self.consumed = self
                                .consumed
                                .checked_add(u64::try_from(consumed_from_chunk).unwrap_or(u64::MAX))
                                .ok_or(PackError::IntegerOverflow {
                                    context: "pack scan consumed bytes",
                                })?;
                            self.remaining_entries -= 1;
                            self.phase = if self.remaining_entries == 0 {
                                ScanPhase::Trailer
                            } else {
                                ScanPhase::EntryHeader
                            };
                        }
                    }
                }
                ScanPhase::Trailer => {
                    let trailer_len = self.format.digest_len();
                    if self.buffered.len() < trailer_len {
                        return Ok(ScanStatus::NeedInput);
                    }
                    self.advance(trailer_len)?;
                    let pack_len = self.consumed;
                    self.phase = ScanPhase::Finished { pack_len };
                    return Ok(ScanStatus::Finished { pack_len });
                }
                ScanPhase::Finished { pack_len } => {
                    let pack_len = *pack_len;
                    return Ok(ScanStatus::Finished { pack_len });
                }
            }
        }
    }

    fn advance(&mut self, bytes: usize) -> Result<(), PackError> {
        self.buffered.drain(..bytes);
        self.consumed = self
            .consumed
            .checked_add(u64::try_from(bytes).unwrap_or(u64::MAX))
            .ok_or(PackError::IntegerOverflow {
                context: "pack scan consumed bytes",
            })?;
        Ok(())
    }
}

fn base_length(
    header: &PackEntryHeader,
    entry_start: u64,
    input: &[u8],
    format: ObjectFormat,
    deadline: &mut impl Deadline,
) -> Result<usize, PackError> {
    match header.kind {
        EntryKind::OfsDelta | EntryKind::RefDelta => {
            let parsed = parse_delta_base(header.kind, entry_start, input, format, deadline)?;
            Ok(match parsed {
                ParsedDeltaBase::Ofs { consumed, .. } | ParsedDeltaBase::Ref { consumed, .. } => {
                    consumed
                }
            })
        }
        EntryKind::Commit | EntryKind::Tree | EntryKind::Blob | EntryKind::Tag => Ok(0),
    }
}
