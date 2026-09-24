//! Bounded RFC 1952 metadata admission. This parser never retains or interprets
//! names, comments or extra fields, and never exposes them to filesystem code.
//! The enclosing decoder owns cancellation and permanent failure poisoning.

use super::{HttpError, crc_byte};

#[derive(Clone, Copy)]
enum Phase {
    Fixed(u8),
    ExtraLow,
    ExtraHigh(u8),
    Extra(u16),
    Name,
    Comment,
    CrcLow,
    CrcHigh(u8),
    Complete,
}

pub(super) struct Header {
    phase: Phase,
    pending_flags: u8,
    crc: u32,
    bytes: usize,
    limit: usize,
}

impl Header {
    pub(super) const fn new(limit: usize) -> Self {
        Self {
            phase: Phase::Fixed(0),
            pending_flags: 0,
            crc: u32::MAX,
            bytes: 0,
            limit,
        }
    }

    pub(super) const fn is_complete(&self) -> bool {
        matches!(self.phase, Phase::Complete)
    }

    // RFC 1952 orders FHCRC last, despite its lower flag bit.
    fn next_optional(&mut self) -> Phase {
        for (flag, phase) in [
            (4, Phase::ExtraLow),
            (8, Phase::Name),
            (16, Phase::Comment),
            (2, Phase::CrcLow),
        ] {
            if self.pending_flags & flag != 0 {
                self.pending_flags &= !flag;
                return phase;
            }
        }
        Phase::Complete
    }

    pub(super) fn push(&mut self, input: &[u8]) -> Result<usize, HttpError> {
        let mut consumed = 0;
        for &byte in input {
            if self.is_complete() {
                break;
            }
            // Header bytes are body bytes, so this refusal is HTTP 413, not a
            // claim that the already accepted HTTP request head exceeded 431.
            if self.bytes == self.limit {
                return Err(HttpError::BodyTooLarge);
            }
            self.bytes += 1;
            consumed += 1;
            if !matches!(self.phase, Phase::CrcLow | Phase::CrcHigh(_)) {
                self.crc = crc_byte(self.crc, byte);
            }
            self.phase = match self.phase {
                Phase::Fixed(index) => {
                    if (index < 3 && byte != [0x1f, 0x8b, 8][usize::from(index)])
                        || (index == 3 && byte & 0xe0 != 0)
                    {
                        return Err(HttpError::InvalidCompressedBody);
                    }
                    if index == 3 {
                        self.pending_flags = byte & 0x1e; // FTEXT is advisory.
                    }
                    if index == 9 {
                        self.next_optional()
                    } else {
                        Phase::Fixed(index + 1)
                    }
                }
                Phase::ExtraLow => Phase::ExtraHigh(byte),
                Phase::ExtraHigh(low) => {
                    let count = u16::from_le_bytes([low, byte]);
                    if count == 0 {
                        self.next_optional()
                    } else {
                        Phase::Extra(count)
                    }
                }
                Phase::Extra(1) => self.next_optional(),
                Phase::Extra(remaining) => Phase::Extra(remaining - 1),
                Phase::Name | Phase::Comment if byte == 0 => self.next_optional(),
                Phase::Name => Phase::Name,
                Phase::Comment => Phase::Comment,
                Phase::CrcLow => Phase::CrcHigh(byte),
                Phase::CrcHigh(low) => {
                    let actual = (!self.crc).to_le_bytes();
                    if [low, byte] != [actual[0], actual[1]] {
                        return Err(HttpError::InvalidCompressedBody);
                    }
                    Phase::Complete
                }
                Phase::Complete => break,
            };
        }
        Ok(consumed)
    }
}
