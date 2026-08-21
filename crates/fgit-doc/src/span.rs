//! Byte and codepoint spans into one immutable source text.

use core::fmt;
use core::ops::Range;

use crate::limits::{offset_u32, usize_of};

/// A half-open source region carrying both byte and codepoint offsets.
///
/// Both offset families describe the same region of the same source text. A
/// span is produced only by the parser, so `byte_start` and `byte_end` always
/// land on `UTF-8` character boundaries and the codepoint offsets always agree
/// with counting characters over the corresponding byte prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Span {
    byte_start: u32,
    byte_end: u32,
    char_start: u32,
    char_end: u32,
}

impl Span {
    pub(crate) const fn new(
        byte_start: u32,
        byte_end: u32,
        char_start: u32,
        char_end: u32,
    ) -> Self {
        Self {
            byte_start,
            byte_end,
            char_start,
            char_end,
        }
    }

    /// Inclusive byte offset of the first byte in the region.
    #[must_use]
    pub const fn byte_start(self) -> u32 {
        self.byte_start
    }

    /// Exclusive byte offset one past the last byte in the region.
    #[must_use]
    pub const fn byte_end(self) -> u32 {
        self.byte_end
    }

    /// Inclusive codepoint offset of the first character in the region.
    #[must_use]
    pub const fn char_start(self) -> u32 {
        self.char_start
    }

    /// Exclusive codepoint offset one past the last character in the region.
    #[must_use]
    pub const fn char_end(self) -> u32 {
        self.char_end
    }

    /// Byte range usable for slicing the source this span was built against.
    #[must_use]
    pub fn byte_range(self) -> Range<usize> {
        usize_of(self.byte_start)..usize_of(self.byte_end)
    }

    /// Number of bytes in the region.
    #[must_use]
    pub const fn byte_len(self) -> u32 {
        self.byte_end.saturating_sub(self.byte_start)
    }

    /// Number of codepoints in the region.
    #[must_use]
    pub const fn char_len(self) -> u32 {
        self.char_end.saturating_sub(self.char_start)
    }

    /// Whether the region covers no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.byte_start >= self.byte_end
    }

    /// Whether `self` fully covers `other`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.byte_start <= other.byte_start && other.byte_end <= self.byte_end
    }

    /// The smallest span covering both regions.
    #[must_use]
    pub fn hull(self, other: Self) -> Self {
        Self {
            byte_start: self.byte_start.min(other.byte_start),
            byte_end: self.byte_end.max(other.byte_end),
            char_start: self.char_start.min(other.char_start),
            char_end: self.char_end.max(other.char_end),
        }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "bytes {}..{} chars {}..{}",
            self.byte_start, self.byte_end, self.char_start, self.char_end
        )
    }
}

/// A one-based line and column position inside a source text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LineCol {
    /// One-based line number.
    pub line: u32,
    /// One-based column measured in codepoints.
    pub column_chars: u32,
    /// One-based column measured in bytes.
    pub column_bytes: u32,
}

/// Codepoint offsets for every character start in a source text.
///
/// The table is built once per parse and used to convert byte offsets to
/// codepoint offsets in logarithmic time. It is not retained in the parsed
/// document: only the much smaller line table survives the parse.
pub(crate) struct CharIndex {
    starts: Vec<u32>,
}

impl CharIndex {
    pub(crate) fn build(source: &str) -> Self {
        let mut starts = Vec::with_capacity(source.len());
        for (offset, _) in source.char_indices() {
            starts.push(offset_u32(offset));
        }
        Self { starts }
    }

    /// Codepoint offset of the character starting at `byte_offset`.
    ///
    /// For an offset one past the end of the source this returns the total
    /// codepoint count, which is the correct exclusive end of a full-source
    /// span.
    pub(crate) fn char_of_byte(&self, byte_offset: u32) -> u32 {
        let index = self.starts.partition_point(|start| *start < byte_offset);
        offset_u32(index)
    }

    pub(crate) fn span(&self, byte_start: usize, byte_end: usize) -> Span {
        let byte_start = offset_u32(byte_start);
        let byte_end = offset_u32(byte_end);
        Span::new(
            byte_start,
            byte_end,
            self.char_of_byte(byte_start),
            self.char_of_byte(byte_end),
        )
    }
}

/// Byte offsets of the first byte of every line in a source text.
///
/// Line one starts at offset zero; a source ending in a terminator does not
/// gain a trailing empty line entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LineTable {
    starts: Vec<u32>,
}

impl LineTable {
    pub(crate) fn build(source: &str) -> Self {
        let mut starts = vec![0_u32];
        let bytes = source.as_bytes();
        for (offset, byte) in bytes.iter().enumerate() {
            if *byte == b'\n' && offset + 1 < bytes.len() {
                starts.push(offset_u32(offset + 1));
            }
        }
        Self { starts }
    }

    pub(crate) fn position(&self, source: &str, byte_offset: u32) -> LineCol {
        let line_index = self
            .starts
            .partition_point(|start| *start <= byte_offset)
            .saturating_sub(1);
        let line_start = self.starts.get(line_index).copied().unwrap_or(0);
        let prefix = source
            .get(usize_of(line_start)..usize_of(byte_offset))
            .unwrap_or("");
        LineCol {
            line: offset_u32(line_index).saturating_add(1),
            column_chars: offset_u32(prefix.chars().count()).saturating_add(1),
            column_bytes: offset_u32(prefix.len()).saturating_add(1),
        }
    }

    pub(crate) const fn line_count(&self) -> usize {
        self.starts.len()
    }
}
