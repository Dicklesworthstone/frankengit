//! Shared parser state and line handling.

use crate::ast::{Builder, NodeId, NodeKind};
use crate::diagnostic::{Diagnostic, DiagnosticCode};
use crate::limits::{Refusal, RefusalKind, StructuralLimits, usize_of};
use crate::span::{CharIndex, Span};

/// Column width of one tab stop when measuring block indentation.
pub const TAB_WIDTH: usize = 4;

/// One source line, or the remainder of one after a container prefix is stripped.
///
/// `start .. end` is the content; `end .. term_end` is the line terminator,
/// which is empty for a final line with no terminator. Stripping a container
/// prefix only ever moves `start` forward, so every `LineSlice` remains an
/// exact region of the original source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineSlice {
    pub start: usize,
    pub end: usize,
    pub term_end: usize,
}

/// Splits a source into lines, accepting all three common terminators.
pub fn split_lines(source: &str) -> Vec<LineSlice> {
    let bytes = source.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0_usize;
    let mut index = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\n' {
            lines.push(LineSlice {
                start,
                end: index,
                term_end: index + 1,
            });
            index += 1;
            start = index;
        } else if byte == b'\r' {
            let term_end = if bytes.get(index + 1) == Some(&b'\n') {
                index + 2
            } else {
                index + 1
            };
            lines.push(LineSlice {
                start,
                end: index,
                term_end,
            });
            index = term_end;
            start = index;
        } else {
            index += 1;
        }
    }
    if start < bytes.len() {
        lines.push(LineSlice {
            start,
            end: bytes.len(),
            term_end: bytes.len(),
        });
    }
    lines
}

/// Parser state shared by the block and inline phases.
pub struct Ctx<'src> {
    pub source: &'src str,
    pub chars: &'src CharIndex,
    pub limits: StructuralLimits,
    pub builder: Builder,
    pub diagnostics: Vec<Diagnostic>,
}

impl<'src> Ctx<'src> {
    pub const fn new(source: &'src str, chars: &'src CharIndex, limits: StructuralLimits) -> Self {
        Self {
            source,
            chars,
            limits,
            builder: Builder::new(limits.max_nodes),
            diagnostics: Vec::new(),
        }
    }

    pub fn span(&self, start: usize, end: usize) -> Span {
        self.chars.span(start, end)
    }

    pub fn add(
        &mut self,
        kind: NodeKind,
        span: Span,
        parent: Option<NodeId>,
    ) -> Result<NodeId, Refusal> {
        self.builder.add(kind, span, parent)
    }

    pub fn diagnose(&mut self, code: DiagnosticCode, span: Span) {
        self.diagnostics.push(Diagnostic { code, span });
    }

    /// Enforces the nesting ceiling before descending one more level.
    pub fn check_depth(&self, depth: u32) -> Result<(), Refusal> {
        if depth > self.limits.max_depth {
            return Err(Refusal::exceeded(
                RefusalKind::NestingTooDeep,
                u64::from(self.limits.max_depth),
                u64::from(depth),
            ));
        }
        Ok(())
    }

    /// The exact text of a line's content.
    pub fn line_text(&self, line: LineSlice) -> &'src str {
        self.source.get(line.start..line.end).unwrap_or("")
    }

    /// Whether a line holds nothing but whitespace.
    pub fn is_blank(&self, line: LineSlice) -> bool {
        self.line_text(line)
            .bytes()
            .all(|byte| byte.is_ascii_whitespace())
    }
}

/// Measures leading indentation in columns and returns the byte offset after it.
pub const fn measure_indent(text: &str, start: usize) -> (usize, usize) {
    let bytes = text.as_bytes();
    let mut columns = 0_usize;
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b' ' => columns += 1,
            b'\t' => columns += TAB_WIDTH - (columns % TAB_WIDTH),
            _ => break,
        }
        index += 1;
    }
    (columns, index)
}

/// Advances past at most `columns` columns of leading whitespace.
///
/// A tab that straddles the requested boundary is consumed whole. That is a
/// documented deviation from strict tab expansion; it only ever discards
/// whitespace, never content, and it is deterministic.
pub fn strip_columns(source: &str, line: LineSlice, columns: usize) -> LineSlice {
    let bytes = source.as_bytes();
    let mut taken = 0_usize;
    let mut index = line.start;
    while index < line.end && taken < columns {
        match bytes.get(index) {
            Some(b' ') => taken += 1,
            Some(b'\t') => taken += TAB_WIDTH - (taken % TAB_WIDTH),
            _ => break,
        }
        index += 1;
    }
    LineSlice {
        start: index,
        end: line.end,
        term_end: line.term_end,
    }
}

/// Trims trailing blank lines from a collected block range.
pub fn trim_trailing_blanks(ctx: &Ctx<'_>, lines: &[LineSlice]) -> usize {
    let mut count = lines.len();
    while count > 0 {
        let Some(line) = lines.get(count - 1) else {
            break;
        };
        if ctx.is_blank(*line) {
            count -= 1;
        } else {
            break;
        }
    }
    count
}

/// The span covering a run of lines, from the first content byte to the last.
pub fn span_of_lines(ctx: &Ctx<'_>, lines: &[LineSlice]) -> Option<Span> {
    let first = lines.first()?;
    let last = lines.last()?;
    Some(ctx.span(first.start, last.end))
}

/// Enforces the per-line ceiling before any line is examined.
pub fn check_line_lengths(lines: &[LineSlice], limits: StructuralLimits) -> Result<(), Refusal> {
    let ceiling = usize_of(limits.max_line_bytes);
    for line in lines {
        let length = line.end.saturating_sub(line.start);
        if length > ceiling {
            return Err(Refusal::exceeded(
                RefusalKind::LineTooLong,
                u64::from(limits.max_line_bytes),
                crate::limits::as_u64(length),
            ));
        }
    }
    Ok(())
}
