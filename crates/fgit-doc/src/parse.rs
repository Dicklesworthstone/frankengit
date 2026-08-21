//! Parse entry points.
//!
//! Parsing is a pure function of the source bytes and the profile: no clock,
//! no filesystem, no network, no ambient state. The same bytes and profile
//! always produce the same document, the same diagnostics in the same order,
//! and the same refusal.

use crate::ast::Document;
use crate::block;
use crate::builder::{Ctx, check_line_lengths, split_lines};
use crate::diagnostic::Diagnostic;
use crate::limits::{Refusal, RefusalKind};
use crate::profile::ParseProfile;
use crate::span::{CharIndex, LineTable};

/// A parsed document and the diagnostics raised while parsing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseOutput {
    document: Document,
    diagnostics: Vec<Diagnostic>,
}

impl ParseOutput {
    /// The parsed document.
    #[must_use]
    pub const fn document(&self) -> &Document {
        &self.document
    }

    /// Diagnostics in source order.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Consumes the output and returns the document alone.
    #[must_use]
    pub fn into_document(self) -> Document {
        self.document
    }
}

/// Parses a source text with the default safe profile.
pub fn parse(source: &str) -> Result<ParseOutput, Refusal> {
    parse_with(source, ParseProfile::DEFAULT)
}

/// Parses a source text with a caller-chosen profile.
pub fn parse_with(source: &str, profile: ParseProfile) -> Result<ParseOutput, Refusal> {
    profile.limits.check_input_len(source.len())?;
    let lines = split_lines(source);
    check_line_lengths(&lines, profile.limits.structural)?;
    let chars = CharIndex::build(source);
    let mut ctx = Ctx::new(source, &chars, profile.limits.structural);
    block::parse_blocks(&mut ctx, &lines, None, 1)?;
    let mut diagnostics = ctx.diagnostics;
    diagnostics.sort_by_key(|entry| {
        (
            entry.span.byte_start(),
            entry.span.byte_end(),
            entry.code.tag(),
        )
    });
    let document = ctx
        .builder
        .finish(source, profile.id(), LineTable::build(source));
    Ok(ParseOutput {
        document,
        diagnostics,
    })
}

/// Parses raw host-supplied bytes with a caller-chosen profile.
///
/// The renderer core takes bytes, not a decoded string, because the host is the
/// only party that knows where the bytes came from. Invalid `UTF-8` is a typed
/// refusal, never a lossy replacement.
pub fn parse_bytes(bytes: &[u8], profile: ParseProfile) -> Result<ParseOutput, Refusal> {
    profile.limits.check_input_len(bytes.len())?;
    let source =
        core::str::from_utf8(bytes).map_err(|_| Refusal::precondition(RefusalKind::SourceNotUtf8))?;
    parse_with(source, profile)
}
