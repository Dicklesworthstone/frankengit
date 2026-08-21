//! Visible diagnostics for constructs this profile does not execute.
//!
//! Plan section 28.3 requires unsupported or neutralised constructs to produce
//! a visible diagnostic rather than a hidden execution channel. A diagnostic is
//! never a failure: the document still parses, and the construct still appears
//! as text. Diagnostics are emitted in source order.

use crate::span::Span;

/// What a diagnostic reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagnosticCode {
    /// A code fence was opened and never closed; the block ends at the source end.
    UnterminatedCodeFence,
    /// Raw markup was captured verbatim and will be escaped by every renderer.
    RawMarkupNeutralised,
    /// A link or image destination failed the destination policy.
    RejectedDestination,
    /// A link reference definition was found; this profile does not resolve references.
    UnresolvedReference,
    /// The document contains bidirectional formatting characters.
    ///
    /// Emitted once per document, spanning the first run. Every occurrence is
    /// marked inertly by the rendering surfaces; see [`crate::unicode`].
    BidiControlCharacter,
}

impl DiagnosticCode {
    /// Stable machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::UnterminatedCodeFence => "unterminated_code_fence",
            Self::RawMarkupNeutralised => "raw_markup_neutralised",
            Self::RejectedDestination => "rejected_destination",
            Self::UnresolvedReference => "unresolved_reference",
            Self::BidiControlCharacter => "bidi_control_character",
        }
    }
}

/// One diagnostic bound to the exact source region that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Diagnostic {
    /// What is being reported.
    pub code: DiagnosticCode,
    /// The source region the report is about.
    pub span: Span,
}
