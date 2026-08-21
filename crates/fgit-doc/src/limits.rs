//! Resource ceilings and the typed refusals they produce.
//!
//! Every ceiling in [`Limits`] is checked *before* the work it bounds is
//! performed, and a breach produces a [`Refusal`] value rather than a panic,
//! a truncated document, or a silently degraded parse. Hostile input therefore
//! has exactly two outcomes in this crate: a complete result, or a refusal
//! naming the ceiling, the configured value, and the observed value.

use core::fmt;

/// Structural ceilings that change which inputs are *accepted*.
///
/// These participate in the parse-profile identity because two profiles with
/// different structural ceilings do not accept the same set of documents, and
/// an anchor is only meaningful against the profile that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StructuralLimits {
    /// Maximum bytes on one source line, excluding its terminator.
    pub max_line_bytes: u32,
    /// Maximum number of nodes in one parsed document.
    pub max_nodes: u32,
    /// Maximum block/inline container nesting depth.
    pub max_depth: u32,
    /// Maximum number of inline delimiter runs considered in one block.
    pub max_inline_delimiters: u32,
}

impl StructuralLimits {
    /// Hardest nesting depth any profile may configure.
    ///
    /// Renderers walk containers recursively, so an unbounded configured depth
    /// would move a hostile-input hazard from the parser to the renderer. The
    /// cap keeps every recursive walk in this crate within a few hundred small
    /// frames, and a profile that asks for more is refused at parse time
    /// rather than accepted and crashed later.
    pub const HARD_MAX_DEPTH: u32 = 256;

    /// Structural ceilings applied when the caller does not choose others.
    pub const DEFAULT: Self = Self {
        max_line_bytes: 64 * 1024,
        max_nodes: 500_000,
        max_depth: 64,
        max_inline_delimiters: 20_000,
    };

    /// Canonical, injective byte encoding used inside profile identities.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&self.max_line_bytes.to_be_bytes());
        out.extend_from_slice(&self.max_nodes.to_be_bytes());
        out.extend_from_slice(&self.max_depth.to_be_bytes());
        out.extend_from_slice(&self.max_inline_delimiters.to_be_bytes());
        out
    }
}

impl Default for StructuralLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The complete ceiling set for parsing, anchoring, and rendering.
///
/// Ceilings outside [`StructuralLimits`] bound work whose outcome is a
/// refusal but whose *accepted* parse result is unaffected, so they are
/// deliberately excluded from the profile identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Limits {
    /// Ceilings that participate in the parse-profile identity.
    pub structural: StructuralLimits,
    /// Maximum accepted source size in bytes.
    pub max_input_bytes: u32,
    /// Maximum accepted rendered output size in bytes.
    pub max_output_bytes: u32,
    /// Maximum bytes of normalized text retained in one anchor context field.
    pub max_anchor_context_bytes: u32,
    /// Maximum number of inputs accepted by one batch render.
    pub max_batch_inputs: u32,
}

impl Limits {
    /// Ceilings applied when the caller does not choose others.
    pub const DEFAULT: Self = Self {
        structural: StructuralLimits::DEFAULT,
        max_input_bytes: 4 * 1024 * 1024,
        max_output_bytes: 32 * 1024 * 1024,
        max_anchor_context_bytes: 256,
        max_batch_inputs: 100_000,
    };

    /// Checks the configured depth against [`StructuralLimits::HARD_MAX_DEPTH`].
    pub fn check_configuration(&self) -> Result<(), Refusal> {
        if self.structural.max_depth > StructuralLimits::HARD_MAX_DEPTH {
            return Err(Refusal::exceeded(
                RefusalKind::NestingTooDeep,
                u64::from(StructuralLimits::HARD_MAX_DEPTH),
                u64::from(self.structural.max_depth),
            ));
        }
        Ok(())
    }

    /// Checks a source length against [`Limits::max_input_bytes`].
    pub fn check_input_len(&self, observed: usize) -> Result<(), Refusal> {
        let limit = usize_of(self.max_input_bytes);
        if observed > limit {
            return Err(Refusal::exceeded(
                RefusalKind::InputTooLarge,
                u64::from(self.max_input_bytes),
                as_u64(observed),
            ));
        }
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Which ceiling or precondition a [`Refusal`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefusalKind {
    /// The source is larger than the configured input ceiling.
    InputTooLarge,
    /// A single source line is longer than the configured ceiling.
    LineTooLong,
    /// The document would contain more nodes than the configured ceiling.
    TooManyNodes,
    /// Container nesting is deeper than the configured ceiling.
    NestingTooDeep,
    /// One block contains more inline delimiter runs than the ceiling allows.
    TooManyInlineDelimiters,
    /// The rendered output is larger than the configured ceiling.
    OutputTooLarge,
    /// The supplied bytes are not valid `UTF-8`.
    SourceNotUtf8,
    /// A source-object identity is longer than this crate accepts.
    SourceIdTooLong,
    /// An anchor was remapped against a document parsed by another profile.
    ProfileMismatch,
    /// A node identifier does not belong to the document it was used with.
    UnknownNode,
    /// A batch declares more inputs than the configured ceiling.
    TooManyBatchInputs,
    /// A declared batch workload is not usable, for example a zero core cap.
    WorkloadUnusable,
    /// An output name is empty, too long, or not safe for a host path.
    OutputNameInvalid,
    /// Two outputs of one publication requested the same name.
    DuplicateOutputName,
    /// A publication declares no outputs, or more than one reservation may hold.
    TooManyOutputs,
}

impl RefusalKind {
    /// Stable machine-readable tag, used in receipts and rendered output.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::InputTooLarge => "input_too_large",
            Self::LineTooLong => "line_too_long",
            Self::TooManyNodes => "too_many_nodes",
            Self::NestingTooDeep => "nesting_too_deep",
            Self::TooManyInlineDelimiters => "too_many_inline_delimiters",
            Self::OutputTooLarge => "output_too_large",
            Self::SourceNotUtf8 => "source_not_utf8",
            Self::SourceIdTooLong => "source_id_too_long",
            Self::ProfileMismatch => "profile_mismatch",
            Self::UnknownNode => "unknown_node",
            Self::TooManyBatchInputs => "too_many_batch_inputs",
            Self::WorkloadUnusable => "workload_unusable",
            Self::OutputNameInvalid => "output_name_invalid",
            Self::DuplicateOutputName => "duplicate_output_name",
            Self::TooManyOutputs => "too_many_outputs",
        }
    }
}

impl fmt::Display for RefusalKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.tag())
    }
}

/// A typed refusal: the only failure this crate produces.
///
/// `limit` and `observed` are present for every ceiling breach. Refusals that
/// report a precondition rather than a ceiling carry equal values and are
/// still fully described by `kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Refusal {
    kind: RefusalKind,
    limit: u64,
    observed: u64,
}

impl Refusal {
    /// Builds a ceiling-breach refusal.
    #[must_use]
    pub const fn exceeded(kind: RefusalKind, limit: u64, observed: u64) -> Self {
        Self {
            kind,
            limit,
            observed,
        }
    }

    /// Builds a precondition refusal that does not report a numeric ceiling.
    #[must_use]
    pub const fn precondition(kind: RefusalKind) -> Self {
        Self {
            kind,
            limit: 0,
            observed: 0,
        }
    }

    /// Which ceiling or precondition was violated.
    #[must_use]
    pub const fn kind(&self) -> RefusalKind {
        self.kind
    }

    /// The configured ceiling, or zero for a precondition refusal.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// The observed value, or zero for a precondition refusal.
    #[must_use]
    pub const fn observed(&self) -> u64 {
        self.observed
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "fgit-doc refused: {} (limit {}, observed {})",
            self.kind, self.limit, self.observed
        )
    }
}

impl std::error::Error for Refusal {}

/// Widens a `u32` ceiling to `usize` without a lossy conversion.
///
/// `usize` is at least 32 bits on every target this workspace supports, so the
/// fallback is unreachable; it exists so the conversion cannot panic.
#[must_use]
pub(crate) fn usize_of(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Widens a `usize` count to `u64` for reporting inside a [`Refusal`].
#[must_use]
pub(crate) fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Narrows a source offset to `u32`.
///
/// Callers establish `value <= max_input_bytes <= u32::MAX` before any span is
/// built, so the saturation branch is unreachable for accepted documents.
#[must_use]
pub(crate) fn offset_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
