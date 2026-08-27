//! Projection identity: the name of one exact derived generation.
//!
//! A projection read is only meaningful relative to the canonical prefix it
//! was built from. [`ProjectionIdentity`] carries that prefix — incarnation,
//! bound authority head, the closed decision range, and the projection/schema
//! generation counters — plus a build identity so two binaries can tell
//! whether they would have folded the same stream the same way.
//!
//! The rendering is deliberately hand-ordered and golden-tested: identity is
//! compared as text in receipts and across rebuilds, so its byte layout is
//! part of this crate's contract.

use std::fmt;

/// One-based decision sequence position inside one incarnation's stream.
///
/// Stored as `u64` and rendered losslessly; SQLite binding goes through
/// `sqlmodel_core::Value::from_u64_clamped`, whose refusal at positions above
/// `i64::MAX` is a caller bug, not a runtime contingency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectionPosition(u64);

impl ProjectionPosition {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The position immediately before the first decision (the empty fold).
    #[must_use]
    pub const fn genesis() -> Self {
        Self(0)
    }

    #[must_use]
    pub fn successor(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl fmt::Display for ProjectionPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identity of one derived read-model generation.
///
/// Constructed only through [`ProjectionIdentity::new`] with every field
/// present; a projection that cannot name all of them must refuse rather than
/// publish a partial identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionIdentity {
    /// Source repository incarnation these decisions belong to.
    source_incarnation: String,
    /// Authority head this projection is bound to (hex digest).
    authority_head: String,
    /// Generation of that head at bind time.
    authority_head_generation: u64,
    /// First decision sequence covered (inclusive).
    range_start: ProjectionPosition,
    /// Last decision sequence covered (inclusive); `genesis` when empty.
    range_end_inclusive: ProjectionPosition,
    projection_generation: u32,
    schema_generation: u32,
    build_identity: BuildIdentity,
}

/// Who built the binary that produced this generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildIdentity {
    pub crate_version: &'static str,
    pub toolchain: &'static str,
}

impl BuildIdentity {
    #[must_use]
    pub fn current() -> Self {
        Self {
            crate_version: env!("CARGO_PKG_VERSION"),
            toolchain: option_env!("RUSTC_TOOLCHAIN").unwrap_or("unknown"),
        }
    }
}

impl ProjectionIdentity {
    /// The identity of an installed but empty projection: bound to an
    /// incarnation and head, covering no decisions yet.
    #[must_use]
    pub fn new(
        source_incarnation: impl Into<String>,
        authority_head: impl Into<String>,
        authority_head_generation: u64,
        projection_generation: u32,
        schema_generation: u32,
        build_identity: BuildIdentity,
    ) -> Self {
        Self {
            source_incarnation: source_incarnation.into(),
            authority_head: authority_head.into(),
            authority_head_generation,
            range_start: ProjectionPosition::genesis().successor().expect("1 > 0"),
            range_end_inclusive: ProjectionPosition::genesis(),
            projection_generation,
            schema_generation,
            build_identity,
        }
    }

    #[must_use]
    pub const fn range_end(&self) -> ProjectionPosition {
        self.range_end_inclusive
    }

    #[must_use]
    pub fn source_incarnation(&self) -> &str {
        &self.source_incarnation
    }

    #[must_use]
    pub fn authority_head(&self) -> &str {
        &self.authority_head
    }

    #[must_use]
    pub const fn authority_head_generation(&self) -> u64 {
        self.authority_head_generation
    }
    #[must_use]
    pub const fn schema_generation(&self) -> u32 {
        self.schema_generation
    }

    /// Advance the closed range by one contiguous decision.
    ///
    /// The first applied decision sets the start; every later one must be the
    /// exact successor. A gap here means the caller skipped canonical history
    /// and the projection would silently lie about completeness — refused.
    ///
    /// # Errors
    /// [`IdentityAdvanceError::Gap`] when `position` is not the successor of
    /// the current end on a non-empty range.
    pub fn advance_range(
        &mut self,
        position: ProjectionPosition,
    ) -> Result<(), IdentityAdvanceError> {
        let expected = if self.range_end_inclusive == ProjectionPosition::genesis() {
            self.range_start
        } else {
            match self.range_end_inclusive.successor() {
                Some(next) => next,
                None => return Err(IdentityAdvanceError::Overflow),
            }
        };
        if position != expected {
            return Err(IdentityAdvanceError::Gap {
                expected,
                got: position,
            });
        }
        self.range_end_inclusive = position;
        Ok(())
    }

    /// Deterministic receipt text. Field order is contract; do not reorder.
    #[must_use]
    pub fn render_receipt(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str("projection-identity v1\n");
        out.push_str("incarnation ");
        out.push_str(&self.source_incarnation);
        out.push('\n');
        out.push_str("authority-head ");
        out.push_str(&self.authority_head);
        out.push_str(" @");
        out.push_str(&self.authority_head_generation.to_string());
        out.push('\n');
        out.push_str("range ");
        out.push_str(&self.range_start.get().to_string());
        out.push_str("..=");
        out.push_str(&self.range_end_inclusive.get().to_string());
        out.push('\n');
        out.push_str("projection-generation ");
        out.push_str(&self.projection_generation.to_string());
        out.push('\n');
        out.push_str("schema-generation ");
        out.push_str(&self.schema_generation.to_string());
        out.push('\n');
        out.push_str("build ");
        out.push_str(self.build_identity.crate_version);
        out.push('/');
        out.push_str(self.build_identity.toolchain);
        out.push('\n');
        out
    }
}

/// Typed failures of range advancement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityAdvanceError {
    /// `expected` is the only acceptable next sequence; `got` skipped or
    /// duplicated. Carries both sides so callers can diagnose replay vs loss.
    Gap {
        expected: ProjectionPosition,
        got: ProjectionPosition,
    },
    /// The sequence space is exhausted; no further decision can be folded.
    Overflow,
    /// The record (or stored watermark) names a different incarnation or
    /// authority head than the projection identity this fold runs under.
    /// Folding it would mix generations into one read model — the exact lie
    /// the identity exists to make impossible — so it is refused by name.
    BindingMismatch {
        /// Which binding field disagreed (`source_incarnation` or
        /// `authority_head`).
        field: &'static str,
        /// The value the session's identity carries.
        expected: String,
        /// The value the record or stored row carried.
        observed: String,
    },
}

impl fmt::Display for IdentityAdvanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gap { expected, got } => {
                write!(f, "projection gap: expected decision {expected}, got {got}")
            }
            Self::Overflow => f.write_str("projection sequence overflow"),
            Self::BindingMismatch {
                field,
                expected,
                observed,
            } => write!(
                f,
                "projection binding mismatch on {field}: identity expects {expected:?}, record carries {observed:?}"
            ),
        }
    }
}

impl std::error::Error for IdentityAdvanceError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ProjectionIdentity {
        ProjectionIdentity::new(
            "inc-11111111111111111111111111111111",
            "headcafe00000000000000000000000000000000000000000000000000001234",
            7,
            1,
            1,
            BuildIdentity::current(),
        )
    }

    #[test]
    fn empty_range_is_genesis_end_with_successor_start() {
        let id = identity();
        assert_eq!(id.range_end(), ProjectionPosition::genesis());
        assert_eq!(
            id.render_receipt(),
            "projection-identity v1\n\
             incarnation inc-11111111111111111111111111111111\n\
             authority-head headcafe00000000000000000000000000000000000000000000000000001234 @7\n\
             range 1..=0\n\
             projection-generation 1\n\
             schema-generation 1\n\
             build 0.0.1/unknown\n"
        );
    }

    #[test]
    fn advancing_is_contiguous_only() {
        let mut id = identity();
        id.advance_range(ProjectionPosition::new(1)).expect("first");
        id.advance_range(ProjectionPosition::new(2))
            .expect("second");
        assert_eq!(id.range_end(), ProjectionPosition::new(2));

        let gap = id
            .advance_range(ProjectionPosition::new(9))
            .expect_err("gap must refuse");
        assert_eq!(
            gap,
            IdentityAdvanceError::Gap {
                expected: ProjectionPosition::new(3),
                got: ProjectionPosition::new(9),
            }
        );

        let replay = id
            .advance_range(ProjectionPosition::new(2))
            .expect_err("replay must refuse");
        assert_eq!(
            replay,
            IdentityAdvanceError::Gap {
                expected: ProjectionPosition::new(3),
                got: ProjectionPosition::new(2),
            }
        );
    }
}
