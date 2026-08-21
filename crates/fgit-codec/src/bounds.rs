//! Decode bounds.
//!
//! Every length and count in a canonical body is checked against a bound
//! *before* anything is allocated or copied. A hostile body therefore costs a
//! comparison, not a reservation, and the refusal names the bound it hit.

/// Bounds a decoder enforces while reading one body.
///
/// The defaults are sized for canonical protocol bodies, which are small: a
/// seal, a commit record, a decision batch, a head. A caller that legitimately
/// needs more raises the specific bound rather than disabling checking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DecodeLimits {
    /// Largest whole body frame, in bytes.
    pub max_frame_len: u64,
    /// Largest single byte string or text value, in bytes.
    pub max_byte_string_len: u64,
    /// Largest element count in any one collection.
    pub max_element_count: u64,
    /// Deepest nesting of collections and envelopes.
    pub max_depth: u32,
}

impl DecodeLimits {
    /// Bounds sized for ordinary canonical protocol bodies.
    pub const DEFAULT: Self = Self {
        max_frame_len: 16 * 1024 * 1024,
        max_byte_string_len: 8 * 1024 * 1024,
        max_element_count: 1024 * 1024,
        max_depth: 32,
    };

    /// Deliberately tiny bounds, for tests that must observe a refusal.
    pub const MINIMAL: Self = Self {
        max_frame_len: 256,
        max_byte_string_len: 64,
        max_element_count: 4,
        max_depth: 2,
    };
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
