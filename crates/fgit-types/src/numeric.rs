//! Bounded scalars and the closed set of integer widths a canonical encoding
//! may carry.
//!
//! Two rules are enforced here rather than by review:
//!
//! * **No platform-width integers.** [`CanonicalScalar`] is sealed and is
//!   implemented for the eight fixed-width integer types only. `usize` and
//!   `isize` do not implement it, so an encoder generic over
//!   `T: CanonicalScalar` cannot be handed one, and a body whose width depends
//!   on the host cannot be written.
//! * **No floating point.** `f32` and `f64` do not implement
//!   [`CanonicalScalar`] either. Canonical bytes never contain a value whose
//!   bit pattern depends on rounding mode, `NaN` payload, or signed zero.
//!
//! Signed values map to unsigned bits with zigzag so that small negative
//! numbers stay small and ordering of the encoded form is total.

use core::fmt;

use crate::error::TypeRefusal;

mod sealed {
    /// Prevents downstream crates from widening the canonical scalar set.
    pub trait Sealed {}
}

/// Fixed byte width of a canonical integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScalarWidth {
    /// One byte.
    W1,
    /// Two bytes.
    W2,
    /// Four bytes.
    W4,
    /// Eight bytes.
    W8,
}

impl ScalarWidth {
    /// Width in bytes.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        match self {
            Self::W1 => 1,
            Self::W2 => 2,
            Self::W4 => 4,
            Self::W8 => 8,
        }
    }
}

/// An integer type a canonical encoding is allowed to carry.
///
/// The trait is sealed: the members are exactly `u8`, `u16`, `u32`, `u64`,
/// `i8`, `i16`, `i32`, and `i64`.
///
/// A fixed-width integer is accepted:
///
/// ```
/// use fgit_types::numeric::CanonicalScalar;
/// fn encode<T: CanonicalScalar>(value: T) -> u64 { value.to_canonical_bits() }
/// assert_eq!(encode(7_u32), 7);
/// assert_eq!(encode(-1_i32), 1);
/// ```
///
/// A platform-width integer is not, so a body whose width depends on the host
/// cannot be written:
///
/// ```compile_fail
/// use fgit_types::numeric::CanonicalScalar;
/// fn encode<T: CanonicalScalar>(value: T) -> u64 { value.to_canonical_bits() }
/// let _ = encode(7_usize);
/// ```
///
/// Neither is a floating-point value, so canonical bytes never depend on
/// rounding mode or a payload:
///
/// ```compile_fail
/// use fgit_types::numeric::CanonicalScalar;
/// fn encode<T: CanonicalScalar>(value: T) -> u64 { value.to_canonical_bits() }
/// let _ = encode(1.5_f64);
/// ```
///
/// The set cannot be widened downstream, because the supertrait is private:
///
/// ```compile_fail
/// struct Local(u8);
/// impl fgit_types::numeric::CanonicalScalar for Local {
///     const WIDTH: fgit_types::numeric::ScalarWidth = fgit_types::numeric::ScalarWidth::W1;
///     const SIGNED: bool = false;
///     fn to_canonical_bits(self) -> u64 { u64::from(self.0) }
///     fn from_canonical_bits(_bits: u64) -> Result<Self, fgit_types::TypeRefusal> { Ok(Local(0)) }
/// }
/// ```
pub trait CanonicalScalar: sealed::Sealed + Copy + Eq + Ord + fmt::Debug {
    /// Fixed encoded width.
    const WIDTH: ScalarWidth;
    /// Whether the type is signed, and therefore zigzag-mapped.
    const SIGNED: bool;

    /// Maps the value onto the unsigned bit pattern a canonical encoder
    /// writes. Signed types use zigzag mapping.
    fn to_canonical_bits(self) -> u64;

    /// Recovers a value from the unsigned bit pattern.
    ///
    /// Bits outside the type's range are refused rather than truncated.
    fn from_canonical_bits(bits: u64) -> Result<Self, TypeRefusal>;
}

macro_rules! impl_unsigned_scalar {
    ($type:ty, $width:expr, $field:literal) => {
        impl sealed::Sealed for $type {}
        impl CanonicalScalar for $type {
            const WIDTH: ScalarWidth = $width;
            const SIGNED: bool = false;

            fn to_canonical_bits(self) -> u64 {
                u64::from(self)
            }

            fn from_canonical_bits(bits: u64) -> Result<Self, TypeRefusal> {
                Self::try_from(bits).map_err(|_| TypeRefusal::ValueOutOfRange {
                    field: $field,
                    observed: bits,
                    minimum: 0,
                    maximum: u64::from(Self::MAX),
                })
            }
        }
    };
}

macro_rules! impl_signed_scalar {
    ($type:ty, $width:expr, $field:literal) => {
        impl sealed::Sealed for $type {}
        impl CanonicalScalar for $type {
            const WIDTH: ScalarWidth = $width;
            const SIGNED: bool = true;

            fn to_canonical_bits(self) -> u64 {
                zigzag_encode(i64::from(self))
            }

            fn from_canonical_bits(bits: u64) -> Result<Self, TypeRefusal> {
                Self::try_from(zigzag_decode(bits)).map_err(|_| TypeRefusal::ValueOutOfRange {
                    field: $field,
                    observed: bits,
                    minimum: 0,
                    maximum: zigzag_encode(i64::from(Self::MAX)),
                })
            }
        }
    };
}

impl_unsigned_scalar!(u8, ScalarWidth::W1, "u8");
impl_unsigned_scalar!(u16, ScalarWidth::W2, "u16");
impl_unsigned_scalar!(u32, ScalarWidth::W4, "u32");
impl_signed_scalar!(i8, ScalarWidth::W1, "i8");
impl_signed_scalar!(i16, ScalarWidth::W2, "i16");
impl_signed_scalar!(i32, ScalarWidth::W4, "i32");

impl sealed::Sealed for u64 {}
impl CanonicalScalar for u64 {
    const WIDTH: ScalarWidth = ScalarWidth::W8;
    const SIGNED: bool = false;

    fn to_canonical_bits(self) -> u64 {
        self
    }

    fn from_canonical_bits(bits: u64) -> Result<Self, TypeRefusal> {
        Ok(bits)
    }
}

impl sealed::Sealed for i64 {}
impl CanonicalScalar for i64 {
    const WIDTH: ScalarWidth = ScalarWidth::W8;
    const SIGNED: bool = true;

    fn to_canonical_bits(self) -> u64 {
        zigzag_encode(self)
    }

    fn from_canonical_bits(bits: u64) -> Result<Self, TypeRefusal> {
        Ok(zigzag_decode(bits))
    }
}

/// Maps a signed value onto an unsigned one, interleaving negatives.
#[must_use]
pub const fn zigzag_encode(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)).cast_unsigned()
}

/// Inverse of [`zigzag_encode`].
#[must_use]
pub const fn zigzag_decode(bits: u64) -> i64 {
    (bits >> 1).cast_signed() ^ -(bits & 1).cast_signed()
}

/// Declares a monotone, gap-free counter newtype over `u64`.
macro_rules! monotone_counter {
    ($name:ident, $field:literal, $doc:literal) => {
        #[doc = $doc]
        ///
        /// The counter is gap-free: the successor of a value is always
        /// exactly one greater, and exhaustion is a typed refusal rather than
        /// a wrap.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(u64);

        impl $name {
            /// The first value the counter ever takes.
            pub const FIRST: Self = Self(1);

            /// Builds a counter from its wire value.
            ///
            /// Zero is refused: it is reserved to mean "no value yet" in
            /// optional positions, so it can never be a live counter value.
            pub fn try_new(value: u64) -> Result<Self, TypeRefusal> {
                if value == 0 {
                    return Err(TypeRefusal::ValueOutOfRange {
                        field: $field,
                        observed: value,
                        minimum: 1,
                        maximum: u64::MAX,
                    });
                }
                Ok(Self(value))
            }

            /// The wire value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            /// The immediate successor, refusing exhaustion instead of
            /// wrapping.
            pub fn next(self) -> Result<Self, TypeRefusal> {
                self.0
                    .checked_add(1)
                    .map(Self)
                    .ok_or_else(|| TypeRefusal::ValueOutOfRange {
                        field: $field,
                        observed: self.0,
                        minimum: 1,
                        maximum: u64::MAX - 1,
                    })
            }

            /// True when `later` is exactly this value's successor.
            #[must_use]
            pub const fn is_immediate_predecessor_of(self, later: Self) -> bool {
                self.0 < later.0 && later.0 - self.0 == 1
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}", self.0)
            }
        }
    };
}

monotone_counter!(
    DecisionSequence,
    "DecisionSequence",
    "Order of every canonical terminal decision, refusals included."
);
monotone_counter!(
    RepositorySequence,
    "RepositorySequence",
    "Order of committed Repository Commit Records only."
);
monotone_counter!(
    HeadGeneration,
    "HeadGeneration",
    "Monotone generation of the repository authority head."
);
monotone_counter!(
    PolicyEpoch,
    "PolicyEpoch",
    "Epoch of the pinned policy snapshot a decision was evaluated against."
);
monotone_counter!(
    RegistryEpoch,
    "RegistryEpoch",
    "Epoch of the format and algorithm registry needed to interpret a body."
);

/// Canonical codec version carried by every internal identity.
///
/// The major version is the compatibility boundary: a decoder that meets an
/// unknown major refuses. The minor version is additive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CodecVersion {
    major: u16,
    minor: u16,
}

impl CodecVersion {
    /// Builds a codec version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// The compatibility-breaking major version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// The additive minor version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

impl fmt::Display for CodecVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "v{}.{}", self.major, self.minor)
    }
}

/// A byte count bounded by an explicit admission limit.
///
/// Sizes are read before allocation, so the bound belongs to the type rather
/// than to a later check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ByteCount(u64);

impl ByteCount {
    /// Zero bytes.
    pub const ZERO: Self = Self(0);

    /// Builds a byte count, refusing anything above `maximum`.
    pub fn try_new(field: &'static str, value: u64, maximum: u64) -> Result<Self, TypeRefusal> {
        if value > maximum {
            return Err(TypeRefusal::ValueOutOfRange {
                field,
                observed: value,
                minimum: 0,
                maximum,
            });
        }
        Ok(Self(value))
    }

    /// The counted bytes.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ByteCount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}
