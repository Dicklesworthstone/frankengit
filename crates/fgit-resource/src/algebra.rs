//! Graded resource algebra: the ten grades, their vector, and conserved grants.
//!
//! A [`ResourceVector`] is a graded amount: one non-negative integer per
//! [`Grade`]. [`ResourceVector::combine`] composes grades pointwise and is a
//! commutative monoid with [`ResourceVector::ZERO`] as identity.
//! [`ResourceVector::split`] is the only way to divide an amount, and it is
//! *conservative by construction*: it returns a part and a remainder whose
//! `combine` reproduces the original exactly, and it refuses whenever the
//! requested part exceeds the original in any grade. There is no unchecked
//! split, and no constructor that produces an amount out of nothing except
//! [`ResourceVector::single`] / [`ResourceVector::from_grades`], which are the
//! declared capacity boundary of a root region.
//!
//! [`BudgetGrant`] is the owned, ledger-tracked form of an amount. It is
//! `#[must_use]`, it can only come from a ledger, and dropping one returns the
//! amount to the pool *and* records a typed leak — never silence.

use crate::ids::GrantId;
use core::fmt;

/// Number of grades in the algebra.
pub const GRADE_COUNT: usize = 10;

/// One resource grade.
///
/// The list is the one in `docs/CALM_AND_OBLIGATIONS.md` section 6.1 and is
/// closed: adding a grade is a protocol change, not a local convenience.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grade {
    /// Bytes admitted, staged, or written.
    Bytes,
    /// Objects or transfer pieces.
    Objects,
    /// Processor time in microseconds.
    CpuMicros,
    /// Resident bytes held by the effect.
    MemoryBytes,
    /// File descriptors and sockets.
    FileDescriptors,
    /// Bytes leaving the trust boundary.
    EgressBytes,
    /// Money or quota, in millionths of the accounting unit.
    MoneyMicros,
    /// Wall time in microseconds during which a secret is reachable.
    SecretExposureMicros,
    /// Concurrent slots inside one failure domain.
    FailureDomainSlots,
    /// Concurrent human approvals in flight.
    ApprovalCapacity,
}

/// Whether settling an obligation returns a grade to the pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GradeDisposition {
    /// Spending the grade destroys it: settling charges the actual amount.
    Consumable,
    /// The grade is capacity, not substance: settling returns it to the pool.
    Returnable,
}

impl Grade {
    /// Every grade, in declaration order.
    pub const ALL: [Self; GRADE_COUNT] = [
        Self::Bytes,
        Self::Objects,
        Self::CpuMicros,
        Self::MemoryBytes,
        Self::FileDescriptors,
        Self::EgressBytes,
        Self::MoneyMicros,
        Self::SecretExposureMicros,
        Self::FailureDomainSlots,
        Self::ApprovalCapacity,
    ];

    /// Position of this grade inside a [`ResourceVector`].
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Whether settling returns the grade to the pool.
    #[must_use]
    pub const fn disposition(self) -> GradeDisposition {
        match self {
            Self::Bytes
            | Self::Objects
            | Self::CpuMicros
            | Self::EgressBytes
            | Self::MoneyMicros
            | Self::SecretExposureMicros => GradeDisposition::Consumable,
            Self::MemoryBytes
            | Self::FileDescriptors
            | Self::FailureDomainSlots
            | Self::ApprovalCapacity => GradeDisposition::Returnable,
        }
    }

    /// Stable lowercase name, used in receipts and refusals.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Objects => "objects",
            Self::CpuMicros => "cpu_micros",
            Self::MemoryBytes => "memory_bytes",
            Self::FileDescriptors => "file_descriptors",
            Self::EgressBytes => "egress_bytes",
            Self::MoneyMicros => "money_micros",
            Self::SecretExposureMicros => "secret_exposure_micros",
            Self::FailureDomainSlots => "failure_domain_slots",
            Self::ApprovalCapacity => "approval_capacity",
        }
    }
}

const _: () = assert!(Grade::ALL.len() == GRADE_COUNT);

impl fmt::Display for Grade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refusal from the resource algebra.
///
/// Every variant names the offending grade so that a refusal is actionable
/// without re-running the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceError {
    /// Composing two amounts would exceed the representable range.
    ///
    /// The bound is declared, not silently wrapped: an overflowing combine is
    /// a refusal, never a truncation.
    Overflow {
        /// Grade whose sum overflowed.
        grade: Grade,
        /// Left operand in that grade.
        left: u64,
        /// Right operand in that grade.
        right: u64,
    },
    /// A split would have minted budget in `grade`.
    ///
    /// This is the conservation refusal: the requested part exceeded what the
    /// original amount held.
    Conservation {
        /// Grade whose conservation would have been violated.
        grade: Grade,
        /// Amount available in that grade.
        available: u64,
        /// Amount requested in that grade.
        requested: u64,
    },
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Overflow { grade, left, right } => write!(
                f,
                "grade {grade} overflows composing {left} with {right}; the algebra refuses rather than wrapping"
            ),
            Self::Conservation {
                grade,
                available,
                requested,
            } => write!(
                f,
                "grade {grade} cannot yield {requested} from {available}; a split may not mint budget"
            ),
        }
    }
}

impl std::error::Error for ResourceError {}

/// A graded amount: one non-negative integer per [`Grade`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ResourceVector([u64; GRADE_COUNT]);

impl ResourceVector {
    /// The identity of [`ResourceVector::combine`].
    pub const ZERO: Self = Self([0; GRADE_COUNT]);

    /// An amount holding `amount` of `grade` and nothing else.
    #[must_use]
    pub fn single(grade: Grade, amount: u64) -> Self {
        Self::ZERO.with(grade, amount)
    }

    /// An amount built from grade/amount pairs; repeated grades overwrite.
    #[must_use]
    pub fn from_grades(pairs: &[(Grade, u64)]) -> Self {
        let mut value = Self::ZERO;
        for &(grade, amount) in pairs {
            value = value.with(grade, amount);
        }
        value
    }

    /// This amount with `grade` set to `amount`.
    #[must_use]
    pub fn with(mut self, grade: Grade, amount: u64) -> Self {
        if let Some(slot) = self.0.get_mut(grade.index()) {
            *slot = amount;
        }
        self
    }

    /// The amount held in `grade`.
    #[must_use]
    pub fn get(&self, grade: Grade) -> u64 {
        self.0.get(grade.index()).copied().unwrap_or(0)
    }

    /// Whether every grade is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|amount| *amount == 0)
    }

    /// Whether this amount is at least `other` in every grade.
    #[must_use]
    pub fn dominates(&self, other: &Self) -> bool {
        self.first_deficit(other).is_none()
    }

    /// The first grade in which `other` exceeds this amount, if any.
    #[must_use]
    pub fn first_deficit(&self, other: &Self) -> Option<ResourceError> {
        Grade::ALL.into_iter().zip(self.0).zip(other.0).find_map(
            |((grade, available), requested)| {
                (available < requested).then_some(ResourceError::Conservation {
                    grade,
                    available,
                    requested,
                })
            },
        )
    }

    /// Composes two graded amounts pointwise.
    ///
    /// This is the monoid operation: associative, commutative, with
    /// [`ResourceVector::ZERO`] as identity. It refuses on overflow.
    pub fn combine(&self, other: &Self) -> Result<Self, ResourceError> {
        let mut out = [0_u64; GRADE_COUNT];
        let inputs = Grade::ALL.into_iter().zip(self.0).zip(other.0);
        for (slot, ((grade, left), right)) in out.iter_mut().zip(inputs) {
            *slot =
                left.checked_add(right)
                    .ok_or(ResourceError::Overflow { grade, left, right })?;
        }
        Ok(Self(out))
    }

    /// Divides this amount into `part` and the remainder.
    ///
    /// Conservation is structural: on success
    /// `part.combine(&remainder) == *self` holds exactly, because the
    /// remainder is computed as the pointwise difference and `part` is
    /// returned unchanged. A part exceeding this amount in any grade is a
    /// [`ResourceError::Conservation`] refusal, never a clamp.
    pub fn split(&self, part: &Self) -> Result<(Self, Self), ResourceError> {
        if let Some(error) = self.first_deficit(part) {
            return Err(error);
        }
        let mut out = [0_u64; GRADE_COUNT];
        for (slot, (total, taken)) in out.iter_mut().zip(self.0.into_iter().zip(part.0)) {
            // Checked above: `total >= taken` in every grade.
            *slot = total.saturating_sub(taken);
        }
        Ok((*part, Self(out)))
    }

    /// This amount restricted to grades with the given disposition.
    #[must_use]
    pub fn mask(&self, keep: GradeDisposition) -> Self {
        let mut out = [0_u64; GRADE_COUNT];
        for (slot, (grade, amount)) in out.iter_mut().zip(Grade::ALL.into_iter().zip(self.0)) {
            *slot = if grade.disposition() == keep {
                amount
            } else {
                0
            };
        }
        Self(out)
    }

    /// Grade/amount pairs in declaration order.
    #[must_use]
    pub fn pairs(&self) -> [(Grade, u64); GRADE_COUNT] {
        let mut out = [(Grade::Bytes, 0_u64); GRADE_COUNT];
        for (slot, entry) in out.iter_mut().zip(Grade::ALL.into_iter().zip(self.0)) {
            *slot = entry;
        }
        out
    }
}

impl fmt::Display for ResourceVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (grade, amount) in self.pairs() {
            if amount == 0 {
                continue;
            }
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            write!(f, "{grade}={amount}")?;
        }
        if first {
            f.write_str("zero")?;
        }
        Ok(())
    }
}

/// An owned, ledger-tracked budget amount.
///
/// A grant exists only because a ledger removed the amount from its available
/// pool. It cannot be cloned, copied, or constructed by a consumer, so the
/// only ways to obtain budget are to ask a ledger or to
/// [`BudgetGrant::split`] one you already hold. Dropping a grant returns the
/// amount to the pool *and* records a
/// [`crate::custody::LeakClass::BudgetGrantDropped`] leak.
#[must_use = "a budget grant must be spent by reserving an obligation, split, combined, or explicitly released"]
#[derive(Debug)]
pub struct BudgetGrant {
    id: GrantId,
    amount: ResourceVector,
    guard: crate::custody::LeakGuard,
}

impl BudgetGrant {
    pub(crate) const fn from_parts(
        id: GrantId,
        amount: ResourceVector,
        guard: crate::custody::LeakGuard,
    ) -> Self {
        Self { id, amount, guard }
    }

    /// The grant identifier.
    #[must_use]
    pub const fn id(&self) -> GrantId {
        self.id
    }

    /// The graded amount this grant holds.
    #[must_use]
    pub const fn amount(&self) -> ResourceVector {
        self.amount
    }

    /// Carves `part` out of this grant and hands it back as a new grant.
    ///
    /// Conservation is structural: [`ResourceVector::split`] refuses any part
    /// that exceeds this grant in any grade, and the ledger rewrites this
    /// grant to the remainder and registers the part in the same accounting
    /// step. A refusal leaves this grant untouched, so no budget is created or
    /// destroyed on either path.
    pub fn split_off(&mut self, part: &ResourceVector) -> Result<Self, ResourceError> {
        let (taken, rest) = self.amount.split(part)?;
        let handle = self.guard.handle();
        let carved = handle.divide_grant(self.id, taken, rest);
        self.amount = rest;
        Ok(carved)
    }

    /// Absorbs `other` into this grant, composing their grades.
    ///
    /// On overflow refusal `other` is released back to the pool rather than
    /// dropped, so a refusal never destroys budget and never leaks.
    pub fn absorb(&mut self, other: Self) -> Result<(), ResourceError> {
        let total = match self.amount.combine(&other.amount) {
            Ok(total) => total,
            Err(error) => {
                let _receipt = other.release();
                return Err(error);
            }
        };
        let (source, _, handle) = other.into_parts();
        handle.absorb_grant(self.id, source, total);
        self.amount = total;
        Ok(())
    }

    /// Returns the whole amount to the ledger pool.
    pub fn release(self) -> ReleaseReceipt {
        let amount = self.amount;
        let (id, _, handle) = self.into_parts();
        handle.release_grant(id);
        ReleaseReceipt { id, amount }
    }

    /// Disarms the leak guard and yields the parts the ledger needs.
    pub(crate) fn into_parts(self) -> (GrantId, ResourceVector, crate::custody::LedgerHandle) {
        let Self {
            id,
            amount,
            mut guard,
        } = self;
        let handle = guard.handle();
        guard.disarm();
        (id, amount, handle)
    }
}

/// Evidence that a grant returned its amount to the pool.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseReceipt {
    id: GrantId,
    amount: ResourceVector,
}

impl ReleaseReceipt {
    /// The released grant.
    #[must_use]
    pub const fn id(&self) -> GrantId {
        self.id
    }

    /// The amount returned to the pool.
    #[must_use]
    pub const fn amount(&self) -> ResourceVector {
        self.amount
    }
}
