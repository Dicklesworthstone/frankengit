//! The operation classes a capability may authorize.
//!
//! `docs/AGENT_PROTOCOL.md` §6.1 enumerates thirteen initial classes and then
//! forbids the shortcut that makes them pointless: *"A broad `repo_write` or
//! inherited sponsor token is forbidden."* There is deliberately no `All`
//! variant and no way to spell one, because a set that can name everything is
//! the broad token under another name.

use core::fmt;

/// One authorized operation class (`AGENT_PROTOCOL.md` §6.1).
///
/// The discriminants are stable: [`ClassSet`] is a bitmask over them and a
/// serialized capability commits to that mask, so renumbering would silently
/// change what an already-issued token authorizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum OperationClass {
    /// Read a canonical object or body.
    ReadCanonicalObject = 0,
    /// Read an authorized derived generation.
    ReadDerivedGeneration = 1,
    /// Create, read, or modify a `TreeFS` workspace.
    TreeFsWorkspace = 2,
    /// Execute a sandboxed process.
    ExecuteSandboxedProcess = 3,
    /// Reach a named network destination or class.
    NetworkDestination = 4,
    /// Request a purpose-bound secret handle.
    SecretHandle = 5,
    /// Invoke an external integration.
    ExternalIntegration = 6,
    /// Create an immutable candidate object.
    CreateCandidateObject = 7,
    /// Prepare a publication transaction.
    PreparePublication = 8,
    /// Submit a review, check, or evidence record.
    SubmitEvidence = 9,
    /// Mutate an issue, comment, or other forge entity.
    MutateForgeEntity = 10,
    /// Delegate a sub-intent.
    DelegateSubIntent = 11,
    /// Consume compute, model, storage, or network budget.
    ConsumeBudget = 12,
}

/// How many classes exist. A [`ClassSet`] mask uses this many bits.
pub const CLASS_COUNT: usize = 13;

impl OperationClass {
    /// Every class, in discriminant order.
    pub const ALL: [Self; CLASS_COUNT] = [
        Self::ReadCanonicalObject,
        Self::ReadDerivedGeneration,
        Self::TreeFsWorkspace,
        Self::ExecuteSandboxedProcess,
        Self::NetworkDestination,
        Self::SecretHandle,
        Self::ExternalIntegration,
        Self::CreateCandidateObject,
        Self::PreparePublication,
        Self::SubmitEvidence,
        Self::MutateForgeEntity,
        Self::DelegateSubIntent,
        Self::ConsumeBudget,
    ];

    /// The bit this class occupies in a [`ClassSet`].
    #[must_use]
    pub const fn bit(self) -> u16 {
        1_u16 << (self as u8)
    }

    /// A stable name for evidence records and refusal messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadCanonicalObject => "read_canonical_object",
            Self::ReadDerivedGeneration => "read_derived_generation",
            Self::TreeFsWorkspace => "treefs_workspace",
            Self::ExecuteSandboxedProcess => "execute_sandboxed_process",
            Self::NetworkDestination => "network_destination",
            Self::SecretHandle => "secret_handle",
            Self::ExternalIntegration => "external_integration",
            Self::CreateCandidateObject => "create_candidate_object",
            Self::PreparePublication => "prepare_publication",
            Self::SubmitEvidence => "submit_evidence",
            Self::MutateForgeEntity => "mutate_forge_entity",
            Self::DelegateSubIntent => "delegate_sub_intent",
            Self::ConsumeBudget => "consume_budget",
        }
    }
}

impl fmt::Display for OperationClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A set of authorized operation classes.
///
/// # Why a mask rather than a collection
///
/// Attenuation is defined by subset and intersection (§6.2), and both must be
/// total and allocation-free so a verifier can walk a whole ancestry without
/// failing partway for an unrelated reason. A `u16` mask over thirteen stable
/// discriminants makes `is_subset_of` a single instruction and makes the
/// serialized form fixed-width, which matters because the authenticator
/// commits to those bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct ClassSet(u16);

impl ClassSet {
    /// The set authorizing nothing.
    pub const EMPTY: Self = Self(0);

    /// Builds a set from classes, ignoring duplicates.
    #[must_use]
    pub fn from_classes(classes: &[OperationClass]) -> Self {
        let mut mask = 0_u16;
        for class in classes {
            mask |= class.bit();
        }
        Self(mask)
    }

    /// The raw mask, for canonical serialization.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Rebuilds a set from a mask, refusing bits outside the thirteen classes.
    ///
    /// # Errors
    ///
    /// [`UnknownClassBits`] when the mask names a class this build does not
    /// have. A newer issuer's token must not be silently reinterpreted as a
    /// narrower set that happens to fit: that would be a decoder result
    /// accepted without its original commitments.
    pub const fn from_bits(mask: u16) -> Result<Self, UnknownClassBits> {
        let defined: u16 = (1_u16 << CLASS_COUNT) - 1;
        let unknown = mask & !defined;
        if unknown != 0 {
            return Err(UnknownClassBits { unknown });
        }
        Ok(Self(mask))
    }

    /// Whether this set authorizes `class`.
    #[must_use]
    pub const fn contains(self, class: OperationClass) -> bool {
        self.0 & class.bit() != 0
    }

    /// Whether every class here is also in `other`.
    #[must_use]
    pub const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    /// The classes in this set that `other` does not hold.
    ///
    /// This is what names an amplification attempt precisely rather than
    /// reporting that one occurred.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// The classes held by both.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Whether the set authorizes nothing.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// How many classes are authorized.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// The authorized classes, in discriminant order.
    pub fn iter(self) -> impl Iterator<Item = OperationClass> {
        OperationClass::ALL
            .into_iter()
            .filter(move |class| self.contains(*class))
    }
}

impl fmt::Display for ClassSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return formatter.write_str("{}");
        }
        formatter.write_str("{")?;
        for (index, class) in self.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            formatter.write_str(class.as_str())?;
        }
        formatter.write_str("}")
    }
}

/// A serialized class mask named a class this build does not define.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownClassBits {
    /// The bits that matched no known class.
    pub unknown: u16,
}

impl fmt::Display for UnknownClassBits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "capability names operation classes this build does not define (bits {:#06x})",
            self.unknown
        )
    }
}

impl core::error::Error for UnknownClassBits {}
