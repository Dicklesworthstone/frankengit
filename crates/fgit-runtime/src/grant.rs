//! Capability narrowing at ingress and subsystem boundaries.
//!
//! Two capability layers meet here.
//!
//! The runtime layer is Asupersync's: [`CapMask`] tracks spawn, time, random,
//! I/O, and remote authority, and the type-level [`CapSet`] makes widening a
//! compile error via [`SubsetOf`]. `FrankenGit` does not reimplement that; it
//! uses it, and adds the refusal that turns a *runtime* narrowing request
//! into a typed no rather than a silent clamp.
//!
//! The authority layer is `FrankenGit`'s own. Publication, object write,
//! network, database, secret, runner, and billing authority are not runtime
//! concepts — they are repository concepts — so the node tracks them
//! separately. The rule the profile states, "no detached task may retain
//! publication, object, database, network, secret, runner, or billing
//! authority", is enforced on this layer.

use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask, SubsetOf};

use crate::refuse::RuntimeRefusal;

/// A repository-level authority a work unit may hold.
///
/// These are deliberately not runtime capabilities: holding
/// [`Publication`](Self::Publication) means the holder may complete a
/// conditional replacement of the repository authority head, which no amount
/// of I/O capability implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityCapability {
    /// May publish repository state by conditional head replacement.
    Publication,
    /// May write objects into the canonical store.
    ObjectWrite,
    /// May open outbound network connections.
    Network,
    /// May issue commands against the embedded database.
    Database,
    /// May read secret material.
    Secret,
    /// May dispatch work to a runner fleet.
    Runner,
    /// May record billable effects.
    Billing,
}

/// Every authority capability, in declaration order.
const ALL_AUTHORITIES: [AuthorityCapability; 7] = [
    AuthorityCapability::Publication,
    AuthorityCapability::ObjectWrite,
    AuthorityCapability::Network,
    AuthorityCapability::Database,
    AuthorityCapability::Secret,
    AuthorityCapability::Runner,
    AuthorityCapability::Billing,
];

impl AuthorityCapability {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Publication => "publication",
            Self::ObjectWrite => "object_write",
            Self::Network => "network",
            Self::Database => "database",
            Self::Secret => "secret",
            Self::Runner => "runner",
            Self::Billing => "billing",
        }
    }

    /// Every authority capability.
    #[must_use]
    pub const fn all() -> [Self; 7] {
        ALL_AUTHORITIES
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Publication => 1 << 0,
            Self::ObjectWrite => 1 << 1,
            Self::Network => 1 << 2,
            Self::Database => 1 << 3,
            Self::Secret => 1 << 4,
            Self::Runner => 1 << 5,
            Self::Billing => 1 << 6,
        }
    }
}

/// A set of repository authority capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthoritySet(u8);

impl AuthoritySet {
    /// The empty set: no repository authority at all.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// Every authority capability.
    #[must_use]
    pub const fn all() -> Self {
        Self(0b0111_1111)
    }

    /// Add one capability.
    #[must_use]
    pub const fn with(self, capability: AuthorityCapability) -> Self {
        Self(self.0 | capability.bit())
    }

    /// Remove one capability.
    #[must_use]
    pub const fn without(self, capability: AuthorityCapability) -> Self {
        Self(self.0 & !capability.bit())
    }

    /// Whether this set holds `capability`.
    #[must_use]
    pub const fn contains(self, capability: AuthorityCapability) -> bool {
        self.0 & capability.bit() != 0
    }

    /// Whether this set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Intersection — the only legal way to derive a child set.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Whether every capability in `other` is also held here.
    #[must_use]
    pub const fn contains_all(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The capabilities present in `self` but absent from `parent`.
    #[must_use]
    pub fn excess_over(self, parent: Self) -> Vec<AuthorityCapability> {
        ALL_AUTHORITIES
            .into_iter()
            .filter(|capability| self.contains(*capability) && !parent.contains(*capability))
            .collect()
    }

    /// The capabilities held, in declaration order.
    #[must_use]
    pub fn held(self) -> Vec<AuthorityCapability> {
        ALL_AUTHORITIES
            .into_iter()
            .filter(|capability| self.contains(*capability))
            .collect()
    }
}

/// How a work unit is owned, which decides what authority it may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// Owned by a supervisor or scope that joins it before closing.
    Owned,
    /// Detached: nothing joins it. Never permitted to hold authority.
    Detached,
}

/// The capability envelope a subsystem or request runs inside.
///
/// Combines the runtime capability mask with the repository authority set and
/// the ownership shape. Every derivation is a narrowing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityProfile {
    runtime: CapMask,
    authority: AuthoritySet,
    ownership: Ownership,
}

impl CapabilityProfile {
    /// The node-root envelope: full runtime capability, full authority, owned.
    #[must_use]
    pub const fn node_root() -> Self {
        Self {
            runtime: CapMask::all(),
            authority: AuthoritySet::all(),
            ownership: Ownership::Owned,
        }
    }

    /// An explicit envelope.
    ///
    /// # Errors
    ///
    /// [`RuntimeRefusal::DetachedAuthorityRetained`] when a detached unit is
    /// given any repository authority.
    pub fn new(
        runtime: CapMask,
        authority: AuthoritySet,
        ownership: Ownership,
    ) -> Result<Self, RuntimeRefusal> {
        let profile = Self {
            runtime,
            authority,
            ownership,
        };
        profile.verify_detached_holds_no_authority()?;
        Ok(profile)
    }

    /// The runtime capability mask.
    #[must_use]
    pub const fn runtime_mask(self) -> CapMask {
        self.runtime
    }

    /// The repository authority set.
    #[must_use]
    pub const fn authority(self) -> AuthoritySet {
        self.authority
    }

    /// The ownership shape.
    #[must_use]
    pub const fn ownership(self) -> Ownership {
        self.ownership
    }

    /// Narrow to a child envelope, refusing any widening.
    ///
    /// Both layers are checked. `CapMask::intersect` alone would silently drop
    /// the bits a child asked for but could not have; that hides the same
    /// class of construction defect as a silently clamped budget, so a request
    /// for an unheld capability is refused rather than trimmed.
    ///
    /// # Errors
    ///
    /// - [`RuntimeRefusal::CapabilityWidening`] when the requested runtime mask
    ///   or authority set exceeds this one.
    /// - [`RuntimeRefusal::DetachedAuthorityRetained`] when the child is
    ///   detached and would retain authority.
    pub fn narrow(
        self,
        runtime: CapMask,
        authority: AuthoritySet,
        ownership: Ownership,
    ) -> Result<Self, RuntimeRefusal> {
        if !self.runtime.contains(runtime) {
            return Err(RuntimeRefusal::CapabilityWidening {
                missing: first_missing_runtime_bit(self.runtime, runtime),
            });
        }
        if !self.authority.contains_all(authority) {
            let missing = authority
                .excess_over(self.authority)
                .first()
                .map_or("authority", |capability| capability.code());
            return Err(RuntimeRefusal::CapabilityWidening { missing });
        }
        Self::new(
            self.runtime.intersect(runtime),
            self.authority.intersect(authority),
            ownership,
        )
    }

    /// Derive the envelope for detached work: authority is dropped entirely.
    ///
    /// This is the constructive counterpart to the detached-authority refusal.
    /// Detached work is not forbidden — retaining authority while detached is.
    #[must_use]
    pub const fn detached(self) -> Self {
        Self {
            runtime: self.runtime,
            authority: AuthoritySet::none(),
            ownership: Ownership::Detached,
        }
    }

    /// Enforce the detached-authority rule.
    ///
    /// # Errors
    ///
    /// [`RuntimeRefusal::DetachedAuthorityRetained`] naming the first retained
    /// capability in declaration order.
    pub fn verify_detached_holds_no_authority(self) -> Result<(), RuntimeRefusal> {
        if self.ownership == Ownership::Detached
            && let Some(capability) = self.authority.held().first()
        {
            return Err(RuntimeRefusal::DetachedAuthorityRetained {
                capability: capability.code(),
            });
        }
        Ok(())
    }
}

/// Name the first runtime capability requested but not held.
fn first_missing_runtime_bit(held: CapMask, requested: CapMask) -> &'static str {
    /// One named capability bit and the mask that isolates it.
    type NamedBit = (&'static str, fn() -> CapMask);

    const BITS: [NamedBit; 5] = [
        ("spawn", || {
            <CapSet<true, false, false, false, false> as CapSetRuntimeMask>::MASK
        }),
        ("time", || {
            <CapSet<false, true, false, false, false> as CapSetRuntimeMask>::MASK
        }),
        ("random", || {
            <CapSet<false, false, true, false, false> as CapSetRuntimeMask>::MASK
        }),
        ("io", || {
            <CapSet<false, false, false, true, false> as CapSetRuntimeMask>::MASK
        }),
        ("remote", || {
            <CapSet<false, false, false, false, true> as CapSetRuntimeMask>::MASK
        }),
    ];
    for (name, mask) in BITS {
        let bit = mask();
        if requested.contains(bit) && !held.contains(bit) {
            return name;
        }
    }
    "capability"
}

/// The runtime mask for a type-level capability row.
///
/// Bridges the compile-time [`CapSet`] to the runtime [`CapMask`] so a
/// subsystem can declare its capability row in the type system and still hand
/// the node a value to narrow against.
#[must_use]
pub const fn mask_of<C: CapSetRuntimeMask>() -> CapMask {
    C::MASK
}

/// Statically witness that `Sub` is a narrowing of `Super`.
///
/// This compiles only when every capability in `Sub` is present in `Super`;
/// the missing `(true, false)` ordering impl in Asupersync's sealed lattice
/// makes the widening direction a type error. Calling this in a subsystem's
/// own module is how that subsystem pins its narrowing at compile time rather
/// than discovering it at runtime.
pub const fn witness_narrowing<Sub, Super>()
where
    Sub: SubsetOf<Super>,
{
}

#[cfg(test)]
mod tests {
    use super::*;

    type FullCaps = CapSet<true, true, true, true, true>;
    type IoAndTime = CapSet<false, true, false, true, false>;
    type TimeOnly = CapSet<false, true, false, false, false>;

    #[test]
    fn type_level_narrowing_witnesses_compile() {
        // Each of these is a compile-time proof that the narrowing direction
        // is legal. The widening direction (e.g. FullCaps: SubsetOf<TimeOnly>)
        // does not compile, which is exactly the guarantee being relied on.
        witness_narrowing::<IoAndTime, FullCaps>();
        witness_narrowing::<TimeOnly, IoAndTime>();
        witness_narrowing::<TimeOnly, FullCaps>();
        witness_narrowing::<FullCaps, FullCaps>();
    }

    #[test]
    fn runtime_mask_narrowing_is_permitted() {
        let root = CapabilityProfile::node_root();
        let narrowed = root
            .narrow(
                mask_of::<IoAndTime>(),
                AuthoritySet::none().with(AuthorityCapability::Database),
                Ownership::Owned,
            )
            .expect("dropping capabilities is always permitted");

        assert_eq!(narrowed.runtime_mask(), mask_of::<IoAndTime>());
        assert!(narrowed.authority().contains(AuthorityCapability::Database));
        assert!(
            !narrowed
                .authority()
                .contains(AuthorityCapability::Publication)
        );
    }

    #[test]
    fn runtime_capability_widening_is_refused() {
        let root = CapabilityProfile::node_root();
        let subsystem = root
            .narrow(
                mask_of::<TimeOnly>(),
                AuthoritySet::none(),
                Ownership::Owned,
            )
            .expect("narrowing to time-only");

        // Planted widening: a child that holds only `time` asks for `io`.
        let refusal = subsystem
            .narrow(
                mask_of::<IoAndTime>(),
                AuthoritySet::none(),
                Ownership::Owned,
            )
            .expect_err("a child cannot regain a masked capability");
        assert_eq!(
            refusal,
            RuntimeRefusal::CapabilityWidening { missing: "io" }
        );
        assert!(!refusal.is_retryable());

        // Paired permitted case: the same child narrowing to what it holds.
        let ok = subsystem
            .narrow(
                mask_of::<TimeOnly>(),
                AuthoritySet::none(),
                Ownership::Owned,
            )
            .expect("re-requesting a held capability is permitted");
        assert_eq!(ok.runtime_mask(), mask_of::<TimeOnly>());
    }

    #[test]
    fn authority_widening_is_refused() {
        let reader = CapabilityProfile::node_root()
            .narrow(
                CapMask::all(),
                AuthoritySet::none().with(AuthorityCapability::Database),
                Ownership::Owned,
            )
            .expect("narrowing to database-only authority");

        // Planted widening: a projection reader asks for publication authority.
        let refusal = reader
            .narrow(
                CapMask::all(),
                AuthoritySet::none()
                    .with(AuthorityCapability::Database)
                    .with(AuthorityCapability::Publication),
                Ownership::Owned,
            )
            .expect_err("a derived reader cannot grant itself publication");
        assert_eq!(
            refusal,
            RuntimeRefusal::CapabilityWidening {
                missing: "publication"
            }
        );

        // Paired permitted case: narrowing further, to nothing.
        let narrower = reader
            .narrow(CapMask::all(), AuthoritySet::none(), Ownership::Owned)
            .expect("dropping the last authority is permitted");
        assert!(narrower.authority().is_empty());
    }

    #[test]
    fn detached_work_may_not_retain_any_authority() {
        // Planted negative, once per authority capability, so no variant is
        // accidentally exempt.
        for capability in AuthorityCapability::all() {
            let refusal = CapabilityProfile::new(
                CapMask::all(),
                AuthoritySet::none().with(capability),
                Ownership::Detached,
            )
            .expect_err("detached work must not retain authority");
            assert_eq!(
                refusal,
                RuntimeRefusal::DetachedAuthorityRetained {
                    capability: capability.code()
                }
            );
        }
    }

    #[test]
    fn detached_derivation_drops_authority_and_proceeds() {
        let owner = CapabilityProfile::node_root();
        assert!(!owner.authority().is_empty());

        // Paired permitted case: detaching is fine, it just costs authority.
        let detached = owner.detached();
        assert_eq!(detached.ownership(), Ownership::Detached);
        assert!(detached.authority().is_empty());
        assert_eq!(detached.runtime_mask(), CapMask::all());
        detached
            .verify_detached_holds_no_authority()
            .expect("a detached envelope with no authority is admissible");
    }

    #[test]
    fn owned_work_may_hold_publication_authority() {
        // The near-identical permitted twin of the detached refusal above.
        let owned = CapabilityProfile::new(
            CapMask::all(),
            AuthoritySet::none().with(AuthorityCapability::Publication),
            Ownership::Owned,
        )
        .expect("owned work may hold publication authority");
        assert!(owned.authority().contains(AuthorityCapability::Publication));
    }

    #[test]
    fn narrowing_a_detached_child_to_authority_is_refused() {
        let root = CapabilityProfile::node_root();
        let refusal = root
            .narrow(
                CapMask::all(),
                AuthoritySet::none().with(AuthorityCapability::Runner),
                Ownership::Detached,
            )
            .expect_err("a detached child cannot carry runner authority");
        assert_eq!(
            refusal,
            RuntimeRefusal::DetachedAuthorityRetained {
                capability: "runner"
            }
        );

        // Paired permitted case: the same narrowing, owned.
        root.narrow(
            CapMask::all(),
            AuthoritySet::none().with(AuthorityCapability::Runner),
            Ownership::Owned,
        )
        .expect("owned children may carry runner authority");
    }

    #[test]
    fn authority_set_algebra_is_a_lattice() {
        let a = AuthoritySet::none()
            .with(AuthorityCapability::Publication)
            .with(AuthorityCapability::Database);
        let b = AuthoritySet::none()
            .with(AuthorityCapability::Database)
            .with(AuthorityCapability::Network);

        let meet = a.intersect(b);
        assert!(meet.contains(AuthorityCapability::Database));
        assert!(!meet.contains(AuthorityCapability::Publication));
        assert!(!meet.contains(AuthorityCapability::Network));

        // Intersection is monotone: the meet is contained in both sides.
        assert!(a.contains_all(meet));
        assert!(b.contains_all(meet));

        assert!(AuthoritySet::all().contains_all(a));
        assert!(AuthoritySet::none().is_empty());
        assert_eq!(
            a.without(AuthorityCapability::Publication).held(),
            vec![AuthorityCapability::Database]
        );
    }

    #[test]
    fn excess_reports_capabilities_in_declaration_order() {
        let parent = AuthoritySet::none().with(AuthorityCapability::Database);
        let child = AuthoritySet::all();
        let excess = child.excess_over(parent);
        assert_eq!(excess.first(), Some(&AuthorityCapability::Publication));
        assert!(!excess.contains(&AuthorityCapability::Database));
        assert_eq!(excess.len(), AuthorityCapability::all().len() - 1);
    }
}
