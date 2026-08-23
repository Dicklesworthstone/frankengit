//! Capabilities, attenuation-only delegation, and the sealed form a verifier
//! checks (`docs/AGENT_PROTOCOL.md` §6).
//!
//! # The two halves of "widening is impossible"
//!
//! §6.2 says delegation *"may only intersect selectors, reduce quotas, shorten
//! expiry, narrow operations"* and that *"missing ancestry or amplification is
//! refused"*. Those are two different obligations and this module discharges
//! them in two different ways, because they fail in different places.
//!
//! **In the API, widening is unrepresentable.** [`Capability::attenuate`] is
//! the only way to produce a child, and every field it writes is derived by
//! intersection, minimum, or subset check against the parent it was called on.
//! There is no constructor that takes a parent and a wider scope, so a widened
//! child is not a value this crate can build.
//!
//! Intersecting *silently* would satisfy "child ⊆ parent" while violating the
//! other half of §6.2: an amplification attempt must be **refused**, not
//! quietly narrowed. Silent intersection also hides the caller's bug, which is
//! the one thing a capability system must never do. So a request naming
//! anything the parent lacks is an error that names exactly what it tried to
//! add.
//!
//! **In the serialized form, widening is refused by the verifier.** Bytes are
//! not protected by Rust's type system, so [`SealedCapability`] carries an
//! HMAC-SHA256 tag over its canonical encoding, and that encoding commits to
//! the parent's tag. Editing a scope, a budget, an expiry, or a parent link
//! changes the preimage and the tag no longer verifies.
//!
//! [`verify_chain`] then re-checks the attenuation lattice on the decoded
//! values anyway, even though every tag verified. That is deliberate: tag
//! verification proves the issuer authorized these bytes, not that the issuer
//! was correct. A verifier that trusted the tags alone would authorize a
//! widened child the moment one issuer made a mistake or one key leaked.

use core::fmt;

use fgit_crypto::{TAG_BYTES, hmac_sha256, verify_mac};
use fgit_resource::{ResourceVector, algebra::ResourceError};

use crate::classes::{ClassSet, UnknownClassBits};

/// Domain separation for the capability authenticator.
///
/// A tag is only meaningful inside one interpretation of its preimage. Mixing
/// this MAC with any other keyed construction over similar bytes is the
/// key-reuse-with-different-semantics failure §5.2 of `AGENT_PROTOCOL.md`'s
/// parent contract fails closed on.
const CAPABILITY_MAC_DOMAIN: &[u8] = b"frankengit.agent.capability.v1";

/// Opaque capability identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CapabilityId(u128);

impl CapabilityId {
    /// Builds an identity from its raw value.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// The raw value, for canonical encoding.
    #[must_use]
    pub const fn value(self) -> u128 {
        self.0
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cap:{:032x}", self.0)
    }
}

/// A logical instant on the run's clock (`AGENT_PROTOCOL.md` §4.1).
///
/// Logical rather than wall-clock because §6.3 interprets freshness at a named
/// canonical position, and a wall clock is not one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LogicalTime(u64);

impl LogicalTime {
    /// Builds an instant.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for LogicalTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "t{}", self.0)
    }
}

/// An authorization to perform a bounded set of operations.
///
/// Construct a root with [`Capability::issue`] and every descendant with
/// [`Capability::attenuate`]. There is no other constructor, which is what
/// makes a widened child unrepresentable rather than merely refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capability {
    id: CapabilityId,
    parent: Option<CapabilityId>,
    operations: ClassSet,
    quota: ResourceVector,
    not_before: LogicalTime,
    expires_at: LogicalTime,
    depth: u16,
}

impl Capability {
    /// Issues a root capability.
    ///
    /// # Errors
    ///
    /// [`IssueRefused::EmptyScope`] when no class is authorized: a capability
    /// that permits nothing is never the intent, and admitting it would let an
    /// empty set stand in for a forgotten one.
    ///
    /// [`IssueRefused::ExpiryNotAfterStart`] when the validity window is empty
    /// or inverted.
    pub fn issue(
        id: CapabilityId,
        operations: ClassSet,
        quota: ResourceVector,
        not_before: LogicalTime,
        expires_at: LogicalTime,
    ) -> Result<Self, IssueRefused> {
        if operations.is_empty() {
            return Err(IssueRefused::EmptyScope);
        }
        if expires_at <= not_before {
            return Err(IssueRefused::ExpiryNotAfterStart {
                not_before,
                expires_at,
            });
        }
        Ok(Self {
            id,
            parent: None,
            operations,
            quota,
            not_before,
            expires_at,
            depth: 0,
        })
    }

    /// This capability's identity.
    #[must_use]
    pub const fn id(&self) -> CapabilityId {
        self.id
    }

    /// The parent this was attenuated from, if any.
    #[must_use]
    pub const fn parent(&self) -> Option<CapabilityId> {
        self.parent
    }

    /// The authorized operation classes.
    #[must_use]
    pub const fn operations(&self) -> ClassSet {
        self.operations
    }

    /// The resource quota this capability may spend.
    #[must_use]
    pub const fn quota(&self) -> ResourceVector {
        self.quota
    }

    /// The first instant this capability is valid.
    #[must_use]
    pub const fn not_before(&self) -> LogicalTime {
        self.not_before
    }

    /// The instant after which this capability is invalid.
    #[must_use]
    pub const fn expires_at(&self) -> LogicalTime {
        self.expires_at
    }

    /// How many delegations separate this from its root.
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Whether `now` lies inside the validity window.
    #[must_use]
    pub const fn is_valid_at(&self, now: LogicalTime) -> bool {
        now.value() >= self.not_before.value() && now.value() < self.expires_at.value()
    }

    /// Delegates a narrower capability.
    ///
    /// Every field is derived from this capability: operations are checked to
    /// be a subset, quota to be dominated, and the window to be contained. The
    /// result can therefore never exceed the parent along any axis.
    ///
    /// # Errors
    ///
    /// [`AttenuationRefused::OperationsAmplified`] naming the exact classes the
    /// request added; [`AttenuationRefused::QuotaAmplified`] naming the first
    /// grade that exceeded the parent; [`AttenuationRefused::WindowWidened`];
    /// [`AttenuationRefused::EmptyScope`]; [`AttenuationRefused::DepthExhausted`].
    pub fn attenuate(&self, request: &AttenuationRequest) -> Result<Self, AttenuationRefused> {
        if request.operations.is_empty() {
            return Err(AttenuationRefused::EmptyScope);
        }
        let amplified = request.operations.difference(self.operations);
        if !amplified.is_empty() {
            return Err(AttenuationRefused::OperationsAmplified {
                added: amplified,
                parent: self.operations,
            });
        }
        // `dominates` is defined as `first_deficit(..).is_none()`, so asking for
        // the deficit directly is the same test with the reason attached. Going
        // through `dominates` first would need an unreachable fallback grade
        // here, and an unreachable default is how a wrong grade gets reported.
        if let Some(deficit) = self.quota.first_deficit(&request.quota) {
            return Err(AttenuationRefused::QuotaAmplified { deficit });
        }
        if request.not_before < self.not_before || request.expires_at > self.expires_at {
            return Err(AttenuationRefused::WindowWidened {
                requested: (request.not_before, request.expires_at),
                parent: (self.not_before, self.expires_at),
            });
        }
        if request.expires_at <= request.not_before {
            return Err(AttenuationRefused::EmptyWindow {
                not_before: request.not_before,
                expires_at: request.expires_at,
            });
        }
        let depth = self
            .depth
            .checked_add(1)
            .ok_or(AttenuationRefused::DepthExhausted)?;
        Ok(Self {
            id: request.id,
            parent: Some(self.id),
            operations: request.operations,
            quota: request.quota,
            not_before: request.not_before,
            expires_at: request.expires_at,
            depth,
        })
    }

    /// The canonical preimage the authenticator commits to.
    ///
    /// Fixed-width, length-free, and ordered: every field contributes the same
    /// number of bytes in the same position, so no two distinct capabilities
    /// share a preimage and no field can be moved into another's span.
    fn preimage(&self, parent_tag: Option<&[u8; TAG_BYTES]>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CAPABILITY_MAC_DOMAIN.len() + 96 + TAG_BYTES);
        bytes.extend_from_slice(CAPABILITY_MAC_DOMAIN);
        bytes.extend_from_slice(&self.id.value().to_be_bytes());
        bytes.extend_from_slice(
            &self
                .parent
                .map_or(0_u128, CapabilityId::value)
                .to_be_bytes(),
        );
        bytes.push(u8::from(self.parent.is_some()));
        bytes.extend_from_slice(&self.operations.bits().to_be_bytes());
        for (_, amount) in self.quota.pairs() {
            bytes.extend_from_slice(&amount.to_be_bytes());
        }
        bytes.extend_from_slice(&self.not_before.value().to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.value().to_be_bytes());
        bytes.extend_from_slice(&self.depth.to_be_bytes());
        match parent_tag {
            Some(tag) => {
                bytes.push(1);
                bytes.extend_from_slice(tag);
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&[0_u8; TAG_BYTES]);
            }
        }
        bytes
    }

    /// Seals this capability under `key`, binding it to its parent's tag.
    ///
    /// # Errors
    ///
    /// [`SealRefused::ParentTagMissing`] when a delegated capability is sealed
    /// without its parent's tag, and [`SealRefused::ParentTagUnexpected`] for
    /// the reverse. Either would produce a chain whose ancestry cannot be
    /// checked, which §6.2 refuses.
    pub fn seal(
        &self,
        key: &[u8],
        parent_tag: Option<&[u8; TAG_BYTES]>,
    ) -> Result<SealedCapability, SealRefused> {
        match (self.parent.is_some(), parent_tag.is_some()) {
            (true, false) => return Err(SealRefused::ParentTagMissing),
            (false, true) => return Err(SealRefused::ParentTagUnexpected),
            _ => {}
        }
        let tag = hmac_sha256(key, &self.preimage(parent_tag));
        Ok(SealedCapability {
            capability: self.clone(),
            parent_tag: parent_tag.copied(),
            tag,
        })
    }
}

/// The narrower scope a delegation asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttenuationRequest {
    /// Identity for the delegated capability.
    pub id: CapabilityId,
    /// Operation classes requested; must be a subset of the parent's.
    pub operations: ClassSet,
    /// Quota requested; must be dominated by the parent's.
    pub quota: ResourceVector,
    /// Requested validity start; must not precede the parent's.
    pub not_before: LogicalTime,
    /// Requested expiry; must not exceed the parent's.
    pub expires_at: LogicalTime,
}

/// A capability plus the authenticator a verifier checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedCapability {
    capability: Capability,
    parent_tag: Option<[u8; TAG_BYTES]>,
    tag: [u8; TAG_BYTES],
}

impl SealedCapability {
    /// The capability as issued. Untrusted until [`verify_chain`] accepts it.
    #[must_use]
    pub const fn capability(&self) -> &Capability {
        &self.capability
    }

    /// This link's authenticator.
    #[must_use]
    pub const fn tag(&self) -> &[u8; TAG_BYTES] {
        &self.tag
    }

    /// The parent tag this link commits to, if it is a delegation.
    #[must_use]
    pub const fn parent_tag(&self) -> Option<&[u8; TAG_BYTES]> {
        self.parent_tag.as_ref()
    }

    /// Replaces the carried capability without re-sealing.
    ///
    /// This exists so tests can build the tampered token an attacker would
    /// send. It is deliberately the only way to desynchronize body and tag,
    /// and every such value is refused by [`verify_chain`].
    #[must_use]
    pub const fn with_tampered_capability(&self, capability: Capability) -> Self {
        Self {
            capability,
            parent_tag: self.parent_tag,
            tag: self.tag,
        }
    }
}

/// Verifies a delegation chain root-first under `key`.
///
/// Checks, in order, for every link: the authenticator over its own bytes; that
/// its committed parent tag is the previous link's actual tag; and that it is
/// an attenuation of its parent along operations, quota, and window.
///
/// # Errors
///
/// See [`ChainRefused`]. An empty chain is refused rather than treated as
/// trivially valid, because "no ancestry" is exactly what §6.2 names.
pub fn verify_chain(chain: &[SealedCapability], key: &[u8]) -> Result<Capability, ChainRefused> {
    let (root, rest) = chain.split_first().ok_or(ChainRefused::EmptyChain)?;

    if root.capability.parent.is_some() {
        return Err(ChainRefused::MissingAncestry {
            index: 0,
            id: root.capability.id,
        });
    }
    if root.parent_tag.is_some() {
        return Err(ChainRefused::RootCarriesParentTag);
    }
    check_tag(root, 0, key)?;

    let mut parent = &root.capability;
    let mut parent_tag = root.tag;

    for (offset, link) in rest.iter().enumerate() {
        let index = offset + 1;
        check_tag(link, index, key)?;

        match link.capability.parent {
            None => {
                return Err(ChainRefused::MissingAncestry {
                    index,
                    id: link.capability.id,
                });
            }
            Some(named) if named != parent.id => {
                return Err(ChainRefused::AncestryMismatch {
                    index,
                    named,
                    actual: parent.id,
                });
            }
            Some(_) => {}
        }

        match link.parent_tag {
            None => return Err(ChainRefused::ParentTagMissing { index }),
            Some(tag) if !verify_mac(&parent_tag, &tag) => {
                return Err(ChainRefused::ParentTagMismatch { index });
            }
            Some(_) => {}
        }

        // Re-checked even though both tags verified: a valid tag proves the
        // issuer signed these bytes, not that the issuer was right to.
        let amplified = link.capability.operations.difference(parent.operations);
        if !amplified.is_empty() {
            return Err(ChainRefused::OperationsAmplified {
                index,
                added: amplified,
            });
        }
        if let Some(deficit) = parent.quota.first_deficit(&link.capability.quota) {
            return Err(ChainRefused::QuotaAmplified { index, deficit });
        }
        if link.capability.not_before < parent.not_before
            || link.capability.expires_at > parent.expires_at
        {
            return Err(ChainRefused::WindowWidened { index });
        }

        parent = &link.capability;
        parent_tag = link.tag;
    }

    Ok(parent.clone())
}

fn check_tag(link: &SealedCapability, index: usize, key: &[u8]) -> Result<(), ChainRefused> {
    let expected = hmac_sha256(key, &link.capability.preimage(link.parent_tag.as_ref()));
    if verify_mac(&expected, &link.tag) {
        Ok(())
    } else {
        Err(ChainRefused::AuthenticatorMismatch { index })
    }
}

/// Why a root capability could not be issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueRefused {
    /// The capability would authorize nothing.
    EmptyScope,
    /// The validity window is empty or inverted.
    ExpiryNotAfterStart {
        /// Requested start.
        not_before: LogicalTime,
        /// Requested expiry.
        expires_at: LogicalTime,
    },
}

impl fmt::Display for IssueRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScope => {
                formatter.write_str("a capability must authorize at least one operation class")
            }
            Self::ExpiryNotAfterStart {
                not_before,
                expires_at,
            } => write!(
                formatter,
                "capability expiry {expires_at} does not follow its start {not_before}"
            ),
        }
    }
}

impl core::error::Error for IssueRefused {}

/// Why a delegation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttenuationRefused {
    /// The delegation would authorize nothing.
    EmptyScope,
    /// The request named classes the parent does not hold.
    OperationsAmplified {
        /// Exactly the classes that were added.
        added: ClassSet,
        /// What the parent actually holds.
        parent: ClassSet,
    },
    /// The request asked for more of a grade than the parent holds.
    QuotaAmplified {
        /// The algebra's own deficit, naming the grade, the parent's amount,
        /// and the requested one.
        deficit: ResourceError,
    },
    /// The request's validity window is not contained in the parent's.
    WindowWidened {
        /// Requested window.
        requested: (LogicalTime, LogicalTime),
        /// Parent window.
        parent: (LogicalTime, LogicalTime),
    },
    /// The request's own window is empty or inverted.
    EmptyWindow {
        /// Requested start.
        not_before: LogicalTime,
        /// Requested expiry.
        expires_at: LogicalTime,
    },
    /// The delegation chain is already at the representable maximum depth.
    DepthExhausted,
}

impl fmt::Display for AttenuationRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScope => {
                formatter.write_str("a delegation must authorize at least one operation class")
            }
            Self::OperationsAmplified { added, parent } => write!(
                formatter,
                "delegation would amplify operations: adds {added} to a parent holding {parent}"
            ),
            Self::QuotaAmplified { deficit } => {
                write!(formatter, "delegation would amplify quota: {deficit}")
            }
            Self::WindowWidened { requested, parent } => write!(
                formatter,
                "delegation would widen the window: requested {}..{}, parent {}..{}",
                requested.0, requested.1, parent.0, parent.1
            ),
            Self::EmptyWindow {
                not_before,
                expires_at,
            } => write!(
                formatter,
                "delegation expiry {expires_at} does not follow its start {not_before}"
            ),
            Self::DepthExhausted => {
                formatter.write_str("delegation chain is at maximum representable depth")
            }
        }
    }
}

impl core::error::Error for AttenuationRefused {}

/// Why a capability could not be sealed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealRefused {
    /// A delegated capability was sealed without its parent's tag.
    ParentTagMissing,
    /// A root capability was sealed with a parent tag.
    ParentTagUnexpected,
}

impl fmt::Display for SealRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParentTagMissing => formatter
                .write_str("a delegated capability must be sealed against its parent's tag"),
            Self::ParentTagUnexpected => {
                formatter.write_str("a root capability must not be sealed against a parent tag")
            }
        }
    }
}

impl core::error::Error for SealRefused {}

/// Why a delegation chain was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainRefused {
    /// No links were presented.
    EmptyChain,
    /// A link's authenticator does not match its bytes.
    AuthenticatorMismatch {
        /// Position in the chain, root-first.
        index: usize,
    },
    /// A non-root link claims no parent, or the root claims one.
    MissingAncestry {
        /// Position in the chain.
        index: usize,
        /// The capability that lacks ancestry.
        id: CapabilityId,
    },
    /// A link names a parent other than the one preceding it.
    AncestryMismatch {
        /// Position in the chain.
        index: usize,
        /// The parent the link names.
        named: CapabilityId,
        /// The parent actually preceding it.
        actual: CapabilityId,
    },
    /// The root link carries a parent tag.
    RootCarriesParentTag,
    /// A delegated link carries no parent tag.
    ParentTagMissing {
        /// Position in the chain.
        index: usize,
    },
    /// A link's committed parent tag is not its parent's actual tag.
    ParentTagMismatch {
        /// Position in the chain.
        index: usize,
    },
    /// A link authorizes classes its parent does not hold.
    OperationsAmplified {
        /// Position in the chain.
        index: usize,
        /// Exactly the classes added.
        added: ClassSet,
    },
    /// A link asks for more of a grade than its parent holds.
    QuotaAmplified {
        /// Position in the chain.
        index: usize,
        /// The algebra's own deficit for that link.
        deficit: ResourceError,
    },
    /// A link's validity window is not contained in its parent's.
    WindowWidened {
        /// Position in the chain.
        index: usize,
    },
    /// A serialized class mask named an unknown class.
    UnknownClasses(UnknownClassBits),
}

impl fmt::Display for ChainRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChain => {
                formatter.write_str("a capability chain must present at least its root")
            }
            Self::AuthenticatorMismatch { index } => {
                write!(
                    formatter,
                    "capability at index {index} does not match its authenticator"
                )
            }
            Self::MissingAncestry { index, id } => {
                write!(
                    formatter,
                    "capability {id} at index {index} presents no ancestry"
                )
            }
            Self::AncestryMismatch {
                index,
                named,
                actual,
            } => write!(
                formatter,
                "capability at index {index} names parent {named} but follows {actual}"
            ),
            Self::RootCarriesParentTag => {
                formatter.write_str("the root capability carries a parent tag")
            }
            Self::ParentTagMissing { index } => {
                write!(
                    formatter,
                    "delegated capability at index {index} commits to no parent tag"
                )
            }
            Self::ParentTagMismatch { index } => {
                write!(
                    formatter,
                    "capability at index {index} commits to the wrong parent tag"
                )
            }
            Self::OperationsAmplified { index, added } => write!(
                formatter,
                "capability at index {index} amplifies operations by {added}"
            ),
            Self::QuotaAmplified { index, deficit } => {
                write!(
                    formatter,
                    "capability at index {index} amplifies quota: {deficit}"
                )
            }
            Self::WindowWidened { index } => {
                write!(
                    formatter,
                    "capability at index {index} widens its parent's validity window"
                )
            }
            Self::UnknownClasses(inner) => write!(formatter, "{inner}"),
        }
    }
}

impl core::error::Error for ChainRefused {}

#[cfg(test)]
mod tests {
    use super::{Capability, CapabilityId, ChainRefused, LogicalTime, check_tag, verify_chain};
    use crate::classes::{ClassSet, OperationClass};
    use fgit_resource::{ResourceVector, algebra::Grade};

    const KEY: &[u8] = b"issuer-key-for-tests-only";

    /// Why this test is in-src and not in `tests/`.
    ///
    /// `verify_chain` re-checks the attenuation lattice even after every tag
    /// has verified. Reaching that arm requires a chain whose links are all
    /// correctly sealed and whose child nonetheless exceeds its parent — and
    /// building one through the public API is impossible, because `attenuate`
    /// is the only way to make a child and it refuses amplification. That
    /// impossibility is the API-half guarantee, so the arm can only be exercised
    /// from inside the module where the fields are reachable.
    ///
    /// Constructing it here is not a loophole in the guarantee; it is what a
    /// leaked issuer key or a buggy issuer would produce, which is exactly the
    /// case the re-check exists for.
    fn amplified_child_of(parent: &Capability) -> Capability {
        Capability {
            id: CapabilityId::new(2),
            parent: Some(parent.id),
            // Strictly wider than the parent: adds a class it does not hold.
            operations: ClassSet::from_classes(&[
                OperationClass::ReadCanonicalObject,
                OperationClass::SecretHandle,
            ]),
            quota: parent.quota,
            not_before: parent.not_before,
            expires_at: parent.expires_at,
            depth: parent.depth + 1,
        }
    }

    fn root() -> Capability {
        Capability::issue(
            CapabilityId::new(1),
            ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
            ResourceVector::single(Grade::Bytes, 100),
            LogicalTime::new(0),
            LogicalTime::new(100),
        )
        .expect("root issues")
    }

    #[test]
    fn a_correctly_sealed_but_amplified_child_is_still_refused() {
        let parent = root();
        let sealed_parent = parent.seal(KEY, None).expect("root seals");
        let child = amplified_child_of(&parent);
        let sealed_child = child
            .seal(KEY, Some(sealed_parent.tag()))
            .expect("the amplified child seals correctly against its parent");

        // Both tags are genuinely valid: this is not a tampering case. If the
        // verifier trusted its authenticators, it would accept this chain.
        assert!(check_tag(&sealed_parent, 0, KEY).is_ok());
        assert!(check_tag(&sealed_child, 1, KEY).is_ok());

        let refusal = verify_chain(&[sealed_parent, sealed_child], KEY)
            .expect_err("a valid signature over a widened child is still a widened child");
        match refusal {
            ChainRefused::OperationsAmplified { index, added } => {
                assert_eq!(index, 1);
                assert_eq!(
                    added,
                    ClassSet::from_classes(&[OperationClass::SecretHandle])
                );
            }
            other => panic!("expected OperationsAmplified, got {other:?}"),
        }
    }

    #[test]
    fn the_same_chain_without_the_amplification_verifies() {
        // The permitted twin for the test above. Without it, the refusal could
        // come from anything about a hand-built child rather than from the
        // widening specifically.
        let parent = root();
        let sealed_parent = parent.seal(KEY, None).expect("root seals");
        let mut child = amplified_child_of(&parent);
        child.operations = parent.operations;
        let sealed_child = child
            .seal(KEY, Some(sealed_parent.tag()))
            .expect("the narrowed child seals");

        let leaf = verify_chain(&[sealed_parent, sealed_child], KEY)
            .expect("an equally-scoped, correctly sealed child is a legal delegation");
        assert_eq!(leaf.id(), CapabilityId::new(2));
    }
}
