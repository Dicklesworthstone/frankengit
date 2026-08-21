//! Typed intents, statements, and the sealed request they belong to.
//!
//! `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` §13 and plan §15.2 are explicit that
//! canonical commands are **intents**, not pre-baked effects: a caller states
//! what it wants and the precondition it believes holds, and the model decides
//! the effect against a pinned basis. Nothing here carries caller-computed
//! derived state, and no intent names a resulting root.
//!
//! A [`TransactionRequest`] is the canonicalized semantic request of §10 step
//! 2. It carries its own [`TxId`] and canonical request digest rather than
//! deriving them: identity derivation is a digest over canonical bytes and
//! belongs to the codec and crypto registries, not to this crate. What the
//! model *does* enforce is the derivation's law — see
//! [`crate::state::IdentityLedger`] — so a broken derivation is caught here
//! even though the digest itself is computed elsewhere.

use std::collections::BTreeSet;

use fgit_types::hash::Digest;
use fgit_types::identity::{PrincipalId, RepositoryId, TenantId, TxId};
use fgit_types::label::{AsciiSlug, SchemaId};
use fgit_types::native::GitOid;
use fgit_types::vocabulary::MismatchPolicy;

use fgit_types::refs::RefName;

use crate::refs::ExpectedRefState;

/// Largest number of intents the model admits in one transaction.
///
/// A bound must exist before work is allocated (`AGENTS.md` §14: "Are resource
/// and adversarial bounds enforced before allocation/work?"). The value is
/// deliberately small: this is an oracle, and a bounded model campaign wants a
/// small state space.
pub const MAX_INTENTS_PER_TRANSACTION: usize = 64;

/// A client-chosen idempotency key.
///
/// The key has no authority of its own: §3.3 binds it together with tenant,
/// repository, principal, and the canonical request digest to derive one
/// [`TxId`]. Reusing a key with a different digest is a pre-seal rejection,
/// never an alias of the first request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IdempotencyKey(AsciiSlug);

impl IdempotencyKey {
    /// Wraps a validated label as an idempotency key.
    #[must_use]
    pub const fn new(label: AsciiSlug) -> Self {
        Self(label)
    }

    /// The key label.
    #[must_use]
    pub const fn label(&self) -> AsciiSlug {
        self.0
    }
}

/// Identity of one canonical forge stream.
///
/// Forge streams are the aggregate roots of §20: issues, pull requests,
/// reviews, releases, and queues each advance one authenticated logical
/// position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ForgeStreamId(AsciiSlug);

impl ForgeStreamId {
    /// Wraps a validated label as a stream identity.
    #[must_use]
    pub const fn new(label: AsciiSlug) -> Self {
        Self(label)
    }

    /// The stream label.
    #[must_use]
    pub const fn label(&self) -> AsciiSlug {
        self.0
    }
}

/// Identity of one forge entity inside a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ForgeEntityId(AsciiSlug);

impl ForgeEntityId {
    /// Wraps a validated label as an entity identity.
    #[must_use]
    pub const fn new(label: AsciiSlug) -> Self {
        Self(label)
    }

    /// The entity label.
    #[must_use]
    pub const fn label(&self) -> AsciiSlug {
        self.0
    }
}

/// The authenticated logical position of one forge stream.
///
/// Position zero is "stream has never advanced"; it is not a live event index.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ForgeStreamPosition(u64);

impl ForgeStreamPosition {
    /// The position of a stream that has never advanced.
    pub const GENESIS: Self = Self(0);

    /// Wraps a raw position.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw position.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The immediate successor, saturating instead of wrapping.
    ///
    /// Saturation is safe here because the model refuses a stream that has
    /// reached [`u64::MAX`] before it can be advanced again; wrapping would
    /// silently reuse a position.
    #[must_use]
    pub const fn successor(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// True when the stream cannot advance any further.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.0 == u64::MAX
    }
}

/// A canonical forge transition.
///
/// The variants are deliberately few. What the reference model has to capture
/// is §7's atomicity rule — "an RCR classified as a PR merge cannot move the
/// ref without the corresponding forge event batch", and its converse — not a
/// complete forge product surface.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ForgeEventKind {
    /// A pull request was opened against a target ref.
    PullRequestOpened {
        /// The pull request.
        pull_request: ForgeEntityId,
        /// The ref the pull request targets.
        target: RefName,
    },
    /// A pull request merged into its target ref.
    ///
    /// This event may only appear together with a ref effect that moves
    /// `target` in the same transaction.
    PullRequestMerged {
        /// The pull request.
        pull_request: ForgeEntityId,
        /// The ref the merge moves.
        target: RefName,
    },
    /// A pull request closed without merging.
    PullRequestClosed {
        /// The pull request.
        pull_request: ForgeEntityId,
    },
}

impl ForgeEventKind {
    /// The ref this event requires to move in the same transaction, if any.
    #[must_use]
    pub const fn required_ref_effect(&self) -> Option<&RefName> {
        match self {
            Self::PullRequestMerged { target, .. } => Some(target),
            Self::PullRequestOpened { .. } | Self::PullRequestClosed { .. } => None,
        }
    }

    /// The entity this event advances.
    #[must_use]
    pub const fn entity(&self) -> ForgeEntityId {
        match self {
            Self::PullRequestOpened { pull_request, .. }
            | Self::PullRequestMerged { pull_request, .. }
            | Self::PullRequestClosed { pull_request } => *pull_request,
        }
    }
}

/// What a retention root protects.
///
/// §25 separates roots that ordinary policy may retire from roots that a
/// transaction may not remove at all. Removing a legal hold through an
/// ordinary transaction is refused; retiring a grace tombstone is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RetentionClass {
    /// A root held because a canonical ref points at it.
    ReferencedByRef,
    /// A root held by a legal hold or administrator pin. An ordinary
    /// transaction may add one but may not remove one.
    LegalHold,
    /// A grace tombstone retained for a bounded window.
    GraceTombstone,
}

impl RetentionClass {
    /// True when an ordinary sealed transaction may remove a root of this
    /// class.
    #[must_use]
    pub const fn is_ordinarily_removable(self) -> bool {
        match self {
            Self::ReferencedByRef | Self::GraceTombstone => true,
            Self::LegalHold => false,
        }
    }
}

/// One authenticated retention root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RetentionRoot {
    /// The object the root protects.
    pub object: GitOid,
    /// Why it is protected.
    pub class: RetentionClass,
}

/// A stable key for one externally observed effect.
///
/// `AGENTS.md` §9 requires every side effect to carry an idempotency key so a
/// retry cannot duplicate a canonical event (release-blocking invariant 22).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutboxDeliveryKey(AsciiSlug);

impl OutboxDeliveryKey {
    /// Wraps a validated label as a delivery key.
    #[must_use]
    pub const fn new(label: AsciiSlug) -> Self {
        Self(label)
    }

    /// The delivery key label.
    #[must_use]
    pub const fn label(&self) -> AsciiSlug {
        self.0
    }
}

/// A source-control ref intent.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefIntent {
    /// Create or move a ref.
    Update {
        /// The ref to move.
        name: RefName,
        /// The precondition the caller asserts about the basis.
        expected: ExpectedRefState,
        /// The object the ref should hold afterwards.
        new: GitOid,
        /// Whether the caller requested a forced non-fast-forward update.
        force: bool,
    },
    /// Delete a ref.
    Delete {
        /// The ref to delete.
        name: RefName,
        /// The precondition the caller asserts about the basis.
        expected: ExpectedRefState,
    },
}

impl RefIntent {
    /// The ref this intent targets.
    #[must_use]
    pub const fn target(&self) -> &RefName {
        match self {
            Self::Update { name, .. } | Self::Delete { name, .. } => name,
        }
    }

    /// The precondition asserted about the basis.
    #[must_use]
    pub const fn expected(&self) -> &ExpectedRefState {
        match self {
            Self::Update { expected, .. } | Self::Delete { expected, .. } => expected,
        }
    }
}

/// A forge transition intent.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ForgeIntent {
    /// The stream to advance.
    pub stream: ForgeStreamId,
    /// The position the caller believes the stream currently holds.
    pub expected_position: ForgeStreamPosition,
    /// The transition to append.
    pub event: ForgeEventKind,
}

/// A retention-root intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RetentionIntent {
    /// Add a root.
    AddRoot(RetentionRoot),
    /// Remove a root.
    RemoveRoot(RetentionRoot),
}

/// An outbox effect intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutboxIntent {
    /// The stable delivery key that makes the effect idempotent.
    pub delivery_key: OutboxDeliveryKey,
    /// The digest over the effect's canonical parameters.
    pub parameters: Digest,
}

/// One typed intent.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Intent {
    /// A ref intent.
    Ref(RefIntent),
    /// A forge intent.
    Forge(ForgeIntent),
    /// A retention intent.
    Retention(RetentionIntent),
    /// An outbox intent.
    Outbox(OutboxIntent),
}

/// Zero-based position of one statement inside a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatementIndex(pub usize);

/// Zero-based position of one intent inside its statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IntentIndex(pub usize);

/// An addressable position of one intent inside a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IntentAddress {
    /// The statement the intent belongs to.
    pub statement: StatementIndex,
    /// The intent's position inside that statement.
    pub intent: IntentIndex,
}

/// An ordered group of intents sharing one precondition-mismatch policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Statement {
    /// The intents, evaluated in this order with read-your-own-writes.
    pub intents: Vec<Intent>,
    /// What happens when a precondition does not match the basis.
    pub mismatch_policy: MismatchPolicy,
}

/// Which publication epoch a transaction's bodies must reach before the head
/// may reference them.
///
/// §9 refuses one universal ordering. The canonical source profile requires
/// durability *before* visibility; a lower-value derived generation may become
/// visible with an outstanding durability obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DurabilityProfile {
    /// `Absent -> Staged -> DurabilitySatisfied -> Visible`.
    CanonicalSource,
    /// `Absent -> Staged -> Visible(with DurabilityObligation) -> Durable`.
    DerivedGeneration,
}

impl DurabilityProfile {
    /// True when the profile forbids publication before the declared
    /// placement predicate is satisfied.
    #[must_use]
    pub const fn requires_durability_before_visibility(self) -> bool {
        match self {
            Self::CanonicalSource => true,
            Self::DerivedGeneration => false,
        }
    }
}

/// One canonicalized semantic request.
///
/// Every field here is client-visible semantics that the canonical request
/// digest binds (§3.3). Pack encoding, quarantine placement, retry count,
/// receiving node, wall-clock time, and the authority-head basis are excluded
/// by construction: there is nowhere in this type to put them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionRequest {
    /// The logical mutation identity, derived elsewhere per §3.3.
    pub tx_id: TxId,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Target repository.
    pub repository: RepositoryId,
    /// The authenticated principal.
    pub principal: PrincipalId,
    /// The request schema this body conforms to.
    pub schema: SchemaId,
    /// The client-chosen idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Digest over every client-visible semantic field.
    pub canonical_request_digest: Digest,
    /// Ordered statements.
    pub statements: Vec<Statement>,
    /// Objects the request promises are reachable.
    pub promised_closure: BTreeSet<GitOid>,
    /// Whether all commands must publish together.
    pub atomic: bool,
    /// The durability profile publication must satisfy.
    pub durability: DurabilityProfile,
}

impl TransactionRequest {
    /// Total number of intents across every statement.
    #[must_use]
    pub fn intent_count(&self) -> usize {
        self.statements
            .iter()
            .map(|statement| statement.intents.len())
            .sum()
    }

    /// Every intent with its address, in source order.
    pub fn addressed_intents(&self) -> impl Iterator<Item = (IntentAddress, &Intent)> {
        self.statements
            .iter()
            .enumerate()
            .flat_map(|(statement_index, statement)| {
                statement
                    .intents
                    .iter()
                    .enumerate()
                    .map(move |(intent_index, intent)| {
                        (
                            IntentAddress {
                                statement: StatementIndex(statement_index),
                                intent: IntentIndex(intent_index),
                            },
                            intent,
                        )
                    })
            })
    }

    /// The stable seal fields of §5.2, which a retry must reproduce exactly.
    #[must_use]
    pub const fn seal_fields(&self) -> SealFields {
        SealFields {
            tx_id: self.tx_id,
            tenant: self.tenant,
            repository: self.repository,
            principal: self.principal,
            idempotency_key: self.idempotency_key,
            canonical_request_digest: self.canonical_request_digest,
            schema: self.schema,
        }
    }
}

/// The stable identity fields a transaction seal binds.
///
/// §5.2: a retry that presents matching stable fields continues under the
/// existing seal; any conflicting stable field is an idempotency-key-reuse
/// rejection. Admission capability, policy epoch, issuer, and first-seen time
/// are separate receipts and are deliberately absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SealFields {
    /// The logical mutation identity.
    pub tx_id: TxId,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Target repository.
    pub repository: RepositoryId,
    /// The authenticated principal.
    pub principal: PrincipalId,
    /// The client-chosen idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Digest over every client-visible semantic field.
    pub canonical_request_digest: Digest,
    /// The request schema.
    pub schema: SchemaId,
}

impl SealFields {
    /// The tuple §3.3 binds into the transaction identity, excluding the
    /// identity itself.
    ///
    /// Two requests agreeing on this tuple must derive the same [`TxId`], and
    /// two disagreeing on it must not. [`crate::state::IdentityLedger`]
    /// enforces both directions.
    #[must_use]
    pub const fn derivation_inputs(&self) -> TxIdDerivationInputs {
        TxIdDerivationInputs {
            tenant: self.tenant,
            repository: self.repository,
            principal: self.principal,
            idempotency_key: self.idempotency_key,
            canonical_request_digest: self.canonical_request_digest,
        }
    }
}

/// The inputs §3.3 binds into one transaction identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TxIdDerivationInputs {
    /// Owning tenant.
    pub tenant: TenantId,
    /// Target repository.
    pub repository: RepositoryId,
    /// The authenticated principal.
    pub principal: PrincipalId,
    /// The client-chosen idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Digest over every client-visible semantic field.
    pub canonical_request_digest: Digest,
}
