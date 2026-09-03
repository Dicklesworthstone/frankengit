#![forbid(unsafe_code)]
//! The pure deterministic repository reference model: `FrankenGit`'s semantic
//! oracle.
//!
//! Every optimized implementation path — per-core preparation lanes,
//! combiners, storage formats, indexes — must be trace-refinable to one
//! reference semantics (plan §40.1 and §40.5). Without an executable oracle,
//! "correct" quietly degrades into "whatever the implementation happens to
//! do". This crate is that oracle. It is deliberately slow and deliberately
//! simple; its only jobs are to be obviously right, replayable, and diffable.
//!
//! ## What "pure" means here, concretely
//!
//! * Every transition is a free function of the shape
//!   `(&RepositoryState, input) -> (RepositoryState, output)`. The state passed
//!   in is never mutated.
//! * No interior mutability. There is no `Cell`, `RefCell`, `Mutex`, `OnceLock`,
//!   or atomic anywhere in the crate.
//! * No ambient time, randomness, filesystem, network, or async runtime.
//! * No unordered collection. Every map and set is a `BTreeMap` or `BTreeSet`
//!   over a totally ordered key, because plan §16.3 forbids hash iteration
//!   order from being publication semantics.
//!
//! The consequence is the property FG-003c's bounded campaign needs: the same
//! input sequence always produces an identical state, and equal states answer
//! every query identically.
//!
//! ## The shape of the protocol
//!
//! ```text
//! seal ──► quarantine ──► prepare ──► decide ──► stage ──► head CAS
//!  │                          │          │         │          │
//!  │                          │          │         │          └─ the one
//!  │                          │          │         │             linearization
//!  │                          │          │         │             point (§8.3)
//!  │                          │          │         └─ staged, not canonical
//!  │                          │          └─ pure query; changes nothing
//!  │                          └─ one basis head, one policy epoch
//!  └─ identity only; not a commit and not an ordering event
//! ```
//!
//! Three distinctions do most of the work, and each is enforced by a type
//! rather than by a code path that could be missed:
//!
//! * **Rejection is not refusal.** A pre-seal rejection
//!   ([`fgit_types::vocabulary::RequestRejectionCode`]) is not repository
//!   history. A refusal ([`fgit_types::vocabulary::RefusalCode`]) is a terminal
//!   decision that consumes decision sequence. They are separate types with no
//!   conversion.
//! * **Refusals do not advance repository sequence.**
//!   [`fgit_types::vocabulary::DecisionOutcome::Refused`] has nowhere to put a
//!   repository sequence: that lives on [`decision::RepositoryCommitRecord`],
//!   which only a committed outcome names.
//! * **One sealed transaction has at most one terminal decision.** Within a
//!   batch this is unrepresentable — [`decision::DecisionBatch`] can only be
//!   built through [`decision::DecisionBatchDraft`], which refuses a duplicate
//!   transaction at insertion. Across batches it is a typed
//!   [`state::InvariantBreach`], because a second terminal outcome is an
//!   invariant failure (§15.8) and not something to write into history.
//!
//! ## Non-claims
//!
//! Stated plainly, because the claim lattice is checked and this crate sits at
//! the `bounded_model` rank, not at `proof`:
//!
//! * **This crate delegates canonical hashing to `fgit-codec`.** The general
//!   model still carries caller-supplied identity values and enforces their
//!   laws. The focused merge-delivery oracle additionally consumes shared
//!   canonical forge/outbox bodies and asks the codec for their deterministic
//!   roots; it does not define a second byte layout or hash preimage.
//! * **The Git object model is not implemented here.** The model knows only
//!   commit parentage, and only as much as the fast-forward predicate needs.
//!   Trees, blobs, tags, packs, and deltas belong to the object engine.
//! * **The declared subsets are subsets.** Refs are the `refs/` namespace only;
//!   forge state is a small pull-request vocabulary chosen to exercise §7's
//!   ref/forge atomicity rule, not a forge product surface. Both are typed
//!   refusals at the boundary, never silent reinterpretation.
//! * **Durability splits into two conditions, and only one is a decision.**
//!   A request demanding a profile the repository cannot offer is refused
//!   terminally with `DurabilityProfileUnavailable`. A batch whose declared
//!   placement predicate is merely *not satisfied yet* is not refused at all:
//!   [`transition::CasOutcome::DurabilityUnsatisfied`] leaves it staged and
//!   retryable, because §9 makes durability a publication predicate rather
//!   than a verdict on the transaction's semantics.
//! * **An invariant breach is never a decision.** `InternalInvariant` is the
//!   one §15.11 class this model does not emit into the decision stream: it
//!   surfaces as [`state::InvariantBreach`] and the transition does not happen.
//!   Writing a bug into the authenticated history would make it replayable
//!   truth. [`state::InvariantBreach::refusal_code`] gives a boundary that has
//!   no other channel the right code to report it with.
//! * **Passing this model's tests is not a proof.** It is bounded-model
//!   evidence about the model. Connecting it to an implementation requires the
//!   trace-refinement discipline of §40.5, which is a different bead.

pub mod campaign;
pub mod capsule;
pub mod decision;
pub mod effect;
pub mod harness;
pub mod intent;
pub mod machine;
pub mod merge_delivery;
pub mod refs;
pub mod refusal;
pub mod state;
pub mod trace;
pub mod transition;

pub use harness::{IdentityMint, label};
pub use machine::{
    CancellationPhase, CancellationReport, CancellationRequest, ModelInput, ModelOutput, ModelStep,
    step,
};
pub use merge_delivery::{
    MergeDeliveryInput, MergeDeliveryTransition, MergeDeliveryTransitionRefusal,
    apply_merge_delivery_transition,
};
pub use refusal::{MODEL_REFUSAL_SURFACE, RefusalClass, is_model_refusal};
pub use state::{
    AuthorityHead, AuthorityHeadBody, GenesisConfiguration, IdentityLedger, InvariantBreach,
    ModelResult, PolicySnapshot, PrincipalCapabilities, RepositoryRoots, RepositoryState,
};
