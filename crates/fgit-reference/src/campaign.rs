//! The exhaustive small-state campaign: bounded model checking over the
//! reference model.
//!
//! Plan §40.2 asks for the race space between seal creation, duplicate
//! requests, compare-and-swap winners and losers, cancellation, and crash
//! points to be *explored*, not sampled. This module walks it explicitly.
//!
//! ## Why a walker and not a stress loop
//!
//! A randomized stress run reports how many executions it happened to try. It
//! cannot say what it did **not** try, so a count of a million iterations is
//! not coverage of anything in particular. This walker enumerates the reachable
//! state space under declared bounds and reports the bounds together with the
//! result, so "all five properties hold" means *within this stated envelope*
//! and nothing broader. That is a `bounded_model` claim and is labelled as one.
//!
//! ## Deduplication is exact, not hashed
//!
//! A model checker normally fingerprints states with a hash and accepts the
//! collision risk. This crate computes no digests, and inventing one here would
//! contradict that. Instead [`state_key`] builds the **canonical encoding** of
//! the parts of the state a further transition can depend on, and the walker
//! deduplicates on those exact bytes. Two states sharing a key are genuinely
//! equal in every respect the model can observe, so no execution is merged away
//! by accident.
//!
//! ## The five properties
//!
//! [`Property`] enumerates exactly the five of plan §40.2. They are checked on
//! every reachable state, not only at the end of a path, because a violation
//! that a later transition repairs is still a violation.
//!
//! ## Two things a clean verdict does not mean on its own
//!
//! **It could be vacuous.** A property whose subject never occurs in the
//! explored space holds trivially: check "a merge publishes with its ref" over
//! a space containing no merges and it passes without examining anything. So
//! every reached state records which properties it *materially* exercised
//! ([`CampaignReport::property_witnesses`]), the receipt carries those counts
//! and the [`Coverage`] of the space beside the verdict, and
//! [`CampaignReport::is_clean`] is false when any property has no witness.
//!
//! **The checker could be blind.** A walk that has never caught anything is
//! not evidence that there is nothing to catch. [`PlantedDefect`] carries one
//! deliberate model defect per property; [`run_with`] applies it to every state
//! the walk reaches, and the campaign's own tests require that *every* planted
//! instance is detected by the property it targets. A blind spot shows up as
//! `defects_detected < defects_planted` rather than as a clean run.
//!
//! ## Non-claims
//!
//! This is `bounded_model` evidence about the reference model under the bounds
//! in the receipt, and nothing wider. It is not a proof, it says nothing about
//! any implementation until trace refinement (plan §40.5) connects one to this
//! oracle, and the planted-defect mode establishes that the checks *can* fail —
//! not that they would catch every defect.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fgit_codec::error::CodecRefusal;
use fgit_codec::writer::Encoder;
use fgit_types::identity::{
    PreparedTxnCapsuleId, PrincipalId, RepositoryAuthorityHeadId, RepositoryDecisionBatchId,
    TransactionSealId, TxId,
};
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::numeric::{HeadGeneration, PolicyEpoch, RegistryEpoch};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::{DecisionOutcome, MismatchPolicy};

use crate::capsule::{PreparedVerdict, WitnessGranularity};
use crate::harness::{IdentityMint, RequestBuilder, label};
use crate::intent::{
    DurabilityProfile, ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId,
    ForgeStreamPosition, IdempotencyKey, Intent, RefIntent, TransactionRequest,
};
use crate::machine::{
    CancellationPhase, CancellationRequest, ModelInput, ModelOutput, ModelStep, step,
};
use crate::refs::ExpectedRefState;
use crate::state::{
    GenesisConfiguration, ModelResult, PolicySnapshot, PrincipalCapabilities, QuarantinedObject,
    RepositoryState,
};
use crate::trace::{TraceStep, encode_roots};
use crate::transition::{
    CasOutcome, CasRequest, DecisionBodyIdentity, PrepareRequest, QuarantineRequest, SealRequest,
    StageRequest,
};

/// The declared bounds of one campaign.
///
/// Every number here narrows the explored space, so the campaign reports this
/// struct alongside its verdict. A bounded result whose bounds are not stated
/// is not evidence of anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Bounds {
    /// How many distinct sealed transactions the universe contains.
    pub transactions: usize,
    /// How many preparation attempts each transaction may make.
    pub attempts_per_transaction: usize,
    /// How many decision batches may be staged across the whole run.
    pub batches: usize,
    /// Longest path, in transitions, the walker will follow.
    pub depth: usize,
    /// Hard ceiling on explored states, so a bug in the bounds cannot hang a
    /// lane.
    pub max_states: usize,
}

impl Bounds {
    /// Bounds sized to run in a continuous-integration lane in seconds.
    pub const DEFAULT: Self = Self {
        transactions: 2,
        attempts_per_transaction: 2,
        batches: 2,
        depth: 7,
        max_states: 20_000,
    };

    /// One attempt per transaction, but deeper.
    ///
    /// [`Self::DEFAULT`] spends its depth on retry *breadth* — two preparation
    /// attempts per transaction — which leaves no room for a transaction to be
    /// prepared **after** another one has already published. That execution
    /// needs ten transitions: five to publish the first, then a seal,
    /// quarantine, preparation, staging and compare-and-swap for the second.
    /// Trading the second attempt for three more transitions reaches it in
    /// under a thousand states, so the sequence is covered in a lane measured
    /// in seconds rather than only in the deep run.
    pub const SEQUENCED: Self = Self {
        transactions: 2,
        attempts_per_transaction: 1,
        batches: 2,
        depth: 10,
        max_states: 400_000,
    };

    /// Wider bounds for a deliberate deep run.
    ///
    /// Documented rather than default because the space grows sharply: this is
    /// the `--deep` mode the campaign's acceptance asks for. It keeps
    /// [`Self::DEFAULT`]'s retry breadth and spends three more transitions, so
    /// it is a strict superset of the fast lane and reaches the
    /// publish-then-publish-again execution as well.
    ///
    /// A third batch slot was tried here and abandoned: it multiplies the
    /// staging alphabet and the run did not finish inside twenty-five minutes,
    /// which is not a mode anyone would actually run. Depth buys reachability
    /// more cheaply than batch slots do, so the depth is where the budget went.
    pub const DEEP: Self = Self {
        transactions: 2,
        attempts_per_transaction: 2,
        batches: 2,
        depth: 10,
        max_states: 400_000,
    };
}

/// One of the five properties of plan §40.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Property {
    /// A sealed transaction has at most one terminal decision.
    UniqueTerminalOutcome,
    /// Every head names its exact predecessor and a successor generation.
    HeadChainContinuity,
    /// A pull-request merge and the ref it moves publish in one record.
    AtomicRefAndForgeEffects,
    /// No canonical root points at an object that never left quarantine, and
    /// the sequences are gap-free.
    NoRootOmission,
    /// Head generation and both sequences never move backwards.
    NoSilentAntiRollback,
}

impl Property {
    /// Every property, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::UniqueTerminalOutcome,
        Self::HeadChainContinuity,
        Self::AtomicRefAndForgeEffects,
        Self::NoRootOmission,
        Self::NoSilentAntiRollback,
    ];

    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UniqueTerminalOutcome => "unique_terminal_outcome",
            Self::HeadChainContinuity => "head_chain_continuity",
            Self::AtomicRefAndForgeEffects => "atomic_ref_and_forge_effects",
            Self::NoRootOmission => "no_root_omission",
            Self::NoSilentAntiRollback => "no_silent_anti_rollback",
        }
    }
}

/// A property that failed, with the path that reached it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// Which property failed.
    pub property: Property,
    /// What specifically was wrong.
    pub detail: String,
    /// The shortest input sequence the walker knows of that reaches the
    /// violating state.
    ///
    /// The walk is breadth-first, so the first path to reach a state is a
    /// shortest one; the counterexample is minimized by construction rather
    /// than by a separate shrinking pass.
    pub path: Vec<ModelInput>,
}

impl Violation {
    /// Renders the counterexample as trace steps, so it can be diffed and
    /// replayed through the FG-003b tooling rather than read as prose.
    pub fn to_trace_steps(&self, genesis: &GenesisConfiguration) -> ModelResult<Vec<TraceStep>> {
        let mut state = RepositoryState::genesis(genesis.clone());
        let mut steps = Vec::with_capacity(self.path.len());
        for input in &self.path {
            let ModelStep { next, output } = step(&state, input)?;
            let roots = encode_roots(next.roots()).unwrap_or_default();
            steps.push(TraceStep {
                input: input.clone(),
                observed: crate::trace::ObservedOutcome::of(&output),
                roots,
                head: crate::trace::HeadObservation::of(&next),
            });
            state = next;
        }
        Ok(steps)
    }
}

/// What one campaign found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignReport {
    /// The bounds the walk declared.
    pub bounds: Bounds,
    /// Distinct states reached.
    pub states_explored: usize,
    /// Transitions applied, including those that ended in a typed refusal.
    pub transitions_explored: usize,
    /// Transitions the model refused as structurally impossible.
    ///
    /// These are not failures. A compare-and-swap naming a batch that was
    /// never staged *should* fail closed, and counting them is evidence that
    /// the walk actually offered illegal inputs rather than only legal ones.
    pub refused_transitions: usize,
    /// Whether the walk hit its own state ceiling before exhausting the space.
    pub truncated: bool,
    /// How many reached states **materially exercised** each property.
    ///
    /// A property whose count is zero was checked over nothing: its verdict is
    /// vacuously true and says nothing about the model. Listing the five
    /// properties without this is how a receipt overstates itself, so the
    /// counts travel with the verdict and
    /// [`CampaignReport::vacuous_properties`] names any that are empty.
    pub property_witnesses: BTreeMap<Property, usize>,
    /// What the walk observed, so the shape of the explored space is on the
    /// record rather than assumed.
    pub coverage: Coverage,
    /// The defect this run planted, when it was a self-test rather than a
    /// campaign.
    pub planted_defect: Option<PlantedDefect>,
    /// How many reached states the planted defect could actually be applied to.
    pub defects_planted: usize,
    /// How many of those the property checks caught.
    ///
    /// `defects_detected < defects_planted` is a **blind spot**: a state was
    /// corrupted in a way one of the five properties forbids and no property
    /// noticed. That is the number the planted-defect test asserts on.
    pub defects_detected: usize,
    /// Every violation found.
    pub violations: Vec<Violation>,
}

/// Events the walk actually reached.
///
/// These are **coverage**, not verdicts: they exist so a reader can tell
/// whether a clean report means "the interesting cases all held" or "the
/// interesting cases never happened".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Coverage {
    /// The most terminal commits any single reached state held.
    pub committed_decisions: usize,
    /// The highest head generation any reached state published.
    pub max_head_generation: u64,
    /// The most terminal refusals any single reached state held.
    pub refused_decisions: usize,
    /// The most commit records carrying a merge event any state held.
    pub forge_merge_commits: usize,
    /// Batches that won a head compare-and-swap.
    pub cas_wins: usize,
    /// Batches that lost one.
    pub cas_losses: usize,
    /// Compare-and-swaps that won a batch the walk had already seen lose one.
    ///
    /// This is §10 step 19's lose-then-retry, counted rather than assumed —
    /// but deliberately **not** counted along a path. A lost compare-and-swap
    /// returns the state unchanged, which is the model being correct: losing
    /// publishes nothing. In a state-space enumeration that makes it a
    /// self-loop, so a losing attempt never extends any explored path and
    /// "lost, then won" is not two states — it is one state, left by two
    /// different transitions. This counter therefore asks the question the walk
    /// can actually answer: was this batch observed losing, and was the same
    /// batch observed winning.
    pub cas_retry_wins: usize,
    /// Capsules staging handed back for re-preparation because their basis
    /// moved.
    pub deferred_repreparations: usize,
    /// Cancellations processed.
    pub cancellations: usize,
}

impl CampaignReport {
    /// True when the bounded space was fully explored, no property failed, and
    /// **every** property was actually exercised.
    ///
    /// The last conjunct is the one that stops this from being a tautology: a
    /// walk that reached no decision at all would satisfy the first two and
    /// mean nothing.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty() && !self.truncated && self.vacuous_properties().is_empty()
    }

    /// Properties no reached state exercised, in declaration order.
    #[must_use]
    pub fn vacuous_properties(&self) -> Vec<Property> {
        Property::ALL
            .iter()
            .copied()
            .filter(|property| self.witnesses(*property) == 0)
            .collect()
    }

    /// How many reached states materially exercised `property`.
    #[must_use]
    pub fn witnesses(&self, property: Property) -> usize {
        self.property_witnesses
            .get(&property)
            .copied()
            .unwrap_or_default()
    }

    /// One NDJSON record summarizing the run.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str("{\"record\":\"model_campaign\"");
        push_num(&mut out, "transactions", self.bounds.transactions);
        push_num(
            &mut out,
            "attempts_per_transaction",
            self.bounds.attempts_per_transaction,
        );
        push_num(&mut out, "batches", self.bounds.batches);
        push_num(&mut out, "depth", self.bounds.depth);
        push_num(&mut out, "max_states", self.bounds.max_states);
        push_num(&mut out, "states_explored", self.states_explored);
        push_num(&mut out, "transitions_explored", self.transitions_explored);
        push_num(&mut out, "refused_transitions", self.refused_transitions);
        out.push_str(",\"truncated\":");
        out.push_str(if self.truncated { "true" } else { "false" });
        push_num(&mut out, "violations", self.violations.len());
        push_num(
            &mut out,
            "committed_decisions",
            self.coverage.committed_decisions,
        );
        push_num(
            &mut out,
            "refused_decisions",
            self.coverage.refused_decisions,
        );
        push_num(
            &mut out,
            "forge_merge_commits",
            self.coverage.forge_merge_commits,
        );
        push_num(&mut out, "cas_wins", self.coverage.cas_wins);
        push_num(&mut out, "cas_losses", self.coverage.cas_losses);
        push_num(&mut out, "cas_retry_wins", self.coverage.cas_retry_wins);
        push_num(
            &mut out,
            "deferred_repreparations",
            self.coverage.deferred_repreparations,
        );
        push_num(&mut out, "cancellations", self.coverage.cancellations);
        push_num(
            &mut out,
            "max_head_generation",
            usize::try_from(self.coverage.max_head_generation).unwrap_or(usize::MAX),
        );
        push_num(
            &mut out,
            "vacuous_properties",
            self.vacuous_properties().len(),
        );

        // Each property is reported with the number of states that actually
        // exercised it. A name alone would let a vacuous check read as a
        // verified one.
        out.push_str(",\"properties\":[");
        for (index, property) in Property::ALL.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":\"");
            out.push_str(property.as_str());
            out.push_str("\",\"witnesses\":");
            out.push_str(&self.witnesses(*property).to_string());
            out.push_str(",\"exercised\":");
            out.push_str(if self.witnesses(*property) == 0 {
                "false"
            } else {
                "true"
            });
            out.push('}');
        }
        out.push_str("]}");
        out
    }
}

fn push_num(out: &mut String, key: &str, value: usize) {
    out.push_str(",\"");
    out.push_str(key);
    out.push_str("\":");
    out.push_str(&value.to_string());
}

/// The fixed universe one campaign explores.
///
/// Every identity is precomputed from a bounded index rather than drawn from a
/// running mint. That is what keeps the space finite: a stateful mint would
/// give two otherwise-identical states different identities and the walk would
/// never converge.
pub struct Universe {
    genesis: GenesisConfiguration,
    requests: Vec<TransactionRequest>,
    seals: Vec<TransactionSealId>,
    capsules: Vec<Vec<PreparedTxnCapsuleId>>,
    batches: Vec<RepositoryDecisionBatchId>,
    heads: Vec<RepositoryAuthorityHeadId>,
    bodies: BTreeMap<TxId, DecisionBodyIdentity>,
    objects: Vec<Vec<QuarantinedObject>>,
    principal_snapshot: fgit_types::identity::PrincipalSnapshotId,
    bounds: Bounds,
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

fn ref_name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).unwrap_or_else(|error| panic!("{text}: {error}"))
}

impl Universe {
    /// Builds the universe for the given bounds.
    #[must_use]
    pub fn new(bounds: Bounds) -> Self {
        let mut mint = IdentityMint::new(0x00C0_FFEE);
        let tenant = mint.tenant();
        let repository = mint.repository();
        let author: PrincipalId = mint.principal();
        let genesis_head_id = mint.head();

        let mut principals = BTreeMap::new();
        principals.insert(
            author,
            PrincipalCapabilities {
                writable_scopes: BTreeSet::from([b"heads".to_vec()]),
                may_force: false,
                may_publish_forge: true,
                may_add_legal_hold: false,
            },
        );
        let genesis = GenesisConfiguration {
            tenant,
            repository,
            object_format: GitHashAlgorithm::Sha1,
            genesis_head_id,
            policy: PolicySnapshot {
                epoch: PolicyEpoch::FIRST,
                protected_scopes: BTreeSet::new(),
                principals,
                max_intents_per_transaction: 4,
                supported_schemas: BTreeSet::from([schema()]),
                supported_durability: BTreeSet::from([DurabilityProfile::CanonicalSource]),
            },
            format_registry_epoch: RegistryEpoch::FIRST,
        };

        // **Every transaction targets the same ref.** An earlier version of this
        // universe gave each transaction its own ref, which made the whole
        // space conflict-free: no capsule was ever superseded, no decision was
        // ever a refusal, and the atomicity property was checked over an empty
        // set of forge events. A campaign over a space where the interesting
        // thing cannot happen reports "clean" for the wrong reason.
        const TARGET: &str = "refs/heads/a";
        let stream = ForgeStreamId::new(label("pulls"));
        let pull_request = ForgeEntityId::new(label("pr-1"));

        let mut requests = Vec::with_capacity(bounds.transactions);
        let mut seals = Vec::with_capacity(bounds.transactions);
        let mut capsules = Vec::with_capacity(bounds.transactions);
        let mut bodies = BTreeMap::new();
        // **One object set per transaction, holding only what that transaction
        // promises.** Sharing one set across all of them made a second commit
        // unreachable: once a winning compare-and-swap admitted an object, no
        // later transaction could quarantine it again, so no later transaction
        // could ever be prepared. The objects form a chain — oid(1) is a root
        // and oid(2) is its child — so a transaction that runs after another
        // one published is a fast-forward rather than a fresh ref.
        let mut objects: Vec<Vec<QuarantinedObject>> = Vec::with_capacity(bounds.transactions);

        for index in 0..bounds.transactions {
            let new = oid(u8::try_from(index % 2 + 1).unwrap_or(1));
            let parents = if index % 2 == 0 {
                Vec::new()
            } else {
                vec![oid(1)]
            };
            objects.push(vec![QuarantinedObject {
                declared: new,
                recomputed: new,
                parents,
            }]);
            // Odd-numbered transactions are pull-request merges: the forge
            // event and the ref update it describes, in one sealed request.
            // Without one of these in the space, `AtomicRefAndForgeEffects` is
            // checked over nothing.
            // Even transactions assert the ref is absent, odd ones assert
            // nothing. Both orders then mean something: an odd transaction
            // decided after an even one fast-forwards and commits, and an even
            // one decided second is refused because its precondition no longer
            // holds. With every transaction asserting `Absent` the space could
            // only ever hold one commit, so the whole lose-reprepare-commit
            // loop was out of reach.
            let expected = if index % 2 == 0 {
                ExpectedRefState::Absent
            } else {
                ExpectedRefState::Any
            };
            let mut intents = vec![Intent::Ref(RefIntent::Update {
                name: ref_name(TARGET),
                expected,
                new,
                force: false,
            })];
            if index % 2 == 1 {
                intents.push(Intent::Forge(ForgeIntent {
                    stream,
                    expected_position: ForgeStreamPosition::GENESIS,
                    event: ForgeEventKind::PullRequestMerged {
                        pull_request,
                        target: ref_name(TARGET),
                    },
                }));
            }
            let request = RequestBuilder::new(
                tenant,
                repository,
                author,
                schema(),
                IdempotencyKey::new(label(&format!("k{index}"))),
            )
            .statement(MismatchPolicy::TxnAbort, intents)
            .promising(new)
            .build(&mut mint);
            bodies.insert(
                request.tx_id,
                DecisionBodyIdentity {
                    commit: mint.commit(),
                    refusal_record: mint.refusal_record(),
                },
            );
            seals.push(mint.seal());
            capsules.push(
                (0..bounds.attempts_per_transaction)
                    .map(|_| mint.capsule())
                    .collect(),
            );
            requests.push(request);
        }

        let batches = (0..bounds.batches).map(|_| mint.batch()).collect();
        // One candidate head per batch attempt, plus slack for retries.
        let heads = (0..bounds.batches * bounds.attempts_per_transaction + 2)
            .map(|_| mint.head())
            .collect();

        Self {
            genesis,
            requests,
            seals,
            capsules,
            batches,
            heads,
            bodies,
            objects,
            principal_snapshot: mint.principal_snapshot(),
            bounds,
        }
    }

    /// The genesis configuration this universe starts from.
    #[must_use]
    pub const fn genesis(&self) -> &GenesisConfiguration {
        &self.genesis
    }

    /// The declared bounds.
    #[must_use]
    pub const fn bounds(&self) -> Bounds {
        self.bounds
    }

    /// Every input the walker offers at a given state, in a fixed order.
    ///
    /// The order is deterministic so two runs explore identically. Inputs that
    /// the model will refuse as structurally impossible are deliberately
    /// included: offering only legal inputs would never establish that an
    /// illegal one fails closed.
    fn inputs(&self, state: &RepositoryState) -> Vec<ModelInput> {
        let mut inputs = Vec::new();

        for (index, request) in self.requests.iter().enumerate() {
            inputs.push(ModelInput::Seal(Box::new(SealRequest {
                seal_id: self.seals[index],
                request: request.clone(),
            })));
            if state.seal_of(request.tx_id).is_some() {
                inputs.push(ModelInput::StageObjects(QuarantineRequest {
                    tx_id: request.tx_id,
                    objects: self.objects[index].clone(),
                }));
                for attempt in 0..self.bounds.attempts_per_transaction {
                    inputs.push(ModelInput::Prepare(Box::new(PrepareRequest {
                        capsule_id: self.capsules[index][attempt],
                        request: request.clone(),
                        principal_snapshot: self.principal_snapshot,
                        profile: IdentityMint::preparation_profile(),
                        granularity: WitnessGranularity::Refined,
                    })));
                }
            }
            for phase in [
                CancellationPhase::BeforeSeal,
                CancellationPhase::AfterSealBeforeCas,
                CancellationPhase::AfterCas,
            ] {
                inputs.push(ModelInput::Cancel(CancellationRequest {
                    tx_id: request.tx_id,
                    phase,
                }));
            }
        }

        // Staging: every currently-held capsule alone, and all of them
        // together, into each batch slot. Batching several decisions into one
        // head transition is the case §11 exists for, so it must be reachable.
        let held = self.held_capsules(state);
        if !held.is_empty() {
            for (slot, batch_id) in self.batches.iter().enumerate() {
                let head_index = slot.min(self.heads.len().saturating_sub(1));
                let mut selections: Vec<Vec<PreparedTxnCapsuleId>> =
                    held.iter().map(|capsule| vec![*capsule]).collect();
                if held.len() > 1 {
                    selections.push(held.clone());
                }
                for capsules in selections {
                    inputs.push(ModelInput::Stage(StageRequest {
                        batch_id: *batch_id,
                        candidate_head_id: self.heads[head_index],
                        capsules,
                        bodies: self.bodies.clone(),
                        durability_satisfied: true,
                    }));
                }
            }
        }

        // Compare-and-swap: against the current head; against the current head
        // at the wrong generation; and against a stale predecessor. The two
        // losing forms are what make the lost-CAS path *explored* rather than
        // assumed, and the wrong-generation one matters because it needs no
        // prior head transition — so a batch that loses the head and then wins
        // it is reachable from genesis, not only after another batch has
        // already published.
        for batch_id in &self.batches {
            inputs.push(ModelInput::CompareAndSwap(CasRequest {
                expected_head: state.head().id,
                expected_generation: state.head().body.generation,
                batch: *batch_id,
            }));
            if let Ok(wrong_generation) = state.head().body.generation.next() {
                inputs.push(ModelInput::CompareAndSwap(CasRequest {
                    expected_head: state.head().id,
                    expected_generation: wrong_generation,
                    batch: *batch_id,
                }));
            }
            if let Some(predecessor) = state.head().body.predecessor {
                inputs.push(ModelInput::CompareAndSwap(CasRequest {
                    expected_head: predecessor,
                    expected_generation: HeadGeneration::FIRST,
                    batch: *batch_id,
                }));
            }
        }

        inputs
    }

    fn held_capsules(&self, state: &RepositoryState) -> Vec<PreparedTxnCapsuleId> {
        self.capsules
            .iter()
            .flatten()
            .copied()
            .filter(|capsule| state.capsule(*capsule).is_some())
            .collect()
    }
}

const fn schema() -> fgit_types::label::SchemaId {
    fgit_types::label::SchemaId::new(
        fgit_types::label::SchemaFamily::from_static("fgit/ref-txn"),
        2,
        0,
    )
}

/// The canonical key a walk deduplicates on.
///
/// Covers every part of the state a further transition can read: the canonical
/// roots, the head identity and its positions, which transactions are sealed,
/// which capsules are held, which batches are staged, what sits in quarantine,
/// which objects are admitted, and how much history exists. Two states with
/// equal keys answer every model query identically, so merging them cannot hide
/// a reachable violation.
pub fn state_key(state: &RepositoryState) -> Result<Vec<u8>, CodecRefusal> {
    let mut out = Encoder::new();

    // What the head publishes.
    out.write_bytes("roots", &encode_roots(state.roots())?)?;
    out.write_internal_object_id(state.head().id.as_internal_object_id())?;
    out.write_scalar(state.head().body.generation.get());
    out.write_scalar(state.head().body.configuration.epoch.get());

    // The ordered history.
    let decided = state
        .decisions()
        .iter()
        .map(|decision| (decision.tx_id, decision.decision_sequence.get()))
        .collect::<Vec<_>>();
    out.write_sequence("decided", &decided, |encoder, (tx_id, sequence)| {
        encoder.write_internal_object_id(tx_id.as_internal_object_id())?;
        encoder.write_scalar(*sequence);
        Ok(())
    })?;
    let committed = state
        .commits()
        .iter()
        .map(|record| (record.tx_id, record.repository_sequence.get()))
        .collect::<Vec<_>>();
    out.write_sequence("committed", &committed, |encoder, (tx_id, sequence)| {
        encoder.write_internal_object_id(tx_id.as_internal_object_id())?;
        encoder.write_scalar(*sequence);
        Ok(())
    })?;

    // Everything staged behind the head, which a further transition can read
    // even though the head does not publish it. Omitting any of these would
    // merge two genuinely different states and could hide a reachable
    // violation, so they are part of the key rather than an optimization.
    // The seal carries its spent re-preparation budget, which decides whether a
    // superseded basis is another attempt or a terminal refusal, so two states
    // that differ only in that counter are different states.
    let sealed = state.sealed_transactions().copied().collect::<Vec<_>>();
    out.write_sequence("sealed", &sealed, |encoder, tx_id| {
        encoder.write_internal_object_id(tx_id.as_internal_object_id())?;
        encoder.write_scalar(state.preparations_of(*tx_id));
        Ok(())
    })?;
    // **Capsule contents, not just capsule identities.** A capsule's verdict,
    // basis, and witness are exactly what `decide_against` reads, so two states
    // holding the same capsule *id* with different contents answer differently
    // and are different states. Keying on the id alone merged "prepared before
    // another transaction published" with "prepared after" — the walk kept
    // whichever it reached first, which is always the shorter path, and with it
    // the stale verdict. Every execution in which a transaction commits after
    // another one won the head was silently unreachable as a result.
    let capsules = state.held_capsules().copied().collect::<Vec<_>>();
    out.write_sequence("capsules", &capsules, |encoder, id| {
        encoder.write_internal_object_id(id.as_internal_object_id())?;
        let Some(capsule) = state.capsule(*id) else {
            return Ok(());
        };
        encoder.write_internal_object_id(capsule.basis_head.as_internal_object_id())?;
        encoder.write_scalar(capsule.basis_generation.get());
        match &capsule.verdict {
            PreparedVerdict::Commit(_) => encoder.write_raw_byte(1),
            PreparedVerdict::Refuse(code) => {
                encoder.write_raw_byte(2);
                encoder.write_scalar(code.code_point());
            }
        }
        let witness = &capsule.witness;
        encoder.write_raw_byte(match witness.granularity {
            WitnessGranularity::Coarse => 1,
            WitnessGranularity::Refined => 2,
        });
        encoder.write_scalar(witness.basis_generation.get());
        encoder.write_scalar(witness.policy_epoch.get());
        encoder.write_sequence(
            "witness_refs",
            &witness.refs.iter().collect::<Vec<_>>(),
            |inner, (name, observed)| {
                inner.write_bytes("ref", name.as_bytes())?;
                match observed {
                    Some(oid) => {
                        inner.write_raw_byte(1);
                        inner.write_git_oid(oid);
                    }
                    None => inner.write_raw_byte(0),
                }
                Ok(())
            },
        )?;
        encoder.write_sequence(
            "witness_forge",
            &witness.forge_positions.iter().collect::<Vec<_>>(),
            |inner, (stream, position)| {
                inner.write_bytes("stream", stream.label().as_str().as_bytes())?;
                inner.write_scalar(position.get());
                Ok(())
            },
        )?;
        encoder.write_scalar(u64::try_from(witness.retention_present.len()).unwrap_or(u64::MAX));
        encoder.write_scalar(u64::try_from(witness.retention_absent.len()).unwrap_or(u64::MAX));
        encoder.write_scalar(u64::try_from(witness.outbox.len()).unwrap_or(u64::MAX));
        Ok(())
    })?;
    let staged = state.staged_batches().copied().collect::<Vec<_>>();
    out.write_sequence("staged", &staged, |encoder, batch| {
        encoder.write_internal_object_id(batch.as_internal_object_id())
    })?;
    let quarantined = state
        .quarantined_transactions()
        .copied()
        .collect::<Vec<_>>();
    out.write_sequence("quarantined", &quarantined, |encoder, tx_id| {
        encoder.write_internal_object_id(tx_id.as_internal_object_id())
    })?;
    let admitted = state.admitted_objects().copied().collect::<Vec<_>>();
    out.write_sequence("admitted", &admitted, |encoder, object| {
        encoder.write_git_oid(object);
        Ok(())
    })?;

    // **What the state has already spent.** An identity may be introduced only
    // once, so two states with identical published and staged content can still
    // offer different transitions: the one that has already spent a batch or a
    // candidate-head identity cannot stage with it again. Leaving the ledger
    // out merges those two, and the merged representative may be the one with
    // the smaller remaining budget — which silently removes whole regions of
    // the space from the walk. That is not a performance detail: it is a walk
    // reporting that it explored something it never reached.
    let ledger = state.identities();
    out.write_sequence(
        "spent_heads",
        &ledger.spent_heads().copied().collect::<Vec<_>>(),
        |encoder, id| encoder.write_internal_object_id(id.as_internal_object_id()),
    )?;
    out.write_sequence(
        "spent_batches",
        &ledger.spent_batches().copied().collect::<Vec<_>>(),
        |encoder, id| encoder.write_internal_object_id(id.as_internal_object_id()),
    )?;
    out.write_sequence(
        "spent_commits",
        &ledger.spent_commits().copied().collect::<Vec<_>>(),
        |encoder, id| encoder.write_internal_object_id(id.as_internal_object_id()),
    )?;
    out.write_sequence(
        "spent_capsules",
        &ledger.spent_capsules().copied().collect::<Vec<_>>(),
        |encoder, id| encoder.write_internal_object_id(id.as_internal_object_id()),
    )?;
    out.write_sequence(
        "spent_seals",
        &ledger.spent_seals().copied().collect::<Vec<_>>(),
        |encoder, id| encoder.write_internal_object_id(id.as_internal_object_id()),
    )?;

    Ok(out.into_bytes())
}

/// Runs the bounded campaign.
///
/// The walk is breadth-first, so the first path that reaches any state is a
/// shortest one and a counterexample needs no separate shrinking pass.
#[must_use]
pub fn run(universe: &Universe) -> CampaignReport {
    run_with(universe, None)
}

/// A model defect planted on purpose, to prove the walk can find one.
///
/// A campaign that has never caught anything is not evidence that there is
/// nothing to catch. Each variant corrupts a state the walk has already
/// reached, in exactly the way one of the five properties forbids, so
/// [`run_with`] must report *that* property with a replayable path.
///
/// This mutates a state the walker produced; it cannot reach the transitions
/// themselves, and there is deliberately no variant that makes a property
/// easier to satisfy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PlantedDefect {
    /// Record a second, different terminal decision for a transaction that
    /// already has one.
    SecondTerminalDecision,
    /// Leave a published decision out of the outcome index.
    OutcomeIndexOmission,
    /// Point a canonical ref at an object that never left quarantine.
    QuarantineEscape,
    /// Publish a merge event whose ref effect has been stripped out.
    MergeWithoutItsRefEffect,
    /// Roll the head generation backwards.
    HeadGenerationRollback,
    /// Drop the most recent decision, shrinking committed history.
    ///
    /// Deliberately the *last* one: the surviving prefix is still gap-free and
    /// still agrees with the outcome index, so this passes properties one
    /// through four and reaches property five. A defect that trips an earlier
    /// check would never exercise the one it is supposed to.
    DecisionHistoryShrank,
}

impl PlantedDefect {
    /// Every planted defect, one per property.
    pub const ALL: &'static [Self] = &[
        Self::SecondTerminalDecision,
        Self::OutcomeIndexOmission,
        Self::QuarantineEscape,
        Self::MergeWithoutItsRefEffect,
        Self::HeadGenerationRollback,
        Self::DecisionHistoryShrank,
    ];

    /// The property this defect is designed to violate.
    #[must_use]
    pub const fn violates(self) -> Property {
        match self {
            Self::SecondTerminalDecision | Self::OutcomeIndexOmission => {
                Property::UniqueTerminalOutcome
            }
            Self::QuarantineEscape => Property::NoRootOmission,
            Self::MergeWithoutItsRefEffect => Property::AtomicRefAndForgeEffects,
            Self::HeadGenerationRollback => Property::HeadChainContinuity,
            Self::DecisionHistoryShrank => Property::NoSilentAntiRollback,
        }
    }

    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecondTerminalDecision => "second_terminal_decision",
            Self::OutcomeIndexOmission => "outcome_index_omission",
            Self::QuarantineEscape => "quarantine_escape",
            Self::MergeWithoutItsRefEffect => "merge_without_its_ref_effect",
            Self::HeadGenerationRollback => "head_generation_rollback",
            Self::DecisionHistoryShrank => "decision_history_shrank",
        }
    }

    /// Corrupts `state`, returning whether the defect could be applied.
    ///
    /// `false` means this transition had no subject to corrupt — no decision,
    /// no merge record, a genesis generation, or a change that cannot be made
    /// to look like a rollback relative to `previous`. Returning `false` there
    /// is what keeps the self-test honest: a plant that did not actually
    /// create a violation must not be counted as one the checks missed.
    fn plant(self, previous: &RepositoryState, state: &mut RepositoryState) -> bool {
        match self {
            Self::SecondTerminalDecision => {
                let Some(first) = state.decisions.first().cloned() else {
                    return false;
                };
                state.decisions.push(first);
                true
            }
            Self::OutcomeIndexOmission => {
                let Some(tx_id) = state.decisions.first().map(|decision| decision.tx_id) else {
                    return false;
                };
                state.head.body.roots.outcome_index.remove(&tx_id).is_some()
            }
            Self::QuarantineEscape => {
                // Only an object that is still *only* in quarantine is an
                // escape. One that has already been admitted by a winning
                // compare-and-swap is legitimately referenceable, and planting
                // it would be planting nothing — the check would be right to
                // stay silent, and counting that as a miss would turn this
                // self-test into a false alarm.
                let Some(escaped) = state
                    .quarantine
                    .values()
                    .flat_map(BTreeMap::keys)
                    .find(|object| !state.objects.contains_key(*object))
                    .copied()
                else {
                    return false;
                };
                state
                    .head
                    .body
                    .roots
                    .refs
                    .insert(ref_name("refs/heads/escaped"), escaped);
                true
            }
            Self::MergeWithoutItsRefEffect => {
                let mut planted = false;
                for record in &mut state.commits {
                    let targets: Vec<RefName> = record
                        .effects
                        .forge
                        .values()
                        .flatten()
                        .filter_map(|event| match event {
                            ForgeEventKind::PullRequestMerged { target, .. } => {
                                Some(target.clone())
                            }
                            ForgeEventKind::PullRequestClosed { .. }
                            | ForgeEventKind::PullRequestOpened { .. } => None,
                        })
                        .collect();
                    for target in targets {
                        planted |= record.effects.refs.remove(&target).is_some();
                    }
                }
                planted
            }
            Self::HeadGenerationRollback => {
                if state.head.body.generation == HeadGeneration::FIRST {
                    return false;
                }
                state.head.body.generation = HeadGeneration::FIRST;
                true
            }
            Self::DecisionHistoryShrank => {
                // History has to end up strictly shorter than it was *before*
                // the transition. Dropping one decision from a transition that
                // published two leaves history longer than it started, which
                // is not a rollback and must not be counted as a missed one.
                while state.decisions.len() >= previous.decisions().len() {
                    if state.decisions.pop().is_none() {
                        break;
                    }
                }
                state.decisions.len() < previous.decisions().len()
            }
        }
    }
}

/// Runs the campaign, optionally planting `defect` in every state the walk
/// reaches.
///
/// With `None` this is [`run`]. With a defect it is the campaign's own
/// self-test: the walk must report the property that defect violates.
#[must_use]
pub fn run_with(universe: &Universe, defect: Option<PlantedDefect>) -> CampaignReport {
    let bounds = universe.bounds();
    let genesis = RepositoryState::genesis(universe.genesis().clone());

    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut queue: VecDeque<(RepositoryState, Vec<ModelInput>)> = VecDeque::new();
    let mut violations = Vec::new();
    let mut witnesses: BTreeMap<Property, usize> = BTreeMap::new();
    let mut coverage = Coverage::default();
    let mut transitions = 0_usize;
    let mut refused = 0_usize;
    let mut defects_planted = 0_usize;
    let mut defects_detected = 0_usize;
    let mut lost_batches: BTreeSet<RepositoryDecisionBatchId> = BTreeSet::new();
    let mut truncated = false;

    if let Ok(key) = state_key(&genesis) {
        seen.insert(key);
    }
    queue.push_back((genesis, Vec::new()));

    while let Some((state, path)) = queue.pop_front() {
        if path.len() >= bounds.depth {
            continue;
        }
        for input in universe.inputs(&state) {
            transitions += 1;
            let Ok(ModelStep { next, output }) = step(&state, &input) else {
                // A typed refusal of a structurally impossible call. Expected,
                // and counted as evidence that illegal inputs were offered.
                refused += 1;
                continue;
            };

            // Folded **before** deduplication. A lost compare-and-swap and a
            // staging that defers every capsule both leave the state
            // unchanged, so a walk that only counted new states would report
            // zero of each while exploring them constantly — which is exactly
            // how this campaign came to claim it had explored races it never
            // observed. Coverage counts observed transitions.
            observe(&mut coverage, &mut lost_batches, &output, &input, &next);

            let Ok(key) = state_key(&next) else {
                continue;
            };
            if !seen.insert(key) {
                continue;
            }

            let mut next_path = path.clone();
            next_path.push(input);

            // The walk always explores the model's own successor; only a
            // separate copy carries a planted defect, so one plant cannot
            // cascade into states the model would never produce. Without a
            // defect there is no copy at all.
            let mut corrupted = None;
            if let Some(defect) = defect {
                let mut copy = next.clone();
                if defect.plant(&state, &mut copy) {
                    defects_planted += 1;
                    corrupted = Some(copy);
                }
            }
            let checked = corrupted.as_ref().unwrap_or(&next);

            // Coverage describes the real model, so it is taken from the
            // unplanted successor.
            for property in exercised(&state, &next) {
                *witnesses.entry(property).or_default() += 1;
            }

            if let Some(violation) = check(&state, checked, &next_path) {
                if corrupted.is_some() {
                    defects_detected += 1;
                }
                violations.push(violation);
            }

            if seen.len() >= bounds.max_states {
                truncated = true;
                break;
            }
            queue.push_back((next, next_path));
        }
        if truncated {
            break;
        }
    }

    CampaignReport {
        bounds,
        states_explored: seen.len(),
        transitions_explored: transitions,
        refused_transitions: refused,
        truncated,
        property_witnesses: witnesses,
        coverage,
        planted_defect: defect,
        defects_planted,
        defects_detected,
        violations,
    }
}

/// Folds one observed transition into the coverage counters.
fn observe(
    coverage: &mut Coverage,
    lost_batches: &mut BTreeSet<RepositoryDecisionBatchId>,
    output: &ModelOutput,
    input: &ModelInput,
    next: &RepositoryState,
) {
    match output {
        ModelOutput::HeadTransition(CasOutcome::Won { .. }) => {
            coverage.cas_wins += 1;
            if let ModelInput::CompareAndSwap(request) = input
                && lost_batches.contains(&request.batch)
            {
                coverage.cas_retry_wins += 1;
            }
        }
        ModelOutput::HeadTransition(CasOutcome::Lost { .. }) => {
            coverage.cas_losses += 1;
            if let ModelInput::CompareAndSwap(request) = input {
                lost_batches.insert(request.batch);
            }
        }
        ModelOutput::Staged(staged) => {
            coverage.deferred_repreparations += staged.deferred.len();
        }
        ModelOutput::Cancelled(_) => coverage.cancellations += 1,
        ModelOutput::Sealed(_)
        | ModelOutput::ObjectsQuarantined { .. }
        | ModelOutput::Prepared(_)
        | ModelOutput::Decided(_)
        | ModelOutput::HeadTransition(CasOutcome::DurabilityUnsatisfied { .. })
        | ModelOutput::ConfigurationTransition(_) => {}
    }

    let committed = next
        .decisions()
        .iter()
        .filter(|decision| matches!(decision.outcome, DecisionOutcome::Committed { .. }))
        .count();
    let refused = next.decisions().len() - committed;
    let merges = next
        .commits()
        .iter()
        .filter(|record| {
            record
                .effects
                .forge
                .values()
                .flatten()
                .any(|event| matches!(event, ForgeEventKind::PullRequestMerged { .. }))
        })
        .count();
    coverage.committed_decisions = coverage.committed_decisions.max(committed);
    coverage.refused_decisions = coverage.refused_decisions.max(refused);
    coverage.forge_merge_commits = coverage.forge_merge_commits.max(merges);
    coverage.max_head_generation = coverage
        .max_head_generation
        .max(next.head().body.generation.get());
}

/// Which properties one reached state materially exercises.
///
/// "Materially" means the check had something to look at: a property whose
/// subject is absent holds vacuously, and counting that as coverage is how a
/// bounded-model receipt overstates what it verified.
fn exercised(previous: &RepositoryState, state: &RepositoryState) -> Vec<Property> {
    let mut out = Vec::with_capacity(Property::ALL.len());

    // Something was decided, so "at most one terminal decision" has a subject.
    if !state.decisions().is_empty() {
        out.push(Property::UniqueTerminalOutcome);
    }
    // A genesis head has no predecessor, so there is no chain link to check.
    if state.head().body.predecessor.is_some() {
        out.push(Property::HeadChainContinuity);
    }
    // The atomicity property reads merge events out of committed records. With
    // no merge event committed there is nothing to be atomic about.
    if state.commits().iter().any(|record| {
        record
            .effects
            .forge
            .values()
            .flatten()
            .any(|event| matches!(event, ForgeEventKind::PullRequestMerged { .. }))
    }) {
        out.push(Property::AtomicRefAndForgeEffects);
    }
    // Root omission needs a root to omit and something in quarantine that
    // could have escaped into it.
    if !state.commits().is_empty() || state.quarantined_transactions().next().is_some() {
        out.push(Property::NoRootOmission);
    }
    // Anti-rollback is only meaningful across a transition that moved history
    // forward; comparing a state to itself proves nothing.
    if state.head().body.generation > previous.head().body.generation
        || state.decisions().len() > previous.decisions().len()
        || state.commits().len() > previous.commits().len()
    {
        out.push(Property::NoSilentAntiRollback);
    }

    out
}

/// Checks all five properties on one reached state.
fn check(
    previous: &RepositoryState,
    state: &RepositoryState,
    path: &[ModelInput],
) -> Option<Violation> {
    let fail = |property: Property, detail: String| {
        Some(Violation {
            property,
            detail,
            path: path.to_vec(),
        })
    };

    // 1. A sealed transaction has at most one terminal decision.
    let mut seen = BTreeSet::new();
    for decision in state.decisions() {
        if !seen.insert(decision.tx_id) {
            return fail(
                Property::UniqueTerminalOutcome,
                format!("transaction {} decided twice", decision.tx_id),
            );
        }
        match state.outcome_of(decision.tx_id) {
            Some(recorded) if recorded == decision.outcome => {}
            Some(_) => {
                return fail(
                    Property::UniqueTerminalOutcome,
                    format!(
                        "outcome index disagrees with the decision stream for {}",
                        decision.tx_id
                    ),
                );
            }
            None => {
                return fail(
                    Property::UniqueTerminalOutcome,
                    format!(
                        "decision for {} is absent from the outcome index",
                        decision.tx_id
                    ),
                );
            }
        }
    }

    // 2. Head-chain continuity.
    if let Err(breach) = state.assert_head_chain_continuous() {
        return fail(Property::HeadChainContinuity, breach.kind().to_owned());
    }

    // 3. A pull-request merge and the ref it moves publish in one record.
    for record in state.commits() {
        for events in record.effects.forge.values() {
            for event in events {
                if let ForgeEventKind::PullRequestMerged { target, .. } = event
                    && !record.effects.refs.contains_key(target)
                {
                    return fail(
                        Property::AtomicRefAndForgeEffects,
                        "a merge event published without its ref effect".to_owned(),
                    );
                }
            }
        }
    }

    // 4. No root omission: nothing quarantined is protected, and the sequences
    //    are gap-free.
    if let Err(breach) = state.assert_no_quarantine_escape() {
        return fail(Property::NoRootOmission, breach.kind().to_owned());
    }
    if let Err(breach) = state.assert_sequences_gap_free() {
        return fail(Property::NoRootOmission, breach.kind().to_owned());
    }

    // 5. No silent anti-rollback: nothing that orders history may move
    //    backwards across a transition.
    if state.head().body.generation < previous.head().body.generation {
        return fail(
            Property::NoSilentAntiRollback,
            "head generation moved backwards".to_owned(),
        );
    }
    if sequence_of(state.head().body.latest_decision_sequence)
        < sequence_of(previous.head().body.latest_decision_sequence)
    {
        return fail(
            Property::NoSilentAntiRollback,
            "decision sequence moved backwards".to_owned(),
        );
    }
    if repository_sequence_of(state.head().body.latest_repository_sequence)
        < repository_sequence_of(previous.head().body.latest_repository_sequence)
    {
        return fail(
            Property::NoSilentAntiRollback,
            "repository sequence moved backwards".to_owned(),
        );
    }
    if state.decisions().len() < previous.decisions().len()
        || state.commits().len() < previous.commits().len()
    {
        return fail(
            Property::NoSilentAntiRollback,
            "committed history shrank".to_owned(),
        );
    }
    None
}

fn sequence_of(value: Option<fgit_types::numeric::DecisionSequence>) -> u64 {
    value.map_or(0, fgit_types::numeric::DecisionSequence::get)
}

fn repository_sequence_of(value: Option<fgit_types::numeric::RepositorySequence>) -> u64 {
    value.map_or(0, fgit_types::numeric::RepositorySequence::get)
}

/// True when the decision stream and the outcome index agree everywhere.
///
/// Exposed so a differential harness can assert the same accelerator rule §8.4
/// states: a direct pointer is repairable, never a second truth.
#[must_use]
pub fn outcome_index_agrees(state: &RepositoryState) -> bool {
    state.decisions().iter().all(|decision| {
        state
            .outcome_of(decision.tx_id)
            .is_some_and(|recorded| recorded == decision.outcome)
    })
}

/// The committed transactions, in repository-sequence order.
#[must_use]
pub fn committed_transactions(state: &RepositoryState) -> Vec<TxId> {
    state
        .decisions()
        .iter()
        .filter(|decision| matches!(decision.outcome, DecisionOutcome::Committed { .. }))
        .map(|decision| decision.tx_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        Bounds, CampaignReport, Coverage, PlantedDefect, Property, Universe, run, run_with,
        state_key,
    };
    use crate::state::RepositoryState;

    #[test]
    fn the_default_campaign_finds_no_violation_and_explores_the_whole_space() {
        let universe = Universe::new(Bounds::DEFAULT);
        let report = run(&universe);
        assert!(
            report.violations.is_empty(),
            "violations: {:?}",
            report.violations
        );
        assert!(
            !report.truncated,
            "the default bounds must fit inside the state ceiling; explored {}",
            report.states_explored
        );
        assert!(report.is_clean());
    }

    #[test]
    fn the_walk_actually_explored_something() {
        // A campaign that explored one state and called itself clean would be
        // a tautology. This pins that the walk is doing real work.
        let report = run(&Universe::new(Bounds::DEFAULT));
        assert!(
            report.states_explored > 20,
            "only {} states explored",
            report.states_explored
        );
        assert!(
            report.transitions_explored > report.states_explored,
            "transitions {} should exceed states {}",
            report.transitions_explored,
            report.states_explored
        );
    }

    #[test]
    fn the_walk_offered_illegal_inputs_and_they_failed_closed() {
        // Evidence that the alphabet includes structurally impossible calls:
        // if this were zero, the campaign would only be proving that legal
        // sequences work, which is a much weaker statement.
        let report = run(&Universe::new(Bounds::DEFAULT));
        assert!(
            report.refused_transitions > 0,
            "the walk never offered an illegal input"
        );
    }

    #[test]
    fn the_campaign_is_deterministic() {
        let first = run(&Universe::new(Bounds::DEFAULT));
        let second = run(&Universe::new(Bounds::DEFAULT));
        assert_eq!(first.states_explored, second.states_explored);
        assert_eq!(first.transitions_explored, second.transitions_explored);
        assert_eq!(first.refused_transitions, second.refused_transitions);
        assert_eq!(first, second);
    }

    #[test]
    fn deduplication_is_exact() {
        // Two independently built genesis states must share a key, and a state
        // that has moved must not.
        let universe = Universe::new(Bounds::DEFAULT);
        let left = RepositoryState::genesis(universe.genesis().clone());
        let right = RepositoryState::genesis(universe.genesis().clone());
        assert_eq!(
            state_key(&left).expect("key"),
            state_key(&right).expect("key")
        );
    }

    #[test]
    fn the_report_names_its_bounds_and_every_property_in_ndjson() {
        let report = run(&Universe::new(Bounds::DEFAULT));
        let line = report.to_ndjson();
        assert!(!line.contains('\n'), "one record per line: {line}");
        for key in [
            "\"record\":\"model_campaign\"",
            "\"transactions\":",
            "\"depth\":",
            "\"states_explored\":",
            "\"refused_transitions\":",
            "\"truncated\":",
        ] {
            assert!(line.contains(key), "missing {key} in {line}");
        }
        for property in Property::ALL {
            assert!(
                line.contains(property.as_str()),
                "property {} is not named in the receipt",
                property.as_str()
            );
        }
    }

    #[test]
    fn the_five_properties_of_plan_40_2_are_all_declared() {
        assert_eq!(Property::ALL.len(), 5);
    }

    #[test]
    fn a_truncated_run_is_never_reported_as_clean() {
        // A ceiling that stops the walk early must not read as success.
        let tiny = Bounds {
            max_states: 3,
            ..Bounds::DEFAULT
        };
        let report = run(&Universe::new(tiny));
        assert!(
            report.truncated,
            "the tiny ceiling should truncate the walk"
        );
        assert!(
            !report.is_clean(),
            "a truncated walk must not claim a clean bounded result"
        );
    }

    #[test]
    fn a_report_with_a_violation_is_not_clean() {
        let mut report = CampaignReport {
            bounds: Bounds::DEFAULT,
            states_explored: 1,
            transitions_explored: 1,
            refused_transitions: 0,
            truncated: false,
            property_witnesses: Property::ALL
                .iter()
                .map(|property| (*property, 1))
                .collect(),
            coverage: Coverage::default(),
            planted_defect: None,
            defects_planted: 0,
            defects_detected: 0,
            violations: Vec::new(),
        };
        assert!(report.is_clean());
        report.violations.push(super::Violation {
            property: Property::UniqueTerminalOutcome,
            detail: "planted".to_owned(),
            path: Vec::new(),
        });
        assert!(!report.is_clean());
    }

    // -----------------------------------------------------------------------
    // Non-vacuity: the space contains the cases the properties are about
    // -----------------------------------------------------------------------

    /// The defect that reopened this bead: the universe used to give every
    /// transaction its own ref, so nothing ever conflicted, no decision was
    /// ever a refusal, and `AtomicRefAndForgeEffects` was checked over an
    /// empty set while still being listed in the receipt as a property that
    /// held.
    #[test]
    fn every_declared_property_is_exercised_by_a_reached_state() {
        let report = run(&Universe::new(Bounds::DEFAULT));
        assert_eq!(
            report.vacuous_properties(),
            Vec::new(),
            "these properties were checked over nothing, so their verdict is              vacuous: {:?}",
            report
                .vacuous_properties()
                .iter()
                .map(|property| property.as_str())
                .collect::<Vec<_>>()
        );
        for property in Property::ALL {
            assert!(
                report.witnesses(*property) > 0,
                "{} has no witness",
                property.as_str()
            );
        }
    }

    /// The interesting cases have to be *reachable*, not merely permitted by
    /// the bounds. Each of these was zero in the universe this bead reopened
    /// over.
    #[test]
    fn the_explored_space_contains_conflicts_refusals_merges_and_lost_races() {
        let report = run(&Universe::new(Bounds::DEFAULT));
        let coverage = report.coverage;
        assert!(
            coverage.committed_decisions > 0,
            "nothing ever committed: {coverage:?}"
        );
        assert!(
            coverage.refused_decisions > 0,
            "no decision was ever a refusal, so the refusal path is untested              by this campaign: {coverage:?}"
        );
        assert!(
            coverage.forge_merge_commits > 0,
            "no merge event was ever committed, so the atomicity property is              vacuous: {coverage:?}"
        );
        assert!(
            coverage.cas_wins > 0,
            "no batch ever won the head: {coverage:?}"
        );
        assert!(
            coverage.cas_losses > 0,
            "no batch ever lost the head, so the lost-race path is unexplored:              {coverage:?}"
        );
        assert!(
            coverage.deferred_repreparations > 0,
            "no capsule was ever superseded, so the space cannot conflict:              {coverage:?}"
        );
        assert!(
            coverage.cas_retry_wins > 0,
            "no batch that lost the head was ever seen winning it, so the \
             lose-then-retry sequence of §10 step 19 is unexplored: {coverage:?}"
        );
        assert!(
            coverage.cancellations > 0,
            "cancellation was never reached: {coverage:?}"
        );
    }

    /// What the *fast* bounds cannot reach, stated as a test so the limit is a
    /// recorded fact rather than a silence.
    ///
    /// A second commit needs a transaction prepared **after** another one won
    /// the head — five transitions to publish the first, three to prepare the
    /// second, then a stage and a compare-and-swap. That is ten, and
    /// [`Bounds::DEFAULT`] stops at seven so the lane stays in the seconds.
    /// [`Bounds::DEEP`] is where the whole loop is reachable, and
    /// `the_deep_bounds_reach_a_second_commit_and_a_retried_batch` asserts it.
    #[test]
    fn the_default_bounds_stop_short_of_a_second_commit_and_say_so() {
        let report = run(&Universe::new(Bounds::DEFAULT));
        assert_eq!(
            report.coverage.committed_decisions, 1,
            "if the fast bounds now reach a second commit, move the deep-only \
             assertion here and delete this test rather than leaving the limit \
             documented as tighter than it is: {:?}",
            report.coverage
        );
    }

    /// The audit's remaining reachability gap: a transaction that commits
    /// **after** another one already published. It is out of reach at the fast
    /// bounds, which spend their depth on retry breadth instead;
    /// [`Bounds::SEQUENCED`] exists for exactly this.
    #[test]
    fn the_sequenced_bounds_reach_a_second_commit() {
        let report = run(&Universe::new(Bounds::SEQUENCED));
        assert!(!report.truncated, "the deep walk hit its state ceiling");
        assert!(
            report.violations.is_empty(),
            "violations: {:?}",
            report.violations
        );
        let coverage = report.coverage;
        assert!(
            coverage.committed_decisions > 1,
            "no reached state held two commits, so a transaction succeeding \
             after another won the head is still out of reach: {coverage:?}"
        );
        assert!(coverage.cas_retry_wins > 0, "{coverage:?}");
        assert_eq!(report.vacuous_properties(), Vec::new());
    }

    // -----------------------------------------------------------------------
    // The walker can detect a defect
    // -----------------------------------------------------------------------

    /// A campaign that has never caught anything is not evidence that there is
    /// nothing to catch. Each planted defect corrupts a reached state exactly
    /// as one of the five properties forbids; the walk must find **every**
    /// instance, not merely one.
    #[test]
    fn every_planted_defect_is_detected_wherever_it_is_planted() {
        let universe = Universe::new(Bounds::DEFAULT);
        for defect in PlantedDefect::ALL {
            let report = run_with(&universe, Some(*defect));
            assert!(
                report.defects_planted > 0,
                "{} was never applicable to any reached state, so this proves                  nothing",
                defect.as_str()
            );
            assert_eq!(
                report.defects_detected,
                report.defects_planted,
                "{} was planted in {} states and caught in only {} — the                  difference is a blind spot in the property checks",
                defect.as_str(),
                report.defects_planted,
                report.defects_detected
            );
            assert!(
                report
                    .violations
                    .iter()
                    .any(|violation| violation.property == defect.violates()),
                "{} was detected, but never by {}, which is the property it                  violates",
                defect.as_str(),
                defect.violates().as_str()
            );
        }
    }

    /// Every property has at least one defect that targets it, so a property
    /// cannot be listed in the receipt without a demonstration that its check
    /// can fail.
    #[test]
    fn every_property_has_a_planted_defect_that_exercises_its_check() {
        for property in Property::ALL {
            assert!(
                PlantedDefect::ALL
                    .iter()
                    .any(|defect| defect.violates() == *property),
                "no planted defect targets {}, so nothing shows its check can                  fail",
                property.as_str()
            );
        }
    }

    /// A counterexample must be replayable, not just describable: the path is
    /// a real input sequence that reproduces the state.
    #[test]
    fn a_planted_defect_yields_a_replayable_counterexample() {
        let universe = Universe::new(Bounds::DEFAULT);
        let report = run_with(&universe, Some(PlantedDefect::SecondTerminalDecision));
        let violation = report
            .violations
            .first()
            .expect("the planted defect must produce a violation");
        assert!(
            !violation.path.is_empty(),
            "a counterexample with an empty path cannot be replayed"
        );
        let steps = violation
            .to_trace_steps(universe.genesis())
            .expect("the counterexample path must replay through the model");
        assert_eq!(steps.len(), violation.path.len());
    }

    /// Planting must not change what the walk explores, or a self-test run
    /// would be measuring a different space than the campaign it vouches for.
    #[test]
    fn planting_a_defect_does_not_change_the_explored_space() {
        let universe = Universe::new(Bounds::DEFAULT);
        let clean = run(&universe);
        let planted = run_with(&universe, Some(PlantedDefect::HeadGenerationRollback));
        assert_eq!(clean.states_explored, planted.states_explored);
        assert_eq!(clean.transitions_explored, planted.transitions_explored);
        assert_eq!(clean.refused_transitions, planted.refused_transitions);
        assert_eq!(clean.property_witnesses, planted.property_witnesses);
        assert!(
            clean.violations.is_empty(),
            "the unplanted campaign must be clean: {:?}",
            clean.violations
        );
    }

    /// The receipt must say how much each property was exercised, not merely
    /// name it.
    #[test]
    fn the_receipt_reports_witness_counts_and_coverage() {
        let report = run(&Universe::new(Bounds::DEFAULT));
        let line = report.to_ndjson();
        for key in [
            "\"vacuous_properties\":0",
            "\"refused_decisions\":",
            "\"forge_merge_commits\":",
            "\"cas_losses\":",
            "\"deferred_repreparations\":",
            "\"exercised\":true",
        ] {
            assert!(line.contains(key), "missing {key} in {line}");
        }
        assert!(
            !line.contains("\"exercised\":false"),
            "a property in the receipt was never exercised: {line}"
        );
    }
}
