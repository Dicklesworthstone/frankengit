#![forbid(unsafe_code)]

//! Projection-level tests for the FG-041 proof bridge.
//!
//! These histories are built with the reference model's own harness and
//! recorder — never by hand-asserting outcomes — so what the projection
//! receives is exactly what a checked-in golden would carry. The properties
//! pinned here are the ones the refinement evidence depends on:
//!
//! * a pure §10.14 decide stutters instead of fabricating an abstract decision;
//! * a re-decide against an already-terminal transaction projects onto `retry`
//!   carrying the recorded outcome;
//! * a won compare-and-swap reports the ref and forge effect vectors its
//!   publication actually moved, decoded from the recorded canonical roots.

use std::collections::{BTreeMap, BTreeSet};

use fgit_proof_bridge::emit::render;
use fgit_proof_bridge::project::{AbstractOp, AbstractOutcome, project};
use fgit_reference::capsule::WitnessGranularity;
use fgit_reference::harness::{IdentityMint, RequestBuilder, label};
use fgit_reference::intent::{
    DurabilityProfile, ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId,
    ForgeStreamPosition, IdempotencyKey, Intent, RefIntent, TransactionRequest,
};
use fgit_reference::machine::ModelInput;
use fgit_reference::refs::ExpectedRefState;
use fgit_reference::state::{
    GenesisConfiguration, PolicySnapshot, PrincipalCapabilities, QuarantinedObject,
};
use fgit_reference::trace::{GoldenTrace, ObservedOutcome, TraceRecorder};
use fgit_reference::transition::{
    CasRequest, DecisionBodyIdentity, PrepareRequest, QuarantineRequest, SealRequest, StageRequest,
};
use fgit_types::identity::{
    PreparedTxnCapsuleId, PrincipalId, RepositoryDecisionBatchId, RepositoryId, TenantId, TxId,
};
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::numeric::{PolicyEpoch, RegistryEpoch};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::MismatchPolicy;

// ---------------------------------------------------------------------------
// Fixture: one seed pins every identity, mirroring the golden corpus's own
// construction so a projected history here is byte-for-byte the kind of
// history a golden records.
// ---------------------------------------------------------------------------

const fn schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("fgit/ref-txn"), 2, 0)
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes())
        .unwrap_or_else(|error| panic!("{text} is not a valid ref name: {error}"))
}

fn object(id: GitOid, parents: &[GitOid]) -> QuarantinedObject {
    QuarantinedObject {
        declared: id,
        recomputed: id,
        parents: parents.to_vec(),
    }
}

struct Fixture {
    mint: IdentityMint,
    genesis: GenesisConfiguration,
    tenant: TenantId,
    repository: RepositoryId,
    author: PrincipalId,
}

impl Fixture {
    fn new(seed: u64) -> Self {
        let mut mint = IdentityMint::new(seed);
        let tenant = mint.tenant();
        let repository = mint.repository();
        let author = mint.principal();
        let genesis_head_id = mint.head();

        let mut principals = BTreeMap::new();
        principals.insert(
            author,
            PrincipalCapabilities {
                writable_scopes: BTreeSet::from([b"heads".to_vec(), b"tags".to_vec()]),
                may_force: true,
                may_publish_forge: true,
                may_add_legal_hold: true,
            },
        );

        let genesis = GenesisConfiguration {
            tenant,
            repository,
            object_format: GitHashAlgorithm::Sha1,
            genesis_head_id,
            policy: PolicySnapshot {
                epoch: PolicyEpoch::FIRST,
                protected_scopes: BTreeSet::from([b"tags".to_vec()]),
                principals,
                max_intents_per_transaction: 8,
                supported_schemas: BTreeSet::from([schema()]),
                supported_durability: BTreeSet::from([DurabilityProfile::CanonicalSource]),
            },
            format_registry_epoch: RegistryEpoch::FIRST,
        };

        Self {
            mint,
            genesis,
            tenant,
            repository,
            author,
        }
    }

    fn bodies(&mut self, tx_id: TxId) -> BTreeMap<TxId, DecisionBodyIdentity> {
        let mut bodies = BTreeMap::new();
        bodies.insert(
            tx_id,
            DecisionBodyIdentity {
                commit: self.mint.commit(),
                refusal_record: self.mint.refusal_record(),
            },
        );
        bodies
    }

    /// Seals, quarantines, prepares, stages, and publishes one committing
    /// request, recording every step; returns the capsule identity so callers
    /// can interleave decides around the protocol steps.
    fn publish_committing(
        &mut self,
        recorder: &mut TraceRecorder,
        request: &TransactionRequest,
        objects: &[QuarantinedObject],
        capsule_id: PreparedTxnCapsuleId,
    ) -> RepositoryDecisionBatchId {
        let seal_id = self.mint.seal();
        recorder
            .apply(ModelInput::Seal(Box::new(SealRequest {
                seal_id,
                request: request.clone(),
            })))
            .expect("seal");
        if !objects.is_empty() {
            recorder
                .apply(ModelInput::StageObjects(QuarantineRequest {
                    tx_id: request.tx_id,
                    objects: objects.to_vec(),
                }))
                .expect("quarantine");
        }
        recorder
            .apply(ModelInput::Prepare(Box::new(PrepareRequest {
                capsule_id,
                request: request.clone(),
                principal_snapshot: self.mint.principal_snapshot(),
                profile: IdentityMint::preparation_profile(),
                granularity: WitnessGranularity::Refined,
            })))
            .expect("prepare");
        let batch_id = self.mint.batch();
        recorder
            .apply(ModelInput::Stage(StageRequest {
                batch_id,
                candidate_head_id: self.mint.head(),
                capsules: vec![capsule_id],
                bodies: self.bodies(request.tx_id),
                durability_satisfied: true,
            }))
            .expect("stage");
        let head = recorder.state().head();
        recorder
            .apply(ModelInput::CompareAndSwap(CasRequest {
                expected_head: head.id,
                expected_generation: head.body.generation,
                batch: batch_id,
            }))
            .expect("cas");
        batch_id
    }
}

/// A plain ref update of `target` to `new`.
fn ref_update(target: &str, new: GitOid) -> Intent {
    Intent::Ref(RefIntent::Update {
        name: name(target),
        expected: ExpectedRefState::Absent,
        new,
        force: false,
    })
}

/// Builds a committing ref update with optional extra statements, returning
/// both the request and its promised object.
fn commit_request(
    fixture: &mut Fixture,
    key: &str,
    target: &str,
    new: GitOid,
    extra_statements: Vec<(MismatchPolicy, Vec<Intent>)>,
) -> TransactionRequest {
    let mut builder = RequestBuilder::new(
        fixture.tenant,
        fixture.repository,
        fixture.author,
        schema(),
        IdempotencyKey::new(label(key)),
    )
    .statement(MismatchPolicy::TxnAbort, vec![ref_update(target, new)])
    .promising(new);
    for (policy, intents) in extra_statements {
        builder = builder.statement(policy, intents);
    }
    builder.build(&mut fixture.mint)
}

/// One committing ref update whose protocol run interleaves a pure §10.14
/// decide after preparation and/or a post-terminal re-decide after publication.
fn history_with_decides(pure_decide: bool, post_terminal_decide: bool) -> GoldenTrace {
    let mut fixture = Fixture::new(2001);
    let mut recorder = TraceRecorder::new(fixture.genesis.clone());
    let new = oid(1);
    let request = commit_request(&mut fixture, "k1", "refs/heads/main", new, Vec::new());
    let capsule_id = fixture.mint.capsule();

    // Split the protocol around the optional pure decide.
    let seal_id = fixture.mint.seal();
    recorder
        .apply(ModelInput::Seal(Box::new(SealRequest {
            seal_id,
            request: request.clone(),
        })))
        .expect("seal");
    recorder
        .apply(ModelInput::StageObjects(QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        }))
        .expect("quarantine");
    recorder
        .apply(ModelInput::Prepare(Box::new(PrepareRequest {
            capsule_id,
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        })))
        .expect("prepare");
    if pure_decide {
        recorder
            .apply(ModelInput::Decide {
                capsule: capsule_id,
            })
            .expect("pure decide");
    }
    let batch_id = fixture.mint.batch();
    recorder
        .apply(ModelInput::Stage(StageRequest {
            batch_id,
            candidate_head_id: fixture.mint.head(),
            capsules: vec![capsule_id],
            bodies: fixture.bodies(request.tx_id),
            durability_satisfied: true,
        }))
        .expect("stage");
    let head = recorder.state().head();
    recorder
        .apply(ModelInput::CompareAndSwap(CasRequest {
            expected_head: head.id,
            expected_generation: head.body.generation,
            batch: batch_id,
        }))
        .expect("cas");
    if post_terminal_decide {
        // The publication swept the original capsule, but the seal survives:
        // §5.2 lets the same sealed request re-prepare against the new head.
        // Deciding that fresh capsule is what observes AlreadyTerminal —
        // a duplicate decision against an already-terminal transaction.
        let stale_capsule = fixture.mint.capsule();
        recorder
            .apply(ModelInput::Prepare(Box::new(PrepareRequest {
                capsule_id: stale_capsule,
                request: request.clone(),
                principal_snapshot: fixture.mint.principal_snapshot(),
                profile: IdentityMint::preparation_profile(),
                granularity: WitnessGranularity::Refined,
            })))
            .expect("re-prepare after publication");
        recorder
            .apply(ModelInput::Decide {
                capsule: stale_capsule,
            })
            .expect("post-terminal decide");
    }
    recorder.finish()
}

#[test]
fn pure_decide_stutters_and_post_terminal_decide_maps_to_retry() {
    let trace = history_with_decides(true, true);
    let projected = project("decide_positions", &trace).expect("projects without refusal");

    // The step that applied the pure decide observed DecidedCommit but must
    // stutter: nothing became canonical there.
    let pure_index = trace
        .steps
        .iter()
        .position(|step| step.observed == ObservedOutcome::DecidedCommit)
        .expect("the pure decide is in the history");
    assert!(
        projected.steps[pure_index].operations.is_empty(),
        "a §10.14 decide changes no state, so it must stutter, got {:?}",
        projected.steps[pure_index].operations
    );

    // Exactly one retry appears, at the post-terminal decide, carrying the
    // outcome the compare-and-swap recorded rather than an invented one.
    let retries: Vec<&AbstractOp> = projected
        .steps
        .iter()
        .flat_map(|step| &step.operations)
        .filter(|op| matches!(op, AbstractOp::Retry { .. }))
        .collect();
    assert_eq!(
        retries,
        vec![&AbstractOp::Retry {
            target: 0,
            outcome: AbstractOutcome::Committed,
        }],
        "one retry naming the committed transaction"
    );
    let retry_step = projected
        .steps
        .iter()
        .position(|step| {
            step.operations
                .iter()
                .any(|op| matches!(op, AbstractOp::Retry { .. }))
        })
        .expect("the retry lives somewhere");
    assert_eq!(
        trace.steps[retry_step].observed,
        ObservedOutcome::DecidedAlreadyTerminal,
        "the retry sits exactly on the already-terminal observation"
    );

    // The won CAS still attributes the canonical decision itself.
    let cas_index = trace
        .steps
        .iter()
        .position(|step| matches!(step.input, ModelInput::CompareAndSwap(_)))
        .expect("the cas step exists");
    assert!(
        projected.steps[cas_index]
            .operations
            .iter()
            .any(|op| matches!(
                op,
                AbstractOp::Decide {
                    target: 0,
                    outcome: AbstractOutcome::Committed,
                }
            )),
        "the canonical decision belongs to the publication step: {:?}",
        projected.steps[cas_index].operations
    );
}

#[test]
fn a_history_without_extra_decides_projects_no_retry() {
    let trace = history_with_decides(false, false);
    let projected = project("plain", &trace).expect("projects without refusal");
    assert!(
        projected.steps.iter().all(|step| step
            .operations
            .iter()
            .all(|op| !matches!(op, AbstractOp::Retry { .. }))),
        "no retry can appear where no re-decide was recorded"
    );
}

#[test]
fn publish_reports_ref_and_forge_effects_from_the_recorded_roots() {
    let mut fixture = Fixture::new(2002);
    let mut recorder = TraceRecorder::new(fixture.genesis.clone());

    // A pull-request merge is only permitted coupled to the exact ref update
    // it describes (§7), so one statement carries both intents.
    let stream = ForgeStreamId::new(label("pulls"));
    let entity = ForgeEntityId::new(label("pr-1"));
    let merge_target = "refs/heads/main";
    let new = oid(7);
    let request = commit_request(
        &mut fixture,
        "k-merge",
        merge_target,
        new,
        vec![(
            MismatchPolicy::TxnAbort,
            vec![Intent::Forge(ForgeIntent {
                stream,
                expected_position: ForgeStreamPosition::GENESIS,
                event: ForgeEventKind::PullRequestMerged {
                    pull_request: entity,
                    target: name(merge_target),
                },
            })],
        )],
    );
    let capsule_id = fixture.mint.capsule();
    fixture.publish_committing(&mut recorder, &request, &[object(new, &[])], capsule_id);

    let trace = recorder.finish();
    let projected = project("ref_forge", &trace).expect("projects without refusal");
    let cas_index = trace
        .steps
        .iter()
        .position(|step| step.observed == ObservedOutcome::CasWon)
        .expect("the publication won");
    let ops = &projected.steps[cas_index].operations;
    let Some(AbstractOp::Publish {
        ref_effects,
        forge_effects,
        ..
    }) = ops.first()
    else {
        panic!("a won compare-and-swap projects a publish first, got {ops:?}");
    };
    assert_eq!(ref_effects.len(), 1, "the merge's ref update is one effect");
    assert_eq!(
        forge_effects,
        &[0, 1],
        "stream dictionary index 0 advanced to position 1"
    );

    // The rendered vector carries what the projection found.
    let rendered = render(std::slice::from_ref(&projected));
    // Generations stay concrete in the vector (genesis 1, so this
    // publication moves head 1 -> 2); Refinement.lean rebases them.
    assert!(rendered.contains("Op.publish 1 2 [0] [0, 1]"));
}

#[test]
fn plain_publication_reports_only_the_ref_effect() {
    let mut fixture = Fixture::new(2003);
    let mut recorder = TraceRecorder::new(fixture.genesis.clone());
    let new = oid(3);
    let request = commit_request(&mut fixture, "k1", "refs/heads/main", new, Vec::new());
    let capsule_id = fixture.mint.capsule();
    fixture.publish_committing(&mut recorder, &request, &[object(new, &[])], capsule_id);

    let trace = recorder.finish();
    let projected = project("ref_only", &trace).expect("projects without refusal");
    let cas_index = trace
        .steps
        .iter()
        .position(|step| step.observed == ObservedOutcome::CasWon)
        .expect("the publication won");
    match &projected.steps[cas_index].operations[0] {
        AbstractOp::Publish {
            ref_effects,
            forge_effects,
            ..
        } => {
            assert_eq!(ref_effects.len(), 1, "one ref moved");
            assert!(forge_effects.is_empty(), "no forge stream advanced");
        }
        other => panic!("expected a publish first, got {other:?}"),
    }
}

#[test]
fn projection_is_deterministic() {
    let trace = history_with_decides(true, true);
    let first = project("determinism", &trace).expect("first projection");
    let second = project("determinism", &trace).expect("second projection");
    assert_eq!(first, second);
}
