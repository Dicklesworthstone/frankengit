//! Golden traces: the checked-in histories every future differential test
//! compares against, plus replay and diff coverage.
//!
//! ## How the goldens are maintained
//!
//! The test **never** regenerates a golden. It builds each history from a fixed
//! seed, encodes it, and asserts the bytes equal the checked-in file. A change
//! to the model or to the trace format therefore fails here, loudly, with the
//! step that moved — which is the entire point of a golden.
//!
//! Writing the files is a separate, explicitly opted-in action:
//! `FGIT_REFERENCE_WRITE_GOLDENS=1 cargo test -p fgit-reference --test goldens`.
//! That switch exists so the files can be created and so a *deliberate* format
//! change can be landed with the new bytes visible in the diff. It is off by
//! default and the assertions run either way, so it cannot be used to make a
//! red test green without the change appearing in review.
//!
//! ## Platform stability
//!
//! The acceptance line asks for the trace tests to run under an alternate
//! target where one is available. None is installed in this environment
//! (running a big-endian or 32-bit target needs an emulator that is not
//! present), so that is recorded as an explicit follow-up rather than claimed.
//! What *is* enforced here are the three properties that make host dependence
//! impossible in the first place:
//!
//! * nothing host-width reaches the wire — counts are widened to `u64` and
//!   `usize` is not a `CanonicalScalar` at all, so the compiler refuses it;
//! * every scalar is big-endian by the codec's construction;
//! * every collection is written in canonical encoded-byte order, asserted
//!   below by building the same logical history through different insertion
//!   orders and requiring identical bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fgit_reference::harness::{IdentityMint, RequestBuilder, label};
use fgit_reference::intent::{
    DurabilityProfile, ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId,
    ForgeStreamPosition, IdempotencyKey, Intent, RefIntent, TransactionRequest,
};
use fgit_reference::machine::ModelInput;
use fgit_reference::refs::ExpectedRefState;
use fgit_reference::state::{
    GenesisConfiguration, PolicySnapshot, PrincipalCapabilities, QuarantinedObject, RepositoryRoots,
};
use fgit_reference::trace::{
    DivergenceKind, GoldenTrace, ObservedOutcome, TraceRecorder, decode, decode_roots, diff,
    encode, encode_roots, replay,
};
use fgit_reference::transition::{
    CasRequest, DecisionBodyIdentity, PrepareRequest, QuarantineRequest, SealRequest, StageRequest,
};
use fgit_types::identity::{PrincipalId, RepositoryId, TenantId};
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::numeric::{PolicyEpoch, RegistryEpoch};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::MismatchPolicy;

// ---------------------------------------------------------------------------
// Fixture
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

fn update(target: &str, expected: ExpectedRefState, new: GitOid) -> Intent {
    Intent::Ref(RefIntent::Update {
        name: name(target),
        expected,
        new,
        force: false,
    })
}

/// A scenario whose identities and policy are fixed by one seed.
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

    fn request(
        &mut self,
        key: &str,
        target: &str,
        expected: ExpectedRefState,
        new: GitOid,
    ) -> TransactionRequest {
        RequestBuilder::new(
            self.tenant,
            self.repository,
            self.author,
            schema(),
            IdempotencyKey::new(label(key)),
        )
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(target, expected, new)],
        )
        .promising(new)
        .build(&mut self.mint)
    }

    fn bodies(
        &mut self,
        request: &TransactionRequest,
    ) -> BTreeMap<fgit_types::identity::TxId, DecisionBodyIdentity> {
        let mut bodies = BTreeMap::new();
        bodies.insert(
            request.tx_id,
            DecisionBodyIdentity {
                commit: self.mint.commit(),
                refusal_record: self.mint.refusal_record(),
            },
        );
        bodies
    }
}

// ---------------------------------------------------------------------------
// The six required histories
// ---------------------------------------------------------------------------

/// An empty repository: genesis and nothing else.
fn history_genesis() -> GoldenTrace {
    TraceRecorder::new(Fixture::new(1001).genesis).finish()
}

/// One ordinary commit, driven step by step through the whole protocol.
fn history_simple_commit() -> GoldenTrace {
    let mut fixture = Fixture::new(1002);
    let mut recorder = TraceRecorder::new(fixture.genesis.clone());
    let new = oid(1);
    let request = fixture.request("k1", "refs/heads/main", ExpectedRefState::Absent, new);

    apply_full_transaction(
        &mut recorder,
        &mut fixture,
        &request,
        &[object(new, &[])],
        true,
    );
    recorder.finish()
}

/// A transaction that is refused: it promises an object it never stages.
fn history_refusal_only() -> GoldenTrace {
    let mut fixture = Fixture::new(1003);
    let mut recorder = TraceRecorder::new(fixture.genesis.clone());
    let promised = oid(9);
    let request = fixture.request("k1", "refs/heads/main", ExpectedRefState::Absent, promised);

    // No `StageObjects` step: the promise cannot be honoured, so the decision
    // is a refusal that still consumes a decision sequence.
    apply_full_transaction(&mut recorder, &mut fixture, &request, &[], true);
    recorder.finish()
}

/// Two transactions decided in one batch: one commits, one is refused.
fn history_multi_decision_batch() -> GoldenTrace {
    let mut fixture = Fixture::new(1004);
    let mut recorder = TraceRecorder::new(fixture.genesis.clone());

    let good = oid(1);
    let committing = fixture.request("k1", "refs/heads/main", ExpectedRefState::Absent, good);
    let refused = fixture.request("k2", "refs/heads/dev", ExpectedRefState::Absent, oid(9));

    for request in [&committing, &refused] {
        let seal_id = fixture.mint.seal();
        recorder
            .apply(ModelInput::Seal(Box::new(SealRequest {
                seal_id,
                request: request.clone(),
            })))
            .expect("seal");
    }
    // Only the committing transaction stages its object.
    recorder
        .apply(ModelInput::StageObjects(QuarantineRequest {
            tx_id: committing.tx_id,
            objects: vec![object(good, &[])],
        }))
        .expect("quarantine");

    let mut capsules = Vec::new();
    let mut bodies = BTreeMap::new();
    for request in [&committing, &refused] {
        let capsule_id = fixture.mint.capsule();
        recorder
            .apply(ModelInput::Prepare(Box::new(PrepareRequest {
                capsule_id,
                request: request.clone(),
                principal_snapshot: fixture.mint.principal_snapshot(),
                profile: IdentityMint::preparation_profile(),
                granularity: fgit_reference::capsule::WitnessGranularity::Refined,
            })))
            .expect("prepare");
        capsules.push(capsule_id);
        bodies.insert(
            request.tx_id,
            DecisionBodyIdentity {
                commit: fixture.mint.commit(),
                refusal_record: fixture.mint.refusal_record(),
            },
        );
    }

    let batch_id = fixture.mint.batch();
    recorder
        .apply(ModelInput::Stage(StageRequest {
            batch_id,
            candidate_head_id: fixture.mint.head(),
            capsules,
            bodies,
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
    recorder.finish()
}

/// A lost compare-and-swap followed by a retry under the *same* seal.
fn history_cas_loss_retry() -> GoldenTrace {
    let mut fixture = Fixture::new(1005);
    let mut recorder = TraceRecorder::new(fixture.genesis.clone());

    // The transaction that will lose the race.
    let loser = fixture.request(
        "k-loser",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
    );
    let loser_seal = fixture.mint.seal();
    recorder
        .apply(ModelInput::Seal(Box::new(SealRequest {
            seal_id: loser_seal,
            request: loser.clone(),
        })))
        .expect("seal");
    recorder
        .apply(ModelInput::StageObjects(QuarantineRequest {
            tx_id: loser.tx_id,
            objects: vec![object(oid(1), &[])],
        }))
        .expect("quarantine");
    let loser_capsule = fixture.mint.capsule();
    recorder
        .apply(ModelInput::Prepare(Box::new(PrepareRequest {
            capsule_id: loser_capsule,
            request: loser.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: fgit_reference::capsule::WitnessGranularity::Refined,
        })))
        .expect("prepare");
    let loser_batch = fixture.mint.batch();
    let stale_head = recorder.state().head().id;
    let stale_generation = recorder.state().head().body.generation;
    recorder
        .apply(ModelInput::Stage(StageRequest {
            batch_id: loser_batch,
            candidate_head_id: fixture.mint.head(),
            capsules: vec![loser_capsule],
            bodies: fixture.bodies(&loser),
            durability_satisfied: true,
        }))
        .expect("stage");

    // A competing transaction takes the head first.
    let winner = fixture.request(
        "k-winner",
        "refs/heads/other",
        ExpectedRefState::Absent,
        oid(2),
    );
    apply_full_transaction(
        &mut recorder,
        &mut fixture,
        &winner,
        &[object(oid(2), &[])],
        true,
    );

    // The original attempt now names a predecessor that is no longer current.
    recorder
        .apply(ModelInput::CompareAndSwap(CasRequest {
            expected_head: stale_head,
            expected_generation: stale_generation,
            batch: loser_batch,
        }))
        .expect("a lost compare-and-swap is ordinary");

    // Retry under the SAME seal: re-prepare against the new head, restage, and
    // publish. The sealed request never changes.
    let retry_capsule = fixture.mint.capsule();
    recorder
        .apply(ModelInput::Prepare(Box::new(PrepareRequest {
            capsule_id: retry_capsule,
            request: loser.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: fgit_reference::capsule::WitnessGranularity::Refined,
        })))
        .expect("re-prepare");
    let retry_batch = fixture.mint.batch();
    recorder
        .apply(ModelInput::Stage(StageRequest {
            batch_id: retry_batch,
            candidate_head_id: fixture.mint.head(),
            capsules: vec![retry_capsule],
            bodies: fixture.bodies(&loser),
            durability_satisfied: true,
        }))
        .expect("restage");
    let head = recorder.state().head();
    recorder
        .apply(ModelInput::CompareAndSwap(CasRequest {
            expected_head: head.id,
            expected_generation: head.body.generation,
            batch: retry_batch,
        }))
        .expect("cas");
    recorder.finish()
}

/// The same request presented twice: the second continues under the first seal.
fn history_idempotent_duplicate() -> GoldenTrace {
    let mut fixture = Fixture::new(1006);
    let mut recorder = TraceRecorder::new(fixture.genesis.clone());
    let new = oid(1);
    let request = fixture.request("k1", "refs/heads/main", ExpectedRefState::Absent, new);

    for _ in 0..2 {
        let seal_id = fixture.mint.seal();
        recorder
            .apply(ModelInput::Seal(Box::new(SealRequest {
                seal_id,
                request: request.clone(),
            })))
            .expect("seal");
    }
    recorder
        .apply(ModelInput::StageObjects(QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        }))
        .expect("quarantine");
    let capsule_id = fixture.mint.capsule();
    recorder
        .apply(ModelInput::Prepare(Box::new(PrepareRequest {
            capsule_id,
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: fgit_reference::capsule::WitnessGranularity::Refined,
        })))
        .expect("prepare");
    let batch_id = fixture.mint.batch();
    recorder
        .apply(ModelInput::Stage(StageRequest {
            batch_id,
            candidate_head_id: fixture.mint.head(),
            capsules: vec![capsule_id],
            bodies: fixture.bodies(&request),
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
    // A third presentation, now that the transaction is terminal.
    let seal_id = fixture.mint.seal();
    recorder
        .apply(ModelInput::Seal(Box::new(SealRequest { seal_id, request })))
        .expect("seal after commit");
    recorder.finish()
}

/// A decision observed twice: once as a pure §10.14 revalidation before the
/// batch published (which changes nothing and is recorded as DecidedCommit),
/// and once after publication, when the same sealed request re-prepares
/// against the new head and deciding the fresh capsule reports
/// AlreadyTerminal. This is the history that pins terminal uniqueness end to
/// end: the second observation must carry the first CAS's outcome and change
/// nothing, which is exactly what the proof bridge projects onto
/// `Operation.retry`.
fn history_duplicate_decide_terminal_uniqueness() -> GoldenTrace {
    let mut fixture = Fixture::new(1007);
    let mut recorder = TraceRecorder::new(fixture.genesis.clone());
    let new = oid(1);
    let request = fixture.request("k1", "refs/heads/main", ExpectedRefState::Absent, new);

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
    let capsule_id = fixture.mint.capsule();
    recorder
        .apply(ModelInput::Prepare(Box::new(PrepareRequest {
            capsule_id,
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: fgit_reference::capsule::WitnessGranularity::Refined,
        })))
        .expect("prepare");
    // The pure revalidation: concludes Commit without changing state.
    recorder
        .apply(ModelInput::Decide {
            capsule: capsule_id,
        })
        .expect("pure decide");
    let batch_id = fixture.mint.batch();
    recorder
        .apply(ModelInput::Stage(StageRequest {
            batch_id,
            candidate_head_id: fixture.mint.head(),
            capsules: vec![capsule_id],
            bodies: fixture.bodies(&request),
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
    // The publication swept the original capsule, but the seal survives
    // (§5.2): the same sealed request may re-prepare against the new head.
    let stale_capsule = fixture.mint.capsule();
    recorder
        .apply(ModelInput::Prepare(Box::new(PrepareRequest {
            capsule_id: stale_capsule,
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: fgit_reference::capsule::WitnessGranularity::Refined,
        })))
        .expect("re-prepare after publication");
    // Deciding the stale basis observes the recorded outcome — the duplicate
    // decision terminal uniqueness is about.
    recorder
        .apply(ModelInput::Decide {
            capsule: stale_capsule,
        })
        .expect("post-terminal decide");
    recorder.finish()
}

/// One sealed transaction whose single statement couples a pull-request merge
/// event with the exact ref update it describes — §7's only permitted shape
/// for a merge. One won compare-and-swap makes the ref movement and the forge
/// position advance visible together, which is the history the atomic-
/// visibility theorem's data path needs.
fn history_ref_forge_atomic_visibility() -> GoldenTrace {
    let mut fixture = Fixture::new(1008);
    let mut recorder = TraceRecorder::new(fixture.genesis.clone());

    let stream = ForgeStreamId::new(label("pulls"));
    let entity = ForgeEntityId::new(label("pr-1"));
    let new = oid(7);
    let request = RequestBuilder::new(
        fixture.tenant,
        fixture.repository,
        fixture.author,
        schema(),
        IdempotencyKey::new(label("k-merge")),
    )
    .statement(
        MismatchPolicy::TxnAbort,
        vec![
            Intent::Forge(ForgeIntent {
                stream,
                expected_position: ForgeStreamPosition::GENESIS,
                event: ForgeEventKind::PullRequestMerged {
                    pull_request: entity,
                    target: name("refs/heads/main"),
                },
            }),
            update("refs/heads/main", ExpectedRefState::Absent, new),
        ],
    )
    .promising(new)
    .build(&mut fixture.mint);

    apply_full_transaction(
        &mut recorder,
        &mut fixture,
        &request,
        &[object(new, &[])],
        true,
    );
    recorder.finish()
}

/// Drives one request through seal, quarantine, prepare, stage, and the head
/// compare-and-swap, recording every step.
fn apply_full_transaction(
    recorder: &mut TraceRecorder,
    fixture: &mut Fixture,
    request: &TransactionRequest,
    objects: &[QuarantinedObject],
    durability_satisfied: bool,
) {
    let seal_id = fixture.mint.seal();
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
    let capsule_id = fixture.mint.capsule();
    recorder
        .apply(ModelInput::Prepare(Box::new(PrepareRequest {
            capsule_id,
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: fgit_reference::capsule::WitnessGranularity::Refined,
        })))
        .expect("prepare");
    let batch_id = fixture.mint.batch();
    recorder
        .apply(ModelInput::Stage(StageRequest {
            batch_id,
            candidate_head_id: fixture.mint.head(),
            capsules: vec![capsule_id],
            bodies: fixture.bodies(request),
            durability_satisfied,
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
}

// ---------------------------------------------------------------------------
// Golden file plumbing
// ---------------------------------------------------------------------------

/// Every checked-in golden, with the history that must reproduce it.
fn goldens() -> Vec<(&'static str, GoldenTrace)> {
    vec![
        ("genesis", history_genesis()),
        ("simple_commit", history_simple_commit()),
        ("refusal_only", history_refusal_only()),
        ("multi_decision_batch", history_multi_decision_batch()),
        ("cas_loss_retry", history_cas_loss_retry()),
        ("idempotent_duplicate", history_idempotent_duplicate()),
        (
            "duplicate_decide_terminal_uniqueness",
            history_duplicate_decide_terminal_uniqueness(),
        ),
        (
            "ref_forge_atomic_visibility",
            history_ref_forge_atomic_visibility(),
        ),
    ]
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("goldens")
        .join(format!("{name}.fgtrace"))
}

fn writing_goldens() -> bool {
    std::env::var_os("FGIT_REFERENCE_WRITE_GOLDENS").is_some()
}

/// Reads a checked-in golden.
///
/// When the opt-in write switch is set, the file is produced from `trace`
/// first. Doing that here rather than in one designated test is deliberate:
/// tests run in parallel and in no guaranteed order, so a test that only read
/// would race the test that only wrote.
fn read_golden(name: &str, trace: &GoldenTrace) -> Vec<u8> {
    let path = golden_path(name);
    if writing_goldens() {
        let bytes = encode(trace).unwrap_or_else(|error| panic!("{name}: encode: {error}"));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("{name}: cannot create goldens dir: {error}"));
        }
        // Skip the write when the content already matches, then write through a
        // temporary file and rename. `fs::write` truncates before it fills, so
        // a sibling test reading the same golden concurrently can observe zero
        // bytes; rename is atomic, so a reader sees either the old file or the
        // new one and never a torn one.
        let current = std::fs::read(&path).ok();
        if current.as_deref() != Some(bytes.as_slice()) {
            let temporary = path.with_extension(format!("tmp{}", std::process::id()));
            std::fs::write(&temporary, &bytes)
                .unwrap_or_else(|error| panic!("{name}: cannot write golden: {error}"));
            std::fs::rename(&temporary, &path)
                .unwrap_or_else(|error| panic!("{name}: cannot publish golden: {error}"));
        }
    }
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{name}: golden {} is missing ({error}). Create it once with \
             FGIT_REFERENCE_WRITE_GOLDENS=1 and commit it.",
            path.display()
        )
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn every_checked_in_golden_matches_the_history_that_produced_it() {
    for (name, trace) in goldens() {
        let bytes = encode(&trace).unwrap_or_else(|error| panic!("{name}: encode failed: {error}"));
        let checked_in = read_golden(name, &trace);
        assert_eq!(
            checked_in.len(),
            bytes.len(),
            "{name}: golden length moved ({} checked in, {} produced)",
            checked_in.len(),
            bytes.len()
        );
        assert!(
            checked_in == bytes,
            "{name}: the model or the trace format changed; the golden no longer matches"
        );
    }
}

#[test]
fn every_checked_in_golden_replays_to_byte_identical_roots() {
    for (name, expected) in goldens() {
        let bytes = read_golden(name, &expected);
        let trace = decode(&bytes).unwrap_or_else(|error| panic!("{name}: decode failed: {error}"));
        let report =
            replay(&trace).unwrap_or_else(|error| panic!("{name}: replay failed: {error}"));
        assert!(
            report.is_faithful(),
            "{name}: replay diverged: {}",
            report.to_ndjson()
        );
        assert_eq!(report.steps_replayed, trace.steps.len(), "{name}");

        // The acceptance line, stated literally: the roots replay reaches are
        // byte-identical to the ones the trace recorded.
        let replayed_roots = encode_roots(report.state.roots())
            .unwrap_or_else(|error| panic!("{name}: cannot encode replayed roots: {error}"));
        let recorded_roots = trace
            .steps
            .last()
            .map_or_else(
                || encode_roots(&RepositoryRoots::default()),
                |step| Ok(step.roots.clone()),
            )
            .unwrap_or_else(|error| panic!("{name}: cannot encode genesis roots: {error}"));
        assert_eq!(
            replayed_roots, recorded_roots,
            "{name}: replayed roots are not byte-identical to the recorded roots"
        );
    }
}

#[test]
fn every_golden_round_trips_through_the_codec_without_moving_a_byte() {
    for (name, expected) in goldens() {
        let bytes = read_golden(name, &expected);
        let decoded = decode(&bytes).unwrap_or_else(|error| panic!("{name}: decode: {error}"));
        let re_encoded =
            encode(&decoded).unwrap_or_else(|error| panic!("{name}: re-encode: {error}"));
        assert!(
            re_encoded == bytes,
            "{name}: decode then encode did not reproduce the original bytes"
        );
        let decoded_again =
            decode(&re_encoded).unwrap_or_else(|error| panic!("{name}: re-decode: {error}"));
        assert_eq!(decoded_again, decoded, "{name}: decoding is not stable");
    }
}

#[test]
fn the_required_histories_are_all_present_and_distinct() {
    let names = goldens()
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>();
    // The six required-v1 histories must never shrink. The two entries below
    // them joined when frankengit-njsz / frankengit-4sh7 added a duplicate-
    // decide terminal-uniqueness history and a ref+forge atomic-visibility
    // history: without them no checked-in golden decides the same transaction
    // twice or moves a forge stream, so those proof paths had no data.
    assert_eq!(
        names,
        BTreeSet::from([
            "cas_loss_retry",
            "duplicate_decide_terminal_uniqueness",
            "genesis",
            "idempotent_duplicate",
            "multi_decision_batch",
            "ref_forge_atomic_visibility",
            "refusal_only",
            "simple_commit",
        ])
    );

    // Distinct histories must produce distinct bytes, or a golden is not
    // pinning what its name says it pins.
    let mut encodings = BTreeSet::new();
    for (name, trace) in goldens() {
        let bytes = encode(&trace).unwrap_or_else(|error| panic!("{name}: encode: {error}"));
        assert!(encodings.insert(bytes), "{name}: duplicates another golden");
    }
}

#[test]
fn each_history_exercises_the_shape_its_name_claims() {
    // A golden whose name promises a refusal but records a commit would still
    // round-trip perfectly. These assertions are what stop a golden from
    // silently becoming a test of nothing.
    let simple = history_simple_commit();
    assert_eq!(
        simple.steps.last().map(|step| step.observed),
        Some(ObservedOutcome::CasWon)
    );
    assert!(
        simple
            .steps
            .iter()
            .any(|step| step.observed == ObservedOutcome::SealCreated)
    );

    let refusal = history_refusal_only();
    assert_eq!(
        refusal.steps.last().map(|step| step.observed),
        Some(ObservedOutcome::CasWon),
        "the batch still publishes; it publishes a refusal"
    );
    let replayed = replay(&refusal).expect("replay");
    assert_eq!(
        replayed.state.commits().len(),
        0,
        "a refusal-only history commits nothing"
    );
    assert_eq!(
        replayed.state.decisions().len(),
        1,
        "a refusal still consumes a decision sequence"
    );

    let multi = replay(&history_multi_decision_batch()).expect("replay");
    assert_eq!(multi.state.decisions().len(), 2, "two terminal decisions");
    assert_eq!(multi.state.commits().len(), 1, "one of them committed");

    let cas = history_cas_loss_retry();
    assert!(
        cas.steps
            .iter()
            .any(|step| step.observed == ObservedOutcome::CasLost),
        "the CAS-loss history must actually lose a compare-and-swap"
    );
    let cas_replayed = replay(&cas).expect("replay");
    assert_eq!(
        cas_replayed.state.commits().len(),
        2,
        "the loser retries under the same seal and both transactions commit"
    );

    let duplicate = history_idempotent_duplicate();
    let retries = duplicate
        .steps
        .iter()
        .filter(|step| step.observed == ObservedOutcome::SealRetry)
        .count();
    assert_eq!(retries, 2, "the second and third presentations are retries");

    let genesis = history_genesis();
    assert!(genesis.steps.is_empty(), "genesis records no step");
}

#[test]
fn a_divergence_names_the_step_the_input_and_both_roots_and_is_ndjson() {
    let reference = history_simple_commit();
    let empty_roots = encode_roots(&RepositoryRoots::default()).expect("encode empty roots");

    // Pick a step whose roots are genuinely non-empty. Early steps in a
    // history leave the roots untouched, so overwriting one of those with the
    // empty encoding would plant nothing and the test would pass vacuously.
    let tampered = reference
        .steps
        .iter()
        .position(|step| step.roots != empty_roots)
        .expect("a committing history must change its roots at some step");
    let mut candidate = reference.clone();
    candidate.steps[tampered].roots = empty_roots;
    assert_ne!(
        candidate.steps[tampered].roots, reference.steps[tampered].roots,
        "the tamper must actually change the step"
    );

    let divergence = diff(&reference, &candidate).expect("a planted change is found");
    assert_eq!(divergence.step_index, tampered);
    assert_eq!(divergence.kind, DivergenceKind::Roots);
    assert_ne!(divergence.input_kind, "");
    assert_ne!(divergence.expected_roots, divergence.actual_roots);

    let line = divergence.to_ndjson();
    assert!(!line.contains('\n'), "an NDJSON record is one line: {line}");
    assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
    for key in [
        "\"record\":\"trace_divergence\"",
        "\"step_index\":",
        "\"kind\":\"roots\"",
        "\"input\":",
        "\"expected_roots\":",
        "\"actual_roots\":",
        "\"expected_head_generation\":",
        "\"actual_head_generation\":",
    ] {
        assert!(line.contains(key), "NDJSON record is missing {key}: {line}");
    }
    assert!(
        parses_as_flat_json_object(&line),
        "NDJSON record is not a well-formed flat object: {line}"
    );
}

#[test]
fn diffing_a_truncated_candidate_reports_the_first_missing_step() {
    let reference = history_simple_commit();
    let mut candidate = reference.clone();
    candidate.steps.truncate(1);
    let divergence = diff(&reference, &candidate).expect("a missing step is a divergence");
    assert_eq!(divergence.step_index, 1);
    assert_eq!(divergence.actual_roots, "");
}

#[test]
fn two_identical_traces_do_not_diff() {
    let reference = history_multi_decision_batch();
    let candidate = reference.clone();
    assert!(
        diff(&reference, &candidate).is_none(),
        "a trace must not diverge from itself"
    );
}

#[test]
fn roots_encoding_round_trips_and_is_injective_over_content() {
    for (name, expected) in goldens() {
        let bytes = read_golden(name, &expected);
        let trace = decode(&bytes).unwrap_or_else(|error| panic!("{name}: decode: {error}"));
        for (index, step) in trace.steps.iter().enumerate() {
            let roots = decode_roots(&step.roots)
                .unwrap_or_else(|error| panic!("{name} step {index}: decode roots: {error}"));
            let re_encoded = encode_roots(&roots)
                .unwrap_or_else(|error| panic!("{name} step {index}: encode roots: {error}"));
            assert!(
                re_encoded == step.roots,
                "{name} step {index}: roots did not round-trip"
            );
        }
    }
}

#[test]
fn canonical_ordering_makes_insertion_order_irrelevant() {
    // The platform-stability proxy: the same logical roots built through
    // different insertion orders must encode to identical bytes. If any
    // collection leaked iteration order onto the wire, this would fail.
    let mut ascending = RepositoryRoots::default();
    for seed in 1_u8..6 {
        ascending
            .refs
            .insert(name(&format!("refs/heads/b{seed}")), oid(seed));
    }
    let mut descending = RepositoryRoots::default();
    for seed in (1_u8..6).rev() {
        descending
            .refs
            .insert(name(&format!("refs/heads/b{seed}")), oid(seed));
    }
    assert_eq!(ascending, descending);
    assert!(
        encode_roots(&ascending).expect("encode") == encode_roots(&descending).expect("encode"),
        "insertion order reached the wire"
    );
}

#[test]
fn a_trace_from_a_foreign_domain_is_refused_rather_than_reinterpreted() {
    // The frame carries a domain separation tag. Handing the trace decoder a
    // roots body — same codec, same build, different domain — must be refused,
    // not read as a trace with surprising contents.
    let roots = encode_roots(&RepositoryRoots::default()).expect("encode roots");
    let error = decode(&roots).expect_err("a roots body is not a trace");
    let rendered = error.to_string();
    assert!(!rendered.is_empty(), "the refusal must explain itself");

    // The permitted twin: the same bytes through the decoder that owns that
    // domain succeed.
    assert_eq!(
        decode_roots(&roots).expect("roots decode"),
        RepositoryRoots::default()
    );
}

#[test]
fn a_truncated_trace_is_refused_rather_than_partially_accepted() {
    let bytes = encode(&history_simple_commit()).expect("encode");
    for cut in [1_usize, bytes.len() / 2, bytes.len() - 1] {
        let error = decode(&bytes[..cut]).expect_err("a truncated frame must be refused");
        assert_ne!(error.to_string(), "");
    }
    // The permitted twin: the whole frame decodes.
    assert!(decode(&bytes).is_ok());
}

/// A deliberately small, strict checker for a flat JSON object.
///
/// The diff output has to be machine-readable, so a test that only looked for
/// substrings would not establish it. This walks the record and rejects an
/// unbalanced or mis-quoted one. It is not a general JSON parser and does not
/// need to be: the records this asserts on are flat objects of strings and
/// unsigned integers by construction.
fn parses_as_flat_json_object(line: &str) -> bool {
    let mut characters = line.chars().peekable();
    if characters.next() != Some('{') {
        return false;
    }
    loop {
        if !consume_json_string(&mut characters) {
            return false;
        }
        if characters.next() != Some(':') {
            return false;
        }
        match characters.peek() {
            Some('"') => {
                if !consume_json_string(&mut characters) {
                    return false;
                }
            }
            Some(digit) if digit.is_ascii_digit() => {
                while characters.peek().is_some_and(char::is_ascii_digit) {
                    characters.next();
                }
            }
            _ => return false,
        }
        match characters.next() {
            Some(',') => {}
            Some('}') => return characters.next().is_none(),
            _ => return false,
        }
    }
}

fn consume_json_string(characters: &mut core::iter::Peekable<core::str::Chars<'_>>) -> bool {
    if characters.next() != Some('"') {
        return false;
    }
    while let Some(character) = characters.next() {
        match character {
            '"' => return true,
            '\\' => {
                if characters.next().is_none() {
                    return false;
                }
            }
            control if control < ' ' => return false,
            _ => {}
        }
    }
    false
}
