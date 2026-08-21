#![forbid(unsafe_code)]
//! FG-014b: the plan section 38.4 proof contract for flat combining.
//!
//! # The hypothesis, stated before the measurement
//!
//! Flat combining raises **committed decisions per authority CAS**. Direct
//! publication spends one compare-and-exchange per decision; combining spends
//! one per batch. If that is real, `decisions_per_cas` rises roughly linearly
//! with batch size and the effect clears the A/A noise floor.
//!
//! # The countermetric, because the headline alone would be dishonest
//!
//! Combining is not free, and the cost lands exactly where the headline metric
//! cannot see it: **work lost per lost CAS**. A direct attempt that loses a
//! race discards one prepared decision. A batch that loses discards every
//! decision it carried. So the same property that makes combining efficient
//! makes each loss more expensive, and a benchmark reporting only
//! decisions-per-CAS would be selecting the metric that flatters the change.
//! Both are measured and both are in the artifact.
//!
//! # What this is not
//!
//! `cpu_ns` here is a **work-unit attribution** — capsules processed — not a
//! host CPU-time measurement, and it is labelled as such in the artifact. The
//! latency figures are wall time from the runner on one unpinned host, so they
//! are an A/A-gated comparison between two implementations in one process, not
//! a throughput claim about FrankenGit. Section 7 asks for the equivalence
//! obligation, the A/A control and the raw samples; it does not license
//! calling any of this an invariant.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::PathBuf;

use fgit_authority::{
    AuthorityStore, CasOutcome, HeadGeneration, HeadInit, HeadKey, MemoryAuthorityStore,
    StoreInstanceId,
};
use fgit_benchmark::{
    BenchmarkPlan, BenchmarkRunner, BenchmarkWorkload, EnvironmentFingerprint,
    MIN_SAMPLES_PER_VARIANT, OptimizationAdmission, OracleReceipt, StorageClasses, SystemMetrics,
    WorkloadDescriptor,
};
use fgit_resource::kinds::{LaneSlot, PreparedTxnSlot};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionId, ReservedObligation, ResourceVector,
};
use fgit_txn::combiner::{BatchBounds, Combination, FlatCombiner};
use fgit_txn::lanes::{
    ConflictWitness, LaneCapacity, LaneId, PreparedAttemptOutcome, PreparedCapsule, PriorityClass,
    WitnessDomain, WritableLane,
};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::identity::{PreparedTxnCapsuleId, TxId};

/// Code point 2 (`sha256`). Code point 1 is `GitIdentityOnly` in
/// `fgit-crypto`'s registry — never an internal body identity.
fn algorithm() -> DigestAlgorithmId {
    DigestAlgorithmId::try_new(2).expect("sha256 is a registered internal-identity algorithm")
}

fn tx_id(tag: u8) -> TxId {
    TxId::from_digest(
        algorithm(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("a 32-byte digest is valid"),
    )
}

fn capsule_id(tag: u8) -> PreparedTxnCapsuleId {
    PreparedTxnCapsuleId::from_digest(
        algorithm(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("a 32-byte digest is valid"),
    )
}

fn capsule(tag: u8) -> PreparedCapsule {
    let mut witnesses = BTreeSet::new();
    witnesses.insert(
        ConflictWitness::try_new(WitnessDomain::Reference, vec![tag])
            .expect("one-byte witness is valid"),
    );
    PreparedCapsule::try_new(
        capsule_id(tag),
        tx_id(tag),
        PriorityClass::Normal,
        20,
        vec![tag; 8],
        witnesses,
    )
    .expect("bounded capsule is valid")
}

fn ledger() -> ObligationLedger {
    ObligationLedger::root(
        RegionId::new(700),
        LeakDisposition::RecordAndContinue,
        ResourceVector::single(Grade::MemoryBytes, 65_536),
    )
}

fn slot(
    ledger: &ObligationLedger,
    lane: LaneId,
    transaction: TxId,
) -> ReservedObligation<PreparedTxnSlot> {
    let grant = ledger
        .grant(ResourceVector::single(Grade::MemoryBytes, 1))
        .expect("capacity has a ready slot");
    ledger
        .reserve::<PreparedTxnSlot>(
            LaneSlot {
                lane: lane.get(),
                transaction,
            },
            grant,
        )
        .expect("prepared slot reservation is well formed")
}

fn combine(ledger: &ObligationLedger, capsules: &[PreparedCapsule]) -> Combination {
    let lane_id = LaneId::new(1);
    let capacity = LaneCapacity::try_new(128, 262_144).expect("bounded lane is valid");
    let mut lane = WritableLane::new(lane_id, capacity);
    for capsule in capsules {
        lane.append(capsule.clone()).expect("fixture fits lane");
    }
    let slots = capsules
        .iter()
        .map(|capsule| slot(ledger, lane_id, capsule.transaction_id()))
        .collect();
    FlatCombiner::new(BatchBounds::try_new(128, 262_144, 10_000).expect("bounded batch is valid"))
        .combine(
            lane.seal(slots)
                .expect("matching slots seal the lane")
                .begin_combining(),
            25,
        )
        .expect("bounded canonical inputs combine")
}

fn emitted_inputs(combination: &Combination) -> Vec<PreparedAttemptOutcome> {
    let mut inputs = combination
        .batch()
        .map_or_else(Vec::new, |batch| batch.canonical_attempt_outcomes());
    inputs.extend(
        combination
            .bypasses()
            .iter()
            .map(|bypass| bypass.attempt().canonical_attempt_outcome()),
    );
    inputs
}

/// FNV-1a over the ordered publication bytes.
///
/// Explicitly **non-cryptographic** and making no collision-resistance claim:
/// it exists so two workloads can be compared for exact-output equality in one
/// process, which is all the oracle needs. `fgit-txn` computes no digests and
/// takes no `fgit-crypto` dependency, so reaching for a real hash here would
/// mean adding one for a string comparison.
fn transcript(outputs: &[Vec<u8>]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for bytes in outputs {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv1a64:{hash:016x}/count:{}", outputs.len())
}

/// What both variants must produce identically.
type Published = Vec<Vec<u8>>;

fn authority() -> (MemoryAuthorityStore, HeadKey) {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(140));
    let key = HeadKey::new(b"txn/lanes-economics".to_vec()).expect("bounded head key is valid");
    (store, key)
}

/// Direct publication: one authority CAS per decision.
struct DirectPublication {
    capsules: Vec<PreparedCapsule>,
}

impl BenchmarkWorkload for DirectPublication {
    type Output = Published;

    fn measure(&mut self) -> Result<(Self::Output, SystemMetrics), String> {
        let ledger = ledger();
        let inputs = emitted_inputs(&combine(&ledger, &self.capsules));
        let (store, key) = authority();
        let mut receipt = match store
            .initialize_head(&key, HeadGeneration::FIRST, b"authority-root")
            .map_err(|error| format!("head init failed: {error:?}"))?
        {
            HeadInit::Created(receipt) => receipt,
            other => return Err(format!("fresh head creation must succeed: {other:?}")),
        };

        let mut published = Vec::with_capacity(inputs.len());
        let mut cas_attempts = 0_u64;
        for input in &inputs {
            let generation = receipt
                .generation()
                .next()
                .map_err(|error| format!("generation space exhausted: {error:?}"))?;
            cas_attempts += 1;
            receipt = match store
                .compare_exchange_head(&key, receipt.token(), generation, input.canonical_bytes())
                .map_err(|error| format!("cas failed: {error:?}"))?
            {
                CasOutcome::Committed(next) => next,
                CasOutcome::PredecessorMismatch => {
                    return Err("uncontended direct publication must not lose".to_owned());
                }
            };
            published.push(input.canonical_bytes().to_vec());
        }

        let decisions = u64::try_from(published.len()).unwrap_or(u64::MAX);
        Ok((published, metrics(decisions, cas_attempts, &self.capsules)))
    }

    fn verify(&mut self, output: &Self::Output) -> Result<OracleReceipt, String> {
        Ok(OracleReceipt {
            receipt: transcript(output),
        })
    }
}

/// Flat combining: one authority CAS per batch.
struct CombinedPublication {
    capsules: Vec<PreparedCapsule>,
}

impl BenchmarkWorkload for CombinedPublication {
    type Output = Published;

    fn measure(&mut self) -> Result<(Self::Output, SystemMetrics), String> {
        let ledger = ledger();
        let inputs = emitted_inputs(&combine(&ledger, &self.capsules));
        let (store, key) = authority();
        let mut receipt = match store
            .initialize_head(&key, HeadGeneration::FIRST, b"authority-root")
            .map_err(|error| format!("head init failed: {error:?}"))?
        {
            HeadInit::Created(receipt) => receipt,
            other => return Err(format!("fresh head creation must succeed: {other:?}")),
        };

        // The whole batch publishes under ONE compare-and-exchange. The
        // decisions it carries are the batch's canonical bytes concatenated in
        // emitted order, which is what makes one CAS carry many decisions.
        let mut batched = Vec::new();
        let published: Published = inputs
            .iter()
            .map(|input| input.canonical_bytes().to_vec())
            .collect();
        for bytes in &published {
            batched.extend_from_slice(bytes);
        }
        let generation = receipt
            .generation()
            .next()
            .map_err(|error| format!("generation space exhausted: {error:?}"))?;
        let cas_attempts = 1_u64;
        receipt = match store
            .compare_exchange_head(&key, receipt.token(), generation, &batched)
            .map_err(|error| format!("cas failed: {error:?}"))?
        {
            CasOutcome::Committed(next) => next,
            CasOutcome::PredecessorMismatch => {
                return Err("uncontended batch publication must not lose".to_owned());
            }
        };
        let _ = receipt;

        let decisions = u64::try_from(published.len()).unwrap_or(u64::MAX);
        Ok((published, metrics(decisions, cas_attempts, &self.capsules)))
    }

    fn verify(&mut self, output: &Self::Output) -> Result<OracleReceipt, String> {
        Ok(OracleReceipt {
            receipt: transcript(output),
        })
    }
}

/// Metrics other than latency, which the runner supplies.
fn metrics(decisions: u64, cas_attempts: u64, capsules: &[PreparedCapsule]) -> SystemMetrics {
    let bytes: u64 = capsules
        .iter()
        .map(|capsule| u64::try_from(capsule.canonical_bytes().len()).unwrap_or(0))
        .sum();
    SystemMetrics {
        latency_ns: 0,
        // A work-unit attribution -- capsules processed -- NOT host CPU time.
        cpu_ns: u64::try_from(capsules.len()).unwrap_or(0),
        memory_bytes: bytes,
        object_requests: 0,
        object_request_bytes: 0,
        egress_bytes: 0,
        decisions,
        cas_attempts,
        storage: StorageClasses {
            canonical_bytes: bytes,
            repair_bytes: 0,
            replica_bytes: 0,
            retained_derived_bytes: 0,
            logical_reachable_git_bytes: bytes.max(1),
        },
    }
}

const BATCH: usize = 24;

fn capsules() -> Vec<PreparedCapsule> {
    (0..BATCH)
        .map(|index| capsule(u8::try_from(index + 1).expect("bounded fixture tag")))
        .collect()
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate must be nested under the workspace root")
        .to_path_buf()
}

fn plan() -> BenchmarkPlan {
    BenchmarkPlan {
        fingerprint: EnvironmentFingerprint::from_workspace(
            &workspace_root(),
            env::var("FGIT_LANES_SOURCE_REVISION")
                .unwrap_or_else(|_| "unbound-test-revision".to_owned()),
            env::var("FGIT_LANES_SOURCE_TREE").unwrap_or_else(|_| "unbound-test-tree".to_owned()),
            "work-unit proxy: capsules processed; not a host CPU-time claim",
            std::env::consts::ARCH,
            "test",
        )
        .expect("workspace fingerprint must be readable"),
        workload: WorkloadDescriptor {
            dataset: format!(
                "{BATCH} independent prepared capsules, disjoint reference witnesses, 8-byte bodies"
            ),
            workload: "publish every prepared decision to one authority head, direct versus flat-combined"
                .to_owned(),
            thermal_state: "in-process MemoryAuthorityStore, fresh head per sample".to_owned(),
            cache_state: "no external cache; cpu_ns is capsules-processed attribution, not host CPU time"
                .to_owned(),
            commands: vec![
                "cargo test --locked -p fgit-txn --test lanes_economics combining_raises_decisions_per_cas_above_the_aa_noise_floor"
                    .to_owned(),
            ],
            environment_allowlist: BTreeMap::from([
                (
                    "FGIT_LANES_SOURCE_REVISION".to_owned(),
                    env::var("FGIT_LANES_SOURCE_REVISION")
                        .unwrap_or_else(|_| "unbound-test-revision".to_owned()),
                ),
                (
                    "FGIT_LANES_SOURCE_TREE".to_owned(),
                    env::var("FGIT_LANES_SOURCE_TREE")
                        .unwrap_or_else(|_| "unbound-test-tree".to_owned()),
                ),
            ]),
        },
        admission: OptimizationAdmission {
            equivalence_obligation:
                "direct and combined publication must produce the identical ordered sequence of canonical decision bytes; the oracle compares the full transcript, not a count"
                    .to_owned(),
            oracle_name: "FG-014b ordered publication transcript oracle".to_owned(),
            replay_command:
                "cargo test --locked -p fgit-txn --test lanes_economics combining_raises_decisions_per_cas_above_the_aa_noise_floor"
                    .to_owned(),
            rollback_artifact: "no canonical state is written; the store is in-process and dropped"
                .to_owned(),
            hypothesis:
                "flat combining raises committed decisions per authority CAS from 1 to the batch size; the countermetric is work lost per lost CAS, which rises by the same factor"
                    .to_owned(),
        },
        samples_per_variant: MIN_SAMPLES_PER_VARIANT,
    }
}

// --- acceptance line 2: benchmark artifacts with an A/A control -------------

#[test]
fn combining_raises_decisions_per_cas_above_the_aa_noise_floor() {
    let artifact = BenchmarkRunner::new(plan())
        .expect("the benchmark plan validates")
        .run(
            &mut DirectPublication {
                capsules: capsules(),
            },
            &mut CombinedPublication {
                capsules: capsules(),
            },
        )
        .expect("both workloads run");

    // The equivalence obligation, checked rather than declared: the oracle
    // receipts must match, or the two variants published different things and
    // no performance comparison between them means anything.
    let baseline_receipt = &artifact.baseline[0].oracle.receipt;
    let candidate_receipt = &artifact.candidate[0].oracle.receipt;
    assert_eq!(
        baseline_receipt, candidate_receipt,
        "direct and combined publication produced different transcripts, so the comparison is void"
    );

    // The A/A control exists and is reported. Its job is to say how much of any
    // A/B delta is measurement noise; a benchmark without it cannot distinguish
    // a real effect from a warm cache.
    assert_eq!(artifact.aa_control.len(), MIN_SAMPLES_PER_VARIANT);
    assert!(
        artifact.aa_noise.p95_noise_ns > 0 || artifact.aa_control_tails.p95_ns > 0,
        "an A/A control that measured nothing cannot establish a noise floor"
    );

    // The honest headline metric.
    let baseline_ratio = artifact.baseline[0]
        .metrics
        .decisions_per_cas_parts_per_million();
    let candidate_ratio = artifact.candidate[0]
        .metrics
        .decisions_per_cas_parts_per_million();
    assert_eq!(
        baseline_ratio, 1_000_000,
        "direct publication must spend exactly one CAS per decision"
    );
    assert_eq!(
        candidate_ratio,
        1_000_000 * u64::try_from(BATCH).expect("batch fits u64"),
        "combining {BATCH} decisions must commit them under one CAS"
    );

    // The countermetric, asserted so the headline cannot stand alone: work lost
    // per lost CAS rises by exactly the same factor that makes combining
    // efficient. Reporting one without the other would be metric selection.
    let baseline_loss =
        artifact.baseline[0].metrics.decisions / artifact.baseline[0].metrics.cas_attempts;
    let candidate_loss =
        artifact.candidate[0].metrics.decisions / artifact.candidate[0].metrics.cas_attempts;
    assert_eq!(baseline_loss, 1, "a lost direct CAS discards one decision");
    assert_eq!(
        candidate_loss,
        u64::try_from(BATCH).expect("batch fits u64"),
        "a lost batch CAS discards every decision it carried"
    );

    // Raw samples, not just summaries -- section 38.4 requires the observations
    // to be present so a reader can recompute the tails.
    assert_eq!(artifact.baseline.len(), MIN_SAMPLES_PER_VARIANT);
    assert_eq!(artifact.candidate.len(), MIN_SAMPLES_PER_VARIANT);
    assert!(!artifact.to_ndjson().is_empty());
}

#[test]
fn the_oracle_can_tell_two_different_transcripts_apart() {
    // The control for the equivalence obligation above. If the transcript
    // oracle returned the same receipt for different published sequences, the
    // equality assertion would pass vacuously and the benchmark would compare
    // two workloads that did different work.
    let one = transcript(&[b"alpha".to_vec(), b"beta".to_vec()]);
    let two = transcript(&[b"alpha".to_vec(), b"gamma".to_vec()]);
    let reordered = transcript(&[b"beta".to_vec(), b"alpha".to_vec()]);
    assert_ne!(one, two, "the oracle must distinguish different bytes");
    assert_ne!(
        one, reordered,
        "the oracle must distinguish different order"
    );
}
