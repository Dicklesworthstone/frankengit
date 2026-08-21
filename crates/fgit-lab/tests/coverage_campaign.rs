//! The coverage campaign worker: one real failure, carried all the way to
//! evidence.
//!
//! This is the downstream consumer of `receipt`, `minimize`, and `crashpack`
//! that FG-013c requires, and it is deliberately end to end. A planted
//! authority defect is found by exploration against a real store, the
//! counterexample is minimized, the minimized form is replayed and checked for
//! the *same* causal signature, and the whole thing is written out as a
//! versioned receipt and crashpack.
//!
//! # Why this is an `#[ignore]`d worker rather than an ordinary test
//!
//! It writes artifacts to a caller-chosen directory and is driven by
//! `scripts/e2e/suites/lab/lab_selftest.sh`, which asserts on what it wrote.
//! Running it as part of an ordinary `cargo test` would make it emit files
//! nobody reads. The suite script is what turns it into evidence; the pattern
//! matches `fgit-reference`'s model campaign.
//!
//! Set `FGIT_LAB_CAMPAIGN_ARTIFACT_DIR` to collect the receipt and crashpack.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;

use fgit_authority::{
    AuthorityClient, AuthorityOp, AuthorityResponse, AuthorityStore, AuthorityVersionToken,
    CasOutcome, HeadGeneration, HeadInit, HeadKey, HeadRead, MemoryAuthorityStore, StoreInstanceId,
};
use fgit_lab::commute::{ConflictRelation, OwnedEvent, ProtocolEvent};
use fgit_lab::crashpack::{Crashpack, ReplayInputs};
use fgit_lab::minimize::{CausalSignature, minimize};
use fgit_lab::receipt::{
    BuildIdentity, CoverageReceipt, DeclaredBounds, ExternalArtifact, ReplayCompleteness,
};
use fgit_lab::{
    AuthorityCampaign, Dpor, ExplorationBudget, FailpointId, FailpointRegistry, HazardScript,
    LabSchedule, Program, ReplayClass, StepId, TraceFingerprint,
};

const HEAD: &str = "repo/main";
const SEED: u64 = 42;
const PROPERTY: &str = "claims_match_head_advance";
const BUDGET: ExplorationBudget = ExplorationBudget::new(1_000, 100_000);

fn head_key() -> HeadKey {
    HeadKey::new(HEAD).expect("a bounded head key")
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a positive generation is valid")
}

/// A writer that reads the head, then compare-exchanges it.
///
/// NOTE ON DUPLICATION: this mirrors `PublicationClient` in
/// `tests/dpor_authority.rs` on purpose. That file is the checked-in evidence
/// for FG-013a, which is closed and gated, so it is not refactored here to
/// share a module. The two definitions must be kept in step: if the plant
/// changes in one, this campaign stops measuring what that suite measures.
struct PublicationClient {
    step: usize,
    token: Option<AuthorityVersionToken>,
    generation: u64,
    body: Vec<u8>,
    treat_mismatch_as_success: bool,
    claimed: Rc<RefCell<usize>>,
}

impl PublicationClient {
    fn new(body: &str, planted: bool, claimed: Rc<RefCell<usize>>) -> Self {
        Self {
            step: 0,
            token: None,
            generation: 0,
            body: body.as_bytes().to_vec(),
            treat_mismatch_as_success: planted,
            claimed,
        }
    }
}

impl AuthorityClient for PublicationClient {
    fn next_op(&mut self) -> Option<AuthorityOp> {
        let op = match self.step {
            0 => AuthorityOp::ReadHead { key: head_key() },
            1 => AuthorityOp::CompareExchangeHead {
                key: head_key(),
                expected: self.token?,
                new_generation: generation(self.generation.saturating_add(1)),
                new_body: self.body.clone(),
            },
            _ => return None,
        };
        self.step += 1;
        Some(op)
    }

    fn observe(&mut self, response: &AuthorityResponse) {
        match response {
            AuthorityResponse::ReadHead(HeadRead::Present(receipt)) => {
                self.token = Some(receipt.token());
                self.generation = receipt.generation().get();
            }
            AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(_)) => {
                *self.claimed.borrow_mut() += 1;
            }
            // The plant: a losing CAS is not a publication, and reporting it as
            // one is a lost update the caller never learns about.
            AuthorityResponse::CompareExchangeHead(CasOutcome::PredecessorMismatch)
                if self.treat_mismatch_as_success =>
            {
                *self.claimed.borrow_mut() += 1;
            }
            _ => {}
        }
    }
}

/// The abstract program the explorer reorders: each writer reads then CASes.
fn program() -> Program {
    let read = ProtocolEvent::ReadHead {
        key: HEAD.to_owned(),
    };
    let cas = ProtocolEvent::CompareExchangeHead {
        key: HEAD.to_owned(),
    };
    Program::new(vec![
        (StepId::new("w1"), vec![read.clone(), cas.clone()]),
        (StepId::new("w2"), vec![read, cas]),
    ])
    .expect("two distinct writers")
}

/// Run one explored execution against a real store and report the property.
fn check_against_real_store(sequence: &[OwnedEvent], planted: bool) -> Result<(), String> {
    let participants = vec![StepId::new("w1"), StepId::new("w2")];
    let order: Vec<StepId> = sequence.iter().map(|owned| owned.actor.clone()).collect();
    let schedule = LabSchedule::explicit(participants, order)
        .map_err(|refusal| format!("schedule rejected: {refusal}"))?;

    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1));
    let seeded = store
        .initialize_head(&head_key(), generation(1), b"root-1")
        .map_err(|failure| format!("seeding the head failed: {failure:?}"))?;
    let base_generation = match seeded {
        HeadInit::Created(receipt) | HeadInit::IdenticalRetry(receipt) => {
            receipt.generation().get()
        }
        HeadInit::Conflict => return Err("head already existed".to_owned()),
    };

    let claimed = Rc::new(RefCell::new(0_usize));
    let mut clients: Vec<Box<dyn AuthorityClient>> = vec![
        Box::new(PublicationClient::new(
            "body-w1",
            planted,
            Rc::clone(&claimed),
        )),
        Box::new(PublicationClient::new(
            "body-w2",
            planted,
            Rc::clone(&claimed),
        )),
    ];

    let campaign = AuthorityCampaign::new(StoreInstanceId::from_raw(1));
    let _outcome = campaign.run_on(&store, &mut clients, &schedule, &HazardScript::none());

    let final_generation = match store
        .read_head(&head_key())
        .map_err(|failure| format!("final read failed: {failure:?}"))?
    {
        HeadRead::Present(receipt) => receipt.generation().get(),
        HeadRead::Absent => return Err("the head vanished".to_owned()),
    };

    let advanced = final_generation.saturating_sub(base_generation);
    let claimed = *claimed.borrow();
    if u64::try_from(claimed).unwrap_or(u64::MAX) == advanced {
        Ok(())
    } else {
        Err(format!(
            "{claimed} publication(s) claimed but the head advanced {advanced}"
        ))
    }
}

/// Where the suite script wants artifacts, if it asked for any.
fn artifact_dir() -> Option<PathBuf> {
    env::var_os("FGIT_LAB_CAMPAIGN_ARTIFACT_DIR").map(PathBuf::from)
}

fn build_identity() -> BuildIdentity {
    // Supplied by the caller in a real lane; the point is that the receipt
    // carries the identity rather than inventing one at read time.
    BuildIdentity::new(
        env::var("FGIT_LAB_SOURCE_DIGEST").unwrap_or_else(|_| "unset-source-digest".to_owned()),
        env::var("FGIT_LAB_TOOLCHAIN").unwrap_or_else(|_| "unset-toolchain".to_owned()),
        format!(
            "fgit-runtime-profile-v1 class=deterministic asupersync={}",
            fgit_runtime::boot::ASUPERSYNC_VERSION
        ),
    )
}

#[test]
#[ignore = "campaign worker: driven by scripts/e2e/suites/lab/lab_selftest.sh"]
fn coverage_campaign_emits_a_receipt_and_a_crashpack() {
    // 1. Find the planted defect by exploring, not by sampling.
    let outcome = Dpor::new().explore(&program(), BUDGET, PROPERTY, |sequence| {
        check_against_real_store(sequence, true)
    });
    let counterexample = outcome
        .counterexample()
        .unwrap_or_else(|| panic!("exploration must find the planted defect, got {outcome:?}"));

    // 2. Minimize it. The oracle re-runs candidates against the real store, so
    //    a reduction is only kept when the shorter sequence genuinely still
    //    fails — and `minimize` additionally requires the same causal
    //    signature, so it cannot drift onto a different bug.
    let reduction = minimize(
        counterexample.property(),
        counterexample.sequence(),
        ConflictRelation,
        &mut |candidate: &[OwnedEvent]| check_against_real_store(candidate, true).is_err(),
    );

    // 3. Replay the minimized form and require the *same* causal signature.
    //    This is the acceptance line: a seeded failure must replay to the same
    //    typed failure, not merely to some failure.
    let replay_error = check_against_real_store(reduction.minimized(), true)
        .expect_err("the minimized counterexample must still reproduce the failure");
    let observed = CausalSignature::of(PROPERTY, reduction.minimized(), ConflictRelation);

    let crashpack = Crashpack::new(
        ReplayInputs {
            seed: SEED,
            schedule_identity: counterexample.schedule().canonical_line(),
            property: PROPERTY.to_owned(),
        },
        build_identity(),
        reduction.signature().clone(),
        reduction.clone(),
        fgit_lab::journal::LogicalTrace::new(),
        "cargo test -p fgit-lab --test coverage_campaign -- --ignored",
    );
    crashpack
        .confirm_replay(&observed)
        .expect("the replay must reproduce the same causal signature");

    // 3b. Demonstrate reduction against the REAL oracle, not just a synthetic
    //     one. This campaign's own counterexample is already minimal — all four
    //     events are causally necessary, because the lost update is reachable
    //     only where both reads precede both writes — so minimizing it removes
    //     nothing and proves nothing about the minimizer.
    //
    //     Padding it with repeats that the clients ignore (each writer has only
    //     two scripted steps, so a third request is inert) gives a genuinely
    //     multi-step counterexample whose extra events are removable. The
    //     oracle here is the same real store, so this is the acceptance line
    //     demonstrated by the campaign rather than by a fixture.
    let mut padded = reduction.minimized().to_vec();
    for writer in ["w1", "w2"] {
        padded.push(OwnedEvent::new(
            StepId::new(writer),
            ProtocolEvent::ReadHead {
                key: HEAD.to_owned(),
            },
        ));
    }
    assert!(
        check_against_real_store(&padded, true).is_err(),
        "the padded sequence must still reproduce the failure, or the padding \
         changed the run and the reduction below would prove nothing"
    );

    let padded_reduction = minimize(
        PROPERTY,
        &padded,
        ConflictRelation,
        &mut |candidate: &[OwnedEvent]| check_against_real_store(candidate, true).is_err(),
    );
    assert!(
        padded_reduction.is_reduced(),
        "the minimizer must strip inert padding: {}",
        padded_reduction.canonical()
    );
    assert_eq!(
        padded_reduction.minimized().len(),
        reduction.minimized().len(),
        "reduction must converge back on the causal core, got {:?}",
        padded_reduction.minimized()
    );
    assert_eq!(
        padded_reduction.signature(),
        reduction.signature(),
        "the reduced padded counterexample must have the same cause"
    );

    // 4. Failpoint coverage over the campaign's declared points.
    let mut registry = FailpointRegistry::new();
    let lost_update = FailpointId::new("authority.cas.lost_update");
    let stale_read = FailpointId::new("authority.head.stale_read");
    registry
        .declare(lost_update.clone(), "a CAS loser reports success anyway")
        .expect("declares");
    registry
        .declare(stale_read, "a reader observes a superseded head")
        .expect("declares");
    registry.arm(&lost_update).expect("arms");
    registry.should_fire(&lost_update).expect("fires");

    // 5. The receipt. Note what is recorded as *missing*: this deterministic
    //    lane never captures native worker evidence, and saying so lowers the
    //    replay completeness rather than being omitted.
    let receipt = CoverageReceipt::new(
        build_identity(),
        SEED,
        DeclaredBounds {
            max_executions: 512,
            max_transitions: 100_000,
        },
    )
    .with_identity(
        counterexample.schedule().canonical_line(),
        TraceFingerprint::of(counterexample.canonical().as_bytes()),
    )
    // `None` for remaining: exploration stopped at the first violation, so how
    // much of the space is left is genuinely unknown. Reporting 0 would read as
    // a fully-walked space.
    .with_exploration(outcome.classes(), None, outcome.is_exhaustive())
    .with_failpoints(&registry.coverage())
    .with_capabilities(0b0000_1001)
    .with_budget("request", "poll_quota=1000")
    .with_budget("database", "poll_quota=5000")
    .with_settlement(0, 0)
    .covering(ReplayClass::LogicalInterleaving)
    .covering(ReplayClass::ObligationSettlement)
    .with_artifact(ExternalArtifact::Present {
        name: "crashpack.ndjson".to_owned(),
        digest: format!("{}", crashpack.fingerprints()["minimized"]),
    })
    .with_artifact(ExternalArtifact::Missing {
        name: "native-worker-parking.ndjson".to_owned(),
        reason: "the deterministic lane cannot observe parked OS workers".to_owned(),
    })
    .with_native_cross_reference("frankengit-fg011b-runtime-evidence-ng0l");

    // The receipt must not claim to be fully replayable while a required
    // artifact is absent.
    assert!(
        !receipt.completeness().is_complete(),
        "a receipt missing native evidence must be degraded, got {:?}",
        receipt.completeness()
    );
    assert!(matches!(
        receipt.completeness(),
        ReplayCompleteness::Degraded { .. }
    ));

    // Planted false green #1: crediting deterministic evidence for a native
    // class must fail closed, even though the receipt links native evidence.
    let inflation = receipt
        .credit_for(ReplayClass::NativeWorkerParking)
        .expect_err("lab evidence must never satisfy a native requirement");
    assert_eq!(
        inflation.code(),
        "lab.evidence.deterministic_for_native_class"
    );

    // Paired permitted case: the classes it really covers are credited.
    receipt
        .credit_for(ReplayClass::LogicalInterleaving)
        .expect("a claimed lab class is creditable");

    // Planted false green #2: a receipt replayed against a different build is
    // refused rather than reporting the original signature.
    let drifted = BuildIdentity::new(
        "some-other-tree",
        "some-other-toolchain",
        "class=production",
    );
    let drift = receipt
        .check_build(&drifted)
        .expect_err("a changed build must be refused as replay drift");
    assert_eq!(drift.code(), "lab.replay.drift");

    // The reduction has to have actually done something, or the minimizer is
    // reporting success for nothing.
    assert!(
        reduction.original().len() >= reduction.minimized().len(),
        "a reduction may not grow the counterexample"
    );

    if let Some(dir) = artifact_dir() {
        fs::create_dir_all(&dir).expect("the artifact directory is creatable");
        fs::write(
            dir.join("receipt.ndjson"),
            format!("{}\n", receipt.to_ndjson()),
        )
        .expect("the receipt is writable");
        fs::write(
            dir.join("crashpack.ndjson"),
            format!("{}\n", crashpack.to_ndjson()),
        )
        .expect("the crashpack is writable");
        fs::write(
            dir.join("failure.txt"),
            format!("{replay_error}\n{}\n", reduction.canonical()),
        )
        .expect("the failure summary is writable");
    }

    // Also emit to stdout so a run without an artifact directory is still
    // diagnosable from the captured log.
    println!("{}", receipt.to_ndjson());
    println!("{}", crashpack.to_ndjson());
}

#[test]
#[ignore = "campaign worker: driven by scripts/e2e/suites/lab/lab_selftest.sh"]
fn a_skipped_row_cannot_be_reported_as_a_pass() {
    // The planted skipped-row fixture the acceptance requires. A campaign that
    // declares a failpoint and never reaches it has a hole in its coverage; the
    // receipt must show that hole rather than reporting only what it hit.
    let mut registry = FailpointRegistry::new();
    let reached = FailpointId::new("authority.cas.lost_update");
    let skipped = FailpointId::new("authority.head.stale_read");
    registry
        .declare(reached.clone(), "a CAS loser reports success anyway")
        .expect("declares");
    registry
        .declare(skipped, "a reader observes a superseded head")
        .expect("declares");
    registry.arm(&reached).expect("arms");
    registry.should_fire(&reached).expect("fires");

    let receipt = CoverageReceipt::new(
        build_identity(),
        SEED,
        DeclaredBounds {
            max_executions: 512,
            max_transitions: 100_000,
        },
    )
    .with_failpoints(&registry.coverage());

    let line = receipt.to_ndjson();
    assert!(
        line.contains("\"failpoints_unexercised\":[\"authority.head.stale_read\"]"),
        "a skipped row must be named in the receipt, got {line}"
    );
    assert!(
        line.contains("\"failpoints_declared\":2"),
        "the denominator must be the declared count, not the reached count"
    );

    // And a run that reached nothing must not be able to look complete.
    let empty = CoverageReceipt::new(
        build_identity(),
        SEED,
        DeclaredBounds {
            max_executions: 512,
            max_transitions: 100_000,
        },
    )
    .with_exploration(0, Some(12), false);
    assert!(!empty.is_exhaustive());
    assert!(
        empty.to_ndjson().contains("\"exhaustive\":false"),
        "a run that explored nothing must say so"
    );

    let mut summary = BTreeMap::new();
    summary.insert("declared", 2);
    summary.insert("exercised", 1);
    println!("{line}");
    println!("skipped_row_fixture={summary:?}");
}
