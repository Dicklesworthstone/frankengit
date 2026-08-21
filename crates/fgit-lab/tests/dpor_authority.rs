//! DPOR driving the real faultable `AuthorityStore`, with a planted defect.
//!
//! The unit tests in `search` establish the explorer against a modelled event
//! sequence. This establishes it against the thing that actually matters: a
//! real `MemoryAuthorityStore` from `fgit-authority`, driven through its own
//! `drive()`, with real tokens and real compare-exchange semantics.
//!
//! # What is planted, and what is not
//!
//! **The store is not modified.** Planting a defect in the store would be
//! testing a fake. The defect is planted in a *client*: `PublicationClient`
//! with `treat_mismatch_as_success` set reports a publication it did not make
//! when its CAS loses. That is a realistic client bug — treating
//! `PredecessorMismatch` as "someone else already wrote what I wanted" is a
//! mistake a person makes — and it is exactly the class `BoldIbis`'s own planted
//! backends cover from the other side.
//!
//! # Why the bug is interleaving-dependent
//!
//! Two writers each read the head then compare-exchange with the token they
//! read.
//!
//! - **Serialised** (`w1` reads, `w1` commits, `w2` reads, `w2` commits): both
//!   genuinely commit, the head advances twice, and the planted client behaves
//!   identically to the correct one. No violation — this is the interleaving a
//!   naive test would hit.
//! - **Both read first** (`w1` reads, `w2` reads, `w1` commits, `w2` loses):
//!   the correct client reports one commit and the head advanced once. The
//!   planted client reports *two* commits while the head advanced once. The
//!   claimed publications no longer match the head, which is a lost update.
//!
//! So the property is `claimed_commits == head_advance`, and it is violated
//! only in interleavings where both reads precede both writes. Finding it is
//! the whole point of exploring rather than running one schedule.

use fgit_authority::{
    AuthorityClient, AuthorityOp, AuthorityResponse, AuthorityStore, AuthorityVersionToken,
    CasOutcome, HeadGeneration, HeadInit, HeadKey, HeadRead, MemoryAuthorityStore, StoreInstanceId,
};
use fgit_lab::commute::{OwnedEvent, ProtocolEvent};
use fgit_lab::{
    AuthorityCampaign, Dpor, ExplorationBudget, ExplorationOutcome, HazardScript, LabSchedule,
    Program, StepId,
};
use std::cell::RefCell;
use std::rc::Rc;

const HEAD: &str = "repo/main";
const GENEROUS: ExplorationBudget = ExplorationBudget::new(1_000, 100_000);

fn head_key() -> HeadKey {
    HeadKey::new(HEAD.as_bytes().to_vec()).expect("key is within bounds")
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a positive generation is valid")
}

/// A writer that reads the head, then compare-exchanges against what it read.
///
/// `treat_mismatch_as_success` is the plant: when set, a losing CAS is
/// recorded as a commit the client never made.
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
            // The plant. A losing CAS is not a publication, and reporting it
            // as one is a lost update the caller never learns about.
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
///
/// Returns `Err` when the writers' claimed publications disagree with how far
/// the head actually advanced.
fn check_against_real_store(sequence: &[OwnedEvent], planted: bool) -> Result<(), String> {
    let participants = vec![StepId::new("w1"), StepId::new("w2")];
    let order: Vec<StepId> = sequence.iter().map(|owned| owned.actor.clone()).collect();
    let schedule = LabSchedule::explicit(participants, order)
        .map_err(|refusal| format!("schedule rejected: {refusal}"))?;

    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1));
    // Seed the head so both writers have something to read and compare against.
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

    // Ground truth: how far the head actually moved.
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

#[test]
fn correct_clients_survive_every_interleaving() {
    // The control. If this ever fails, the plant below proves nothing,
    // because a failure would no longer be attributable to the plant.
    let outcome = Dpor::new().explore(
        &program(),
        GENEROUS,
        "claims_match_head_advance",
        |sequence| check_against_real_store(sequence, false),
    );

    assert!(
        outcome.is_exhaustive(),
        "correct clients must pass every class, got {outcome:?}"
    );
    assert!(outcome.counterexample().is_none());
    // Both writers conflict on the same head key at every step, so no two
    // events commute: 4 events, 2 per participant, 6 interleavings.
    assert_eq!(outcome.classes(), 6);
}

#[test]
fn the_planted_client_defect_is_found_by_exploration() {
    // The planted lost update is reachable only where both reads precede both
    // writes, so a single schedule would very likely miss it.
    let outcome = Dpor::new().explore(
        &program(),
        GENEROUS,
        "claims_match_head_advance",
        |sequence| check_against_real_store(sequence, true),
    );

    let counterexample = outcome.counterexample().unwrap_or_else(|| {
        panic!("exploration must find the planted lost update, got {outcome:?}")
    });

    assert_eq!(counterexample.property(), "claims_match_head_advance");
    assert!(
        counterexample.detail().contains("claimed"),
        "detail should name the mismatch: {}",
        counterexample.detail()
    );
    assert!(!outcome.is_exhaustive());
}

#[test]
fn the_counterexample_schedule_replays_the_violation() {
    // A counterexample that cannot be re-run is a story, not evidence.
    let outcome = Dpor::new().explore(
        &program(),
        GENEROUS,
        "claims_match_head_advance",
        |sequence| check_against_real_store(sequence, true),
    );
    let counterexample = outcome.counterexample().expect("a violation");

    // Re-run the exact recorded sequence: it must fail the same way.
    let replayed = check_against_real_store(counterexample.sequence(), true)
        .expect_err("the counterexample must reproduce");
    assert_eq!(replayed, counterexample.detail());

    // And the same sequence with correct clients must pass, which is what
    // makes the plant the cause rather than the interleaving alone.
    check_against_real_store(counterexample.sequence(), false)
        .expect("the same interleaving is fine for a correct client");
}

#[test]
fn the_exported_schedule_is_an_ordinary_replayable_schedule() {
    let outcome = Dpor::new().explore(
        &program(),
        GENEROUS,
        "claims_match_head_advance",
        |sequence| check_against_real_store(sequence, true),
    );
    let schedule = outcome
        .counterexample()
        .expect("a violation")
        .schedule()
        .clone();

    assert_eq!(schedule.len(), 4);
    assert_eq!(schedule.participants().len(), 2);
    for step in schedule.order() {
        assert!(schedule.participants().contains(step));
    }

    // Quotable, so someone else can reproduce it from the report alone.
    let line = schedule.canonical_line();
    assert!(line.starts_with("fgit-lab-schedule-v1"));
    assert!(line.contains("participants=w1,w2"));

    // And it round-trips through the replay path unchanged.
    let requoted =
        LabSchedule::explicit(schedule.participants().to_vec(), schedule.order().to_vec())
            .expect("an exported schedule is a valid explicit schedule");
    assert_eq!(requoted.order(), schedule.order());
}

#[test]
fn the_violating_interleaving_is_both_reads_before_both_writes() {
    // Naming the shape rather than only asserting that *something* failed:
    // if the explorer ever reports a different shape, the plant or the
    // conflict relation has changed and the test should say so.
    let outcome = Dpor::new().explore(
        &program(),
        GENEROUS,
        "claims_match_head_advance",
        |sequence| check_against_real_store(sequence, true),
    );
    let sequence = outcome.counterexample().expect("a violation").sequence();

    let mut reads_before_first_cas = 0;
    let mut seen_cas = false;
    for owned in sequence {
        match owned.event {
            ProtocolEvent::ReadHead { .. } if !seen_cas => reads_before_first_cas += 1,
            ProtocolEvent::CompareExchangeHead { .. } => seen_cas = true,
            _ => {}
        }
    }
    assert_eq!(
        reads_before_first_cas,
        2,
        "the lost update requires both reads to precede both writes: {:?}",
        sequence
            .iter()
            .map(OwnedEvent::canonical)
            .collect::<Vec<_>>()
    );
}

#[test]
fn exploration_reports_incomplete_rather_than_missing_the_bug_silently() {
    // With a bound too small to reach the violating class, the answer must be
    // Incomplete — never Exhaustive, which would read as "no bug exists".
    let tight = ExplorationBudget::new(1, 100_000);
    let outcome = Dpor::new().explore(&program(), tight, "claims_match_head_advance", |sequence| {
        check_against_real_store(sequence, true)
    });

    assert!(
        !outcome.is_exhaustive(),
        "a bounded search must never claim exhaustiveness"
    );
    match outcome {
        ExplorationOutcome::Incomplete { classes, .. } => assert_eq!(classes, 1),
        ExplorationOutcome::Violation { .. } => {
            // Acceptable only if the very first class happened to violate.
        }
        ExplorationOutcome::Exhaustive { .. } => {
            panic!("bounded exploration reported exhaustive")
        }
    }
}
