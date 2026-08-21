//! One run that composes every fault class, and replays byte-identically.
//!
//! The acceptance sentence is "storage, packet, budget, cancellation, panic,
//! and obligation faults compose without ambient time/RNG or schedule
//! nondeterminism". The unit tests establish each class on its own; this
//! establishes the *conjunction*, which is the part that actually fails in
//! practice — a fault model usually stays deterministic in isolation and
//! stops being deterministic once it shares a run with the others.
//!
//! So this drives a real `MemoryAuthorityStore` under a scripted storage
//! plan, folds the campaign's caller-visible trace into the lab's, exercises
//! declared failpoints, applies the packet/object-store/execution hazards at
//! their scheduled indices, opens and settles obligations, walks the
//! cancellation phases, and closes the region — then does the whole thing
//! again and requires the two traces to be equal byte for byte.

use fgit_authority::{
    AuthorityClient, AuthorityOp, HeadGeneration, HeadKey, ImmutableKey, StoreInstanceId,
};
use fgit_lab::harness::CANCELLATION_PHASES;
use fgit_lab::hazard::{CancelPhase, ExecutionFault, ScheduledHazard};
use fgit_lab::journal::TraceEvent;
use fgit_lab::verdict::Settlement;
use fgit_lab::{
    AuthorityCampaign, HazardScript, Lab, LabConfig, LabRefusal, LabSchedule, LogicalTrace,
    ScriptedClient, StepId,
};
use fgit_runtime::BudgetClass;

const SEED: u64 = 0x5EED_1AB0;
const SPAN: u64 = 12;

fn participants() -> Vec<StepId> {
    vec![StepId::new("writer"), StepId::new("reader")]
}

fn schedule() -> LabSchedule {
    LabSchedule::round_robin(participants(), 2).expect("a round-robin schedule is valid")
}

/// A storage plan plus every non-storage hazard class, all in one script.
fn composed_hazards() -> HazardScript {
    let seeded = HazardScript::seeded(SEED, SPAN, 3, 4);
    let mut hazards = seeded.hazards().to_vec();
    // Add the three execution-facing classes explicitly so the script is
    // guaranteed to carry all of them rather than depending on what the seed
    // happened to choose.
    hazards.push(ScheduledHazard::Execution {
        at: fgit_authority::OpIndex::from_raw(1),
        fault: ExecutionFault::BudgetExhausted {
            dimension: fgit_runtime::Exhaustion::PollQuota,
        },
    });
    hazards.push(ScheduledHazard::Execution {
        at: fgit_authority::OpIndex::from_raw(2),
        fault: ExecutionFault::Cancelled {
            phase: CancelPhase::Finalize,
        },
    });
    hazards.push(ScheduledHazard::Execution {
        at: fgit_authority::OpIndex::from_raw(3),
        fault: ExecutionFault::PanicContained,
    });
    HazardScript::explicit(seeded.storage().clone(), hazards)
}

fn immutable(name: &str) -> ImmutableKey {
    ImmutableKey::new(name.as_bytes().to_vec()).expect("key is within bounds")
}

fn head(name: &str) -> HeadKey {
    HeadKey::new(name.as_bytes().to_vec()).expect("key is within bounds")
}

fn clients() -> Vec<Box<dyn AuthorityClient>> {
    vec![
        Box::new(ScriptedClient::new(vec![
            AuthorityOp::PutIfAbsent {
                key: immutable("blob/alpha"),
                body: b"alpha".to_vec(),
            },
            AuthorityOp::InitializeHead {
                key: head("repo/main"),
                generation: HeadGeneration::try_new(1).expect("generation 1 is valid"),
                body: b"root-1".to_vec(),
            },
        ])),
        Box::new(ScriptedClient::new(vec![
            AuthorityOp::ReadImmutable {
                key: immutable("blob/alpha"),
            },
            AuthorityOp::ReadHead {
                key: head("repo/main"),
            },
        ])),
    ]
}

const FAILPOINTS: [(&str, &str); 3] = [
    (
        "authority.cas.after_effect",
        "endpoint dies after the head CAS applied",
    ),
    (
        "packet.sideband.truncate",
        "sideband frame truncated mid-payload",
    ),
    (
        "object.write.ambiguous",
        "object write reported failed after the bytes landed",
    ),
];

/// The whole composed scenario, as a function of the lab alone.
///
/// Everything it consumes is either lab state or a constant, so two calls with
/// the same [`LabConfig`] must produce the same events.
fn composed_run(lab: &mut Lab) -> Result<(), LabRefusal> {
    for (name, description) in FAILPOINTS {
        lab.declare_failpoint(fgit_lab::FailpointId::new(name), description)?;
    }

    lab.record_context(BudgetClass::Request);
    lab.record_context(BudgetClass::Database);

    // Storage faults: a real store, driven through fgit-authority's own
    // scripted plan, with only caller-visible facts folded into our trace.
    let hazards = composed_hazards();
    let campaign = AuthorityCampaign::new(StoreInstanceId::from_raw(1)).with_ticks_per_op(2);
    let mut clients = clients();
    let outcome = campaign.run(&mut clients, &schedule(), &hazards);
    lab.absorb_trace(outcome.trace());

    // Packet, object-store, and execution hazards at their scheduled indices.
    for hazard in hazards.hazards() {
        lab.advance(1);
        lab.record_fault(hazard.canonical());
    }

    // Failpoints, reached deterministically.
    for (name, _) in FAILPOINTS {
        let id = fgit_lab::FailpointId::new(name);
        lab.failpoints().arm(&id)?;
        lab.reach_failpoint(&id)?;
    }

    // Obligations opened and settled across the run.
    lab.region().task_started();
    lab.obligations().opened("outbox/1");
    lab.obligations().opened("secret-lease/1");
    lab.obligations().settled("outbox/1", Settlement::Committed);
    lab.obligations()
        .settled("secret-lease/1", Settlement::Transferred);
    lab.region().task_finished();

    // Cancellation phases, in the fixed order.
    for phase in CANCELLATION_PHASES {
        lab.advance(1);
        lab.record_cancellation(phase)?;
    }

    Ok(())
}

fn config() -> LabConfig {
    LabConfig::new(SEED, schedule(), composed_hazards())
}

#[test]
fn every_fault_class_composes_in_one_run() {
    let mut lab = Lab::start(config());
    composed_run(&mut lab).expect("the composed scenario runs");
    let run = lab
        .finish()
        .expect("every obligation settled, so the region is quiescent");

    let text = String::from_utf8(run.trace().canonical_bytes()).expect("the trace is utf-8");

    // Storage: real operations against the real store reached the trace.
    assert!(text.contains("invoke:put_if_absent"), "{text}");
    assert!(text.contains("invoke:read_head"), "{text}");

    // Packet and object-store hazards.
    assert!(
        text.contains("packet.") || text.contains("object."),
        "the seeded script must schedule at least one resource-facing hazard: {text}"
    );

    // The three execution-facing classes, each explicitly present.
    assert!(text.contains("exec.budget_exhausted:poll_quota"), "{text}");
    assert!(text.contains("exec.cancelled:finalize"), "{text}");
    assert!(text.contains("exec.panic_contained"), "{text}");

    // Cancellation ordering survived the composition.
    let request = text.find("phase=request").expect("request phase recorded");
    let drain = text.find("phase=drain").expect("drain phase recorded");
    let finalize = text
        .find("phase=finalize")
        .expect("finalize phase recorded");
    assert!(request < drain && drain < finalize, "{text}");

    // Obligations: both settled, region closed clean.
    let oracle = run
        .oracle()
        .expect("a quiescent close yields an oracle report");
    assert_eq!(oracle.settlements().len(), 2);
    assert!(text.contains("region_closed"));
    assert!(text.contains("outstanding=0"));
}

#[test]
fn the_composed_run_replays_byte_identically() {
    // The acceptance property applied to the conjunction rather than to each
    // class alone: this is where a fault model that is deterministic in
    // isolation usually stops being deterministic.
    let first = {
        let mut lab = Lab::start(config());
        composed_run(&mut lab).expect("runs");
        lab.finish().expect("quiescent")
    };
    let second = {
        let mut lab = Lab::start(config());
        composed_run(&mut lab).expect("runs");
        lab.finish().expect("quiescent")
    };

    assert_eq!(
        first.trace().canonical_bytes(),
        second.trace().canonical_bytes(),
        "a composed run must replay byte for byte"
    );
    first
        .trace()
        .expect_matches(second.trace())
        .expect("no divergence");
    assert_eq!(first.trace().fingerprint(), second.trace().fingerprint());
    assert_eq!(first.steps(), second.steps());
    assert_eq!(first.draws(), second.draws());
    assert_eq!(first.finished_at(), second.finished_at());
}

#[test]
fn verify_replay_accepts_the_composed_scenario() {
    // The same property through the harness's own checker, which is what a
    // campaign would actually call.
    let run = Lab::verify_replay(&config(), composed_run)
        .expect("the composed scenario is deterministic");
    assert!(
        run.trace().len() > 20,
        "the composed run should be substantial"
    );
}

#[test]
fn the_composed_run_exercises_every_declared_failpoint() {
    // Coverage is reported, not assumed: a campaign that declared three
    // points and reached three points may claim completeness.
    let mut lab = Lab::start(config());
    composed_run(&mut lab).expect("runs");
    let run = lab.finish().expect("quiescent");

    let coverage = run.coverage();
    assert_eq!(coverage.declared_count(), FAILPOINTS.len());
    assert!(
        coverage.is_complete(),
        "unexercised: {:?}",
        coverage.unexercised()
    );
    for (name, _) in FAILPOINTS {
        assert!(
            coverage.canonical_line().contains(&format!("hit:{name}=")),
            "{name} missing from {}",
            coverage.canonical_line()
        );
    }
}

#[test]
fn a_composed_run_that_strands_an_obligation_cannot_close_clean() {
    // Paired negative for the quiescent close above: same scenario, one
    // obligation left open, and the region refuses rather than reporting a
    // clean run with a leak inside it.
    let mut lab = Lab::start(config());
    composed_run(&mut lab).expect("runs");
    lab.obligations().opened("runner-slot/9");

    let refusal = lab
        .finish()
        .expect_err("an outstanding obligation must block a clean close");
    assert_eq!(refusal, LabRefusal::RegionNotQuiescent { outstanding: 1 });
    assert!(refusal.indicts_subject());
}

#[test]
fn the_composed_trace_carries_the_supported_format_marker() {
    let mut lab = Lab::start(config());
    composed_run(&mut lab).expect("runs");
    let run = lab.finish().expect("quiescent");
    LogicalTrace::check_version(&run.trace().canonical_bytes())
        .expect("the composed trace uses the current format");
}

#[test]
fn a_different_seed_changes_the_composed_trace() {
    // Guards against the composition accidentally washing out the seed: if
    // two seeds produced the same trace, replay identity would be vacuous.
    let run_with = |seed: u64| {
        let config = LabConfig::new(seed, schedule(), HazardScript::seeded(seed, SPAN, 3, 4));
        let mut lab = Lab::start(config);
        lab.record_context(BudgetClass::Request);
        for hazard in HazardScript::seeded(seed, SPAN, 3, 4).hazards() {
            lab.advance(1);
            lab.record_fault(hazard.canonical());
        }
        lab.finish_reporting_leaks().trace().canonical_bytes()
    };
    assert_ne!(run_with(SEED), run_with(SEED ^ 0xFFFF));
}

#[test]
fn the_config_line_pins_every_input_the_composed_run_depends_on() {
    // The reproduction recipe must name the seed, the profile, the schedule
    // and the fault script — anything a run depends on that is missing here
    // is a determinism hole.
    let line = config().canonical_line();
    assert!(line.contains(&format!("seed={SEED}")));
    assert!(line.contains("class=deterministic"));
    assert!(line.contains("fgit-lab-schedule-v1"));
    assert!(line.contains("fgit-lab-hazards-v1"));
    assert!(line.contains("workers=1"));
    assert!(line.contains("parking=false"));
    assert_eq!(line, config().canonical_line());
}

#[test]
fn the_composed_run_records_no_wall_clock_instant() {
    // Every instant in the trace is a lab tick (`tN`). A real timestamp
    // leaking in would be the determinism failure this crate exists to
    // prevent, and it would be invisible in a passing replay of a single run.
    let mut lab = Lab::start(config());
    composed_run(&mut lab).expect("runs");
    let run = lab.finish().expect("quiescent");

    for event in run.trace().events() {
        let line = event.canonical_line();
        for field in line.split('\t') {
            // Instants are bare `tN` fields; anything with `=` is a named
            // value (`ticks=3`, `steps=4`) and is not an instant.
            if field.contains('=') {
                continue;
            }
            if let Some(rest) = field.strip_prefix('t') {
                assert!(
                    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()),
                    "non-tick instant `{field}` in `{line}`"
                );
            }
        }
        assert!(
            !matches!(event, TraceEvent::ClockAdvanced { ticks, .. } if *ticks > 1_000_000),
            "implausibly large tick count suggests a wall-clock value: {line}"
        );
    }
}
