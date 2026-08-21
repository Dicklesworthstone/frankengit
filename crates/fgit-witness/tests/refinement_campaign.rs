#![forbid(unsafe_code)]
//! Bounded, schedule-bound evidence for witness refinement and retry liveness.
//!
//! This is an independent test campaign over the published `fgit-witness`
//! surface. It does not make a production policy decision and does not claim
//! that its finite schedules establish fairness for unbounded executions.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::PathBuf,
};

use fgit_witness::{
    Action, Attempt, Cost, EscalationTrigger, Footprint, Inputs, Posterior, PriorityClass, Scope,
    retry::{self, STARVATION_AGE_TICKS, STARVATION_ATTEMPTS},
    voi,
};

const CORPUS: &str = include_str!("corpus/refinement-schedules.tsv");
const CORPUS_SCHEMA: &str = "frankengit.witness-refinement-corpus.v1";
const RECEIPT_SCHEMA: &str = "frankengit.witness-evidence.v1";
const DEFAULT_SEED: u64 = 0x025B_CAFE;
const EXPECTED_HEADER: &str = "label\tleft_scope\tright_scope\texpected_conflict\tleft_write_key\tright_write_key\tsaved\tcpu\tio\tlatency\trisk\tbudget\tposterior_successes\tposterior_failures\texpected_success_ppm\tretry_age_ticks";

#[derive(Debug)]
struct ScheduleCase {
    label: String,
    left: Footprint,
    right: Footprint,
    expected_conflict: bool,
    left_write_key: String,
    right_write_key: String,
    voi_inputs: Inputs,
    posterior_successes: u32,
    posterior_failures: u32,
    expected_success_ppm: u32,
    retry_age_ticks: u32,
}

#[derive(Clone, Copy, Debug)]
struct ConcreteTurn {
    turn: u32,
    participant: &'static str,
    outcome: &'static str,
}

fn parse_scope(encoded: &str) -> Scope {
    let (kind, value) = encoded
        .split_once(':')
        .unwrap_or_else(|| panic!("scope must contain a family separator: {encoded}"));
    match kind {
        "exact-ref" => Scope::ExactRef(value.as_bytes().to_vec()),
        "ref-namespace" => Scope::RefNamespace(value.as_bytes().to_vec()),
        "exact-path" => Scope::ExactPath(value.as_bytes().to_vec()),
        "path-prefix" => Scope::PathPrefix(value.as_bytes().to_vec()),
        "policy" => Scope::PolicyDomain(value.as_bytes().to_vec()),
        "forge-stream" => Scope::ForgeStream(value.as_bytes().to_vec()),
        "forge-entity" => {
            let (stream, entity) = value
                .split_once(':')
                .unwrap_or_else(|| panic!("forge entity must name stream and entity: {encoded}"));
            Scope::ForgeEntity {
                stream: stream.as_bytes().to_vec(),
                entity: entity.as_bytes().to_vec(),
            }
        }
        _ => panic!("unknown scope family in corpus: {kind}"),
    }
}

fn parse_u64(label: &str, field: &str, value: &str) -> u64 {
    value
        .parse()
        .unwrap_or_else(|error| panic!("{label}: {field} must be an unsigned integer: {error}"))
}

fn parse_u32(label: &str, field: &str, value: &str) -> u32 {
    let value = parse_u64(label, field, value);
    u32::try_from(value).unwrap_or_else(|_| panic!("{label}: {field} must fit in a u32: {value}"))
}

fn load_corpus() -> Vec<ScheduleCase> {
    let mut records = CORPUS
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let header = records
        .next()
        .expect("refinement corpus must have a header");
    assert_eq!(header, EXPECTED_HEADER, "refinement corpus header drifted");

    let cases: Vec<_> = records
        .map(|line| {
            let columns: Vec<_> = line.split('\t').collect();
            assert_eq!(
                columns.len(),
                16,
                "refinement corpus row must have 16 tab-separated fields: {line}"
            );
            let expected_conflict = match columns[3] {
                "true" => true,
                "false" => false,
                other => panic!(
                    "{}: expected_conflict must be true or false, got {other}",
                    columns[0]
                ),
            };
            ScheduleCase {
                label: columns[0].to_owned(),
                left: Footprint::from_scopes([parse_scope(columns[1])]),
                right: Footprint::from_scopes([parse_scope(columns[2])]),
                expected_conflict,
                left_write_key: columns[4].to_owned(),
                right_write_key: columns[5].to_owned(),
                voi_inputs: Inputs {
                    expected_saved_retry_cost: Cost::new(parse_u64(
                        columns[0], "saved", columns[6],
                    )),
                    refinement_cpu_cost: Cost::new(parse_u64(columns[0], "cpu", columns[7])),
                    refinement_io_cost: Cost::new(parse_u64(columns[0], "io", columns[8])),
                    added_latency_cost: Cost::new(parse_u64(columns[0], "latency", columns[9])),
                    risk_margin: Cost::new(parse_u64(columns[0], "risk", columns[10])),
                    budget: Cost::new(parse_u64(columns[0], "budget", columns[11])),
                },
                posterior_successes: parse_u32(columns[0], "posterior_successes", columns[12]),
                posterior_failures: parse_u32(columns[0], "posterior_failures", columns[13]),
                expected_success_ppm: parse_u32(columns[0], "expected_success_ppm", columns[14]),
                retry_age_ticks: parse_u32(columns[0], "retry_age_ticks", columns[15]),
            }
        })
        .collect();

    assert!(!cases.is_empty(), "refinement campaign cannot be vacuous");
    assert!(
        cases.iter().any(|case| case.expected_conflict),
        "campaign needs a true-conflict control"
    );
    assert!(
        cases.iter().any(|case| !case.expected_conflict),
        "campaign needs a false-conflict refinement win"
    );
    cases
}

/// Runs the concrete two-write reference schedule in both serial orders.
///
/// Rows name the exact write key exercised by the schedule. Equal final maps
/// mean the schedule is serializable in either order; unequal maps expose the
/// non-commuting write that a refined admission must not clear.
fn reference_model_serializable(case: &ScheduleCase) -> bool {
    let mut left_then_right = BTreeMap::new();
    left_then_right.insert(case.left_write_key.clone(), "left");
    left_then_right.insert(case.right_write_key.clone(), "right");

    let mut right_then_left = BTreeMap::new();
    right_then_left.insert(case.right_write_key.clone(), "right");
    right_then_left.insert(case.left_write_key.clone(), "left");

    left_then_right == right_then_left
}

fn campaign_seed() -> u64 {
    match env::var("FGIT_WITNESS_CAMPAIGN_SEED") {
        Ok(value) => {
            let digits = value.strip_prefix("0x").unwrap_or(&value);
            u64::from_str_radix(digits, 16).unwrap_or_else(|error| {
                panic!("FGIT_WITNESS_CAMPAIGN_SEED must be hexadecimal: {error}")
            })
        }
        Err(_) => DEFAULT_SEED,
    }
}

fn pessimal_posterior() -> Posterior {
    let mut posterior = Posterior::uniform();
    for _ in 0..64 {
        posterior.observe(false);
    }
    posterior
}

fn write_receipt(lines: &[String]) {
    let Ok(dir) = env::var("FGIT_WITNESS_CAMPAIGN_ARTIFACT_DIR") else {
        return;
    };
    let path = PathBuf::from(dir).join("witness-refinement.ndjson");
    fs::create_dir_all(
        path.parent()
            .expect("witness campaign artifact must have a parent directory"),
    )
    .expect("witness campaign artifact directory must be creatable");
    fs::write(path, format!("{}\n", lines.join("\n")))
        .expect("witness campaign receipt must be writable");
}

#[test]
fn deterministic_refinement_safety_fairness_and_starvation_campaign() {
    let cases = load_corpus();
    let seed = campaign_seed();
    let mut receipt_lines = Vec::new();
    let mut refined_admissions = 0_usize;
    let mut true_conflict_removals = 0_usize;
    let mut refinement_wins = 0_usize;
    let mut refinement_losses = 0_usize;

    for case in &cases {
        let exact_conflict = case.left.overlaps(&case.right);
        assert_eq!(
            exact_conflict, case.expected_conflict,
            "{}: corpus conflict classification must agree with exact witnesses",
            case.label
        );
        assert_eq!(
            !exact_conflict,
            reference_model_serializable(case),
            "{}: the exact witness and its concrete two-write schedule disagree",
            case.label
        );

        let decision = voi::decide(case.voi_inputs);
        assert!(
            decision.refines(),
            "{}: the declared bounded VOI inputs must fund this exact refinement",
            case.label
        );
        receipt_lines.push(voi::receipt(case.voi_inputs, decision));

        let mut corpus_posterior = Posterior::uniform();
        for _ in 0..case.posterior_successes {
            corpus_posterior.observe(true);
        }
        for _ in 0..case.posterior_failures {
            corpus_posterior.observe(false);
        }
        assert_eq!(
            corpus_posterior.success_probability().parts_per_million(),
            case.expected_success_ppm,
            "{}: integer posterior counts must produce the receipted ppm value",
            case.label
        );
        let bounded_retry = Attempt {
            attempts: 0,
            age_ticks: case.retry_age_ticks,
            priority: PriorityClass::Background,
            posterior: corpus_posterior,
        };
        let bounded_action = retry::decide(bounded_retry);
        assert!(
            matches!(bounded_action, Action::BackoffFor { .. }),
            "{}: the named non-starved schedule must remain below escalation",
            case.label
        );
        receipt_lines.push(retry::receipt(bounded_retry, bounded_action));

        let admitted = !case.left.overlaps(&case.right);
        if admitted {
            refined_admissions += 1;
            refinement_wins += 1;
            assert!(
                reference_model_serializable(case),
                "{}: a refined admission must be serializable in the reference schedule",
                case.label
            );
        } else {
            refinement_losses += 1;
        }
        if admitted && !reference_model_serializable(case) {
            true_conflict_removals += 1;
        }
    }

    assert_eq!(
        true_conflict_removals, 0,
        "exact refinement may remove false conflicts only"
    );
    assert_eq!(
        refined_admissions, 7,
        "the named disjoint schedules must admit"
    );
    assert_eq!(
        refinement_wins, 7,
        "all seven disjoint refinements avoid a retry"
    );
    assert_eq!(
        refinement_losses, 6,
        "all six true conflicts remain conservative refusals after exact comparison"
    );

    // A deliberately unsafe, test-local control clears one known true conflict.
    // The same reference comparator above must detect it. This does not alter
    // product behavior; it proves the campaign would fail if refinement made
    // the forbidden transition.
    let true_conflicts: Vec<_> = cases.iter().filter(|case| case.expected_conflict).collect();
    let seeded_index = (seed as usize) % true_conflicts.len();
    let seeded_unsafe_label = &true_conflicts[seeded_index].label;
    let unsafe_offenders: Vec<_> = cases
        .iter()
        .filter(|case| {
            let unsafe_refined = if &case.label == seeded_unsafe_label {
                Footprint::empty()
            } else {
                case.left.clone()
            };
            let unsafe_admitted = !unsafe_refined.overlaps(&case.right);
            unsafe_admitted && !reference_model_serializable(case)
        })
        .map(|case| case.label.as_str())
        .collect();
    assert_eq!(
        unsafe_offenders,
        vec![seeded_unsafe_label.as_str()],
        "the seeded unsafe refiner must be caught by the independent reference schedule"
    );

    // Every row starts at a generation witness, which conflicts with every
    // concurrent change. Exact refinement removes only the six false aborts
    // above; all true conflicts remain blocked.
    let coarse_aborts = cases
        .iter()
        .filter(|case| Footprint::conservative().overlaps(&case.right))
        .count();
    let refined_aborts = cases
        .iter()
        .filter(|case| case.left.overlaps(&case.right))
        .count();
    assert_eq!(
        coarse_aborts,
        cases.len(),
        "generation witnesses must be conservative"
    );
    assert_eq!(
        refined_aborts, 6,
        "exact witnesses retain every true conflict"
    );
    assert_eq!(
        coarse_aborts - refined_aborts,
        refinement_wins,
        "the observed false-abort reduction must equal the named refinement wins"
    );

    // Concrete adversarial schedule: one contender commits before each old
    // transaction attempt. The old background transaction loses eight times;
    // on the ninth decision it enters the serialized component and commits.
    let mut turns = Vec::new();
    let mut retry_receipts = Vec::new();
    let posterior = pessimal_posterior();
    let mut turn = 0_u32;
    for attempt_number in 0..STARVATION_ATTEMPTS {
        let contender = if attempt_number % 2 == 0 {
            "contender-a"
        } else {
            "contender-b"
        };
        turn += 1;
        turns.push(ConcreteTurn {
            turn,
            participant: contender,
            outcome: "committed_conflicting_update",
        });
        let attempt = Attempt {
            attempts: attempt_number,
            age_ticks: attempt_number,
            priority: PriorityClass::Background,
            posterior,
        };
        let action = retry::decide(attempt);
        assert!(
            !matches!(action, Action::EscalateToSerialized { .. }),
            "old transaction must not escalate before the declared attempt bound"
        );
        retry_receipts.push(retry::receipt(attempt, action));
        turn += 1;
        turns.push(ConcreteTurn {
            turn,
            participant: "old",
            outcome: "conflict_refused",
        });
    }
    let escalated_attempt = Attempt {
        attempts: STARVATION_ATTEMPTS,
        age_ticks: STARVATION_ATTEMPTS,
        priority: PriorityClass::Background,
        posterior,
    };
    let escalated_action = retry::decide(escalated_attempt);
    assert_eq!(
        escalated_action,
        Action::EscalateToSerialized {
            trigger: EscalationTrigger::AttemptCount,
        },
        "the old transaction must escalate at the hard attempt bound regardless of posterior"
    );
    let escalation_receipt = retry::receipt(escalated_attempt, escalated_action);
    assert!(
        escalation_receipt.contains("\"action\":\"escalate_to_serialized\"")
            && escalation_receipt.contains("\"trigger\":\"attempt_count\""),
        "the starvation receipt must bind its hard escalation trigger"
    );
    retry_receipts.push(escalation_receipt);
    turn += 1;
    turns.push(ConcreteTurn {
        turn,
        participant: "old",
        outcome: "serialized_evaluation",
    });
    turn += 1;
    turns.push(ConcreteTurn {
        turn,
        participant: "old",
        outcome: "serialized_commit",
    });
    let starvation_bound_turn = STARVATION_ATTEMPTS.saturating_mul(2).saturating_add(2);
    assert_eq!(
        turn, starvation_bound_turn,
        "schedule must retain its declared bound"
    );
    for (expected_turn, entry) in (1_u32..).zip(&turns) {
        assert_eq!(
            entry.turn, expected_turn,
            "the concrete adversarial schedule must retain its total order"
        );
    }
    let participants_with_commits: BTreeSet<_> = turns
        .iter()
        .filter(|entry| {
            entry.outcome == "committed_conflicting_update" || entry.outcome == "serialized_commit"
        })
        .map(|entry| entry.participant)
        .collect();
    assert_eq!(
        participants_with_commits,
        BTreeSet::from(["contender-a", "contender-b", "old"]),
        "the named adversarial schedule must leave no named participant without a commit"
    );

    // The separate age threshold is also independent of priority and the
    // pessimistic posterior. These receipt rows bind each concrete check.
    for priority in [
        PriorityClass::Background,
        PriorityClass::Interactive,
        PriorityClass::Foreground,
    ] {
        let aged_attempt = Attempt {
            attempts: 0,
            age_ticks: STARVATION_AGE_TICKS,
            priority,
            posterior,
        };
        let action = retry::decide(aged_attempt);
        assert_eq!(
            action,
            Action::EscalateToSerialized {
                trigger: EscalationTrigger::Age,
            },
            "{priority:?}: age escalation cannot be vetoed by priority or posterior"
        );
        retry_receipts.push(retry::receipt(aged_attempt, action));
    }

    // Regime reset discards a hostile history before the next decision. The
    // exact counts and deterministic fallback action are part of the receipt.
    let mut stale_posterior = pessimal_posterior();
    assert_ne!(
        stale_posterior.counts(),
        (1, 1),
        "drill needs non-uniform history"
    );
    stale_posterior.reset_for_regime();
    assert_eq!(
        stale_posterior.counts(),
        (1, 1),
        "a regime reset must discard stale contention observations"
    );
    let reset_attempt = Attempt {
        attempts: 1,
        age_ticks: 1,
        priority: PriorityClass::Interactive,
        posterior: stale_posterior,
    };
    let reset_action = retry::decide(reset_attempt);
    assert!(
        matches!(reset_action, Action::BackoffFor { .. }),
        "the uniform post-reset posterior must follow the deterministic bounded fallback"
    );
    retry_receipts.push(retry::receipt(reset_attempt, reset_action));

    receipt_lines.extend(retry_receipts);
    receipt_lines.insert(
        0,
        format!(
            "{{\"schema\":\"{RECEIPT_SCHEMA}\",\"record\":\"campaign_summary\",\"corpus_schema\":\"{CORPUS_SCHEMA}\",\"seed\":\"0x{seed:016x}\",\"schedules\":{},\"refined_admissions\":{refined_admissions},\"true_conflict_removals\":{true_conflict_removals},\"coarse_aborts\":{coarse_aborts},\"refined_aborts\":{refined_aborts},\"false_abort_reduction\":{},\"refinement_wins\":{refinement_wins},\"refinement_losses\":{refinement_losses},\"seeded_unsafe_refiner_caught\":true,\"starvation_schedule\":\"contender-before-old-v1\",\"starvation_commit_turn\":{turn},\"starvation_bound_turn\":{starvation_bound_turn},\"all_named_participants_committed\":true,\"age_escalation_priorities\":3,\"regime_reset\":true,\"non_claim\":\"bounded named schedules; not an unbounded fairness or VOI-calibration claim\"}}",
            cases.len(),
            coarse_aborts - refined_aborts,
        ),
    );
    write_receipt(&receipt_lines);
    println!("{}", receipt_lines[0]);
}
