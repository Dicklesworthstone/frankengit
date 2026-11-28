use super::*;
use fgit_proof_bridge::AbstractOp;

fn seed(name: &str) -> GoldenTrace {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fgit-reference/tests/goldens")
            .join(name),
    )
    .expect("checked-in reference history");
    fgit_reference::trace::decode(&bytes).expect("valid source")
}

#[test]
fn both_orders_reexecute_and_only_the_winner_is_decided_at_the_first_head() {
    let original = seed("cas_loss_retry.fgtrace");
    let traces = explore(&original, BUDGET).unwrap();
    assert_eq!(traces.len(), 2);
    let winners: Vec<_> = traces
        .iter()
        .map(|trace| {
            let [won, lost, _, _, _] = &trace.steps[trace.steps.len() - 5..] else {
                panic!("two CAS steps")
            };
            let [
                AbstractOp::Publish { ref_effects, .. },
                AbstractOp::Decide { target, .. },
            ] = &won.operations[..]
            else {
                panic!("the winning batch must publish one terminal decision")
            };
            assert_eq!(ref_effects.len(), 1);
            assert_eq!(won.generation_after, trace.genesis_generation + 1);
            assert_eq!(lost.generation_after, won.generation_after);
            assert!(matches!(
                &lost.operations[..],
                [AbstractOp::InterruptedPublication { .. }]
            ));
            trace
                .transactions
                .iter()
                .find(|(index, _)| index == target)
                .unwrap()
                .1
                .clone()
        })
        .collect();
    assert_ne!(winners[0], winners[1]);
    assert_eq!(
        fgit_proof_bridge::render(&traces),
        fgit_proof_bridge::render(&explore(&original, BUDGET).unwrap())
    );
}

#[test]
fn missing_race_incomplete_search_and_corrupt_recorded_observation_refuse() {
    assert!(explore(&seed("simple_commit.fgtrace"), BUDGET).is_err());
    let mut original = seed("cas_loss_retry.fgtrace");
    assert!(explore(&original, ExplorationBudget::new(1, 32)).is_err());
    original.steps[0].observed = ObservedOutcome::CasWon;
    assert!(explore(&original, BUDGET).is_err());
    assert!(
        explore_with_ref_conflict(&original, BUDGET)
            .unwrap_err()
            .contains("seed diverged")
    );
}

#[test]
fn reprepare_uses_the_actual_losing_seal_and_both_distinct_refs_survive() {
    let original = seed("cas_loss_retry.fgtrace");
    let runs = histories(&original, BUDGET).unwrap();
    assert_eq!(
        runs[0].1, original,
        "the supplied schedule replays every source input"
    );
    let original_state = replay(&original).unwrap().state;
    let expected = original_state.decisions();
    let [first, second] = expected else {
        panic!("two distinct original decisions")
    };
    for ((_, run), (winner, loser)) in runs.iter().zip([(first, second), (second, first)]) {
        let state = replay(run).unwrap().state;
        let [won, retried] = state.decisions() else {
            panic!("two decisions")
        };
        assert_eq!((won.tx_id, retried.tx_id), (winner.tx_id, loser.tx_id));
        assert!(won.is_committed() && retried.is_committed());
        assert_eq!(state.roots().refs, original_state.roots().refs);
        assert_eq!(state.roots().refs.len(), 2);
        let [prepare, stage, cas] = &run.steps[run.steps.len() - 3..] else {
            unreachable!()
        };
        let ModelInput::Prepare(prepared) = &prepare.input else {
            panic!("missing retry preparation")
        };
        let original_seal = run
            .steps
            .iter()
            .find_map(|step| match &step.input {
                ModelInput::Seal(s) if s.request.tx_id == loser.tx_id => Some(s),
                _ => None,
            })
            .unwrap();
        assert_eq!(prepared.request, original_seal.request);
        assert_eq!(
            state.seal_of(loser.tx_id).unwrap().seal_id,
            original_seal.seal_id
        );
        assert_eq!(state.preparations_of(loser.tx_id), 2);
        assert_eq!(prepare.head, stage.head);
        let ModelInput::CompareAndSwap(retry) = &cas.input else {
            panic!("missing retry CAS")
        };
        let published = state.batch(retry.batch).unwrap();
        assert_eq!(published.predecessor_head(), retry.expected_head);
        assert_eq!(
            published.predecessor_generation(),
            retry.expected_generation
        );
        assert_eq!(published.decisions(), [*retried]);
    }
}

#[test]
fn an_occupied_original_target_refuses_the_loser_in_each_order() {
    let original = seed("cas_loss_retry.fgtrace");
    let conflict = same_ref_seed(&original).unwrap();
    let traces = explore_with_ref_conflict(&original, BUDGET).unwrap();
    let names: Vec<_> = traces.iter().map(|trace| trace.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "dpor_first_wins",
            "dpor_second_wins",
            "dpor_conflict_first_wins",
            "dpor_conflict_second_wins",
        ]
    );
    let source_decisions = replay(&conflict).unwrap().state.decisions().to_vec();
    let [a, b] = source_decisions.as_slice() else {
        panic!("two original writers")
    };
    for ((_, run), (winner, loser)) in histories(&conflict, BUDGET)
        .unwrap()
        .iter()
        .zip([(a, b), (b, a)])
    {
        let state = replay(run).unwrap().state;
        let [won, refused] = state.decisions() else {
            panic!("two terminals")
        };
        assert_eq!((won.tx_id, refused.tx_id), (winner.tx_id, loser.tx_id));
        assert!(won.is_committed());
        assert!(matches!(
            refused.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ExpectedOldRefMismatch,
                ..
            }
        ));
        let winning_roots =
            fgit_reference::trace::decode_roots(&run.steps[run.steps.len() - 5].roots).unwrap();
        assert_eq!(state.roots().refs, winning_roots.refs);
        assert_eq!(state.roots().refs.len(), 1);
    }
}

#[test]
fn incomplete_retry_and_faithfully_recorded_changed_semantics_refuse() {
    let original = seed("cas_loss_retry.fgtrace");
    let mut incomplete = original.clone();
    incomplete.steps.truncate(incomplete.steps.len() - 3);
    assert!(replay(&incomplete).unwrap().is_faithful());
    assert!(explore(&incomplete, BUDGET).is_err());

    // The reference model takes digest identity as input. Change a semantic
    // field while retaining that digest; the bridge must compare the complete
    // request with its original seal, even if model replay remains faithful.
    let mut mutated = TraceRecorder::new(original.genesis);
    for (i, step) in original.steps.into_iter().enumerate() {
        let mut input = step.input;
        if i == 10
            && let ModelInput::Prepare(prepared) = &mut input
        {
            prepared.request.atomic = !prepared.request.atomic;
        }
        mutated.apply(input).unwrap();
    }
    let changed = mutated.finish();
    assert!(replay(&changed).unwrap().is_faithful());
    assert!(
        explore(&changed, BUDGET)
            .unwrap_err()
            .contains("original loser's sealed request")
    );
}
