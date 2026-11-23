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
fn both_orders_reexecute_and_only_the_winning_transaction_is_decided() {
    let original = seed("cas_loss_retry.fgtrace");
    let traces = explore(&original, BUDGET).unwrap();
    assert_eq!(traces.len(), 2);
    let winners: Vec<_> = traces
        .iter()
        .map(|trace| {
            let [won, lost] = &trace.steps[trace.steps.len() - 2..] else {
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
}
