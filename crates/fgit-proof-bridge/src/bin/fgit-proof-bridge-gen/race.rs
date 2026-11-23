//! Replay two previously staged contenders in every DPOR schedule on one head.
use fgit_lab::commute::ProtocolEvent;
use fgit_lab::{Dpor, ExplorationBudget, ExplorationOutcome, Program, StepId};
use fgit_proof_bridge::{ProjectedTrace, project};
use fgit_reference::machine::ModelInput;
use fgit_reference::trace::{GoldenTrace, ObservedOutcome, TraceRecorder, replay};

pub(super) const BUDGET: ExplorationBudget = ExplorationBudget::new(4, 32);

pub(super) fn explore(
    seed: &GoldenTrace,
    budget: ExplorationBudget,
) -> Result<Vec<ProjectedTrace>, String> {
    let replayed = replay(seed).map_err(|e| format!("cannot replay seed: {e:?}"))?;
    if !replayed.is_faithful() {
        return Err(format!("seed diverged at step {}", replayed.steps_replayed));
    }
    // Reuse recorded *inputs*. Each candidate must already be staged at the
    // common predecessor, so only the two conditional publications reorder.
    let mut races = seed.steps.windows(2).enumerate().filter(|(_, pair)| {
        matches!((&pair[0].input, &pair[1].input),
            (ModelInput::CompareAndSwap(a), ModelInput::CompareAndSwap(b))
            if a.expected_head == b.expected_head && a.expected_generation == b.expected_generation && a.batch != b.batch)
    });
    let Some((index, pair)) = races.next() else {
        return Err("seed has no adjacent competing CAS pair".into());
    };
    if races.next().is_some() {
        return Err("seed contains multiple competing CAS pairs".into());
    }
    let mut prefix = TraceRecorder::new(seed.genesis.clone());
    for step in &seed.steps[..index] {
        prefix
            .apply(step.input.clone())
            .map_err(|e| format!("cannot prepare race: {e:?}"))?;
    }
    let head = prefix.state().head();
    let event = ProtocolEvent::CompareExchangeHead {
        key: head.id.to_string(),
    };
    let actors = [StepId::new("first"), StepId::new("second")];
    let program = Program::new(
        actors
            .iter()
            .map(|actor| (actor.clone(), vec![event.clone()]))
            .collect(),
    )
    .map_err(|e| format!("invalid DPOR program: {e:?}"))?;
    let mut traces = std::collections::BTreeMap::new();
    let outcome = Dpor::new().explore(
        &program,
        budget,
        "one_winner_at_one_predecessor",
        |schedule| {
            let [winner, loser] = schedule else {
                return Err("expected two CAS attempts".into());
            };
            let order = match (&winner.actor, &loser.actor) {
                (a, b) if a == &actors[0] && b == &actors[1] => [0, 1],
                (a, b) if a == &actors[1] && b == &actors[0] => [1, 0],
                _ => return Err("unexpected participant sequence".into()),
            };
            let mut recording = prefix.clone();
            let won = recording
                .apply(pair[order[0]].input.clone())
                .map_err(|e| format!("first CAS: {e:?}"))?
                .clone();
            let lost = recording
                .apply(pair[order[1]].input.clone())
                .map_err(|e| format!("second CAS: {e:?}"))?;
            if won.observed != ObservedOutcome::CasWon
                || lost.observed != ObservedOutcome::CasLost
                || lost.head != won.head
                || lost.roots != won.roots
            {
                return Err(
                    "competing publications failed to retain exactly the winner's head and roots"
                        .into(),
                );
            }
            let name = format!("dpor_{}_wins", winner.actor);
            let trace = project(&name, &recording.finish())
                .map_err(|e| format!("cannot project {name}: {e:?}"))?;
            if traces.insert(order, trace).is_some() {
                return Err("repeated schedule".into());
            }
            Ok(())
        },
    );
    if !matches!(outcome, ExplorationOutcome::Exhaustive { classes: 2, .. }) || traces.len() != 2 {
        return Err(format!(
            "incomplete or divergent two-writer exploration: {outcome:?}"
        ));
    }
    Ok(traces.into_values().collect())
}

#[cfg(test)]
#[path = "race_tests.rs"]
mod tests;
