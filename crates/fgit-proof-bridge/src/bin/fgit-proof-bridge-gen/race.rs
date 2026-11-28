//! Replay two previously staged contenders in every DPOR schedule on one head.
use fgit_lab::commute::ProtocolEvent;
use fgit_lab::{Dpor, ExplorationBudget, ExplorationOutcome, Program, StepId};
use fgit_proof_bridge::{ProjectedTrace, project};
use fgit_reference::harness::IdentityMint;
use fgit_reference::intent::{Intent, RefIntent};
use fgit_reference::machine::ModelInput;
use fgit_reference::trace::{GoldenTrace, ObservedOutcome, TraceRecorder, replay};
use fgit_types::refs::RefName;
use fgit_types::{DecisionOutcome, RefusalCode};

#[path = "race_retry.rs"]
mod retry;

pub(super) const BUDGET: ExplorationBudget = ExplorationBudget::new(4, 32);

pub(super) fn explore(
    seed: &GoldenTrace,
    budget: ExplorationBudget,
) -> Result<Vec<ProjectedTrace>, String> {
    histories(seed, budget)?
        .into_iter()
        .map(|(name, history)| {
            project(&name, &history).map_err(|e| format!("cannot project {name}: {e:?}"))
        })
        .collect()
}

pub(super) fn explore_with_ref_conflict(
    seed: &GoldenTrace,
    budget: ExplorationBudget,
) -> Result<Vec<ProjectedTrace>, String> {
    // Validate and schedule the supplied history before deriving a counterpart.
    let mut traces = explore(seed, budget)?;
    let conflict = same_ref_seed(seed)?;
    for (name, history) in histories(&conflict, budget)? {
        let replayed = replay(&history).map_err(|e| format!("cannot replay {name}: {e:?}"))?;
        if !replayed.is_faithful()
            || !matches!(
                replayed.state.decisions(),
                [won, refused] if won.is_committed()
                    && matches!(
                        refused.outcome,
                        DecisionOutcome::Refused { code: RefusalCode::ExpectedOldRefMismatch, .. }
                    )
            )
            || replayed.state.roots().refs.len() != 1
        {
            return Err(format!(
                "{name}: expected one ref and a losing expected-old refusal"
            ));
        }
        let name = name.replacen("dpor_", "dpor_conflict_", 1);
        traces.push(project(&name, &history).map_err(|e| format!("cannot project {name}: {e:?}"))?);
    }
    Ok(traces)
}

fn same_ref_seed(seed: &GoldenTrace) -> Result<GoldenTrace, String> {
    let mut recorder = TraceRecorder::new(seed.genesis.clone());
    let digest = IdentityMint::new(20261125).digest();
    let main = RefName::try_new(b"refs/heads/main").map_err(|e| format!("invalid ref: {e:?}"))?;
    let mut changed_seals = 0;
    let mut changed_preparations = 0;
    for step in &seed.steps {
        let mut input = step.input.clone();
        let request_and_count = match &mut input {
            ModelInput::Seal(seal) => Some((&mut seal.request, &mut changed_seals)),
            ModelInput::Prepare(prepare) => Some((&mut prepare.request, &mut changed_preparations)),
            _ => None,
        };
        if let Some((request, count)) = request_and_count
            && let [statement] = request.statements.as_mut_slice()
            && let [Intent::Ref(RefIntent::Update { name, .. })] = statement.intents.as_mut_slice()
            && name.as_bytes() == b"refs/heads/other"
        {
            *name = main.clone();
            request.canonical_request_digest = digest;
            *count += 1;
        }
        recorder
            .apply(input)
            .map_err(|e| format!("cannot record same-ref scenario: {e:?}"))?;
    }
    if (changed_seals, changed_preparations) != (1, 2) {
        return Err("expected one seal and two preparations of the other-ref writer".into());
    }
    Ok(recorder.finish())
}

fn histories(
    seed: &GoldenTrace,
    budget: ExplorationBudget,
) -> Result<Vec<(String, GoldenTrace)>, String> {
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
    let contenders = [
        retry::contender(&seed.steps[..index], &pair[0].input)?,
        retry::contender(&seed.steps[..index], &pair[1].input)?,
    ];
    if contenders[0].request.tx_id == contenders[1].request.tx_id {
        return Err("the two staged writers have the same transaction".into());
    }
    let retry = retry::Retry::from_tail(&seed.steps[index + 2..], contenders[1])?;
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
            if recording
                .state()
                .outcome_of(contenders[order[0]].request.tx_id)
                .is_none()
            {
                return Err("first publication did not decide the scheduled winner".into());
            }
            retry.publish(&mut recording, contenders[order[1]])?;
            let name = format!("dpor_{}_wins", winner.actor);
            if traces.insert(order, (name, recording.finish())).is_some() {
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
