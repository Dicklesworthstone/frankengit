//! Reprepare the scheduled loser against the winner's published head.
use fgit_reference::capsule::PreparedVerdict;
use fgit_reference::machine::ModelInput;
use fgit_reference::trace::{ObservedOutcome, TraceRecorder, TraceStep};
use fgit_reference::transition::{CasRequest, DecisionBodyIdentity, PrepareRequest, StageRequest};
use fgit_types::DecisionOutcome;

pub(super) fn contender<'a>(
    prefix: &'a [TraceStep],
    cas: &ModelInput,
) -> Result<&'a PrepareRequest, String> {
    let ModelInput::CompareAndSwap(cas) = cas else {
        return Err("expected a CAS contender".into());
    };
    let capsule = prefix
        .iter()
        .find_map(|step| match &step.input {
            ModelInput::Stage(stage) if stage.batch_id == cas.batch => {
                match stage.capsules.as_slice() {
                    [only] => Some(*only),
                    _ => None,
                }
            }
            _ => None,
        })
        .ok_or("each contender must stage one capsule")?;
    let prepared = prefix
        .iter()
        .find_map(|step| match &step.input {
            ModelInput::Prepare(prepared) if prepared.capsule_id == capsule => {
                Some(prepared.as_ref())
            }
            _ => None,
        })
        .ok_or("contender has no preparation")?;
    if !prefix.iter().any(|step| {
        matches!(&step.input, ModelInput::Seal(seal)
        if step.observed == ObservedOutcome::SealCreated && seal.request == prepared.request)
    }) {
        return Err("contender did not prepare its original sealed request".into());
    }
    Ok(prepared)
}

pub(super) struct Retry<'a> {
    prepare: &'a PrepareRequest,
    stage: &'a StageRequest,
    bodies: DecisionBodyIdentity,
}

impl<'a> Retry<'a> {
    pub(super) fn from_tail(
        tail: &'a [TraceStep],
        original_loser: &PrepareRequest,
    ) -> Result<Self, String> {
        let [p, s, c] = tail else {
            return Err(
                "expected the seed's reprepare, stage and publication after CAS loss".into(),
            );
        };
        let (
            ModelInput::Prepare(prepare),
            ModelInput::Stage(stage),
            ModelInput::CompareAndSwap(cas),
        ) = (&p.input, &s.input, &c.input)
        else {
            return Err("unexpected retry inputs".into());
        };
        if prepare.request != original_loser.request
            || stage.capsules != [prepare.capsule_id]
            || stage.batch_id != cas.batch
            || stage.bodies.len() != 1
            || c.observed != ObservedOutcome::CasWon
        {
            return Err("seed retry does not republish the original loser's sealed request".into());
        }
        let bodies = *stage
            .bodies
            .get(&prepare.request.tx_id)
            .ok_or("missing retry decision body")?;
        Ok(Self {
            prepare,
            stage,
            bodies,
        })
    }

    pub(super) fn publish(
        &self,
        recording: &mut TraceRecorder,
        loser: &PrepareRequest,
    ) -> Result<(), String> {
        let tx = loser.request.tx_id;
        let state = recording.state();
        let seal = state.seal_of(tx).ok_or("loser has no seal")?.seal_id;
        let head = state.head();
        let cas = CasRequest {
            expected_head: head.id,
            expected_generation: head.body.generation,
            batch: self.stage.batch_id,
        };
        if state.outcome_of(tx).is_some() {
            return Err("loser was already decided".into());
        }
        // Each schedule is an independent run, so it can use the same fresh
        // capsule, batch, result and head IDs from the recorded retry. The
        // reversed order uses its own loser's original request and credentials.
        let mut prepare = if self.prepare.request == loser.request {
            self.prepare
        } else {
            loser
        }
        .clone();
        prepare.capsule_id = self.prepare.capsule_id;
        recording
            .apply(ModelInput::Prepare(Box::new(prepare)))
            .map_err(|e| format!("reprepare: {e:?}"))?;
        let capsule = recording
            .state()
            .capsule(self.prepare.capsule_id)
            .ok_or("retry capsule absent")?;
        if capsule.tx_id != tx
            || capsule.seal_id != seal
            || capsule.basis_head != cas.expected_head
            || capsule.basis_generation != cas.expected_generation
            || capsule.canonical_request_digest != loser.request.canonical_request_digest
        {
            return Err(
                "retry preparation changed the seal or did not use the winning basis".into(),
            );
        }
        let expected = match &capsule.verdict {
            PreparedVerdict::Commit(_) => DecisionOutcome::Committed {
                repository_commit_id: self.bodies.commit,
            },
            PreparedVerdict::Refuse(code) => DecisionOutcome::Refused {
                code: *code,
                refusal_record_id: self.bodies.refusal_record,
            },
        };
        let mut stage = self.stage.clone();
        stage.bodies = [(tx, self.bodies)].into();
        let staged = recording
            .apply(ModelInput::Stage(stage))
            .map_err(|e| format!("retry stage: {e:?}"))?;
        if staged.observed != ObservedOutcome::Staged || recording.state().outcome_of(tx).is_some()
        {
            return Err("retry stage was deferred or published early".into());
        }
        let published = recording
            .apply(ModelInput::CompareAndSwap(cas))
            .map_err(|e| format!("retry CAS: {e:?}"))?;
        if published.observed != ObservedOutcome::CasWon
            || recording.state().outcome_of(tx) != Some(expected)
        {
            return Err("retry did not publish the revalidated loser's exact outcome".into());
        }
        Ok(())
    }
}
