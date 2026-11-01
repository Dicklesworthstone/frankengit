//! Shared authenticated candidate intake. Every consumer retains each newly
//! authenticated observation before checking eligibility or touching payloads.

use super::super::approval::witness::WitnessGuard;
use super::super::approval::{
    AuthenticatedApprovalObservation, LoadedApprovalTrust, VerifiedApproval,
};
use super::super::profile::Deadline;
use super::Options;
use super::engine::{Checkpoint, highest, selection_json};

pub(in super::super) struct AuthenticatedCandidates {
    observations: Vec<AuthenticatedApprovalObservation>,
    selected: usize,
}

pub(in super::super) struct CapturedSelection {
    pub(in super::super) approval: VerifiedApproval,
    pub(in super::super) envelope: Vec<u8>,
    pub(in super::super) selected: usize,
    pub(in super::super) aliases: Vec<usize>,
    pub(in super::super) json: String,
}

pub(in super::super) fn inspect(
    options: &Options,
    trust: &LoadedApprovalTrust,
    witness: &mut Option<WitnessGuard<'_>>,
    deadline: Deadline,
    mut checkpoint: impl FnMut(Checkpoint) -> Result<(), String>,
) -> Result<AuthenticatedCandidates, String> {
    if options.candidates.is_empty() || options.candidates.len() > super::MAX_CANDIDATES {
        return Err("selected recovery requires 1..64 explicit candidate pairs".into());
    }
    let mut observations = Vec::with_capacity(options.candidates.len());
    for candidate in &options.candidates {
        deadline.check()?;
        let observation = trust.inspect_path(&candidate.approval)?;
        // Authentication creates the durable high-water retention obligation.
        // No next candidate, observer, expiry or payload gate may precede it.
        if let Some(witness) = witness.as_mut() {
            witness.observe(&observation)?;
        }
        observations.push(observation);
        checkpoint(Checkpoint::ApprovalObserved)?;
    }
    checkpoint(Checkpoint::AllApprovalsAuthenticated)?;
    deadline.check()?;
    let selected = highest(&observations)?;
    if let Some(witness) = witness.as_mut() {
        witness.require(&observations[selected])?;
    }
    Ok(AuthenticatedCandidates {
        observations,
        selected,
    })
}

impl AuthenticatedCandidates {
    pub(in super::super) fn capture(
        self,
        options: &Options,
        witness: Option<String>,
        deadline: Deadline,
        mut checkpoint: impl FnMut(Checkpoint) -> Result<(), String>,
    ) -> Result<CapturedSelection, String> {
        let winner = &self.observations[self.selected];
        let aliases = self
            .observations
            .iter()
            .enumerate()
            .filter_map(|(index, observation)| observation.same_statement(winner).then_some(index))
            .collect::<Vec<_>>();
        let json = selection_json(
            &options.candidates,
            &self.observations,
            self.selected,
            aliases.len(),
            witness,
            options.replica_failover.is_some(),
            options.reconstruction.is_some(),
        );
        checkpoint(Checkpoint::WinnerSelected)?;
        deadline.check()?;
        let observation = self
            .observations
            .into_iter()
            .nth(self.selected)
            .ok_or("selected recovery internal candidate mismatch")?;
        let (approval, envelope) = observation.into_verified_with_envelope(
            options.expected,
            options.profile.transfer.max_archive_bytes,
        )?;
        Ok(CapturedSelection {
            approval,
            envelope,
            selected: self.selected,
            aliases,
            json,
        })
    }
}
