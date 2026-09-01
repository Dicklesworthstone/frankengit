//! Explicit continuity for an activated task claim and action packet.
//!
//! [`crate::ActiveTaskClaim`] records the exact situation that first observed
//! its post-claim task generation. It does not imply that a later situation is
//! equivalent. [`ActiveClaimContinuityReceipt`] supplies that missing proof for
//! the narrow, useful case in which **only logical observation time advances**:
//! the authenticated authority receipt, Intent Run, workspace, and every
//! situation component remain byte-for-byte identical.
//!
//! This is intentionally stricter than “the task generation is unchanged.” A
//! peer, conflict, capability, obligation, evidence, or search-generation
//! change may invalidate a plan even when the task row did not move. Until a
//! typed plan-relative invalidation witness exists, accepting any such change
//! would turn absence of analysis into permission.
//!
//! [`AgentActionPacketContinuation`] binds the proof to one already-built
//! [`crate::AgentActionPacket`]. It does not rewrite the packet or authorize an
//! effect. An executor consumes the original packet plus this continuation and
//! still re-checks every mandatory precondition through the ordinary broker and
//! obligation path.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::Digest;

use crate::{
    ActiveTaskClaim, ActiveTaskClaimId, AgentActionPacket, AgentActionPacketId,
    AgentChangePlanId, AgentSituationReceipt, IntentRun, LogicalTime, RunId,
    SituationAuthorityChange, SituationComponentKind, SituationDelta, SituationId,
    SituationRefusal, WorkTaskId,
};

const CLAIM_CONTINUITY_DOMAIN: &[u8] = b"frankengit.agent.claim-continuity/v1\0";
const PACKET_CONTINUATION_DOMAIN: &[u8] =
    b"frankengit.agent.action-packet-continuation/v1\0";

/// Stable identity of one active-claim continuity proof.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActiveClaimContinuityReceiptId([u8; 32]);

impl ActiveClaimContinuityReceiptId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ActiveClaimContinuityReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("claim-continuity:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable identity of one action-packet continuation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentActionPacketContinuationId([u8; 32]);

impl AgentActionPacketContinuationId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AgentActionPacketContinuationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("action-packet-continuation:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Proof that an activated claim's complete observation context did not change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveClaimContinuityReceipt {
    receipt_id: ActiveClaimContinuityReceiptId,
    active_claim_id: ActiveTaskClaimId,
    from_situation_id: SituationId,
    to_situation_id: SituationId,
    run_id: RunId,
    task_id: WorkTaskId,
    task_projection_generation: [u8; 32],
    from_observed_at: LogicalTime,
    to_observed_at: LogicalTime,
}

impl ActiveClaimContinuityReceipt {
    /// Proves that only logical observation time advanced after claim activation.
    ///
    /// # Errors
    ///
    /// Refuses claim/situation/run substitution, legacy or mismatched authority,
    /// non-advancing or rolled-back time, expired claim/run, unavailable task
    /// projection, any authority/run/workspace/component change, and
    /// unrepresentable canonical framing.
    pub fn establish(
        active_claim: ActiveTaskClaim,
        activation_situation: &AgentSituationReceipt,
        later_situation: &AgentSituationReceipt,
        run: &IntentRun,
    ) -> Result<Self, ActiveClaimContinuityRefusal> {
        let activation_id = *activation_situation.situation_id().as_bytes();
        if active_claim.situation_id() != activation_id {
            return Err(ActiveClaimContinuityRefusal::ActivationSituationMismatch {
                expected: active_claim.situation_id(),
                observed: activation_id,
            });
        }
        if active_claim.assignee() != run.run_id() {
            return Err(ActiveClaimContinuityRefusal::ClaimRunMismatch);
        }
        if activation_situation.intent_run_id() != Some(run.run_id())
            || later_situation.intent_run_id() != Some(run.run_id())
        {
            return Err(ActiveClaimContinuityRefusal::SituationRunMismatch);
        }
        let authority = run
            .authority_read_receipt()
            .ok_or(ActiveClaimContinuityRefusal::RunAuthorityReceiptRequired)?;
        if activation_situation.authority_read_receipt() != authority
            || later_situation.authority_read_receipt() != authority
        {
            return Err(ActiveClaimContinuityRefusal::RunAuthorityMismatch);
        }
        if later_situation.observed_at() <= activation_situation.observed_at() {
            return Err(ActiveClaimContinuityRefusal::ObservationDidNotAdvance {
                from: activation_situation.observed_at(),
                to: later_situation.observed_at(),
            });
        }
        if !active_claim.is_live_at(later_situation.observed_at()) {
            return Err(ActiveClaimContinuityRefusal::ClaimExpired {
                expires_at: active_claim.expires_at(),
                observed_at: later_situation.observed_at(),
            });
        }
        if !run.is_open_at(later_situation.observed_at()) {
            return Err(ActiveClaimContinuityRefusal::RunExpired {
                expires_at: run.expiry(),
                observed_at: later_situation.observed_at(),
            });
        }

        let delta = SituationDelta::between(activation_situation, later_situation)
            .map_err(ActiveClaimContinuityRefusal::Situation)?;
        validate_delta(&delta)?;

        let task_projection_generation = activation_situation
            .component(SituationComponentKind::TaskProjection)
            .generation_commitment()
            .ok_or(ActiveClaimContinuityRefusal::TaskProjectionUnavailable)?;
        let later_generation = later_situation
            .component(SituationComponentKind::TaskProjection)
            .generation_commitment()
            .ok_or(ActiveClaimContinuityRefusal::TaskProjectionUnavailable)?;
        if later_generation != task_projection_generation {
            return Err(ActiveClaimContinuityRefusal::ComponentChanged {
                kind: SituationComponentKind::TaskProjection,
            });
        }

        let mut receipt = Self {
            receipt_id: ActiveClaimContinuityReceiptId([0; 32]),
            active_claim_id: active_claim.activation_id(),
            from_situation_id: activation_situation.situation_id(),
            to_situation_id: later_situation.situation_id(),
            run_id: run.run_id(),
            task_id: active_claim.task_id(),
            task_projection_generation,
            from_observed_at: activation_situation.observed_at(),
            to_observed_at: later_situation.observed_at(),
        };
        receipt.receipt_id =
            ActiveClaimContinuityReceiptId(claim_continuity_commitment(&receipt)?);
        Ok(receipt)
    }

    /// Revalidates this receipt against the live objects an executor presents.
    ///
    /// # Errors
    ///
    /// Refuses receipt substitution or a run/claim that is no longer live at
    /// the receipt's later observation.
    pub fn validate_for(
        &self,
        active_claim: ActiveTaskClaim,
        later_situation: &AgentSituationReceipt,
        run: &IntentRun,
    ) -> Result<(), ActiveClaimContinuityRefusal> {
        if active_claim.activation_id() != self.active_claim_id {
            return Err(ActiveClaimContinuityRefusal::ClaimIdentityMismatch);
        }
        if active_claim.assignee() != self.run_id || run.run_id() != self.run_id {
            return Err(ActiveClaimContinuityRefusal::ClaimRunMismatch);
        }
        if active_claim.task_id() != self.task_id {
            return Err(ActiveClaimContinuityRefusal::ClaimTaskMismatch);
        }
        if later_situation.situation_id() != self.to_situation_id {
            return Err(ActiveClaimContinuityRefusal::LaterSituationMismatch);
        }
        if later_situation.intent_run_id() != Some(self.run_id) {
            return Err(ActiveClaimContinuityRefusal::SituationRunMismatch);
        }
        let authority = run
            .authority_read_receipt()
            .ok_or(ActiveClaimContinuityRefusal::RunAuthorityReceiptRequired)?;
        if later_situation.authority_read_receipt() != authority {
            return Err(ActiveClaimContinuityRefusal::RunAuthorityMismatch);
        }
        if later_situation.observed_at() != self.to_observed_at {
            return Err(ActiveClaimContinuityRefusal::LaterSituationMismatch);
        }
        if !active_claim.is_live_at(self.to_observed_at) {
            return Err(ActiveClaimContinuityRefusal::ClaimExpired {
                expires_at: active_claim.expires_at(),
                observed_at: self.to_observed_at,
            });
        }
        if !run.is_open_at(self.to_observed_at) {
            return Err(ActiveClaimContinuityRefusal::RunExpired {
                expires_at: run.expiry(),
                observed_at: self.to_observed_at,
            });
        }
        let generation = later_situation
            .component(SituationComponentKind::TaskProjection)
            .generation_commitment()
            .ok_or(ActiveClaimContinuityRefusal::TaskProjectionUnavailable)?;
        if generation != self.task_projection_generation {
            return Err(ActiveClaimContinuityRefusal::ComponentChanged {
                kind: SituationComponentKind::TaskProjection,
            });
        }
        Ok(())
    }

    /// Stable continuity-receipt identity.
    #[must_use]
    pub const fn receipt_id(self) -> ActiveClaimContinuityReceiptId {
        self.receipt_id
    }

    /// Activated claim being extended.
    #[must_use]
    pub const fn active_claim_id(self) -> ActiveTaskClaimId {
        self.active_claim_id
    }

    /// Claim-activation situation.
    #[must_use]
    pub const fn from_situation_id(self) -> SituationId {
        self.from_situation_id
    }

    /// Later equivalent situation.
    #[must_use]
    pub const fn to_situation_id(self) -> SituationId {
        self.to_situation_id
    }

    /// Intent Run whose context remained unchanged.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Task whose claim remained applicable.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }

    /// Unchanged task-projection generation.
    #[must_use]
    pub const fn task_projection_generation(self) -> [u8; 32] {
        self.task_projection_generation
    }

    /// Activation observation time.
    #[must_use]
    pub const fn from_observed_at(self) -> LogicalTime {
        self.from_observed_at
    }

    /// Later observation time.
    #[must_use]
    pub const fn to_observed_at(self) -> LogicalTime {
        self.to_observed_at
    }
}

/// A later-time binding for one immutable Level-1 action packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentActionPacketContinuation {
    continuation_id: AgentActionPacketContinuationId,
    action_packet_id: AgentActionPacketId,
    claim_continuity_id: ActiveClaimContinuityReceiptId,
    from_situation_id: SituationId,
    to_situation_id: SituationId,
    plan_id: AgentChangePlanId,
    active_claim_id: ActiveTaskClaimId,
    task_id: WorkTaskId,
    run_id: RunId,
    task_projection_generation: [u8; 32],
    observed_at: LogicalTime,
    packet_continuation_contract_root: Digest,
    precondition_recheck_root: Digest,
}

impl AgentActionPacketContinuation {
    /// Binds one existing action packet to a later equivalent situation.
    ///
    /// # Errors
    ///
    /// Refuses an invalid continuity receipt, packet/claim/plan/run/task or
    /// generation substitution, and unrepresentable canonical framing.
    pub fn build(
        packet: &AgentActionPacket,
        continuity: ActiveClaimContinuityReceipt,
        later_situation: &AgentSituationReceipt,
        active_claim: ActiveTaskClaim,
        run: &IntentRun,
        precondition_recheck_root: Digest,
    ) -> Result<Self, ActionPacketContinuationRefusal> {
        continuity
            .validate_for(active_claim, later_situation, run)
            .map_err(ActionPacketContinuationRefusal::Continuity)?;
        if packet.situation_id() != continuity.from_situation_id {
            return Err(ActionPacketContinuationRefusal::PacketSituationMismatch);
        }
        if packet.active_claim_id() != continuity.active_claim_id {
            return Err(ActionPacketContinuationRefusal::PacketClaimMismatch);
        }
        if packet.task_id() != continuity.task_id {
            return Err(ActionPacketContinuationRefusal::PacketTaskMismatch);
        }
        if packet.run_id() != continuity.run_id {
            return Err(ActionPacketContinuationRefusal::PacketRunMismatch);
        }
        if *packet.task_projection_generation() != continuity.task_projection_generation {
            return Err(ActionPacketContinuationRefusal::PacketGenerationMismatch);
        }

        let mut receipt = Self {
            continuation_id: AgentActionPacketContinuationId([0; 32]),
            action_packet_id: packet.packet_id(),
            claim_continuity_id: continuity.receipt_id,
            from_situation_id: continuity.from_situation_id,
            to_situation_id: continuity.to_situation_id,
            plan_id: packet.plan_id(),
            active_claim_id: continuity.active_claim_id,
            task_id: continuity.task_id,
            run_id: continuity.run_id,
            task_projection_generation: continuity.task_projection_generation,
            observed_at: continuity.to_observed_at,
            packet_continuation_contract_root: packet.continuation_contract_root(),
            precondition_recheck_root,
        };
        receipt.continuation_id =
            AgentActionPacketContinuationId(packet_continuation_commitment(&receipt)?);
        Ok(receipt)
    }

    /// Stable packet-continuation identity.
    #[must_use]
    pub const fn continuation_id(self) -> AgentActionPacketContinuationId {
        self.continuation_id
    }

    /// Original Level-1 action packet.
    #[must_use]
    pub const fn action_packet_id(self) -> AgentActionPacketId {
        self.action_packet_id
    }

    /// Claim-continuity proof.
    #[must_use]
    pub const fn claim_continuity_id(self) -> ActiveClaimContinuityReceiptId {
        self.claim_continuity_id
    }

    /// Original packet situation.
    #[must_use]
    pub const fn from_situation_id(self) -> SituationId {
        self.from_situation_id
    }

    /// Later equivalent situation.
    #[must_use]
    pub const fn to_situation_id(self) -> SituationId {
        self.to_situation_id
    }

    /// Packet plan.
    #[must_use]
    pub const fn plan_id(self) -> AgentChangePlanId {
        self.plan_id
    }

    /// Activated claim.
    #[must_use]
    pub const fn active_claim_id(self) -> ActiveTaskClaimId {
        self.active_claim_id
    }

    /// Packet task.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }

    /// Packet run.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Unchanged task-projection generation.
    #[must_use]
    pub const fn task_projection_generation(self) -> [u8; 32] {
        self.task_projection_generation
    }

    /// Later observation time.
    #[must_use]
    pub const fn observed_at(self) -> LogicalTime {
        self.observed_at
    }

    /// Original packet continuation contract.
    #[must_use]
    pub const fn packet_continuation_contract_root(self) -> Digest {
        self.packet_continuation_contract_root
    }

    /// Evidence that mandatory packet preconditions were re-checked.
    #[must_use]
    pub const fn precondition_recheck_root(self) -> Digest {
        self.precondition_recheck_root
    }
}

/// Why active-claim continuity could not be established or revalidated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActiveClaimContinuityRefusal {
    /// Claim names another activation situation.
    ActivationSituationMismatch {
        /// Situation retained by the claim.
        expected: [u8; 32],
        /// Supplied activation situation.
        observed: [u8; 32],
    },
    /// Claim identity differs from the receipt.
    ClaimIdentityMismatch,
    /// Claim task differs from the receipt.
    ClaimTaskMismatch,
    /// Claim or situations name another run.
    ClaimRunMismatch,
    /// Situation run differs from the supplied run.
    SituationRunMismatch,
    /// Supplied run lacks a complete authenticated authority receipt.
    RunAuthorityReceiptRequired,
    /// Run and situations carry different authority receipts.
    RunAuthorityMismatch,
    /// Later situation does not match the receipt.
    LaterSituationMismatch,
    /// Observation time did not strictly advance.
    ObservationDidNotAdvance {
        /// Activation time.
        from: LogicalTime,
        /// Proposed later time.
        to: LogicalTime,
    },
    /// Activated claim expired before the later observation.
    ClaimExpired {
        /// Exclusive claim expiry.
        expires_at: LogicalTime,
        /// Later observation.
        observed_at: LogicalTime,
    },
    /// Intent Run expired before the later observation.
    RunExpired {
        /// Exclusive run expiry.
        expires_at: LogicalTime,
        /// Later observation.
        observed_at: LogicalTime,
    },
    /// Task projection was omitted.
    TaskProjectionUnavailable,
    /// Authenticated authority context changed.
    AuthorityChanged,
    /// Bound Intent Run changed.
    IntentRunChanged,
    /// Bound workspace changed.
    WorkspaceChanged,
    /// One situation component changed.
    ComponentChanged {
        /// First changed component in canonical order.
        kind: SituationComponentKind,
    },
    /// Situation-delta construction refused the endpoints.
    Situation(SituationRefusal),
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for ActiveClaimContinuityRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "active-claim continuity refused: {self:?}")
    }
}

impl core::error::Error for ActiveClaimContinuityRefusal {}

impl From<CodecRefusal> for ActiveClaimContinuityRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

/// Why an action packet could not be continued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionPacketContinuationRefusal {
    /// Active-claim continuity proof failed.
    Continuity(ActiveClaimContinuityRefusal),
    /// Packet belongs to another source situation.
    PacketSituationMismatch,
    /// Packet belongs to another activated claim.
    PacketClaimMismatch,
    /// Packet belongs to another task.
    PacketTaskMismatch,
    /// Packet belongs to another run.
    PacketRunMismatch,
    /// Packet and continuity receipt name different task generations.
    PacketGenerationMismatch,
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for ActionPacketContinuationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "action-packet continuation refused: {self:?}")
    }
}

impl core::error::Error for ActionPacketContinuationRefusal {}

impl From<CodecRefusal> for ActionPacketContinuationRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_delta(delta: &SituationDelta) -> Result<(), ActiveClaimContinuityRefusal> {
    if !matches!(
        delta.authority_change(),
        SituationAuthorityChange::Unchanged
    ) || delta.authority_receipt_changed()
    {
        return Err(ActiveClaimContinuityRefusal::AuthorityChanged);
    }
    if delta.intent_run_changed() {
        return Err(ActiveClaimContinuityRefusal::IntentRunChanged);
    }
    if delta.workspace_changed() {
        return Err(ActiveClaimContinuityRefusal::WorkspaceChanged);
    }
    if let Some(change) = delta.component_changes().first() {
        return Err(ActiveClaimContinuityRefusal::ComponentChanged {
            kind: change.kind(),
        });
    }
    if !delta.observation_time_advanced() {
        return Err(ActiveClaimContinuityRefusal::ObservationDidNotAdvance {
            from: LogicalTime::new(0),
            to: LogicalTime::new(0),
        });
    }
    Ok(())
}

fn claim_continuity_commitment(
    receipt: &ActiveClaimContinuityReceipt,
) -> Result<[u8; 32], ActiveClaimContinuityRefusal> {
    let mut encoder = Encoder::with_capacity(384);
    encoder.write_bytes("active_claim_continuity_domain", CLAIM_CONTINUITY_DOMAIN)?;
    encoder.write_raw(receipt.active_claim_id.as_bytes());
    encoder.write_raw(receipt.from_situation_id.as_bytes());
    encoder.write_raw(receipt.to_situation_id.as_bytes());
    encoder.write_raw(&receipt.run_id.value().to_be_bytes());
    encoder.write_raw(receipt.task_id.as_bytes());
    encoder.write_raw(&receipt.task_projection_generation);
    encoder.write_scalar(receipt.from_observed_at.value());
    encoder.write_scalar(receipt.to_observed_at.value());
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn packet_continuation_commitment(
    receipt: &AgentActionPacketContinuation,
) -> Result<[u8; 32], ActionPacketContinuationRefusal> {
    let mut encoder = Encoder::with_capacity(512);
    encoder.write_bytes(
        "agent_action_packet_continuation_domain",
        PACKET_CONTINUATION_DOMAIN,
    )?;
    encoder.write_raw(receipt.action_packet_id.as_bytes());
    encoder.write_raw(receipt.claim_continuity_id.as_bytes());
    encoder.write_raw(receipt.from_situation_id.as_bytes());
    encoder.write_raw(receipt.to_situation_id.as_bytes());
    encoder.write_raw(receipt.plan_id.as_bytes());
    encoder.write_raw(receipt.active_claim_id.as_bytes());
    encoder.write_raw(receipt.task_id.as_bytes());
    encoder.write_raw(&receipt.run_id.value().to_be_bytes());
    encoder.write_raw(&receipt.task_projection_generation);
    encoder.write_scalar(receipt.observed_at.value());
    encoder.write_digest(&receipt.packet_continuation_contract_root)?;
    encoder.write_digest(&receipt.precondition_recheck_root)?;
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}
