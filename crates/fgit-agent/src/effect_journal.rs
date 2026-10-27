//! Bounded, versioned persistence and recovery of the existing effect journal.
//!
//! A journal records responsibility; it never authenticates a run, grants a
//! capability, or publishes repository state. Recovery requires the original
//! independently authenticated `IntentRun`. A caller-supplied acknowledged tail
//! is required before the recovered inventory can become a reconciliation
//! report: a hash chain alone cannot detect replacement by a valid old prefix.

use core::{fmt, num::NonZeroU32};
use std::collections::BTreeMap;

use fgit_codec::{DecodeLimits, Decoder, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_resource::{
    DownstreamIdempotency, EscalationReason, IdempotencyKey, LifecycleEvent, ObligationClass,
    ObligationState, ReconcilePlan, ReconcilePolicy, ResourceVector, TerminalFailureReason,
    algebra::Grade,
    settlement::{DeliveryVerdict, Observation, ProbeVerdict, ReconcileState, ReconcileTransition},
};
use fgit_types::PrincipalId;

use crate::{
    AgentInstanceId, CapabilityId, EffectBroker, EffectClass, EffectId, EffectJournalEntry,
    EffectJournalEvent, EffectJournalReplay, EffectRecord, EffectTerminalOutcome, IntentRun,
    IntentRunCommitment, LogicalTime, OperationClass, ReconciliationEvidence,
    RunReconciliationReport,
};

/// Local responsibility-log profile. This is not a canonical repository body.
pub const EFFECT_JOURNAL_PROFILE: &str = "frankengit-agent-effect-journal-v1";
/// Whole-journal read and append bound.
pub const MAX_EFFECT_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
/// Maximum individual append, including reconciliation evidence.
pub const MAX_EFFECT_JOURNAL_FRAME_BYTES: usize = 256 * 1024;
/// Maximum lifecycle events admitted by this bounded profile.
pub const MAX_EFFECT_JOURNAL_ENTRIES: u64 = 32_768;
const MAGIC: &[u8] = b"FGIT-EFFECT-JOURNAL\0\x01";
const FRAME_DOMAIN: &[u8] = b"frankengit.agent.effect-journal-frame/v1\0";
const HEADER_DOMAIN: &[u8] = b"frankengit.agent.effect-journal-header/v1\0";

/// An acknowledged exact journal prefix, retained outside the journal itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectJournalPosition {
    /// Number of complete events in this prefix.
    pub entries: u64,
    /// Exact byte length, including the versioned header.
    pub bytes: u64,
    /// Hash of the header or the final chained frame.
    pub digest: [u8; 32],
}

/// Definite or ambiguous append failure. All failures stop new issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectJournalPersistenceRefusal {
    /// The owner was cancelled or its finite context budget expired.
    Cancelled,
    /// The declared journal or frame bound was exhausted.
    Limit,
    /// The writer or runtime context is no longer available.
    Unavailable,
    /// The exact run, sequence, event, or file identity changed.
    Binding,
    /// An I/O or sync failed; the new bytes may already be durable.
    OutcomeUnknown,
}

/// Host-owned durable append boundary. A successful append MUST include the
/// host's declared durability barrier, not merely a userspace write. The host
/// retains single-writer custody until this value is dropped. After any error
/// the broker stops issuing new work; already-owned cleanup remains visible.
pub trait EffectJournalSink: fmt::Debug {
    /// Complete run for which this fresh writer was created.
    fn run_commitment(&self) -> IntentRunCommitment;
    /// Last successfully acknowledged prefix.
    fn position(&self) -> EffectJournalPosition;
    /// Persist exactly the next event, at most once.
    fn append(&mut self, entry: &EffectJournalEntry)
    -> Result<(), EffectJournalPersistenceRefusal>;
}

/// Codec/recovery failures never silently discard a suffix or invent a record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectJournalCodecRefusal {
    /// This profile accepts complete authenticated runs only.
    AuthenticatedRunRequired,
    /// Run/read canonical identity failed.
    RunIdentity,
    /// Unknown version, malformed framing, tag, or canonical encoding.
    Format,
    /// A byte, event, output, or reconciliation bound was exceeded.
    Limit,
    /// The journal was written for another complete run.
    RunMismatch,
    /// The sequence or predecessor digest changed.
    Chain,
    /// An interrupted or corrupt suffix follows this verified prefix.
    IncompleteTail(EffectJournalPosition),
    /// The supplied acknowledged prefix is absent or differs.
    AnchorMismatch,
    /// A complete inventory cannot be inferred without an external tail anchor.
    AnchorRequired,
    /// The recorded events are not a legal broker history.
    Replay,
    /// The resulting inventory violates run, time, budget, or lifecycle rules.
    Reconciliation,
}

impl fmt::Display for EffectJournalCodecRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "agent effect journal refused: {self:?}")
    }
}
impl core::error::Error for EffectJournalCodecRefusal {}

/// Stateful codec used by a host that owns the append file. Encoding does not
/// acknowledge persistence; the host advances its acknowledged position only
/// after writing and synchronizing the returned frame.
#[derive(Clone, Debug)]
pub struct EffectJournalEncoder {
    run: IntentRun,
    run_commitment: IntentRunCommitment,
    position: EffectJournalPosition,
    effects: usize,
}

impl EffectJournalEncoder {
    /// Creates the exact versioned header for one original authenticated run.
    pub fn new(run: &IntentRun) -> Result<(Self, Vec<u8>), EffectJournalCodecRefusal> {
        let authority = run
            .authority_read_receipt()
            .ok_or(EffectJournalCodecRefusal::AuthenticatedRunRequired)?;
        let commitment = run
            .commitment()
            .map_err(|_| EffectJournalCodecRefusal::RunIdentity)?;
        let read = authority
            .receipt_id()
            .map_err(|_| EffectJournalCodecRefusal::RunIdentity)?;
        let mut header = Vec::with_capacity(128);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&run.run_id().value().to_be_bytes());
        header.extend_from_slice(commitment.as_bytes());
        header.extend_from_slice(read.as_bytes());
        let digest = hash(&[HEADER_DOMAIN, &header]);
        header.extend_from_slice(&digest);
        let position = EffectJournalPosition {
            entries: 0,
            bytes: header.len() as u64,
            digest,
        };
        Ok((
            Self {
                run: run.clone(),
                run_commitment: commitment,
                position,
                effects: 0,
            },
            header,
        ))
    }

    /// Complete run bound by the immutable header.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Position after all frames encoded by this instance.
    #[must_use]
    pub const fn position(&self) -> EffectJournalPosition {
        self.position
    }

    /// Encodes one bounded event; refused calls leave this encoder unchanged.
    pub fn encode(
        &mut self,
        entry: &EffectJournalEntry,
    ) -> Result<Vec<u8>, EffectJournalCodecRefusal> {
        if entry.sequence != self.position.entries {
            return Err(EffectJournalCodecRefusal::Chain);
        }
        if self.position.entries >= MAX_EFFECT_JOURNAL_ENTRIES {
            return Err(EffectJournalCodecRefusal::Limit);
        }
        if matches!(entry.event, EffectJournalEvent::Accepted(_))
            && self.effects >= crate::reconcile::MAX_RECONCILIATION_EFFECTS
        {
            return Err(EffectJournalCodecRefusal::Limit);
        }
        let mut encoder = Encoder::with_capacity(512);
        encode_event(&mut encoder, &self.run, &entry.event)?;
        let payload = encoder.into_bytes();
        let length = 8 + 32 + payload.len() + 32;
        if length > MAX_EFFECT_JOURNAL_FRAME_BYTES {
            return Err(EffectJournalCodecRefusal::Limit);
        }
        let total = self
            .position
            .bytes
            .checked_add(length as u64 + 4)
            .ok_or(EffectJournalCodecRefusal::Limit)?;
        if total > MAX_EFFECT_JOURNAL_BYTES as u64 {
            return Err(EffectJournalCodecRefusal::Limit);
        }
        let mut frame = Vec::with_capacity(length + 4);
        frame.extend_from_slice(&(length as u32).to_be_bytes());
        frame.extend_from_slice(&entry.sequence.to_be_bytes());
        frame.extend_from_slice(&self.position.digest);
        frame.extend_from_slice(&payload);
        let digest = hash(&[FRAME_DOMAIN, &frame]);
        frame.extend_from_slice(&digest);
        self.position = EffectJournalPosition {
            entries: entry.sequence + 1,
            bytes: total,
            digest,
        };
        if matches!(entry.event, EffectJournalEvent::Accepted(_)) {
            self.effects += 1;
        }
        Ok(frame)
    }
}

/// A decoded original-run history. It contains evidence and cleanup debt, never
/// a live broker, a grant, a dispatch instruction, or an auto-retry operation.
#[derive(Clone, Debug)]
pub struct RecoveredEffectJournal {
    run_commitment: IntentRunCommitment,
    position: EffectJournalPosition,
    anchored: bool,
    entries: Vec<EffectJournalEntry>,
    replay: EffectJournalReplay,
}

impl RecoveredEffectJournal {
    /// Reads every byte and replays every event. `expected_tail` must be the
    /// exact acknowledged final position, not a position read from these same
    /// untrusted bytes. A missing anchor permits inspection only.
    pub fn decode(
        run: &IntentRun,
        bytes: &[u8],
        expected_tail: Option<EffectJournalPosition>,
    ) -> Result<Self, EffectJournalCodecRefusal> {
        if bytes.len() > MAX_EFFECT_JOURNAL_BYTES {
            return Err(EffectJournalCodecRefusal::Limit);
        }
        if bytes.get(..MAGIC.len()) != Some(MAGIC) {
            return Err(EffectJournalCodecRefusal::Format);
        }
        let (mut encoder, header) = EffectJournalEncoder::new(run)?;
        if bytes.get(..header.len()) != Some(header.as_slice()) {
            return Err(EffectJournalCodecRefusal::RunMismatch);
        }
        let mut remaining = &bytes[header.len()..];
        let mut entries = Vec::new();
        let mut downstream_keys = BTreeMap::new();
        while !remaining.is_empty() {
            let prefix = encoder.position();
            if entries.len() as u64 >= MAX_EFFECT_JOURNAL_ENTRIES {
                return Err(EffectJournalCodecRefusal::Limit);
            }
            let Some(length) = remaining.get(..4) else {
                return Err(EffectJournalCodecRefusal::IncompleteTail(prefix));
            };
            let length = u32::from_be_bytes(
                length
                    .try_into()
                    .map_err(|_| EffectJournalCodecRefusal::Format)?,
            ) as usize;
            if length > MAX_EFFECT_JOURNAL_FRAME_BYTES || length < 73 {
                return Err(EffectJournalCodecRefusal::Format);
            }
            let Some(frame) = remaining.get(..length + 4) else {
                return Err(EffectJournalCodecRefusal::IncompleteTail(prefix));
            };
            let sequence = u64::from_be_bytes(
                frame[4..12]
                    .try_into()
                    .map_err(|_| EffectJournalCodecRefusal::Format)?,
            );
            if sequence != prefix.entries || frame[12..44] != prefix.digest {
                return Err(EffectJournalCodecRefusal::Chain);
            }
            let end = frame.len() - 32;
            if frame[end..] != hash(&[FRAME_DOMAIN, &frame[..end]]) {
                return Err(EffectJournalCodecRefusal::IncompleteTail(prefix));
            }
            let mut decoder = Decoder::new(&frame[44..end], DecodeLimits::DEFAULT);
            let event = decode_event(&mut decoder, run, &downstream_keys)?;
            if let EffectJournalEvent::BoundObligation {
                effect_id,
                external_idempotency_key: Some(key),
                ..
            } = &event
            {
                downstream_keys.insert(*effect_id, *key);
            }
            decoder
                .finish()
                .map_err(|_| EffectJournalCodecRefusal::Format)?;
            let entry = EffectJournalEntry { sequence, event };
            // Decode/re-encode equality closes all alternative encodings and
            // keeps the host encoder and recovery reader on one byte contract.
            if encoder.encode(&entry)? != frame {
                return Err(EffectJournalCodecRefusal::Format);
            }
            entries.push(entry);
            remaining = &remaining[length + 4..];
        }
        let position = encoder.position();
        if expected_tail.is_some_and(|tail| tail != position) {
            return Err(EffectJournalCodecRefusal::AnchorMismatch);
        }
        let replay =
            EffectBroker::replay(&entries).map_err(|_| EffectJournalCodecRefusal::Replay)?;
        Ok(Self {
            run_commitment: encoder.run_commitment(),
            position,
            anchored: expected_tail.is_some(),
            entries,
            replay,
        })
    }

    /// Complete locally observed tail. It is not an external anti-rollback anchor.
    #[must_use]
    pub const fn position(&self) -> EffectJournalPosition {
        self.position
    }
    /// Every decoded event in original order.
    #[must_use]
    pub fn entries(&self) -> &[EffectJournalEntry] {
        &self.entries
    }
    /// Reconstructed responsibility, available for forensic inspection.
    #[must_use]
    pub fn records(&self) -> &[EffectRecord] {
        self.replay.records()
    }
    /// Whether the independently retained exact final position matched.
    #[must_use]
    pub const fn is_anchored(&self) -> bool {
        self.anchored
    }

    /// Produces the existing debt-preserving reconciliation type only after an
    /// exact external tail anchor proves inventory completeness.
    pub fn reconciliation_report(
        &self,
        run: &IntentRun,
        observed_at: LogicalTime,
    ) -> Result<RunReconciliationReport, EffectJournalCodecRefusal> {
        if !self.anchored {
            return Err(EffectJournalCodecRefusal::AnchorRequired);
        }
        if run
            .commitment()
            .map_err(|_| EffectJournalCodecRefusal::RunIdentity)?
            != self.run_commitment
        {
            return Err(EffectJournalCodecRefusal::RunMismatch);
        }
        RunReconciliationReport::build(run, self.records().to_vec(), observed_at)
            .map_err(|_| EffectJournalCodecRefusal::Reconciliation)
    }
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = <Sha256 as GitHashAlgorithm>::Hasher::new();
    for bytes in parts {
        h.update(bytes);
    }
    h.finish()
}

type Result<T, E = EffectJournalCodecRefusal> = core::result::Result<T, E>;
fn raw<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.take("journal_fixed", N)
        .map_err(|_| EffectJournalCodecRefusal::Format)?
        .try_into()
        .map_err(|_| EffectJournalCodecRefusal::Format)
}
fn byte(d: &mut Decoder<'_>) -> Result<u8> {
    d.read_raw_byte("journal_tag")
        .map_err(|_| EffectJournalCodecRefusal::Format)
}
fn num(d: &mut Decoder<'_>) -> Result<u64> {
    d.read_scalar("journal_number")
        .map_err(|_| EffectJournalCodecRefusal::Format)
}
fn count(d: &mut Decoder<'_>, maximum: usize, minimum_width: usize) -> Result<usize> {
    let n = d
        .read_scalar::<u32>("journal_count")
        .map_err(|_| EffectJournalCodecRefusal::Format)? as usize;
    if n > maximum || n > d.remaining() / minimum_width {
        return Err(EffectJournalCodecRefusal::Limit);
    }
    Ok(n)
}
fn resources(e: &mut Encoder, v: ResourceVector) {
    for grade in Grade::ALL {
        e.write_scalar(v.get(grade));
    }
}
fn read_resources(d: &mut Decoder<'_>) -> Result<ResourceVector> {
    let mut v = ResourceVector::ZERO;
    for grade in Grade::ALL {
        v = v.with(grade, num(d)?);
    }
    Ok(v)
}
fn option_id(e: &mut Encoder, id: Option<EffectId>) {
    e.write_raw_byte(u8::from(id.is_some()));
    if let Some(id) = id {
        e.write_raw(&id.value().to_be_bytes());
    }
}
fn read_option_id(d: &mut Decoder<'_>) -> Result<Option<EffectId>> {
    match byte(d)? {
        0 => Ok(None),
        1 => Ok(Some(EffectId::new(u128::from_be_bytes(raw(d)?)))),
        _ => Err(EffectJournalCodecRefusal::Format),
    }
}

fn encode_event(e: &mut Encoder, run: &IntentRun, event: &EffectJournalEvent) -> Result<()> {
    match event {
        EffectJournalEvent::Accepted(record) => {
            if record.run_id != run.run_id()
                || record.run_commitment
                    != run
                        .commitment()
                        .map_err(|_| EffectJournalCodecRefusal::RunIdentity)?
                || record.source_authority_receipt.as_ref() != run.authority_read_receipt()
            {
                return Err(EffectJournalCodecRefusal::RunMismatch);
            }
            if record.obligation_state != ObligationState::Reserved
                || record.obligation_class.is_some()
                || record.external_idempotency_key.is_some()
                || record.terminal_outcome.is_some()
                || !record.output_commitments.is_empty()
                || record.reconciliation_evidence.is_some()
                || !record.budget_consumed.is_zero()
            {
                return Err(EffectJournalCodecRefusal::Replay);
            }
            e.write_raw_byte(1);
            e.write_raw(&record.effect_id.value().to_be_bytes());
            e.write_raw(&record.agent_instance_id.value().to_be_bytes());
            option_id(e, record.parent_effect_id);
            e.write_raw(&record.capability_id.value().to_be_bytes());
            e.write_raw_byte(class_code(record.effect_class));
            e.write_raw_byte(record.operation as u8);
            e.write_raw(&record.input_commitment);
            resources(e, record.budget_reserved);
            e.write_scalar(record.accepted_at.value());
        }
        EffectJournalEvent::BoundObligation {
            effect_id,
            obligation_class,
            external_idempotency_key,
        } => {
            e.write_raw_byte(2);
            e.write_raw(&effect_id.value().to_be_bytes());
            e.write_raw_byte(obligation_code(*obligation_class));
            e.write_raw_byte(u8::from(external_idempotency_key.is_some()));
            if let Some(key) = external_idempotency_key {
                e.write_digest(&key.digest())
                    .map_err(|_| EffectJournalCodecRefusal::Format)?;
            }
        }
        EffectJournalEvent::Lifecycle {
            effect_id,
            event,
            budget_consumed,
            output_commitments,
            reconciliation_evidence,
            terminal_outcome,
        } => {
            if output_commitments.len() > crate::reconcile::MAX_EFFECT_OUTPUT_COMMITMENTS {
                return Err(EffectJournalCodecRefusal::Limit);
            }
            e.write_raw_byte(3);
            e.write_raw(&effect_id.value().to_be_bytes());
            e.write_raw_byte(event_code(*event));
            resources(e, *budget_consumed);
            e.write_scalar(output_commitments.len() as u32);
            for output in output_commitments {
                e.write_raw(output);
            }
            e.write_raw_byte(u8::from(reconciliation_evidence.is_some()));
            if let Some(evidence) = reconciliation_evidence {
                if evidence.transitions.len()
                    > crate::reconcile::MAX_EFFECT_RECONCILIATION_TRANSITIONS
                {
                    return Err(EffectJournalCodecRefusal::Limit);
                }
                e.write_raw_byte(match evidence.downstream_idempotency {
                    DownstreamIdempotency::Strong => 1,
                    DownstreamIdempotency::Weak => 2,
                });
                e.write_scalar(evidence.transitions.len() as u32);
                for transition in &evidence.transitions {
                    state(e, transition.from());
                    observation(e, transition.observation());
                    state(e, transition.to());
                }
            }
            terminal(e, *terminal_outcome);
        }
    }
    Ok(())
}

fn decode_event(
    d: &mut Decoder<'_>,
    run: &IntentRun,
    downstream_keys: &BTreeMap<EffectId, IdempotencyKey>,
) -> Result<EffectJournalEvent> {
    let tag = byte(d)?;
    let effect_id = EffectId::new(u128::from_be_bytes(raw(d)?));
    match tag {
        1 => {
            let agent_instance_id = AgentInstanceId::new(u128::from_be_bytes(raw(d)?));
            let parent_effect_id = read_option_id(d)?;
            let capability_id = CapabilityId::new(u128::from_be_bytes(raw(d)?));
            let effect_class = read_class(byte(d)?)?;
            let operation = *OperationClass::ALL
                .get(usize::from(byte(d)?))
                .ok_or(EffectJournalCodecRefusal::Format)?;
            Ok(EffectJournalEvent::Accepted(Box::new(EffectRecord {
                effect_id,
                run_id: run.run_id(),
                run_commitment: run
                    .commitment()
                    .map_err(|_| EffectJournalCodecRefusal::RunIdentity)?,
                agent_instance_id,
                parent_effect_id,
                capability_id,
                effect_class,
                operation,
                input_commitment: raw(d)?,
                source_authority_receipt: run.authority_read_receipt().cloned(),
                budget_reserved: read_resources(d)?,
                budget_consumed: ResourceVector::ZERO,
                external_idempotency_key: None,
                obligation_state: ObligationState::Reserved,
                obligation_class: None,
                terminal_outcome: None,
                output_commitments: Vec::new(),
                reconciliation_evidence: None,
                accepted_at: LogicalTime::new(num(d)?),
            })))
        }
        2 => {
            let obligation_class = read_obligation(byte(d)?)?;
            let external_idempotency_key = match byte(d)? {
                0 => None,
                1 => Some(IdempotencyKey::new(
                    d.read_digest()
                        .map_err(|_| EffectJournalCodecRefusal::Format)?,
                )),
                _ => return Err(EffectJournalCodecRefusal::Format),
            };
            Ok(EffectJournalEvent::BoundObligation {
                effect_id,
                obligation_class,
                external_idempotency_key,
            })
        }
        3 => {
            let event = read_event(byte(d)?)?;
            let budget_consumed = read_resources(d)?;
            let n = count(d, crate::reconcile::MAX_EFFECT_OUTPUT_COMMITMENTS, 32)?;
            let mut output_commitments = Vec::with_capacity(n);
            for _ in 0..n {
                output_commitments.push(raw(d)?);
            }
            let reconciliation_evidence = match byte(d)? {
                0 => None,
                1 => {
                    let downstream_idempotency = match byte(d)? {
                        1 => DownstreamIdempotency::Strong,
                        2 => DownstreamIdempotency::Weak,
                        _ => return Err(EffectJournalCodecRefusal::Format),
                    };
                    let n = count(
                        d,
                        crate::reconcile::MAX_EFFECT_RECONCILIATION_TRANSITIONS,
                        6,
                    )?;
                    let mut transitions = Vec::with_capacity(n);
                    for _ in 0..n {
                        let from = read_state(d)?;
                        let observed = read_observation(d)?;
                        let to = read_state(d)?;
                        transitions.push(rebuild_transition(
                            *downstream_keys
                                .get(&effect_id)
                                .ok_or(EffectJournalCodecRefusal::Replay)?,
                            downstream_idempotency,
                            from,
                            observed,
                            to,
                        )?);
                    }
                    Some(ReconciliationEvidence {
                        downstream_idempotency,
                        transitions,
                    })
                }
                _ => return Err(EffectJournalCodecRefusal::Format),
            };
            Ok(EffectJournalEvent::Lifecycle {
                effect_id,
                event,
                budget_consumed,
                output_commitments,
                reconciliation_evidence,
                terminal_outcome: read_terminal(d)?,
            })
        }
        _ => Err(EffectJournalCodecRefusal::Format),
    }
}

fn class_code(v: EffectClass) -> u8 {
    match v {
        EffectClass::PureCanonicalRead => 1,
        EffectClass::DerivedLocalWrite => 2,
        EffectClass::ImmutableCandidateCreation => 3,
        EffectClass::PreparedCanonicalMutation => 4,
        EffectClass::CanonicalMutation => 5,
        EffectClass::ExternalEffect => 6,
    }
}
fn read_class(v: u8) -> Result<EffectClass> {
    match v {
        1 => Ok(EffectClass::PureCanonicalRead),
        2 => Ok(EffectClass::DerivedLocalWrite),
        3 => Ok(EffectClass::ImmutableCandidateCreation),
        4 => Ok(EffectClass::PreparedCanonicalMutation),
        5 => Ok(EffectClass::CanonicalMutation),
        6 => Ok(EffectClass::ExternalEffect),
        _ => Err(EffectJournalCodecRefusal::Format),
    }
}
fn obligation_code(v: ObligationClass) -> u8 {
    match v {
        ObligationClass::ObjectAdmissionPermit => 1,
        ObligationClass::PreparedTxnSlot => 2,
        ObligationClass::HeadCasAttempt => 3,
        ObligationClass::OutboxEffectPermit => 4,
        ObligationClass::SecretLease => 5,
        ObligationClass::WorkspaceLease => 6,
        ObligationClass::RunnerSlot => 7,
        ObligationClass::RetentionPin => 8,
        ObligationClass::RepairPermit => 9,
        ObligationClass::ContextBudgetPermit => 10,
        ObligationClass::BillingReservation => 11,
    }
}
fn read_obligation(v: u8) -> Result<ObligationClass> {
    ObligationClass::ALL
        .get(usize::from(
            v.checked_sub(1).ok_or(EffectJournalCodecRefusal::Format)?,
        ))
        .copied()
        .ok_or(EffectJournalCodecRefusal::Format)
}
fn event_code(v: LifecycleEvent) -> u8 {
    match v {
        LifecycleEvent::Commit => 1,
        LifecycleEvent::Abort => 2,
        LifecycleEvent::Acknowledge => 3,
        LifecycleEvent::Defer => 4,
        LifecycleEvent::Escalate => 5,
        LifecycleEvent::FailTerminally => 6,
        LifecycleEvent::Leak => 7,
    }
}
fn read_event(v: u8) -> Result<LifecycleEvent> {
    match v {
        1 => Ok(LifecycleEvent::Commit),
        2 => Ok(LifecycleEvent::Abort),
        3 => Ok(LifecycleEvent::Acknowledge),
        4 => Ok(LifecycleEvent::Defer),
        5 => Ok(LifecycleEvent::Escalate),
        6 => Ok(LifecycleEvent::FailTerminally),
        7 => Ok(LifecycleEvent::Leak),
        _ => Err(EffectJournalCodecRefusal::Format),
    }
}
fn failure_code(v: TerminalFailureReason) -> u8 {
    match v {
        TerminalFailureReason::PermanentDownstreamRejection => 1,
        TerminalFailureReason::ValidityWindowExpired => 2,
        TerminalFailureReason::OperatorDecision => 3,
    }
}
fn read_failure(v: u8) -> Result<TerminalFailureReason> {
    match v {
        1 => Ok(TerminalFailureReason::PermanentDownstreamRejection),
        2 => Ok(TerminalFailureReason::ValidityWindowExpired),
        3 => Ok(TerminalFailureReason::OperatorDecision),
        _ => Err(EffectJournalCodecRefusal::Format),
    }
}
fn escalation_code(v: EscalationReason) -> u8 {
    match v {
        EscalationReason::IndeterminateDelivery => 1,
        EscalationReason::RetryBudgetExhausted => 2,
        EscalationReason::ProbeContractViolation => 3,
        EscalationReason::PolicyRequiresHuman => 4,
    }
}
fn read_escalation(v: u8) -> Result<EscalationReason> {
    match v {
        1 => Ok(EscalationReason::IndeterminateDelivery),
        2 => Ok(EscalationReason::RetryBudgetExhausted),
        3 => Ok(EscalationReason::ProbeContractViolation),
        4 => Ok(EscalationReason::PolicyRequiresHuman),
        _ => Err(EffectJournalCodecRefusal::Format),
    }
}
fn terminal(e: &mut Encoder, v: Option<EffectTerminalOutcome>) {
    match v {
        None => e.write_raw_byte(0),
        Some(EffectTerminalOutcome::Acknowledged) => e.write_raw_byte(1),
        Some(EffectTerminalOutcome::Aborted) => e.write_raw_byte(2),
        Some(EffectTerminalOutcome::TerminallyFailed { reason }) => {
            e.write_raw_byte(3);
            e.write_raw_byte(failure_code(reason));
        }
        Some(EffectTerminalOutcome::Escalated { owner, reason }) => {
            e.write_raw_byte(4);
            e.write_raw(owner.as_bytes());
            e.write_raw_byte(escalation_code(reason));
        }
    }
}
fn read_terminal(d: &mut Decoder<'_>) -> Result<Option<EffectTerminalOutcome>> {
    match byte(d)? {
        0 => Ok(None),
        1 => Ok(Some(EffectTerminalOutcome::Acknowledged)),
        2 => Ok(Some(EffectTerminalOutcome::Aborted)),
        3 => Ok(Some(EffectTerminalOutcome::TerminallyFailed {
            reason: read_failure(byte(d)?)?,
        })),
        4 => Ok(Some(EffectTerminalOutcome::Escalated {
            owner: PrincipalId::from_bytes(raw(d)?),
            reason: read_escalation(byte(d)?)?,
        })),
        _ => Err(EffectJournalCodecRefusal::Format),
    }
}
fn state(e: &mut Encoder, v: ReconcileState) {
    match v {
        ReconcileState::Pending { attempt } => {
            e.write_raw_byte(1);
            e.write_scalar(attempt);
        }
        ReconcileState::Probing { attempt } => {
            e.write_raw_byte(2);
            e.write_scalar(attempt);
        }
        ReconcileState::Delivered { attempt } => {
            e.write_raw_byte(3);
            e.write_scalar(attempt);
        }
        ReconcileState::Undeliverable { reason } => {
            e.write_raw_byte(4);
            e.write_raw_byte(failure_code(reason));
        }
        ReconcileState::Indeterminate { reason } => {
            e.write_raw_byte(5);
            e.write_raw_byte(escalation_code(reason));
        }
    }
}
fn read_state(d: &mut Decoder<'_>) -> Result<ReconcileState> {
    match byte(d)? {
        1 => Ok(ReconcileState::Pending {
            attempt: d
                .read_scalar("attempt")
                .map_err(|_| EffectJournalCodecRefusal::Format)?,
        }),
        2 => Ok(ReconcileState::Probing {
            attempt: d
                .read_scalar("attempt")
                .map_err(|_| EffectJournalCodecRefusal::Format)?,
        }),
        3 => Ok(ReconcileState::Delivered {
            attempt: d
                .read_scalar("attempt")
                .map_err(|_| EffectJournalCodecRefusal::Format)?,
        }),
        4 => Ok(ReconcileState::Undeliverable {
            reason: read_failure(byte(d)?)?,
        }),
        5 => Ok(ReconcileState::Indeterminate {
            reason: read_escalation(byte(d)?)?,
        }),
        _ => Err(EffectJournalCodecRefusal::Format),
    }
}
fn observation(e: &mut Encoder, v: Observation) {
    match v {
        Observation::Delivery(v) => {
            e.write_raw_byte(1);
            e.write_raw_byte(match v {
                DeliveryVerdict::Accepted => 1,
                DeliveryVerdict::DuplicateSuppressed => 2,
                DeliveryVerdict::TransientFailure => 3,
                DeliveryVerdict::PermanentRejection => 4,
                DeliveryVerdict::AmbiguousTimeout => 5,
            });
        }
        Observation::Probe(v) => {
            e.write_raw_byte(2);
            e.write_raw_byte(match v {
                ProbeVerdict::Delivered => 1,
                ProbeVerdict::NotDelivered => 2,
                ProbeVerdict::Unknown => 3,
            });
        }
    }
}
fn read_observation(d: &mut Decoder<'_>) -> Result<Observation> {
    match byte(d)? {
        1 => Ok(Observation::Delivery(match byte(d)? {
            1 => DeliveryVerdict::Accepted,
            2 => DeliveryVerdict::DuplicateSuppressed,
            3 => DeliveryVerdict::TransientFailure,
            4 => DeliveryVerdict::PermanentRejection,
            5 => DeliveryVerdict::AmbiguousTimeout,
            _ => return Err(EffectJournalCodecRefusal::Format),
        })),
        2 => Ok(Observation::Probe(match byte(d)? {
            1 => ProbeVerdict::Delivered,
            2 => ProbeVerdict::NotDelivered,
            3 => ProbeVerdict::Unknown,
            _ => return Err(EffectJournalCodecRefusal::Format),
        })),
        _ => Err(EffectJournalCodecRefusal::Format),
    }
}

// ReconcileTransition has no unchecked public constructor. Rebuild each stored
// observation through the real state machine. The old record did not retain its
// retry ceiling, so infer only the bound needed to reproduce this exact step;
// this never constructs a runnable recovery plan or authorizes another attempt.
fn rebuild_transition(
    key: IdempotencyKey,
    idempotency: DownstreamIdempotency,
    from: ReconcileState,
    observation: Observation,
    to: ReconcileState,
) -> Result<ReconcileTransition> {
    let attempt = match from {
        ReconcileState::Pending { attempt } | ReconcileState::Probing { attempt } => attempt,
        _ => return Err(EffectJournalCodecRefusal::Replay),
    };
    let maximum = if matches!(
        to,
        ReconcileState::Indeterminate {
            reason: EscalationReason::RetryBudgetExhausted
        }
    ) {
        attempt
    } else {
        u32::MAX
    };
    let maximum = NonZeroU32::new(maximum).ok_or(EffectJournalCodecRefusal::Replay)?;
    let mut plan = ReconcilePlan::from_state(key, idempotency, ReconcilePolicy::new(maximum), from)
        .map_err(|_| EffectJournalCodecRefusal::Replay)?;
    if plan
        .observe(observation)
        .map_err(|_| EffectJournalCodecRefusal::Replay)?
        != to
    {
        return Err(EffectJournalCodecRefusal::Replay);
    }
    plan.transitions()
        .first()
        .copied()
        .ok_or(EffectJournalCodecRefusal::Replay)
}
