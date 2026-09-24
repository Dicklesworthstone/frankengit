//! Immutable, publisher-owned observations of trusted-local workflow jobs.
//!
//! These records are canonical statements that a principal reported a result,
//! NOT independent execution attestations. There is deliberately no successful
//! or neutral protected-check conclusion in this profile. Exact evidence bytes
//! live inside the event, so publication cannot strand a separately stored body.

use core::fmt;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RefusalCode};

use crate::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventPayload};

pub const MAX_CHECK_JOB_BYTES: usize = 1024;
pub const MAX_CHECK_EVIDENCE_BYTES: usize = 1024 * 1024;
const ID_DOMAIN: &[u8] = b"frankengit/trusted-workflow-check/v1\0";
const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

/// Full 256-bit execution identity, never a truncated run or job counter.
/// The lowercase base32 stream label fits the existing 64-byte label contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct WorkflowCheckId([u8; 32]);

impl WorkflowCheckId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Decode exactly the spelling emitted by Display. Nonzero padding bits,
    /// uppercase, aliases, short IDs and trailing bytes never select a stream.
    pub fn from_label(label: &str) -> Option<Self> {
        let encoded = label.strip_prefix("check/")?.as_bytes();
        if encoded.len() != 52 {
            return None;
        }
        let mut result = [0_u8; 32];
        for (index, &byte) in encoded.iter().enumerate() {
            let value = ALPHABET.iter().position(|candidate| *candidate == byte)?;
            for shift in 0..5 {
                let bit_index = index * 5 + shift;
                let bit = (value >> (4 - shift)) & 1;
                if bit_index >= 256 {
                    if bit != 0 {
                        return None;
                    }
                } else {
                    result[bit_index / 8] |= u8::try_from(bit).ok()? << (7 - bit_index % 8);
                }
            }
        }
        Some(Self(result))
    }
}
impl fmt::Display for WorkflowCheckId {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("check/")?;
        for index in 0..52 {
            let mut value = 0usize;
            for shift in 0..5 {
                let bit_index = index * 5 + shift;
                value <<= 1;
                if bit_index < 256 {
                    value |= usize::from((self.0[bit_index / 8] >> (7 - bit_index % 8)) & 1);
                }
            }
            write!(out, "{}", char::from(ALPHABET[value]))?;
        }
        Ok(())
    }
}

/// Successful local commands still need independent verification. None of
/// these observations can satisfy a required successful check by themselves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowCheckConclusion {
    ActionRequired,
    Failure,
    Cancelled,
    TimedOut,
}

/// Stable submitted execution coordinates and the original normalized evidence.
/// The current repository head and publication time do not enter this request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowCheckRecord {
    pub source_ref: RefName,
    pub source_commit: GitOid,
    pub run_id: [u8; 32],
    pub attempt_id: [u8; 32],
    pub graph_root: [u8; 32],
    pub job: String,
    pub conclusion: WorkflowCheckConclusion,
    pub evidence: Vec<u8>,
}

impl WorkflowCheckRecord {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        // This first publication profile binds a current canonical branch.
        // Unpublished candidates and annotated-tag peeling need their own
        // admitted input boundary; neither is guessed from an object ID.
        if !self.source_ref.as_bytes().starts_with(b"refs/heads/")
            || self.source_commit.is_zero()
            || self.job.is_empty()
            || self.job.len() > MAX_CHECK_JOB_BYTES
            || self.job.chars().any(char::is_control)
            || self.evidence.is_empty()
            || self.evidence.len() > MAX_CHECK_EVIDENCE_BYTES
        {
            return Err(super::invalid_native("workflow_check.record"));
        }
        Ok(())
    }

    /// The reporting principal is supplied by authentication, not by job text.
    /// One publisher/run/attempt/job has one immutable terminal observation.
    pub fn proposed_event(
        &self,
        actor: PrincipalId,
        format: GitHashAlgorithm,
    ) -> Result<ForgeEvent, RefusalCode> {
        self.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        if self.source_commit.algorithm() != format {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let change = NativeWorkflowCheck {
            actor,
            record: self.clone(),
        };
        Ok(ForgeEvent {
            aggregate: AggregateId::WorkflowCheck(change.id()),
            version: AggregateVersion::FIRST,
            payload: ForgeEventPayload::WorkflowCheckObservedNative(change),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeWorkflowCheck {
    /// The principal reporting the observation, not an inferred runner identity.
    pub actor: PrincipalId,
    pub record: WorkflowCheckRecord,
}
impl NativeWorkflowCheck {
    #[must_use]
    pub fn id(&self) -> WorkflowCheckId {
        // The complete job-name digest keeps this derivation's scratch space
        // fixed-size even for an unvalidated public value. No nonce truncation.
        let mut out = [0_u8; ID_DOMAIN.len() + 16 + 32 + 32 + 32];
        let mut cursor = 0;
        let job = fgit_crypto::sha256_digest(self.record.job.as_bytes());
        for part in [
            ID_DOMAIN,
            self.actor.as_bytes().as_slice(),
            self.record.run_id.as_slice(),
            self.record.attempt_id.as_slice(),
            job.as_slice(),
        ] {
            out[cursor..cursor + part.len()].copy_from_slice(part);
            cursor += part.len();
        }
        WorkflowCheckId(fgit_crypto::sha256_digest(&out))
    }

    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.record.validate()?;
        out.write_opaque_id(self.actor.as_bytes());
        out.write_bytes(
            "workflow_check.source_ref",
            self.record.source_ref.as_bytes(),
        )?;
        out.write_git_oid(&self.record.source_commit);
        out.write_bytes("workflow_check.run", &self.record.run_id)?;
        out.write_bytes("workflow_check.attempt", &self.record.attempt_id)?;
        out.write_bytes("workflow_check.graph", &self.record.graph_root)?;
        out.write_bytes("workflow_check.job", self.record.job.as_bytes())?;
        out.write_scalar(match self.record.conclusion {
            WorkflowCheckConclusion::ActionRequired => 1_u32,
            WorkflowCheckConclusion::Failure => 2,
            WorkflowCheckConclusion::Cancelled => 3,
            WorkflowCheckConclusion::TimedOut => 4,
        });
        out.write_bytes("workflow_check.evidence", &self.record.evidence)?;
        Ok(())
    }

    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let actor = PrincipalId::from_bytes(input.read_opaque_id("workflow_check.actor")?);
        let source_ref = RefName::try_new(input.read_bytes("workflow_check.source_ref")?)?;
        let source_commit = input.read_git_oid()?;
        let run_id = array(input, "workflow_check.run")?;
        let attempt_id = array(input, "workflow_check.attempt")?;
        let graph_root = array(input, "workflow_check.graph")?;
        let job = input.read_bytes("workflow_check.job")?;
        if job.is_empty() || job.len() > MAX_CHECK_JOB_BYTES {
            return Err(super::invalid_native("workflow_check.job"));
        }
        let job =
            std::str::from_utf8(job).map_err(|_| super::invalid_native("workflow_check.job"))?;
        if job.chars().any(char::is_control) {
            return Err(super::invalid_native("workflow_check.job"));
        }
        let job = job.to_owned();
        let conclusion = match input.read_scalar::<u32>("workflow_check.conclusion")? {
            1 => WorkflowCheckConclusion::ActionRequired,
            2 => WorkflowCheckConclusion::Failure,
            3 => WorkflowCheckConclusion::Cancelled,
            4 => WorkflowCheckConclusion::TimedOut,
            _ => return Err(super::invalid_native("workflow_check.conclusion")),
        };
        let evidence = input.read_bytes("workflow_check.evidence")?;
        if evidence.is_empty() || evidence.len() > MAX_CHECK_EVIDENCE_BYTES {
            return Err(super::invalid_native("workflow_check.evidence"));
        }
        let value = Self {
            actor,
            record: WorkflowCheckRecord {
                source_ref,
                source_commit,
                run_id,
                attempt_id,
                graph_root,
                job,
                conclusion,
                evidence: evidence.to_vec(),
            },
        };
        value.record.validate()?;
        Ok(value)
    }
}
fn array(input: &mut Decoder<'_>, field: &'static str) -> Result<[u8; 32], CodecRefusal> {
    input
        .read_bytes(field)?
        .try_into()
        .map_err(|_| super::invalid_native(field))
}

pub(super) fn validate_event(event: &ForgeEvent) -> Result<(), CodecRefusal> {
    if matches!(event.aggregate, AggregateId::WorkflowCheck(_))
        != matches!(
            event.payload,
            ForgeEventPayload::WorkflowCheckObservedNative(_)
        )
    {
        return Err(super::invalid_native("workflow_check.aggregate_kind"));
    }
    if let ForgeEventPayload::WorkflowCheckObservedNative(change) = &event.payload {
        change.record.validate()?;
        if event.version != AggregateVersion::FIRST
            || event.aggregate != AggregateId::WorkflowCheck(change.id())
        {
            return Err(super::invalid_native("workflow_check.aggregate_version"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
