//! Version two recovery carrier for independently sealed large receives.
//!
//! Canonical chunks and the original wire permutation are committed through
//! the existing SemanticRequest/ScopedEntry vocabulary and TxId derivation.
//! The binding request is never sealed or published. Each real child keeps the
//! original receive schema, per-index key and one-command request.

use super::{codec, invalid};
use fgit_authority::{
    ExpectedOld, ProposedNew, PushOption, ScopedEntry, SealAttempt, SemanticRequest,
    canonical_request_digest,
};
use fgit_codec::{DecodeLimits, Decoder, Encoder, decode_body, encode_body};
use fgit_types::{AsciiSlug, RefName, RefusalCode, SchemaFamily, SchemaId};

use crate::{
    AdmissionContext, AdmissionError, MAX_ADMISSION_COMMANDS, MAX_RECEIVE_SESSION_COMMANDS,
    MAX_SESSION_OPTION_COPY_BYTES, SessionPlan, seal_attempt,
};

pub(super) const VERSION: u32 = 2;
pub(super) const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_CHUNKS: usize = MAX_RECEIVE_SESSION_COMMANDS.div_ceil(MAX_ADMISSION_COMMANDS);
const BINDING_SCHEMA: SchemaId =
    SchemaId::new(SchemaFamily::from_static("receive-session-binding"), 2, 0);
pub(super) const LIMITS: DecodeLimits = DecodeLimits {
    frame_bytes: MAX_BYTES as u64,
    byte_string_bytes: MAX_BYTES as u64,
    elements: MAX_RECEIVE_SESSION_COMMANDS as u64,
    depth: 16,
};
const CHUNK_LIMITS: DecodeLimits = DecodeLimits {
    elements: MAX_ADMISSION_COMMANDS as u64,
    ..LIMITS
};

type Checkpoint<'a> = &'a (dyn Fn() -> Result<(), RefusalCode> + Sync);
fn check(checkpoint: Checkpoint<'_>) -> Result<(), AdmissionError> {
    checkpoint().map_err(AdmissionError::AsyncProjectionUnavailable)
}

pub(super) struct Descriptor {
    chunks: Vec<SemanticRequest>,
    wire_order: Vec<usize>,
}

impl Descriptor {
    pub(super) fn from_plan(
        context: &AdmissionContext,
        plan: &SessionPlan,
        checkpoint: Checkpoint<'_>,
    ) -> Result<Self, AdmissionError> {
        if plan.atomic
            || plan.command_count <= MAX_ADMISSION_COMMANDS
            || plan.command_count > MAX_RECEIVE_SESSION_COMMANDS
            || plan.lowered.len() != plan.command_count
            || plan.tx_ids.len() != plan.command_count
        {
            return Err(invalid());
        }
        let first = &plan.lowered.first().ok_or_else(invalid)?.semantic;
        let options = first.push_options().to_vec();
        let mut commands = Vec::with_capacity(plan.command_count);
        for (wire_index, lowered) in plan.lowered.iter().enumerate() {
            check(checkpoint)?;
            let [command] = lowered.semantic.ref_commands() else {
                return Err(invalid());
            };
            if lowered.semantic.object_format() != context.object_format
                || lowered.semantic.request_schema() != fgit_authority::RECEIVE_ADMISSION_SCHEMA
                || lowered.semantic.atomic()
                || !lowered.semantic.scoped_entries().is_empty()
                || lowered.semantic.push_options() != options
            {
                return Err(invalid());
            }
            commands.push((wire_index, command.clone()));
        }
        commands.sort_by(|left, right| left.1.name.cmp(&right.1.name));
        let mut wire_order = vec![0; commands.len()];
        for (canonical_index, (wire_index, _)) in commands.iter().enumerate() {
            check(checkpoint)?;
            wire_order[*wire_index] = canonical_index;
        }
        let chunks = commands
            .chunks(MAX_ADMISSION_COMMANDS)
            .map(|chunk| {
                check(checkpoint)?;
                SemanticRequest::build(
                    fgit_authority::RECEIVE_ADMISSION_SCHEMA,
                    context.object_format,
                    false,
                    chunk.iter().map(|(_, command)| command.clone()).collect(),
                    options.clone(),
                    Vec::new(),
                )
                .map_err(AdmissionError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let descriptor = Self { chunks, wire_order };
        descriptor.validate(checkpoint)?;
        // The carrier cannot silently substitute a second lowering rule.
        for (index, lowered) in plan.lowered.iter().enumerate() {
            check(checkpoint)?;
            if descriptor.child_attempt(context, index)? != seal_attempt(context, lowered) {
                return Err(invalid());
            }
        }
        Ok(descriptor)
    }

    fn validate(&self, checkpoint: Checkpoint<'_>) -> Result<(), AdmissionError> {
        check(checkpoint)?;
        if !(2..=MAX_CHUNKS).contains(&self.chunks.len())
            || self.wire_order.len() <= MAX_ADMISSION_COMMANDS
            || self.wire_order.len() > MAX_RECEIVE_SESSION_COMMANDS
        {
            return Err(invalid());
        }
        let first = self.chunks.first().ok_or_else(invalid)?;
        let mut count = 0_usize;
        let mut previous: Option<&RefName> = None;
        for (index, chunk) in self.chunks.iter().enumerate() {
            check(checkpoint)?;
            let commands = chunk.ref_commands();
            if commands.is_empty()
                || commands.len() > MAX_ADMISSION_COMMANDS
                || (index + 1 < self.chunks.len() && commands.len() != MAX_ADMISSION_COMMANDS)
                || chunk.object_format() != first.object_format()
                || chunk.atomic()
                || chunk.request_schema() != fgit_authority::RECEIVE_ADMISSION_SCHEMA
                || !chunk.scoped_entries().is_empty()
                || chunk.push_options() != first.push_options()
            {
                return Err(invalid());
            }
            let options = chunk
                .push_options()
                .iter()
                .map(|option| PushOption::new(option.as_bytes().to_vec()))
                .collect::<Result<Vec<_>, _>>()?;
            let rebuilt = SemanticRequest::build(
                chunk.request_schema(),
                chunk.object_format(),
                false,
                commands.to_vec(),
                options,
                Vec::new(),
            )?;
            if rebuilt != *chunk {
                return Err(invalid());
            }
            for command in commands {
                check(checkpoint)?;
                if previous.is_some_and(|name| name >= &command.name)
                    || command.force
                    || matches!(command.expected_old, ExpectedOld::Unspecified)
                    || matches!(command.expected_old, ExpectedOld::Exactly(oid) if oid.is_zero())
                    || matches!(command.proposed_new, ProposedNew::Update(oid) if oid.is_zero())
                {
                    return Err(invalid());
                }
                previous = Some(&command.name);
            }
            count = count.checked_add(commands.len()).ok_or_else(invalid)?;
        }
        if count != self.wire_order.len() {
            return Err(invalid());
        }
        let mut seen = vec![false; count];
        for &index in &self.wire_order {
            check(checkpoint)?;
            let slot = seen.get_mut(index).ok_or_else(invalid)?;
            if *slot {
                return Err(invalid());
            }
            *slot = true;
        }
        // A hostile descriptor must not amplify options while reconstructing
        // every child. Match the admission preflight's independent work bound.
        let observed = crate::session_option_work(
            first.push_options().iter().map(PushOption::as_bytes),
            count,
        );
        if observed > MAX_SESSION_OPTION_COPY_BYTES {
            return Err(AdmissionError::PushOptionWorkExceeded {
                limit: MAX_SESSION_OPTION_COPY_BYTES,
                observed,
            });
        }
        Ok(())
    }

    pub(super) const fn len(&self) -> usize {
        self.wire_order.len()
    }

    pub(super) fn encode(&self, checkpoint: Checkpoint<'_>) -> Result<Vec<u8>, AdmissionError> {
        self.validate(checkpoint)?;
        let mut observed = self
            .wire_order
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|n| n.checked_add(3 * size_of::<u32>()))
            .ok_or_else(invalid)?;
        let mut encoded = Vec::with_capacity(self.chunks.len());
        for chunk in &self.chunks {
            check(checkpoint)?;
            let bytes = encode_body(chunk).map_err(codec)?;
            observed = observed
                .checked_add(size_of::<u32>())
                .and_then(|n| n.checked_add(bytes.len()))
                .ok_or_else(invalid)?;
            if observed > MAX_BYTES {
                return Err(AdmissionError::SessionDescriptorBytesExceeded {
                    limit: MAX_BYTES,
                    observed,
                });
            }
            encoded.push(bytes);
        }
        let mut out = Encoder::new();
        out.write_scalar(VERSION);
        out.write_sequence("receive-session.chunks", &encoded, |out, bytes| {
            out.write_bytes("receive-session.chunk", bytes)
        })
        .map_err(codec)?;
        let indices = self
            .wire_order
            .iter()
            .map(|index| {
                check(checkpoint)?;
                u16::try_from(*index).map_err(|_| invalid())
            })
            .collect::<Result<Vec<_>, _>>()?;
        out.write_sequence("receive-session.wire-order", &indices, |out, index| {
            out.write_scalar(*index);
            Ok(())
        })
        .map_err(codec)?;
        let bytes = out.into_bytes();
        if bytes.len() != observed {
            return Err(invalid());
        }
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8], checkpoint: Checkpoint<'_>) -> Result<Self, AdmissionError> {
        if bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let mut input = Decoder::new(bytes, LIMITS);
        if input
            .read_scalar::<u32>("receive-session.version")
            .map_err(codec)?
            != VERSION
        {
            return Err(invalid());
        }
        // Bound the outer chunk count before allocating or reading chunk bodies;
        // the independent permutation below admits all sixteen thousand indices.
        let count = input
            .read_scalar::<u32>("receive-session.chunks")
            .map_err(codec)? as usize;
        if !(2..=MAX_CHUNKS).contains(&count) {
            return Err(invalid());
        }
        let mut chunks = Vec::with_capacity(count);
        for _ in 0..count {
            check(checkpoint)?;
            let bytes = input.read_bytes("receive-session.chunk").map_err(codec)?;
            chunks.push(decode_body::<SemanticRequest>(bytes, CHUNK_LIMITS).map_err(codec)?);
        }
        let wire_order = input
            .read_sequence("receive-session.wire-order", |input| {
                input
                    .read_scalar::<u16>("receive-session.index")
                    .map(usize::from)
            })
            .map_err(codec)?;
        input.finish().map_err(codec)?;
        let descriptor = Self { chunks, wire_order };
        descriptor.validate(checkpoint)?;
        if descriptor.encode(checkpoint)? != bytes {
            return Err(invalid());
        }
        Ok(descriptor)
    }

    pub(super) fn whole_attempt(
        &self,
        context: &AdmissionContext,
        checkpoint: Checkpoint<'_>,
    ) -> Result<SealAttempt, AdmissionError> {
        self.validate(checkpoint)?;
        if self.chunks[0].object_format() != context.object_format {
            return Err(invalid());
        }
        let namespace = AsciiSlug::from_static("receive-session");
        let mut entries = vec![ScopedEntry::new(
            namespace,
            AsciiSlug::from_static("command-count"),
            u32::try_from(self.len())
                .map_err(|_| invalid())?
                .to_be_bytes()
                .to_vec(),
        )?];
        for (index, chunk) in self.chunks.iter().enumerate() {
            check(checkpoint)?;
            let mut out = Encoder::new();
            out.write_digest(&canonical_request_digest(chunk)?)
                .map_err(codec)?;
            entries.push(ScopedEntry::new(
                namespace,
                binding_key("chunk", index)?,
                out.into_bytes(),
            )?);
        }
        // Scoped values stay within the existing 4096-byte canonical vocabulary.
        // Binding order as well as chunk digests rejects reordered same-key
        // retries before even the first derived child key can be reserved.
        for (index, indices) in self
            .wire_order
            .chunks(fgit_authority::MAX_SCOPED_VALUE_BYTES / size_of::<u16>())
            .enumerate()
        {
            let mut out = Encoder::new();
            for &position in indices {
                check(checkpoint)?;
                out.write_scalar(u16::try_from(position).map_err(|_| invalid())?);
            }
            entries.push(ScopedEntry::new(
                namespace,
                binding_key("wire-order", index)?,
                out.into_bytes(),
            )?);
        }
        Ok(SealAttempt {
            tenant_id: context.tenant_id,
            repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: context.idempotency_key.clone(),
            request: SemanticRequest::build(
                BINDING_SCHEMA,
                context.object_format,
                false,
                Vec::new(),
                Vec::new(),
                entries,
            )?,
        })
    }

    pub(super) fn child_attempt(
        &self,
        context: &AdmissionContext,
        index: usize,
    ) -> Result<SealAttempt, AdmissionError> {
        let position = *self.wire_order.get(index).ok_or_else(invalid)?;
        let chunk = self
            .chunks
            .get(position / MAX_ADMISSION_COMMANDS)
            .ok_or_else(invalid)?;
        let command = chunk
            .ref_commands()
            .get(position % MAX_ADMISSION_COMMANDS)
            .ok_or_else(invalid)?
            .clone();
        if chunk.object_format() != context.object_format {
            return Err(invalid());
        }
        Ok(SealAttempt {
            tenant_id: context.tenant_id,
            repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: super::super::non_atomic_command_key(&context.idempotency_key, index)?,
            request: SemanticRequest::build(
                fgit_authority::RECEIVE_ADMISSION_SCHEMA,
                context.object_format,
                false,
                vec![command],
                chunk.push_options().to_vec(),
                Vec::new(),
            )?,
        })
    }
}

fn binding_key(prefix: &str, index: usize) -> Result<AsciiSlug, AdmissionError> {
    AsciiSlug::try_new(
        "receive-session.binding-key",
        format!("{prefix}-{index:04}").as_bytes(),
    )
    .map_err(|_| invalid())
}

#[cfg(test)]
mod tests;
