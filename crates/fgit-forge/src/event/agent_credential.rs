//! Canonical sponsored authentication for bounded source reads and forge metadata.
//!
//! These immutable grants identify an agent and its operator-attested sponsor.
//! They do not authorize code publication, reviews, merges, administration, or an
//! agent run.
//! A host must additionally establish and enforce its sponsored IntentRun before
//! using any granted operation. Issuance and revocation become authoritative
//! only when ordinary repository admission selects these events.

use super::{ForgeEvent, ForgeEventPayload, invalid_native};
use crate::{AggregateId, AggregateVersion, ExpectedVersion};
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PrincipalId, RefusalCode, RepositoryId, RepositoryIncarnationId, TenantId};

pub const ISSUES_READ: u16 = 1 << 0;
pub const ISSUES_WRITE: u16 = 1 << 1;
pub const PULLS_READ: u16 = 1 << 2;
pub const PULLS_WRITE: u16 = 1 << 3;
pub const DISCUSSIONS_READ: u16 = 1 << 4;
pub const DISCUSSIONS_WRITE: u16 = 1 << 5;
pub const OUTCOMES_READ: u16 = 1 << 6;
/// Bounded current source, search and context reads through the native API.
/// The host must enforce its closed read-route profile and canonical visibility;
/// this flag does not grant Git transport, history snapshots or candidate work.
pub const SOURCE_READ: u16 = 1 << 7;
pub const ALL_OPERATIONS: u16 = (1 << 8) - 1;
/// A grant cannot survive indefinitely without a new sponsor decision.
pub const MAX_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;
const LABEL_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// SHA-256 commitment to the bearer bytes. No secret is stored in forge history.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentCredentialId([u8; 32]);

impl AgentCredentialId {
    #[must_use]
    pub fn try_new(bytes: [u8; 32]) -> Option<Self> {
        bytes.iter().any(|byte| *byte != 0).then_some(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lossless lowercase RFC 4648 base32 fits the 64-byte forge-label bound.
    #[must_use]
    pub fn aggregate_label(&self) -> String {
        let mut label = String::with_capacity(58);
        label.push_str("agent/");
        for index in 0..52 {
            let mut value = 0usize;
            for shift in 0..5 {
                let bit_index = index * 5 + shift;
                value <<= 1;
                if bit_index < 256 {
                    value |= usize::from((self.0[bit_index / 8] >> (7 - bit_index % 8)) & 1);
                }
            }
            label.push(char::from(LABEL_ALPHABET[value]));
        }
        label
    }

    /// Only the canonical lowercase spelling selects a stream. Padding, aliases,
    /// nonzero unused bits and the reserved zero identity are refused.
    #[must_use]
    pub fn from_aggregate_label(label: &str) -> Option<Self> {
        let encoded = label.strip_prefix("agent/")?.as_bytes();
        if encoded.len() != 52 {
            return None;
        }
        let mut result = [0_u8; 32];
        for (index, &byte) in encoded.iter().enumerate() {
            let value = LABEL_ALPHABET
                .iter()
                .position(|candidate| *candidate == byte)?;
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
        Self::try_new(result)
    }
}

impl core::fmt::Display for AgentCredentialId {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(out, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Explicit operator attestation; possession of a token never infers this kind.
/// Agent sponsorship and transitive delegation are outside this closed profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SponsorKind {
    Human,
    Service,
}

impl SponsorKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Service => "service",
        }
    }

    #[must_use]
    pub const fn code_point(self) -> u32 {
        match self {
            Self::Human => 1,
            Self::Service => 2,
        }
    }

    #[must_use]
    pub const fn from_code_point(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Human),
            2 => Some(Self::Service),
            _ => None,
        }
    }
}

/// One repository incarnation, one agent, one sponsoring human or service.
/// Times are Unix seconds, checked by the authenticating host. They are not an
/// Agent Protocol logical clock or an assertion of canonical-read freshness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentCredentialGrant {
    pub agent: PrincipalId,
    pub sponsor: PrincipalId,
    pub sponsor_kind: SponsorKind,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Independent explicit flags. Write never grants read or another effect.
    pub operations: u16,
}

impl AgentCredentialGrant {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if [
            self.agent.as_bytes(),
            self.sponsor.as_bytes(),
            self.tenant.as_bytes(),
            self.repository.as_bytes(),
            self.incarnation.as_bytes(),
        ]
        .iter()
        .any(|id| id.iter().all(|byte| *byte == 0))
            || self.agent == self.sponsor
        {
            return Err(invalid_native("agent_credential.principals_and_binding"));
        }
        if self.issued_at == 0
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_LIFETIME_SECONDS
        {
            return Err(invalid_native("agent_credential.lifetime"));
        }
        if self.operations == 0 || self.operations & !ALL_OPERATIONS != 0 {
            return Err(invalid_native("agent_credential.operations"));
        }
        Ok(())
    }

    /// Every requested flag must be explicit and known. Zero grants nothing.
    #[must_use]
    pub const fn permits(&self, operation: u16) -> bool {
        operation != 0
            && operation & !ALL_OPERATIONS == 0
            && self.operations & !ALL_OPERATIONS == 0
            && self.operations & operation == operation
    }

    fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_opaque_id(self.agent.as_bytes());
        out.write_opaque_id(self.sponsor.as_bytes());
        out.write_scalar(self.sponsor_kind.code_point());
        out.write_opaque_id(self.tenant.as_bytes());
        out.write_opaque_id(self.repository.as_bytes());
        out.write_opaque_id(self.incarnation.as_bytes());
        out.write_scalar(self.issued_at);
        out.write_scalar(self.expires_at);
        out.write_scalar(self.operations);
        Ok(())
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let agent = PrincipalId::from_bytes(input.read_opaque_id("agent_credential.agent")?);
        let sponsor = PrincipalId::from_bytes(input.read_opaque_id("agent_credential.sponsor")?);
        let offset = input.offset();
        let observed = input.read_scalar::<u32>("agent_credential.sponsor_kind")?;
        let sponsor_kind =
            SponsorKind::from_code_point(observed).ok_or(CodecRefusal::VariantUnknown {
                field: "agent_credential.sponsor_kind",
                observed,
                offset,
            })?;
        let value = Self {
            agent,
            sponsor,
            sponsor_kind,
            tenant: TenantId::from_bytes(input.read_opaque_id("agent_credential.tenant")?),
            repository: RepositoryId::from_bytes(
                input.read_opaque_id("agent_credential.repository")?,
            ),
            incarnation: RepositoryIncarnationId::from_bytes(
                input.read_opaque_id("agent_credential.incarnation")?,
            ),
            issued_at: input.read_scalar("agent_credential.issued_at")?,
            expires_at: input.read_scalar("agent_credential.expires_at")?,
            operations: input.read_scalar("agent_credential.operations")?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentCredentialAction {
    Issue(AgentCredentialGrant),
    /// Permanent tombstone retaining the original grant at the current frontier.
    Revoke(AgentCredentialGrant),
}

impl AgentCredentialAction {
    #[must_use]
    pub const fn grant(&self) -> &AgentCredentialGrant {
        match self {
            Self::Issue(grant) | Self::Revoke(grant) => grant,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeAgentCredentialEvent {
    pub actor: PrincipalId,
    pub action: AgentCredentialAction,
}

impl NativeAgentCredentialEvent {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if self.actor.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(invalid_native("agent_credential.actor"));
        }
        self.action.grant().validate()?;
        if let AgentCredentialAction::Issue(grant) = self.action {
            if self.actor != grant.sponsor {
                return Err(invalid_native("agent_credential.sponsor_actor"));
            }
        }
        Ok(())
    }

    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_opaque_id(self.actor.as_bytes());
        match self.action {
            AgentCredentialAction::Issue(grant) => {
                out.write_scalar(1u32);
                grant.write(out)?;
            }
            AgentCredentialAction::Revoke(grant) => {
                out.write_scalar(2u32);
                grant.write(out)?;
            }
        }
        Ok(())
    }

    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let actor = PrincipalId::from_bytes(input.read_opaque_id("agent_credential.actor")?);
        let offset = input.offset();
        let action = match input.read_scalar::<u32>("agent_credential.action")? {
            1 => AgentCredentialAction::Issue(AgentCredentialGrant::read(input)?),
            2 => AgentCredentialAction::Revoke(AgentCredentialGrant::read(input)?),
            observed => {
                return Err(CodecRefusal::VariantUnknown {
                    field: "agent_credential.action",
                    observed,
                    offset,
                });
            }
        };
        let value = Self { actor, action };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentCredentialCommand {
    pub id: AgentCredentialId,
    pub expected_version: ExpectedVersion,
    pub action: AgentCredentialAction,
}

impl AgentCredentialCommand {
    pub fn proposed_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(previous) => previous
                .next()
                .map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        let event = ForgeEvent {
            aggregate: AggregateId::AgentCredential(self.id),
            version,
            payload: ForgeEventPayload::AgentCredentialChangedNative(NativeAgentCredentialEvent {
                actor,
                action: self.action,
            }),
        };
        validate_event(&event).map_err(|_| RefusalCode::EvidenceInvalid)?;
        Ok(event)
    }
}

/// Derived state of exactly one canonical issue/revoke stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentCredentialSnapshot {
    pub id: AgentCredentialId,
    pub version: AggregateVersion,
    pub grant: AgentCredentialGrant,
    pub revoked: bool,
    pub last_actor: PrincipalId,
}

pub(super) fn validate_event(event: &ForgeEvent) -> Result<(), CodecRefusal> {
    if matches!(event.aggregate, AggregateId::AgentCredential(_))
        != matches!(
            event.payload,
            ForgeEventPayload::AgentCredentialChangedNative(_)
        )
    {
        return Err(invalid_native("agent_credential.aggregate_kind"));
    }
    if let ForgeEventPayload::AgentCredentialChangedNative(change) = &event.payload {
        change.validate()?;
        let required_version = match change.action {
            AgentCredentialAction::Issue(_) => 1,
            AgentCredentialAction::Revoke(_) => 2,
        };
        if event.version.get() != required_version {
            return Err(invalid_native("agent_credential.aggregate_version"));
        }
    }
    Ok(())
}

/// Replay refuses any change to sponsor or scope in a permanent revocation.
/// Administrator authorization belongs to admission, not this structural fold.
pub fn apply_event(
    previous: Option<&AgentCredentialSnapshot>,
    event: &ForgeEvent,
) -> Result<AgentCredentialSnapshot, RefusalCode> {
    validate_event(event).map_err(|_| RefusalCode::EvidenceInvalid)?;
    let (AggregateId::AgentCredential(id), ForgeEventPayload::AgentCredentialChangedNative(change)) =
        (event.aggregate, &event.payload)
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    match (previous, change.action) {
        (None, AgentCredentialAction::Issue(grant)) => Ok(AgentCredentialSnapshot {
            id,
            version: event.version,
            grant,
            revoked: false,
            last_actor: change.actor,
        }),
        (Some(previous), AgentCredentialAction::Revoke(grant))
            if previous.id == id
                && !previous.revoked
                && previous.grant == grant
                && previous.version.is_immediate_predecessor_of(event.version) =>
        {
            Ok(AgentCredentialSnapshot {
                version: event.version,
                revoked: true,
                last_actor: change.actor,
                ..*previous
            })
        }
        _ => Err(RefusalCode::EvidenceStale),
    }
}

#[cfg(test)]
mod tests;
