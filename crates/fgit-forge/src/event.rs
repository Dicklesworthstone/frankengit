//! Canonical forge events. Tags 1 through 4 retain their exact historical
//! encoding; tag 5 carries native Git identities without reinterpreting a
//! legacy internal `Digest`. Older readers refuse the new kind explicitly.

use fgit_codec::attest::{BodyIdentity, body_id};
use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{Digest, DomainTag, ForgeEventId, GitOid, RefName, SchemaFamily};

use crate::ForgeRefusal;
use crate::aggregate::{
    AGGREGATE_KIND_ORGANISATION, AGGREGATE_KIND_TEAM, AggregateId, AggregateVersion,
    OrganisationNumber, PullRequestNumber, TeamNumber,
};

const KIND_OPENED: u32 = 1;
const KIND_HEAD_ADVANCED: u32 = 2;
const KIND_MERGE_COMMITTED: u32 = 3;
const KIND_CLOSED: u32 = 4;
const KIND_NATIVE_MERGE_COMMITTED: u32 = 5;

/// Complete native coordinates of one merge. The resulting target is always
/// `merge_commit`; there is no independently writable, contradictory after-tip.
/// Source and merge-base coordinates are included so the event commitment also
/// binds the source-side precondition of a sealed merge request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMerge {
    pub source_ref: RefName,
    pub source_tip: GitOid,
    pub base_tip: GitOid,
    pub target_ref: RefName,
    pub target_tip_before: GitOid,
    pub merge_commit: GitOid,
}

impl NativeMerge {
    /// Check the closed branch-merge profile before encoding or admission.
    /// No internal-digest/native-OID conversion is performed.
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if self.source_ref == self.target_ref
            || !self.source_ref.as_bytes().starts_with(b"refs/heads/")
            || !self.target_ref.as_bytes().starts_with(b"refs/heads/")
        {
            return Err(invalid_native("native_merge.branches"));
        }
        let format = self.merge_commit.algorithm();
        if [self.source_tip, self.base_tip, self.target_tip_before, self.merge_commit]
            .iter().any(|oid| oid.is_zero() || oid.algorithm() != format)
        {
            return Err(invalid_native("native_merge.object_format"));
        }
        if self.target_tip_before == self.merge_commit {
            return Err(invalid_native("native_merge.target_transition"));
        }
        Ok(())
    }

    fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_bytes("source_ref", self.source_ref.as_bytes())?;
        out.write_git_oid(&self.source_tip);
        out.write_git_oid(&self.base_tip);
        out.write_bytes("target_ref", self.target_ref.as_bytes())?;
        out.write_git_oid(&self.target_tip_before);
        out.write_git_oid(&self.merge_commit);
        Ok(())
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let value = Self {
            source_ref: RefName::try_new(input.read_bytes("source_ref")?).map_err(CodecRefusal::from)?,
            source_tip: input.read_git_oid()?,
            base_tip: input.read_git_oid()?,
            target_ref: RefName::try_new(input.read_bytes("target_ref")?).map_err(CodecRefusal::from)?,
            target_tip_before: input.read_git_oid()?,
            merge_commit: input.read_git_oid()?,
        };
        value.validate()?;
        Ok(value)
    }
}

fn invalid_native(field: &'static str) -> CodecRefusal {
    CodecRefusal::ValueUnrepresentable { field, observed: 0, limit: 1 }
}

/// Legacy event kinds keep their internal-digest fields and original bytes.
/// New durable merges use `MergeCommittedNative`, never a bytewise cast of
/// those fields into a Git identity. Unknown kinds fail closed on old readers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForgeEventPayload {
    PullRequestOpened {
        source_ref: Vec<u8>,
        target_ref: Vec<u8>,
        source_tip: Digest,
        target_tip: Digest,
    },
    PullRequestHeadAdvanced { source_tip: Digest },
    MergeCommitted {
        merge_commit: Digest,
        target_ref: Vec<u8>,
        target_tip_before: Digest,
        target_tip_after: Digest,
    },
    PullRequestClosed { withdrawn: bool },
    /// Native branch-merge receipt, wire kind 5. Existing kinds are unchanged.
    MergeCommittedNative(NativeMerge),
}

impl ForgeEventPayload {
    #[must_use]
    pub const fn kind(&self) -> u32 {
        match self {
            Self::PullRequestOpened { .. } => KIND_OPENED,
            Self::PullRequestHeadAdvanced { .. } => KIND_HEAD_ADVANCED,
            Self::MergeCommitted { .. } => KIND_MERGE_COMMITTED,
            Self::PullRequestClosed { .. } => KIND_CLOSED,
            Self::MergeCommittedNative(_) => KIND_NATIVE_MERGE_COMMITTED,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeEvent {
    pub aggregate: AggregateId,
    pub version: AggregateVersion,
    pub payload: ForgeEventPayload,
}

// Preserve the established nonzero PR slot and zero escape for other aggregates.
fn write_aggregate(out: &mut Encoder, aggregate: AggregateId) {
    match aggregate {
        AggregateId::PullRequest(number) => out.write_scalar(number.get()),
        AggregateId::Organisation(number) => {
            out.write_scalar(0_u64);
            out.write_scalar(AGGREGATE_KIND_ORGANISATION);
            out.write_scalar(number.get());
        }
        AggregateId::Team(number) => {
            out.write_scalar(0_u64);
            out.write_scalar(AGGREGATE_KIND_TEAM);
            out.write_scalar(number.get());
        }
    }
}

fn read_aggregate(input: &mut Decoder<'_>) -> Result<AggregateId, CodecRefusal> {
    let slot = input.read_scalar::<u64>("aggregate")?;
    if slot != 0 {
        return Ok(AggregateId::PullRequest(counter("aggregate", slot)?));
    }
    let kind_offset = input.offset();
    let kind = input.read_scalar::<u32>("aggregate.kind")?;
    match kind {
        AGGREGATE_KIND_ORGANISATION => Ok(AggregateId::Organisation(counter(
            "aggregate.organisation", input.read_scalar::<u64>("aggregate.organisation")?,
        )?)),
        AGGREGATE_KIND_TEAM => Ok(AggregateId::Team(counter(
            "aggregate.team", input.read_scalar::<u64>("aggregate.team")?,
        )?)),
        unknown => Err(CodecRefusal::VariantUnknown {
            field: "aggregate.kind", observed: unknown, offset: kind_offset,
        }),
    }
}

fn write_event(out: &mut Encoder, event: &ForgeEvent) -> Result<(), CodecRefusal> {
    write_aggregate(out, event.aggregate);
    out.write_scalar(event.version.get());
    out.write_scalar(event.payload.kind());
    match &event.payload {
        ForgeEventPayload::PullRequestOpened { source_ref, target_ref, source_tip, target_tip } => {
            out.write_bytes("source_ref", source_ref)?;
            out.write_bytes("target_ref", target_ref)?;
            out.write_digest(source_tip)?;
            out.write_digest(target_tip)?;
        }
        ForgeEventPayload::PullRequestHeadAdvanced { source_tip } => out.write_digest(source_tip)?,
        ForgeEventPayload::MergeCommitted { merge_commit, target_ref, target_tip_before, target_tip_after } => {
            out.write_digest(merge_commit)?;
            out.write_bytes("target_ref", target_ref)?;
            out.write_digest(target_tip_before)?;
            out.write_digest(target_tip_after)?;
        }
        ForgeEventPayload::PullRequestClosed { withdrawn } => out.write_bool(*withdrawn),
        ForgeEventPayload::MergeCommittedNative(merge) => {
            if !matches!(event.aggregate, AggregateId::PullRequest(_)) {
                return Err(invalid_native("native_merge.aggregate"));
            }
            merge.write(out)?;
        }
    }
    Ok(())
}

fn read_event(input: &mut Decoder<'_>) -> Result<ForgeEvent, CodecRefusal> {
    let aggregate = read_aggregate(input)?;
    let version = counter("version", input.read_scalar::<u64>("version")?)?;
    let kind_offset = input.offset();
    let kind = input.read_scalar::<u32>("kind")?;
    let payload = match kind {
        KIND_OPENED => ForgeEventPayload::PullRequestOpened {
            source_ref: input.read_bytes("source_ref")?.to_vec(),
            target_ref: input.read_bytes("target_ref")?.to_vec(),
            source_tip: input.read_digest()?,
            target_tip: input.read_digest()?,
        },
        KIND_HEAD_ADVANCED => ForgeEventPayload::PullRequestHeadAdvanced { source_tip: input.read_digest()? },
        KIND_MERGE_COMMITTED => ForgeEventPayload::MergeCommitted {
            merge_commit: input.read_digest()?,
            target_ref: input.read_bytes("target_ref")?.to_vec(),
            target_tip_before: input.read_digest()?,
            target_tip_after: input.read_digest()?,
        },
        KIND_CLOSED => ForgeEventPayload::PullRequestClosed { withdrawn: input.read_bool("withdrawn")? },
        KIND_NATIVE_MERGE_COMMITTED => {
            if !matches!(aggregate, AggregateId::PullRequest(_)) {
                return Err(invalid_native("native_merge.aggregate"));
            }
            ForgeEventPayload::MergeCommittedNative(NativeMerge::read(input)?)
        }
        unknown => return Err(CodecRefusal::VariantUnknown {
            field: "kind", observed: unknown, offset: kind_offset,
        }),
    };
    Ok(ForgeEvent { aggregate, version, payload })
}

fn counter<T: Counter>(field: &'static str, value: u64) -> Result<T, CodecRefusal> {
    T::build(value).ok_or(CodecRefusal::ValueUnrepresentable { field, observed: value, limit: 1 })
}
trait Counter: Sized { fn build(value: u64) -> Option<Self>; }
impl Counter for PullRequestNumber { fn build(value: u64) -> Option<Self> { Self::try_new(value) } }
impl Counter for AggregateVersion { fn build(value: u64) -> Option<Self> { Self::try_new(value) } }
impl Counter for OrganisationNumber { fn build(value: u64) -> Option<Self> { Self::try_new(value) } }
impl Counter for TeamNumber { fn build(value: u64) -> Option<Self> { Self::try_new(value) } }

impl CanonicalBody for ForgeEvent {
    const DOMAIN: DomainTag = ForgeEventId::DOMAIN_TAG;
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("forge-event");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;
    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> { write_event(out, self) }
    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> { read_event(input) }
}

/// Ordered events admitted by one repository decision; never sorted as a set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeEventBatch { pub events: Vec<ForgeEvent> }
impl ForgeEventBatch {
    #[must_use]
    pub fn of_one(event: ForgeEvent) -> Self { Self { events: vec![event] } }
}
impl CanonicalBody for ForgeEventBatch {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/forge-event-batch/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("forge-event-batch");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;
    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_sequence("events", &self.events, write_event)
    }
    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self { events: input.read_sequence("events", read_event)? })
    }
}

pub fn event_id<I>(identity: &I, event: &ForgeEvent) -> Result<ForgeEventId, ForgeRefusal>
where I: BodyIdentity + ?Sized,
{
    let object = body_id(identity, event).map_err(|cause| match cause {
        CodecRefusal::IdentityDomainUnregistered { .. } => ForgeRefusal::IdentityUnavailable { body: "ForgeEvent" },
        cause => ForgeRefusal::BodyUnrepresentable { cause: Box::new(cause) },
    })?;
    ForgeEventId::from_internal_object_id(object)
        .map_err(|_| ForgeRefusal::IdentityUnavailable { body: "ForgeEvent" })
}
