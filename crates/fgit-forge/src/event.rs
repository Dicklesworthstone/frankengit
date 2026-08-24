//! The forge event model, as canonical bodies.
//!
//! # One body, four payloads
//!
//! Every forge event is one [`ForgeEvent`] carrying a kind tag, rather than one
//! canonical body per kind. That is deliberate. A body per kind would multiply
//! the schema family, the golden set, and the version rules by the number of
//! event kinds, and every new kind would be a new place to get versioning
//! subtly wrong. With one body there is one schema to version, one place an
//! unknown kind is refused, and adding a kind is a payload change governed by
//! the minor rules the codec already enforces.
//!
//! # Versioning, which this crate consumes rather than invents
//!
//! `fgit-codec` already implements the rules the plan requires: an unknown
//! codec major is refused, an unknown schema major is refused, a higher minor
//! is additive and its unparsed suffix is preserved verbatim so re-encoding
//! reproduces the original bytes, and at an implemented minor trailing bytes
//! are refused. This module's obligation is to declare its schema honestly and
//! to refuse an event *kind* it does not implement, which is the one axis the
//! frame cannot check.

use fgit_codec::attest::{BodyIdentity, body_id};
use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{Digest, DomainTag, ForgeEventId, SchemaFamily};

use crate::ForgeRefusal;
use crate::aggregate::{
    AGGREGATE_KIND_ORGANISATION, AGGREGATE_KIND_TEAM, AggregateId, AggregateVersion,
    OrganisationNumber, PullRequestNumber, TeamNumber,
};

const KIND_OPENED: u32 = 1;
const KIND_HEAD_ADVANCED: u32 = 2;
const KIND_MERGE_COMMITTED: u32 = 3;
const KIND_CLOSED: u32 = 4;

/// What happened to a pull request.
///
/// This is the merge-sufficient set: the events needed to carry a pull request
/// from creation to a merge that moved a ref. Review, comment, and label events
/// are forge state too, but nothing in the atomic merge path reads them, and a
/// kind that no canonical decision depends on does not belong in the canonical
/// event model just because a projection would like it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForgeEventPayload {
    /// A pull request was opened against a target.
    PullRequestOpened {
        /// The branch being merged from.
        source_ref: Vec<u8>,
        /// The branch being merged into.
        target_ref: Vec<u8>,
        /// Source tip at the moment of opening.
        source_tip: Digest,
        /// Target tip at the moment of opening.
        target_tip: Digest,
    },
    /// The source branch moved, so any prior merge computation is stale.
    PullRequestHeadAdvanced {
        /// The new source tip.
        source_tip: Digest,
    },
    /// A merge was committed and the target ref moved.
    ///
    /// Both the before and after tips are recorded because the event has to be
    /// checkable on its own: a reader holding only this event must be able to
    /// say which target state it applied to, without consulting a projection.
    MergeCommitted {
        /// The merge commit this event admitted.
        merge_commit: Digest,
        /// The ref that moved.
        target_ref: Vec<u8>,
        /// Target tip the merge was computed against.
        target_tip_before: Digest,
        /// Target tip after the merge.
        target_tip_after: Digest,
    },
    /// The pull request was closed.
    PullRequestClosed {
        /// True when closed without merging.
        withdrawn: bool,
    },
}

impl ForgeEventPayload {
    /// The wire tag for this kind.
    #[must_use]
    pub const fn kind(&self) -> u32 {
        match self {
            Self::PullRequestOpened { .. } => KIND_OPENED,
            Self::PullRequestHeadAdvanced { .. } => KIND_HEAD_ADVANCED,
            Self::MergeCommitted { .. } => KIND_MERGE_COMMITTED,
            Self::PullRequestClosed { .. } => KIND_CLOSED,
        }
    }
}

/// One canonical forge event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeEvent {
    /// The aggregate this event belongs to.
    pub aggregate: AggregateId,
    /// This event's position in that aggregate's stream.
    pub version: AggregateVersion,
    /// What happened.
    pub payload: ForgeEventPayload,
}

/// Writes the aggregate slot.
///
/// A pull request is written bare, exactly as it was before aggregates other
/// than pull requests existed, so its bytes and its `ForgeEventId` are
/// unchanged. Anything else writes the reserved zero -- which no counter can
/// produce and which the reader has always refused -- followed by a kind tag
/// and that kind's id.
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

/// Reads the aggregate slot written by [`write_aggregate`].
fn read_aggregate(input: &mut Decoder<'_>) -> Result<AggregateId, CodecRefusal> {
    let slot = input.read_scalar::<u64>("aggregate")?;
    if slot != 0 {
        return Ok(AggregateId::PullRequest(counter("aggregate", slot)?));
    }
    let kind_offset = input.offset();
    let kind = input.read_scalar::<u32>("aggregate.kind")?;
    match kind {
        AGGREGATE_KIND_ORGANISATION => Ok(AggregateId::Organisation(counter(
            "aggregate.organisation",
            input.read_scalar::<u64>("aggregate.organisation")?,
        )?)),
        AGGREGATE_KIND_TEAM => Ok(AggregateId::Team(counter(
            "aggregate.team",
            input.read_scalar::<u64>("aggregate.team")?,
        )?)),
        // Fail closed, for the same reason an unknown event kind does: the id
        // that follows is this kind's, so a build that does not know the kind
        // cannot know how much to read, and every field after would come from
        // the wrong offset.
        unknown => Err(CodecRefusal::VariantUnknown {
            field: "aggregate.kind",
            observed: unknown,
            offset: kind_offset,
        }),
    }
}

fn write_event(out: &mut Encoder, event: &ForgeEvent) -> Result<(), CodecRefusal> {
    write_aggregate(out, event.aggregate);
    out.write_scalar(event.version.get());
    out.write_scalar(event.payload.kind());
    match &event.payload {
        ForgeEventPayload::PullRequestOpened {
            source_ref,
            target_ref,
            source_tip,
            target_tip,
        } => {
            out.write_bytes("source_ref", source_ref)?;
            out.write_bytes("target_ref", target_ref)?;
            out.write_digest(source_tip)?;
            out.write_digest(target_tip)?;
        }
        ForgeEventPayload::PullRequestHeadAdvanced { source_tip } => {
            out.write_digest(source_tip)?;
        }
        ForgeEventPayload::MergeCommitted {
            merge_commit,
            target_ref,
            target_tip_before,
            target_tip_after,
        } => {
            out.write_digest(merge_commit)?;
            out.write_bytes("target_ref", target_ref)?;
            out.write_digest(target_tip_before)?;
            out.write_digest(target_tip_after)?;
        }
        ForgeEventPayload::PullRequestClosed { withdrawn } => {
            out.write_bool(*withdrawn);
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
        KIND_HEAD_ADVANCED => ForgeEventPayload::PullRequestHeadAdvanced {
            source_tip: input.read_digest()?,
        },
        KIND_MERGE_COMMITTED => ForgeEventPayload::MergeCommitted {
            merge_commit: input.read_digest()?,
            target_ref: input.read_bytes("target_ref")?.to_vec(),
            target_tip_before: input.read_digest()?,
            target_tip_after: input.read_digest()?,
        },
        KIND_CLOSED => ForgeEventPayload::PullRequestClosed {
            withdrawn: input.read_bool("withdrawn")?,
        },
        unknown => {
            // Fail closed. A kind this build does not implement cannot be
            // skipped over, because its payload length is unknown and every
            // field after it would be read from the wrong offset. Guessing
            // would produce a confidently wrong body with a valid identity.
            return Err(CodecRefusal::VariantUnknown {
                field: "kind",
                observed: unknown,
                offset: kind_offset,
            });
        }
    };
    Ok(ForgeEvent {
        aggregate,
        version,
        payload,
    })
}

fn counter<T: Counter>(field: &'static str, value: u64) -> Result<T, CodecRefusal> {
    T::build(value).ok_or(CodecRefusal::ValueUnrepresentable {
        field,
        observed: value,
        limit: 1,
    })
}

trait Counter: Sized {
    fn build(value: u64) -> Option<Self>;
}

impl Counter for PullRequestNumber {
    fn build(value: u64) -> Option<Self> {
        Self::try_new(value)
    }
}

impl Counter for AggregateVersion {
    fn build(value: u64) -> Option<Self> {
        Self::try_new(value)
    }
}

impl Counter for OrganisationNumber {
    fn build(value: u64) -> Option<Self> {
        Self::try_new(value)
    }
}

impl Counter for TeamNumber {
    fn build(value: u64) -> Option<Self> {
        Self::try_new(value)
    }
}

impl CanonicalBody for ForgeEvent {
    const DOMAIN: DomainTag = ForgeEventId::DOMAIN_TAG;
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("forge-event");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        write_event(out, self)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        read_event(input)
    }
}

/// The immutable batch of forge events admitted by one decision.
///
/// A batch is ordered, not a set: two events on the same aggregate are only
/// meaningful in stream order, so sorting them by encoded bytes would destroy
/// the one property that makes them replayable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeEventBatch {
    /// The events, in the order they apply.
    pub events: Vec<ForgeEvent>,
}

impl ForgeEventBatch {
    /// A batch carrying exactly one event.
    #[must_use]
    pub fn of_one(event: ForgeEvent) -> Self {
        Self {
            events: vec![event],
        }
    }
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
        Ok(Self {
            events: input.read_sequence("events", read_event)?,
        })
    }
}

/// The identity of a forge event, computed from its canonical bytes.
///
/// # Errors
///
/// [`ForgeRefusal::BodyUnrepresentable`] when the event has no canonical bytes,
/// and [`ForgeRefusal::IdentityUnavailable`] when this build's registry does not
/// know the forge-event domain.
pub fn event_id<I>(identity: &I, event: &ForgeEvent) -> Result<ForgeEventId, ForgeRefusal>
where
    I: BodyIdentity + ?Sized,
{
    let object = body_id(identity, event).map_err(|cause| match cause {
        CodecRefusal::IdentityDomainUnregistered { .. } => {
            ForgeRefusal::IdentityUnavailable { body: "ForgeEvent" }
        }
        cause => ForgeRefusal::BodyUnrepresentable {
            cause: Box::new(cause),
        },
    })?;
    ForgeEventId::from_internal_object_id(object)
        .map_err(|_| ForgeRefusal::IdentityUnavailable { body: "ForgeEvent" })
}
