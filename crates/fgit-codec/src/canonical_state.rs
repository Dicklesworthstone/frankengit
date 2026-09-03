//! Canonical persisted forge-position and outbox state bodies.
//!
//! The repository authority head publishes `forge_position_root` and
//! `outbox_root`; these shared bodies make those roots independently resolvable.
//! Transition legality remains in `fgit-reference`. This module owns bounded,
//! repository-scoped, canonically ordered bytes and deterministic roots only.
//!
//! Both bodies use the registered `frankengit/generation/v1` identity domain
//! with distinct schema families, so equal payload bytes cannot cross types.

use core::cmp::Ordering;

use fgit_types::{
    AsciiSlug, Digest, DomainTag, RepositoryCommitId, RepositoryId, SchemaFamily, TxId,
};

use crate::{CanonicalBody, CodecRefusal, CryptoBodyIdentity, Decoder, Encoder, body_id};

/// Permanent forge-position entry ceiling for schema v1.
pub const MAX_FORGE_POSITION_STATE_ENTRIES: usize = 16_384;
/// Permanent outbox entry ceiling for schema v1.
pub const MAX_OUTBOX_STATE_ENTRIES: usize = 16_384;

const STATE_DOMAIN: DomainTag = DomainTag::from_static("frankengit/generation/v1");

/// One stream's latest canonical forge-position transition.
///
/// The successor is derived instead of encoded redundantly, preventing a body
/// from claiming a contradictory predecessor/count/successor triple.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ForgePositionStateEntry {
    stream: AsciiSlug,
    predecessor_position: u64,
    event_count: u32,
    event_batch_root: Digest,
}

impl ForgePositionStateEntry {
    /// Creates one valid nonempty position range.
    ///
    /// # Errors
    ///
    /// Refuses zero events and arithmetic overflow.
    pub fn try_new(
        stream: AsciiSlug,
        predecessor_position: u64,
        event_count: u32,
        event_batch_root: Digest,
    ) -> Result<Self, CodecRefusal> {
        validate_position_range(predecessor_position, event_count)?;
        Ok(Self {
            stream,
            predecessor_position,
            event_count,
            event_batch_root,
        })
    }

    /// Canonical stream label.
    #[must_use]
    pub const fn stream(&self) -> AsciiSlug {
        self.stream
    }

    /// Position before the retained event batch.
    #[must_use]
    pub const fn predecessor_position(&self) -> u64 {
        self.predecessor_position
    }

    /// Number of ordered events in the batch.
    #[must_use]
    pub const fn event_count(&self) -> u32 {
        self.event_count
    }

    /// Position after the retained event batch.
    #[must_use]
    pub fn successor_position(&self) -> u64 {
        self.predecessor_position + u64::from(self.event_count)
    }

    /// Immutable event-batch commitment.
    #[must_use]
    pub const fn event_batch_root(&self) -> Digest {
        self.event_batch_root
    }
}

/// Repository-scoped canonical forge-position state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalForgePositionState {
    repository_id: RepositoryId,
    entries: Vec<ForgePositionStateEntry>,
}

impl CanonicalForgePositionState {
    /// Builds a canonical map independent of caller iteration order.
    ///
    /// # Errors
    ///
    /// Refuses an oversized map or a duplicate stream.
    pub fn try_new(
        repository_id: RepositoryId,
        mut entries: Vec<ForgePositionStateEntry>,
    ) -> Result<Self, CodecRefusal> {
        check_entry_count(
            "forge_positions",
            entries.len(),
            MAX_FORGE_POSITION_STATE_ENTRIES,
        )?;
        entries.sort_unstable_by(compare_forge_entries);
        reject_duplicate_forge_streams(&entries)?;
        Ok(Self {
            repository_id,
            entries,
        })
    }

    /// Repository namespace.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Entries in canonical encoded-key order.
    #[must_use]
    pub fn entries(&self) -> &[ForgePositionStateEntry] {
        &self.entries
    }

    /// Looks up one stream.
    #[must_use]
    pub fn entry(&self, stream: AsciiSlug) -> Option<&ForgePositionStateEntry> {
        self.entries
            .binary_search_by(|entry| compare_slug(entry.stream, stream))
            .ok()
            .map(|index| &self.entries[index])
    }

    /// Deterministic authenticated root.
    ///
    /// # Errors
    ///
    /// Refuses canonical encoding or registered-domain identity failure.
    pub fn root(&self) -> Result<Digest, CodecRefusal> {
        canonical_state_root(self)
    }
}

impl CanonicalBody for CanonicalForgePositionState {
    const DOMAIN: DomainTag = STATE_DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("forge-position-state");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        check_entry_count(
            "forge_positions",
            self.entries.len(),
            MAX_FORGE_POSITION_STATE_ENTRIES,
        )?;
        reject_duplicate_forge_streams(&self.entries)?;
        out.write_opaque_id(self.repository_id.as_bytes());
        let values: Vec<(AsciiSlug, ForgePositionValue)> = self
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.stream,
                    ForgePositionValue {
                        predecessor_position: entry.predecessor_position,
                        event_count: entry.event_count,
                        event_batch_root: entry.event_batch_root,
                    },
                )
            })
            .collect();
        out.write_canonical_map(
            "forge_positions",
            &values,
            |out, stream| out.write_bytes("forge_stream", stream.as_bytes()),
            |out, value| {
                validate_position_range(value.predecessor_position, value.event_count)?;
                out.write_scalar(value.predecessor_position);
                out.write_scalar(value.event_count);
                out.write_digest(&value.event_batch_root)
            },
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let values = read_bounded_slug_map(
            input,
            "forge_positions",
            "forge_stream",
            MAX_FORGE_POSITION_STATE_ENTRIES,
            |input| {
                let predecessor_position = input.read_scalar::<u64>("predecessor_position")?;
                let event_count = input.read_scalar::<u32>("event_count")?;
                validate_position_range(predecessor_position, event_count)?;
                Ok(ForgePositionValue {
                    predecessor_position,
                    event_count,
                    event_batch_root: input.read_digest()?,
                })
            },
        )?;
        Ok(Self {
            repository_id,
            entries: values
                .into_iter()
                .map(|(stream, value)| ForgePositionStateEntry {
                    stream,
                    predecessor_position: value.predecessor_position,
                    event_count: value.event_count,
                    event_batch_root: value.event_batch_root,
                })
                .collect(),
        })
    }
}

#[derive(Clone, Copy)]
struct ForgePositionValue {
    predecessor_position: u64,
    event_count: u32,
    event_batch_root: Digest,
}

/// One stable delivery-key binding in canonical outbox state.
///
/// `effect_state_root` points at the existing effect/obligation state rather
/// than duplicating that state machine. `tx_id` and `predecessor_rcr_id` form a
/// non-circular transition basis: the resulting RCR commits this outbox root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalOutboxStateEntry {
    delivery_key: AsciiSlug,
    effect_class: AsciiSlug,
    destination: AsciiSlug,
    payload_root: Digest,
    tx_id: TxId,
    predecessor_rcr_id: Option<RepositoryCommitId>,
    effect_state_root: Digest,
    predecessor_effect_state_root: Option<Digest>,
}

impl CanonicalOutboxStateEntry {
    /// Creates one typed immutable outbox binding.
    #[must_use]
    pub const fn new(
        delivery_key: AsciiSlug,
        effect_class: AsciiSlug,
        destination: AsciiSlug,
        payload_root: Digest,
        tx_id: TxId,
        predecessor_rcr_id: Option<RepositoryCommitId>,
        effect_state_root: Digest,
        predecessor_effect_state_root: Option<Digest>,
    ) -> Self {
        Self {
            delivery_key,
            effect_class,
            destination,
            payload_root,
            tx_id,
            predecessor_rcr_id,
            effect_state_root,
            predecessor_effect_state_root,
        }
    }

    /// Stable idempotency/delivery identity.
    #[must_use]
    pub const fn delivery_key(&self) -> AsciiSlug {
        self.delivery_key
    }

    /// Stable effect class.
    #[must_use]
    pub const fn effect_class(&self) -> AsciiSlug {
        self.effect_class
    }

    /// Stable destination or audience.
    #[must_use]
    pub const fn destination(&self) -> AsciiSlug {
        self.destination
    }

    /// Immutable payload commitment.
    #[must_use]
    pub const fn payload_root(&self) -> Digest {
        self.payload_root
    }

    /// Sealed transaction producing this obligation.
    #[must_use]
    pub const fn tx_id(&self) -> TxId {
        self.tx_id
    }

    /// Previously committed RCR at the transition basis.
    #[must_use]
    pub const fn predecessor_rcr_id(&self) -> Option<RepositoryCommitId> {
        self.predecessor_rcr_id
    }

    /// Current canonical effect/obligation-state commitment.
    #[must_use]
    pub const fn effect_state_root(&self) -> Digest {
        self.effect_state_root
    }

    /// Prior effect-state commitment, when one exists.
    #[must_use]
    pub const fn predecessor_effect_state_root(&self) -> Option<Digest> {
        self.predecessor_effect_state_root
    }
}

/// Repository-scoped canonical outbox index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalOutboxState {
    repository_id: RepositoryId,
    entries: Vec<CanonicalOutboxStateEntry>,
}

impl CanonicalOutboxState {
    /// Builds a canonical map independent of caller iteration order.
    ///
    /// # Errors
    ///
    /// Refuses an oversized map or a duplicate delivery key.
    pub fn try_new(
        repository_id: RepositoryId,
        mut entries: Vec<CanonicalOutboxStateEntry>,
    ) -> Result<Self, CodecRefusal> {
        check_entry_count("outbox_entries", entries.len(), MAX_OUTBOX_STATE_ENTRIES)?;
        entries.sort_unstable_by(compare_outbox_entries);
        reject_duplicate_delivery_keys(&entries)?;
        Ok(Self {
            repository_id,
            entries,
        })
    }

    /// Repository namespace.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Entries in canonical encoded-key order.
    #[must_use]
    pub fn entries(&self) -> &[CanonicalOutboxStateEntry] {
        &self.entries
    }

    /// Looks up one stable delivery key.
    #[must_use]
    pub fn entry(&self, delivery_key: AsciiSlug) -> Option<&CanonicalOutboxStateEntry> {
        self.entries
            .binary_search_by(|entry| compare_slug(entry.delivery_key, delivery_key))
            .ok()
            .map(|index| &self.entries[index])
    }

    /// Deterministic authenticated root.
    ///
    /// # Errors
    ///
    /// Refuses canonical encoding or registered-domain identity failure.
    pub fn root(&self) -> Result<Digest, CodecRefusal> {
        canonical_state_root(self)
    }
}

impl CanonicalBody for CanonicalOutboxState {
    const DOMAIN: DomainTag = STATE_DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("outbox-state");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        check_entry_count(
            "outbox_entries",
            self.entries.len(),
            MAX_OUTBOX_STATE_ENTRIES,
        )?;
        reject_duplicate_delivery_keys(&self.entries)?;
        out.write_opaque_id(self.repository_id.as_bytes());
        let values: Vec<(AsciiSlug, OutboxStateValue)> = self
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.delivery_key,
                    OutboxStateValue {
                        effect_class: entry.effect_class,
                        destination: entry.destination,
                        payload_root: entry.payload_root,
                        tx_id: entry.tx_id,
                        predecessor_rcr_id: entry.predecessor_rcr_id,
                        effect_state_root: entry.effect_state_root,
                        predecessor_effect_state_root: entry.predecessor_effect_state_root,
                    },
                )
            })
            .collect();
        out.write_canonical_map(
            "outbox_entries",
            &values,
            |out, delivery_key| out.write_bytes("outbox_delivery_key", delivery_key.as_bytes()),
            |out, value| {
                out.write_bytes("outbox_effect_class", value.effect_class.as_bytes())?;
                out.write_bytes("outbox_destination", value.destination.as_bytes())?;
                out.write_digest(&value.payload_root)?;
                out.write_internal_object_id(value.tx_id.as_internal_object_id())?;
                out.write_option(value.predecessor_rcr_id.as_ref(), |out, rcr_id| {
                    out.write_internal_object_id(rcr_id.as_internal_object_id())
                })?;
                out.write_digest(&value.effect_state_root)?;
                out.write_option(
                    value.predecessor_effect_state_root.as_ref(),
                    Encoder::write_digest,
                )
            },
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let values = read_bounded_slug_map(
            input,
            "outbox_entries",
            "outbox_delivery_key",
            MAX_OUTBOX_STATE_ENTRIES,
            |input| {
                let effect_class = AsciiSlug::try_new(
                    "outbox_effect_class",
                    input.read_bytes("outbox_effect_class")?,
                )
                .map_err(CodecRefusal::from)?;
                let destination = AsciiSlug::try_new(
                    "outbox_destination",
                    input.read_bytes("outbox_destination")?,
                )
                .map_err(CodecRefusal::from)?;
                let payload_root = input.read_digest()?;
                let tx_id = TxId::from_internal_object_id(input.read_internal_object_id()?)
                    .map_err(CodecRefusal::from)?;
                let predecessor_rcr_id = input.read_option("predecessor_rcr_id", |input| {
                    RepositoryCommitId::from_internal_object_id(input.read_internal_object_id()?)
                        .map_err(CodecRefusal::from)
                })?;
                let effect_state_root = input.read_digest()?;
                let predecessor_effect_state_root =
                    input.read_option("predecessor_effect_state_root", Decoder::read_digest)?;
                Ok(OutboxStateValue {
                    effect_class,
                    destination,
                    payload_root,
                    tx_id,
                    predecessor_rcr_id,
                    effect_state_root,
                    predecessor_effect_state_root,
                })
            },
        )?;
        Ok(Self {
            repository_id,
            entries: values
                .into_iter()
                .map(|(delivery_key, value)| CanonicalOutboxStateEntry {
                    delivery_key,
                    effect_class: value.effect_class,
                    destination: value.destination,
                    payload_root: value.payload_root,
                    tx_id: value.tx_id,
                    predecessor_rcr_id: value.predecessor_rcr_id,
                    effect_state_root: value.effect_state_root,
                    predecessor_effect_state_root: value.predecessor_effect_state_root,
                })
                .collect(),
        })
    }
}

#[derive(Clone, Copy)]
struct OutboxStateValue {
    effect_class: AsciiSlug,
    destination: AsciiSlug,
    payload_root: Digest,
    tx_id: TxId,
    predecessor_rcr_id: Option<RepositoryCommitId>,
    effect_state_root: Digest,
    predecessor_effect_state_root: Option<Digest>,
}

fn read_bounded_slug_map<V, F>(
    input: &mut Decoder<'_>,
    collection_field: &'static str,
    key_field: &'static str,
    schema_limit: usize,
    mut read_value: F,
) -> Result<Vec<(AsciiSlug, V)>, CodecRefusal>
where
    F: FnMut(&mut Decoder<'_>) -> Result<V, CodecRefusal>,
{
    if input.limits().depth == 0 {
        return Err(CodecRefusal::DepthBoundExceeded {
            limit: 0,
            offset: input.offset(),
        });
    }
    let collection_offset = input.offset();
    let declared = u64::from(input.read_scalar::<u32>(collection_field)?);
    let permanent_limit = u64::try_from(schema_limit).unwrap_or(u64::MAX);
    let limit = input.limits().elements.min(permanent_limit);
    if declared > limit {
        return Err(CodecRefusal::CountBoundExceeded {
            field: collection_field,
            observed: declared,
            limit,
        });
    }
    let available = u64::try_from(input.remaining()).unwrap_or(u64::MAX);
    if declared > available {
        return Err(CodecRefusal::CountBoundExceeded {
            field: collection_field,
            observed: declared,
            limit: available,
        });
    }
    let count = usize::try_from(declared).map_err(|_| CodecRefusal::CountBoundExceeded {
        field: collection_field,
        observed: declared,
        limit,
    })?;
    let mut values = Vec::with_capacity(count);
    let mut previous: Option<AsciiSlug> = None;
    for index in 0..count {
        let key = AsciiSlug::try_new(key_field, input.read_bytes(key_field)?)
            .map_err(CodecRefusal::from)?;
        if let Some(previous) = previous {
            let index = u64::try_from(index).unwrap_or(u64::MAX);
            match compare_slug(previous, key) {
                Ordering::Equal => {
                    return Err(CodecRefusal::CollectionDuplicate {
                        field: collection_field,
                        index,
                        offset: collection_offset,
                    });
                }
                Ordering::Greater => {
                    return Err(CodecRefusal::CollectionUnordered {
                        field: collection_field,
                        index,
                        offset: collection_offset,
                    });
                }
                Ordering::Less => {}
            }
        }
        previous = Some(key);
        values.push((key, read_value(input)?));
    }
    Ok(values)
}

fn canonical_state_root<B: CanonicalBody>(body: &B) -> Result<Digest, CodecRefusal> {
    let identity = body_id(&CryptoBodyIdentity, body)?;
    Ok(Digest::new(identity.algorithm(), *identity.digest()))
}

fn validate_position_range(
    predecessor_position: u64,
    event_count: u32,
) -> Result<(), CodecRefusal> {
    if event_count == 0 {
        return Err(CodecRefusal::VariantUnknown {
            field: "event_count",
            observed: 0,
            offset: 0,
        });
    }
    predecessor_position
        .checked_add(u64::from(event_count))
        .ok_or(CodecRefusal::ValueUnrepresentable {
            field: "successor_position",
            observed: predecessor_position,
            limit: u64::MAX - u64::from(event_count),
        })?;
    Ok(())
}

fn check_entry_count(
    field: &'static str,
    observed: usize,
    limit: usize,
) -> Result<(), CodecRefusal> {
    if observed > limit {
        return Err(CodecRefusal::CountBoundExceeded {
            field,
            observed: u64::try_from(observed).unwrap_or(u64::MAX),
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

fn compare_slug(left: AsciiSlug, right: AsciiSlug) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn compare_forge_entries(
    left: &ForgePositionStateEntry,
    right: &ForgePositionStateEntry,
) -> Ordering {
    compare_slug(left.stream, right.stream)
}

fn compare_outbox_entries(
    left: &CanonicalOutboxStateEntry,
    right: &CanonicalOutboxStateEntry,
) -> Ordering {
    compare_slug(left.delivery_key, right.delivery_key)
}

fn reject_duplicate_forge_streams(entries: &[ForgePositionStateEntry]) -> Result<(), CodecRefusal> {
    for (index, adjacent) in entries.windows(2).enumerate() {
        if adjacent[0].stream == adjacent[1].stream {
            return Err(CodecRefusal::CollectionDuplicate {
                field: "forge_positions",
                index: u64::try_from(index + 1).unwrap_or(u64::MAX),
                offset: 0,
            });
        }
    }
    Ok(())
}

fn reject_duplicate_delivery_keys(
    entries: &[CanonicalOutboxStateEntry],
) -> Result<(), CodecRefusal> {
    for (index, adjacent) in entries.windows(2).enumerate() {
        if adjacent[0].delivery_key == adjacent[1].delivery_key {
            return Err(CodecRefusal::CollectionDuplicate {
                field: "outbox_entries",
                index: u64::try_from(index + 1).unwrap_or(u64::MAX),
                offset: 0,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use fgit_types::{DigestAlgorithmId, DigestBytes};

    use super::*;
    use crate::DecodeLimits;

    fn slug(value: &'static str) -> AsciiSlug {
        AsciiSlug::from_static(value)
    }

    fn digest(byte: u8) -> Digest {
        Digest::new(
            DigestAlgorithmId::try_new(2).expect("registered SHA-256 code point"),
            DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest"),
        )
    }

    #[test]
    fn constructor_order_matches_canonical_encoded_key_order() {
        let state = CanonicalForgePositionState::try_new(
            RepositoryId::from_bytes([0x11; 16]),
            vec![
                ForgePositionStateEntry::try_new(slug("zz"), 0, 1, digest(1)).expect("entry"),
                ForgePositionStateEntry::try_new(slug("a"), 2, 1, digest(2)).expect("entry"),
            ],
        )
        .expect("state");
        assert_eq!(state.entries()[0].stream(), slug("a"));
        assert_eq!(state.entries()[1].stream(), slug("zz"));
    }

    #[test]
    fn zero_count_and_overflow_are_refused() {
        assert!(matches!(
            ForgePositionStateEntry::try_new(slug("pulls"), 0, 0, digest(1)),
            Err(CodecRefusal::VariantUnknown {
                field: "event_count",
                observed: 0,
                ..
            })
        ));
        assert!(matches!(
            ForgePositionStateEntry::try_new(slug("pulls"), u64::MAX, 1, digest(1)),
            Err(CodecRefusal::ValueUnrepresentable {
                field: "successor_position",
                ..
            })
        ));
    }

    #[test]
    fn permanent_schema_limit_precedes_collection_allocation() {
        let mut payload = vec![0x11; 16];
        payload.extend_from_slice(
            &u32::try_from(MAX_FORGE_POSITION_STATE_ENTRIES + 1)
                .expect("schema limit fits u32")
                .to_be_bytes(),
        );
        let mut decoder = Decoder::new(&payload, DecodeLimits::DEFAULT);

        assert_eq!(
            CanonicalForgePositionState::read_payload(&mut decoder)
                .expect_err("schema limit must beat the generic decoder limit"),
            CodecRefusal::CountBoundExceeded {
                field: "forge_positions",
                observed: u64::try_from(MAX_FORGE_POSITION_STATE_ENTRIES + 1)
                    .expect("schema limit fits u64"),
                limit: u64::try_from(MAX_FORGE_POSITION_STATE_ENTRIES)
                    .expect("schema limit fits u64"),
            }
        );
    }
}
