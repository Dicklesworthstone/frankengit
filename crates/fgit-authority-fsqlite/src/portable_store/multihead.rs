//! Version-two whole-store snapshots. Head slots are a sorted collection, not
//! an arbitrary winner. One global token ledger may interleave independent
//! per-slot generation histories. This format does not change stored bodies,
//! SQL schema generation, or version-one single-head exports.

use fgit_codec::{CanonicalBody, CodecRefusal, DecodeLimits, Decoder, Encoder};
use fgit_types::label::{DomainTag, SchemaFamily};

use super::{
    AuthorityLimits, BundleRefusal, ExportedBody, ExportedHead, ExportedIssuance,
    HeadKey, ImmutableKey, IssuanceSequence, PortableStoreError, PortableStoreLimits,
    SCHEMA_VERSION, StoreInstanceId, add_bytes, check_body, mint_token,
};

#[path = "multihead/store.rs"]
mod store;
#[cfg(test)]
#[path = "multihead/tests.rs"]
mod tests;

/// Independent hard bound on the number of head slots in a portable image.
pub const MAX_MULTI_HEADS: usize = 65_536;

/// Whole-store bounds, further restricted by the destination authority profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiHeadLimits {
    pub portable: PortableStoreLimits,
    pub max_heads: usize,
}

impl Default for MultiHeadLimits {
    fn default() -> Self {
        Self { portable: PortableStoreLimits::default(), max_heads: 4_096 }
    }
}

impl MultiHeadLimits {
    fn validate(self) -> Result<(), PortableStoreError> {
        self.portable.validate()?;
        if self.max_heads > MAX_MULTI_HEADS {
            return Err(PortableStoreError::InvalidLimits);
        }
        Ok(())
    }
}

/// An entire embedded authority image. This is metadata, not Git object fabric,
/// a signed repository capsule, a routing grant, or evidence of source trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiHeadSnapshot {
    pub schema_version: i64,
    pub instance: u64,
    /// Strictly increasing opaque body keys; no silently sorted input.
    pub bodies: Vec<ExportedBody>,
    /// Strictly increasing opaque head keys; all occupied slots are included.
    pub heads: Vec<ExportedHead>,
    /// The complete global issuance ledger, in contiguous sequence order.
    pub issuance: Vec<ExportedIssuance>,
}

fn bundle_error(error: BundleRefusal) -> PortableStoreError {
    PortableStoreError::Bundle(Box::new(error))
}

fn ordered(previous: &[u8], next: &[u8], collection: &'static str)
    -> Result<(), PortableStoreError>
{
    match previous.cmp(next) {
        std::cmp::Ordering::Less => Ok(()),
        std::cmp::Ordering::Equal => Err(bundle_error(BundleRefusal::Duplicated { collection })),
        std::cmp::Ordering::Greater => Err(bundle_error(BundleRefusal::OutOfOrder { collection })),
    }
}

impl MultiHeadSnapshot {
    /// Validate internal consistency and all declared allocation/work dimensions.
    /// This does not establish provenance, currency, or permission to restore.
    pub fn validate(&self, limits: MultiHeadLimits, authority: AuthorityLimits)
        -> Result<(), PortableStoreError>
    {
        self.validate_with(limits, authority, || Ok(()))
    }

    fn validate_with(&self, limits: MultiHeadLimits, authority: AuthorityLimits,
        mut checkpoint: impl FnMut() -> Result<(), PortableStoreError>,
    ) -> Result<(), PortableStoreError> {
        limits.validate()?;
        checkpoint()?;
        if self.schema_version != SCHEMA_VERSION {
            return Err(bundle_error(BundleRefusal::SchemaGenerationUnsupported {
                observed: self.schema_version, expected: SCHEMA_VERSION,
            }));
        }
        if self.instance > i64::MAX as u64 {
            return Err(PortableStoreError::InvalidSourceToken);
        }
        if self.bodies.len() > limits.portable.max_bodies.min(authority.immutable_slots) {
            return Err(PortableStoreError::Limit("immutable bodies"));
        }
        if self.issuance.len() > limits.portable.max_issuance.min(authority.version_tokens) {
            return Err(PortableStoreError::Limit("issuance rows"));
        }
        if self.heads.len() > limits.max_heads.min(authority.head_slots) {
            return Err(PortableStoreError::Limit("head slots"));
        }
        let maximum = limits.portable.max_field_bytes;
        let mut bytes = 0;
        // Charge each field before cloning keys or comparing large bodies.
        for (index, row) in self.bodies.iter().enumerate() {
            checkpoint()?;
            add_bytes(&mut bytes, row.key.len() as u64, maximum)?;
            add_bytes(&mut bytes, row.body.len() as u64, maximum)?;
            ImmutableKey::new(row.key.clone()).map_err(|_| PortableStoreError::InvalidKey)?;
            check_body(&row.body, authority)?;
            if index > 0 { ordered(&self.bodies[index - 1].key, &row.key, "bodies")?; }
        }
        for (index, head) in self.heads.iter().enumerate() {
            checkpoint()?;
            for field in [&head.key, &head.token, &head.body] {
                add_bytes(&mut bytes, field.len() as u64, maximum)?;
            }
            HeadKey::new(head.key.clone()).map_err(|_| PortableStoreError::InvalidKey)?;
            check_body(&head.body, authority)?;
            if index > 0 { ordered(&self.heads[index - 1].key, &head.key, "heads")?; }
        }
        // One ordinal per head, not an O(heads * issuance) scan or a second
        // cloned ledger. Generations are monotone per head, NOT globally.
        let mut tails: Vec<Option<usize>> = Vec::new();
        tails.try_reserve_exact(self.heads.len()).map_err(|_| PortableStoreError::Allocation)?;
        tails.resize(self.heads.len(), None);
        for (index, row) in self.issuance.iter().enumerate() {
            checkpoint()?;
            for field in [&row.token, &row.head_key, &row.body] {
                add_bytes(&mut bytes, field.len() as u64, maximum)?;
            }
            check_body(&row.body, authority)?;
            if row.sequence != index as u64 + 1 || row.generation == 0
                || row.generation > i64::MAX as u64
            { return Err(PortableStoreError::InvalidLineage); }
            let sequence = IssuanceSequence::new(row.sequence)
                .map_err(|_| PortableStoreError::InvalidSourceToken)?;
            if row.token.as_slice() != mint_token(StoreInstanceId::from_raw(self.instance), sequence)
                .to_opaque_bytes().as_slice()
            { return Err(PortableStoreError::InvalidSourceToken); }
            let head = self.heads.binary_search_by(|head| head.key.cmp(&row.head_key))
                .map_err(|_| PortableStoreError::InvalidLineage)?;
            if tails[head].is_some_and(|previous| self.issuance[previous].generation >= row.generation) {
                return Err(PortableStoreError::InvalidLineage);
            }
            tails[head] = Some(index);
        }
        for (head, tail) in self.heads.iter().zip(tails) {
            checkpoint()?;
            let row = &self.issuance[tail.ok_or(PortableStoreError::InvalidLineage)?];
            if head.token != row.token || head.generation != row.generation || head.body != row.body {
                return Err(bundle_error(BundleRefusal::HeadContradictsIssuance {
                    field: "latest issuance for this head slot",
                }));
            }
        }
        checkpoint()
    }
}

impl CanonicalBody for MultiHeadSnapshot {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/backup-export-bundle/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("authority-export");
    const SCHEMA_MAJOR: u16 = 2;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(self.schema_version);
        out.write_scalar(self.instance);
        out.write_sequence("bodies", &self.bodies, |out, row| {
            out.write_bytes("body_key", &row.key)?;
            out.write_bytes("body_bytes", &row.body)
        })?;
        out.write_sequence("heads", &self.heads, |out, head| {
            out.write_bytes("head_key", &head.key)?;
            out.write_bytes("head_token", &head.token)?;
            out.write_scalar(head.generation);
            out.write_bytes("head_body", &head.body)
        })?;
        out.write_sequence("issuance", &self.issuance, |out, row| {
            out.write_bytes("token", &row.token)?;
            out.write_scalar(row.sequence);
            out.write_bytes("issued_head_key", &row.head_key)?;
            out.write_scalar(row.generation);
            out.write_bytes("issued_body", &row.body)
        })
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let schema_version = input.read_scalar::<i64>("schema_version")?;
        let instance = input.read_scalar::<u64>("instance")?;
        let bodies = input.read_sequence("bodies", |input| {
            Ok(ExportedBody {
                key: input.read_bytes("body_key")?.to_vec(),
                body: input.read_bytes("body_bytes")?.to_vec(),
            })
        })?;
        let heads = input.read_sequence("heads", |input| {
            Ok(ExportedHead {
                key: input.read_bytes("head_key")?.to_vec(),
                token: input.read_bytes("head_token")?.to_vec(),
                generation: input.read_scalar::<u64>("head_generation")?,
                body: input.read_bytes("head_body")?.to_vec(),
            })
        })?;
        let issuance = input.read_sequence("issuance", |input| {
            Ok(ExportedIssuance {
                token: input.read_bytes("token")?.to_vec(),
                sequence: input.read_scalar::<u64>("sequence")?,
                head_key: input.read_bytes("issued_head_key")?.to_vec(),
                generation: input.read_scalar::<u64>("issued_generation")?,
                body: input.read_bytes("issued_body")?.to_vec(),
            })
        })?;
        Ok(Self { schema_version, instance, bodies, heads, issuance })
    }
}

/// Encode the v2 image without changing or silently upgrading the v1 format.
pub fn encode_multi_head_snapshot(snapshot: &MultiHeadSnapshot, limits: MultiHeadLimits,
    authority: AuthorityLimits,
) -> Result<Vec<u8>, PortableStoreError> {
    snapshot.validate(limits, authority)?;
    fgit_codec::encode_body(snapshot).map_err(|error| bundle_error(BundleRefusal::Codec(error)))
}

/// Decode the bounded v2 envelope and then validate every per-slot history.
/// The canonical codec has independent preallocation/decode limits. No fallback
/// attempts to reinterpret a refused v2 image as a v1 image (or conversely).
pub fn decode_multi_head_snapshot(bytes: &[u8], limits: MultiHeadLimits,
    authority: AuthorityLimits,
) -> Result<MultiHeadSnapshot, PortableStoreError> {
    limits.validate()?;
    let snapshot: MultiHeadSnapshot = fgit_codec::decode_body(bytes, DecodeLimits::DEFAULT)
        .map_err(|error| bundle_error(BundleRefusal::Codec(error)))?;
    snapshot.validate(limits, authority)?;
    Ok(snapshot)
}
