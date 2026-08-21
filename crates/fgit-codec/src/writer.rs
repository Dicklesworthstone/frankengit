//! The canonical encoder.
//!
//! Every value has exactly one byte string. Integers are fixed-width
//! big-endian, so there is no shortest-form rule to get wrong. Byte strings
//! and text carry an explicit `u32` length. Collections that are logically
//! unordered are sorted by their own encoded bytes, so a caller cannot change
//! the output by changing the order it happened to build its input in.

use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::InternalObjectId;
use fgit_types::numeric::{CanonicalScalar, CodecVersion};
use fgit_types::{
    DomainTag, GitHashAlgorithm, GitOid, RefName, SchemaId, OPAQUE_ID_LEN,
};

use crate::error::CodecRefusal;

/// Builds canonical bytes.
#[derive(Clone, Debug, Default)]
pub struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    /// A new empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { out: Vec::new() }
    }

    /// A new empty encoder with room reserved.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            out: Vec::with_capacity(capacity),
        }
    }

    /// The bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.out
    }

    /// Consumes the encoder and yields its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.out.len()
    }

    /// True when nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    fn position(&self) -> u64 {
        u64::try_from(self.out.len()).unwrap_or(u64::MAX)
    }

    /// Writes a fixed-width integer, big-endian.
    ///
    /// The bound is the trait: `usize`, `isize`, and floating point do not
    /// implement [`CanonicalScalar`], so they cannot reach the output.
    pub fn write_scalar<T: CanonicalScalar>(&mut self, value: T) {
        let bits = value.to_canonical_bits().to_be_bytes();
        let width = T::WIDTH.byte_len();
        self.out.extend_from_slice(&bits[bits.len() - width..]);
    }

    /// Writes a single byte verbatim.
    pub fn write_raw_byte(&mut self, byte: u8) {
        self.out.push(byte);
    }

    /// Writes bytes verbatim, with no length prefix.
    ///
    /// Only for fixed-width components whose length the schema already fixes.
    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    /// Writes a boolean as `0x00` or `0x01`.
    pub fn write_bool(&mut self, value: bool) {
        self.out.push(u8::from(value));
    }

    fn write_count(&mut self, field: &'static str, count: usize) -> Result<(), CodecRefusal> {
        let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
            field,
            observed: u64::try_from(count).unwrap_or(u64::MAX),
            limit: u64::from(u32::MAX),
        })?;
        self.write_scalar(count);
        Ok(())
    }

    /// Writes a length-prefixed byte string.
    pub fn write_bytes(&mut self, field: &'static str, value: &[u8]) -> Result<(), CodecRefusal> {
        self.write_count(field, value.len())?;
        self.out.extend_from_slice(value);
        Ok(())
    }

    /// Writes length-prefixed text.
    ///
    /// Text is `UTF-8` by construction on this side; the decoder verifies it,
    /// so a body that arrived from elsewhere cannot smuggle other bytes in.
    pub fn write_text(&mut self, field: &'static str, value: &str) -> Result<(), CodecRefusal> {
        self.write_bytes(field, value.as_bytes())
    }

    /// Writes an optional value: a tag byte, then the value when present.
    pub fn write_option<T, F>(
        &mut self,
        value: Option<&T>,
        mut write: F,
    ) -> Result<(), CodecRefusal>
    where
        F: FnMut(&mut Self, &T) -> Result<(), CodecRefusal>,
    {
        match value {
            None => {
                self.out.push(0x00);
                Ok(())
            }
            Some(inner) => {
                self.out.push(0x01);
                write(self, inner)
            }
        }
    }

    /// Writes a sequence whose order is part of its meaning.
    ///
    /// Use this only where the order is semantic, such as the decisions inside
    /// one batch. Anything logically unordered uses
    /// [`Encoder::write_canonical_set`] instead.
    pub fn write_sequence<T, F>(
        &mut self,
        field: &'static str,
        items: &[T],
        mut write: F,
    ) -> Result<(), CodecRefusal>
    where
        F: FnMut(&mut Self, &T) -> Result<(), CodecRefusal>,
    {
        self.write_count(field, items.len())?;
        for item in items {
            write(self, item)?;
        }
        Ok(())
    }

    /// Writes a logically unordered collection in canonical order.
    ///
    /// Elements are sorted by their own encoded bytes and a repeat is refused,
    /// so the same set of values always produces the same bytes no matter what
    /// order the caller supplied them in.
    pub fn write_canonical_set<T, F>(
        &mut self,
        field: &'static str,
        items: &[T],
        mut write: F,
    ) -> Result<(), CodecRefusal>
    where
        F: FnMut(&mut Self, &T) -> Result<(), CodecRefusal>,
    {
        let offset = self.position();
        let mut encoded = Vec::with_capacity(items.len());
        for item in items {
            let mut scratch = Self::new();
            write(&mut scratch, item)?;
            encoded.push(scratch.into_bytes());
        }
        encoded.sort_unstable();
        for index in 1..encoded.len() {
            if encoded[index - 1] == encoded[index] {
                return Err(CodecRefusal::CollectionDuplicate {
                    field,
                    index: u64::try_from(index).unwrap_or(u64::MAX),
                    offset,
                });
            }
        }
        self.write_count(field, encoded.len())?;
        for element in encoded {
            self.out.extend_from_slice(&element);
        }
        Ok(())
    }

    /// Writes a key-to-value collection in canonical order.
    ///
    /// Entries are sorted by encoded key and a repeated key is refused. There
    /// is therefore no such thing as a map whose meaning depends on iteration
    /// order, and no such thing as a map with two values for one key.
    pub fn write_canonical_map<K, V, FK, FV>(
        &mut self,
        field: &'static str,
        entries: &[(K, V)],
        mut write_key: FK,
        mut write_value: FV,
    ) -> Result<(), CodecRefusal>
    where
        FK: FnMut(&mut Self, &K) -> Result<(), CodecRefusal>,
        FV: FnMut(&mut Self, &V) -> Result<(), CodecRefusal>,
    {
        let offset = self.position();
        let mut encoded = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            let mut key_scratch = Self::new();
            write_key(&mut key_scratch, key)?;
            let mut value_scratch = Self::new();
            write_value(&mut value_scratch, value)?;
            encoded.push((key_scratch.into_bytes(), value_scratch.into_bytes()));
        }
        encoded.sort_unstable();
        for index in 1..encoded.len() {
            if encoded[index - 1].0 == encoded[index].0 {
                return Err(CodecRefusal::CollectionDuplicate {
                    field,
                    index: u64::try_from(index).unwrap_or(u64::MAX),
                    offset,
                });
            }
        }
        self.write_count(field, encoded.len())?;
        for (key, value) in encoded {
            self.out.extend_from_slice(&key);
            self.out.extend_from_slice(&value);
        }
        Ok(())
    }

    /// Writes a codec version as two fixed-width components.
    pub fn write_codec_version(&mut self, version: CodecVersion) {
        self.write_scalar(version.major());
        self.write_scalar(version.minor());
    }

    /// Writes a domain separation tag as a length-prefixed label.
    pub fn write_domain_tag(&mut self, tag: DomainTag) -> Result<(), CodecRefusal> {
        self.write_bytes("DomainTag", tag.as_bytes())
    }

    /// Writes a schema identifier: family label, then major and minor.
    pub fn write_schema_id(&mut self, schema: SchemaId) -> Result<(), CodecRefusal> {
        self.write_bytes("SchemaFamily", schema.family().as_bytes())?;
        self.write_scalar(schema.major());
        self.write_scalar(schema.minor());
        Ok(())
    }

    /// Writes a digest body as a length-prefixed byte string.
    pub fn write_digest_bytes(&mut self, digest: &DigestBytes) -> Result<(), CodecRefusal> {
        self.write_bytes("DigestBytes", digest.as_bytes())
    }

    /// Writes an algorithm-tagged digest.
    pub fn write_digest(&mut self, digest: &Digest) -> Result<(), CodecRefusal> {
        self.write_scalar(digest.algorithm().code_point());
        self.write_digest_bytes(digest.bytes())
    }

    /// Writes an internal object identity as its four components.
    pub fn write_internal_object_id(
        &mut self,
        id: &InternalObjectId,
    ) -> Result<(), CodecRefusal> {
        self.write_scalar(id.algorithm().code_point());
        self.write_domain_tag(id.domain())?;
        self.write_codec_version(id.codec_version());
        self.write_digest_bytes(id.digest())
    }

    /// Writes a 128-bit assigned identity verbatim.
    ///
    /// The width is fixed by the type, so no length prefix is needed.
    pub fn write_opaque_id(&mut self, bytes: &[u8; OPAQUE_ID_LEN]) {
        self.out.extend_from_slice(bytes);
    }

    /// Writes a native Git object identity: algorithm, then raw digest.
    ///
    /// The algorithm is always explicit, so a SHA-1 identity and a SHA-256
    /// identity never share an encoding even when their bytes overlap.
    pub fn write_git_oid(&mut self, oid: &GitOid) {
        self.write_scalar(oid.algorithm().code_point());
        self.out.extend_from_slice(oid.as_bytes());
    }

    /// Writes a validated reference name as a length-prefixed byte string.
    pub fn write_ref_name(&mut self, name: &RefName) -> Result<(), CodecRefusal> {
        self.write_bytes("RefName", name.as_bytes())
    }

    /// Writes a Git hash algorithm code point.
    pub fn write_git_hash_algorithm(&mut self, algorithm: GitHashAlgorithm) {
        self.write_scalar(algorithm.code_point());
    }
}
