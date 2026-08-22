//! The bounded canonical decoder.
//!
//! Reading is total: every path either produces a value or a
//! [`CodecRefusal`] naming what was expected, what was observed, and where.
//! Lengths and counts are checked against [`DecodeLimits`] and against the
//! bytes actually remaining before anything is reserved, so a declared length
//! can never cause an allocation the input does not back.
//!
//! Canonical order is re-verified on the way in. An encoder sorts a set; a
//! decoder refuses one that is not sorted. Without that second check a peer
//! could hand over two different byte strings for the same value, and the
//! one-byte-string-per-value rule would hold only for bodies this process
//! happened to write itself.

use fgit_crypto::DigestAlgorithm;
use fgit_types::hash::{Digest, DigestAlgorithmId, DigestBytes};
use fgit_types::identity::InternalObjectId;
use fgit_types::numeric::{CanonicalScalar, CodecVersion};
use fgit_types::{
    DomainTag, GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, OPAQUE_ID_LEN, RefName,
    SchemaFamily, SchemaId,
};

use crate::bounds::DecodeLimits;
use crate::error::CodecRefusal;

/// Reads canonical bytes under explicit bounds.
#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
    depth: u32,
    limits: DecodeLimits,
}

impl<'a> Decoder<'a> {
    /// A decoder over `input`, enforcing `limits`.
    #[must_use]
    pub const fn new(input: &'a [u8], limits: DecodeLimits) -> Self {
        Self {
            input,
            offset: 0,
            depth: 0,
            limits,
        }
    }

    /// Bounds in force.
    #[must_use]
    pub const fn limits(&self) -> DecodeLimits {
        self.limits
    }

    /// Current read offset.
    #[must_use]
    pub fn offset(&self) -> u64 {
        u64::try_from(self.offset).unwrap_or(u64::MAX)
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }

    /// True when every byte has been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Asserts that the input is fully consumed.
    ///
    /// A canonical body has exactly one byte string, so a suffix means the
    /// bytes are not that body's bytes and are refused rather than ignored.
    pub fn finish(&self) -> Result<(), CodecRefusal> {
        if self.remaining() == 0 {
            return Ok(());
        }
        Err(CodecRefusal::TrailingBytes {
            offset: self.offset(),
            remaining: u64::try_from(self.remaining()).unwrap_or(u64::MAX),
        })
    }

    /// Takes exactly `count` bytes.
    pub fn take(&mut self, field: &'static str, count: usize) -> Result<&'a [u8], CodecRefusal> {
        if count > self.remaining() {
            return Err(CodecRefusal::InputTruncated {
                field,
                needed: u64::try_from(count).unwrap_or(u64::MAX),
                available: u64::try_from(self.remaining()).unwrap_or(u64::MAX),
                offset: self.offset(),
            });
        }
        let start = self.offset;
        self.offset += count;
        Ok(&self.input[start..self.offset])
    }

    /// Reads a fixed-width integer, big-endian.
    pub fn read_scalar<T: CanonicalScalar>(
        &mut self,
        field: &'static str,
    ) -> Result<T, CodecRefusal> {
        let width = T::WIDTH.byte_len();
        let bytes = self.take(field, width)?;
        let mut wide = [0_u8; 8];
        wide[8 - width..].copy_from_slice(bytes);
        T::from_canonical_bits(u64::from_be_bytes(wide)).map_err(CodecRefusal::from)
    }

    /// Reads one byte verbatim.
    pub fn read_raw_byte(&mut self, field: &'static str) -> Result<u8, CodecRefusal> {
        Ok(self.take(field, 1)?[0])
    }

    /// Reads a boolean, refusing any byte other than `0x00` or `0x01`.
    pub fn read_bool(&mut self, field: &'static str) -> Result<bool, CodecRefusal> {
        let offset = self.offset();
        match self.read_raw_byte(field)? {
            0x00 => Ok(false),
            0x01 => Ok(true),
            observed => Err(CodecRefusal::BooleanByteInvalid { observed, offset }),
        }
    }

    fn read_length(&mut self, field: &'static str, limit: u64) -> Result<usize, CodecRefusal> {
        let declared = u64::from(self.read_scalar::<u32>(field)?);
        if declared > limit {
            return Err(CodecRefusal::LengthBoundExceeded {
                field,
                observed: declared,
                limit,
            });
        }
        usize::try_from(declared).map_err(|_| CodecRefusal::LengthBoundExceeded {
            field,
            observed: declared,
            limit,
        })
    }

    fn read_count(&mut self, field: &'static str) -> Result<usize, CodecRefusal> {
        let declared = u64::from(self.read_scalar::<u32>(field)?);
        if declared > self.limits.elements {
            return Err(CodecRefusal::CountBoundExceeded {
                field,
                observed: declared,
                limit: self.limits.elements,
            });
        }
        // A collection cannot have more elements than there are bytes left to
        // hold them, so a huge count is refused before anything is reserved.
        // This relies on every element occupying at least one byte, which
        // holds for everything this codec can write: the shortest encoding of
        // anything, an absent optional, is one tag byte. A schema with a
        // genuinely zero-width element would make this bound reject a legal
        // body, so the assumption is stated rather than left implicit.
        let available = u64::try_from(self.remaining()).unwrap_or(u64::MAX);
        if declared > available {
            return Err(CodecRefusal::CountBoundExceeded {
                field,
                observed: declared,
                limit: available,
            });
        }
        usize::try_from(declared).map_err(|_| CodecRefusal::CountBoundExceeded {
            field,
            observed: declared,
            limit: self.limits.elements,
        })
    }

    /// Reads a length-prefixed byte string.
    pub fn read_bytes(&mut self, field: &'static str) -> Result<&'a [u8], CodecRefusal> {
        let length = self.read_length(field, self.limits.byte_string_bytes)?;
        self.take(field, length)
    }

    /// Reads length-prefixed text, refusing anything that is not `UTF-8`.
    pub fn read_text(&mut self, field: &'static str) -> Result<&'a str, CodecRefusal> {
        let offset = self.offset();
        let bytes = self.read_bytes(field)?;
        core::str::from_utf8(bytes).map_err(|_| CodecRefusal::TextNotUtf8 { field, offset })
    }

    /// Reads an optional value, refusing any tag other than `0x00` or `0x01`.
    pub fn read_option<T, F>(
        &mut self,
        field: &'static str,
        mut read: F,
    ) -> Result<Option<T>, CodecRefusal>
    where
        F: FnMut(&mut Self) -> Result<T, CodecRefusal>,
    {
        let offset = self.offset();
        match self.read_raw_byte(field)? {
            0x00 => Ok(None),
            0x01 => read(self).map(Some),
            observed => Err(CodecRefusal::OptionTagInvalid { observed, offset }),
        }
    }

    fn enter(&mut self) -> Result<(), CodecRefusal> {
        if self.depth >= self.limits.depth {
            return Err(CodecRefusal::DepthBoundExceeded {
                limit: self.limits.depth,
                offset: self.offset(),
            });
        }
        self.depth += 1;
        Ok(())
    }

    const fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Reads a sequence whose order is part of its meaning.
    pub fn read_sequence<T, F>(
        &mut self,
        field: &'static str,
        mut read: F,
    ) -> Result<Vec<T>, CodecRefusal>
    where
        F: FnMut(&mut Self) -> Result<T, CodecRefusal>,
    {
        self.enter()?;
        let count = self.read_count(field)?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(read(self)?);
        }
        self.leave();
        Ok(items)
    }

    /// Reads a logically unordered collection, re-verifying canonical order.
    ///
    /// Elements must be in strictly ascending encoded-byte order; equal
    /// neighbours are a duplicate and a descent is a non-canonical encoding.
    pub fn read_canonical_set<T, F>(
        &mut self,
        field: &'static str,
        mut read: F,
    ) -> Result<Vec<T>, CodecRefusal>
    where
        F: FnMut(&mut Self) -> Result<T, CodecRefusal>,
    {
        self.enter()?;
        let collection_offset = self.offset();
        let count = self.read_count(field)?;
        let mut items = Vec::with_capacity(count);
        let mut previous: Option<&'a [u8]> = None;
        for index in 0..count {
            let start = self.offset;
            let item = read(self)?;
            let element = &self.input[start..self.offset];
            if let Some(previous) = previous {
                let index = u64::try_from(index).unwrap_or(u64::MAX);
                if previous == element {
                    return Err(CodecRefusal::CollectionDuplicate {
                        field,
                        index,
                        offset: collection_offset,
                    });
                }
                if previous > element {
                    return Err(CodecRefusal::CollectionUnordered {
                        field,
                        index,
                        offset: collection_offset,
                    });
                }
            }
            previous = Some(element);
            items.push(item);
        }
        self.leave();
        Ok(items)
    }

    /// Reads a key-to-value collection, re-verifying canonical key order.
    pub fn read_canonical_map<K, V, FK, FV>(
        &mut self,
        field: &'static str,
        mut read_key: FK,
        mut read_value: FV,
    ) -> Result<Vec<(K, V)>, CodecRefusal>
    where
        FK: FnMut(&mut Self) -> Result<K, CodecRefusal>,
        FV: FnMut(&mut Self) -> Result<V, CodecRefusal>,
    {
        self.enter()?;
        let collection_offset = self.offset();
        let count = self.read_count(field)?;
        let mut entries = Vec::with_capacity(count);
        let mut previous: Option<&'a [u8]> = None;
        for index in 0..count {
            let start = self.offset;
            let key = read_key(self)?;
            let encoded_key = &self.input[start..self.offset];
            if let Some(previous) = previous {
                let index = u64::try_from(index).unwrap_or(u64::MAX);
                if previous == encoded_key {
                    return Err(CodecRefusal::CollectionDuplicate {
                        field,
                        index,
                        offset: collection_offset,
                    });
                }
                if previous > encoded_key {
                    return Err(CodecRefusal::CollectionUnordered {
                        field,
                        index,
                        offset: collection_offset,
                    });
                }
            }
            previous = Some(encoded_key);
            let value = read_value(self)?;
            entries.push((key, value));
        }
        self.leave();
        Ok(entries)
    }

    /// Reads a codec version.
    pub fn read_codec_version(
        &mut self,
        field: &'static str,
    ) -> Result<CodecVersion, CodecRefusal> {
        let major = self.read_scalar::<u16>(field)?;
        let minor = self.read_scalar::<u16>(field)?;
        Ok(CodecVersion::new(major, minor))
    }

    /// Reads a domain separation tag.
    pub fn read_domain_tag(&mut self) -> Result<DomainTag, CodecRefusal> {
        let bytes = self.read_bytes("DomainTag")?;
        DomainTag::try_new(bytes).map_err(CodecRefusal::from)
    }

    /// Reads a schema identifier.
    pub fn read_schema_id(&mut self) -> Result<SchemaId, CodecRefusal> {
        let family = SchemaFamily::try_new(self.read_bytes("SchemaFamily")?)?;
        let major = self.read_scalar::<u16>("SchemaId.major")?;
        let minor = self.read_scalar::<u16>("SchemaId.minor")?;
        Ok(SchemaId::new(family, major, minor))
    }

    /// Reads a digest body.
    pub fn read_digest_bytes(&mut self) -> Result<DigestBytes, CodecRefusal> {
        let bytes = self.read_bytes("DigestBytes")?;
        DigestBytes::try_new(bytes).map_err(CodecRefusal::from)
    }

    /// Reads an algorithm code point.
    pub fn read_digest_algorithm(&mut self) -> Result<DigestAlgorithmId, CodecRefusal> {
        let code_point = self.read_scalar::<u16>("DigestAlgorithmId")?;
        DigestAlgorithmId::try_new(code_point).map_err(CodecRefusal::from)
    }

    /// Reads an algorithm-tagged digest, checking the body against the output
    /// width its algorithm declares.
    pub fn read_digest(&mut self) -> Result<Digest, CodecRefusal> {
        let algorithm = self.read_digest_algorithm()?;
        let bytes = self.read_digest_bytes()?;
        checked_digest(algorithm, bytes)
    }

    /// Reads an internal object identity.
    ///
    /// The digest body is width-checked exactly as [`Self::read_digest`] checks
    /// one. This site carries the same hostile-frame exposure and is reached by
    /// a different door, so guarding only `read_digest` would close the hole
    /// under one name and leave it open under another.
    pub fn read_internal_object_id(&mut self) -> Result<InternalObjectId, CodecRefusal> {
        let algorithm = self.read_digest_algorithm()?;
        let domain = self.read_domain_tag()?;
        let codec_version = self.read_codec_version("InternalObjectId.codec_version")?;
        let digest = checked_digest(algorithm, self.read_digest_bytes()?)?;
        Ok(InternalObjectId::new(
            algorithm,
            domain,
            codec_version,
            *digest.bytes(),
        ))
    }

    /// Reads a 128-bit assigned identity.
    pub fn read_opaque_id(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; OPAQUE_ID_LEN], CodecRefusal> {
        let bytes = self.take(field, OPAQUE_ID_LEN)?;
        let mut out = [0_u8; OPAQUE_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Reads a Git hash algorithm code point.
    pub fn read_git_hash_algorithm(&mut self) -> Result<GitHashAlgorithm, CodecRefusal> {
        let code_point = self.read_scalar::<u16>("GitHashAlgorithm")?;
        GitHashAlgorithm::from_code_point(code_point).map_err(CodecRefusal::from)
    }

    /// Reads a native Git object identity in the domain its tag names.
    pub fn read_git_oid(&mut self) -> Result<GitOid, CodecRefusal> {
        let algorithm = self.read_git_hash_algorithm()?;
        match algorithm {
            GitHashAlgorithm::Sha1 => {
                let bytes = self.take("GitOidSha1", GitOidSha1::LEN)?;
                let mut raw = [0_u8; GitOidSha1::LEN];
                raw.copy_from_slice(bytes);
                Ok(GitOid::Sha1(GitOidSha1::from_bytes(raw)))
            }
            GitHashAlgorithm::Sha256 => {
                let bytes = self.take("GitOidSha256", GitOidSha256::LEN)?;
                let mut raw = [0_u8; GitOidSha256::LEN];
                raw.copy_from_slice(bytes);
                Ok(GitOid::Sha256(GitOidSha256::from_bytes(raw)))
            }
        }
    }

    /// Reads a reference name, re-validating it against the ref-name rules.
    pub fn read_ref_name(&mut self) -> Result<RefName, CodecRefusal> {
        let bytes = self.read_bytes("RefName")?;
        RefName::try_new(bytes).map_err(CodecRefusal::from)
    }
}

/// Validates a decoded digest body against the output width its algorithm
/// declares in the registry.
///
/// `DigestBytes` already enforces the generic `16..=64` shell bound, but that
/// bound is algorithm-blind: it admits a 20-byte body under the SHA-256 code
/// point. Such a digest claims the stronger construction while carrying 96
/// fewer bits of collision resistance, and nothing downstream re-derives the
/// width, so the frame is accepted on its own say-so. This is the check that
/// makes `TypeRefusal::DigestLengthMismatch` reachable from the wire; before
/// it, the variant could be constructed and asserted on but never fired.
///
/// `fgit-types` is L0 and cannot see the registry, which is why
/// [`Digest::new_checked`] takes the expected width as a parameter rather than
/// looking it up. `fgit-codec` is L2 and already depends on `fgit-crypto`, so
/// the lookup is available here at no architectural cost.
///
/// # Non-claim
///
/// A code point that resolves to no construction is accepted with no width
/// enforced. That covers two distinct regions the registry keeps apart --
/// `CORPUS_RESERVED_CODE_POINTS` (`0xfff0..=0xffff`, which
/// `fgit-crypto` asserts at compile time no registered construction occupies,
/// and which the golden corpus needs in order to round-trip through this
/// reader) and code points that are simply unregistered. This function does
/// not distinguish them and does not enforce registry MEMBERSHIP; that is a
/// separate invariant with a separate refusal, and it is not claimed here.
/// What is closed is the case where a resolvable construction is named and the
/// body does not match its declared width.
fn checked_digest(
    algorithm: DigestAlgorithmId,
    bytes: DigestBytes,
) -> Result<Digest, CodecRefusal> {
    let Some(construction) = DigestAlgorithm::from_id(algorithm) else {
        return Ok(Digest::new(algorithm, bytes));
    };
    Digest::new_checked(algorithm, bytes, construction.digest_len()).map_err(CodecRefusal::from)
}
