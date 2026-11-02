//! Bounded bundle framing around an existing pack representation.
//!
//! This is deliberately a framing receipt, not native-object or graph evidence.
//! A selecting caller must already own verified object/closure evidence and
//! enforce expanded-body/type limits. This module verifies the exact incoming
//! pack's count, byte length, native trailer, strong digest and EOF while copying
//! it to a tentative sink. It never decompresses, chooses deltas or publishes.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_git_object::ObjectType;

use super::{
    CHUNK_BYTES, Control, FullBundleError, NativeHash, Output, StreamFullBundleError,
    StreamFullBundleLimits, header, prerequisite_ids, selected_ids,
};
use crate::{
    BundleReference, Deadline, ObjectFormat, ObjectId, PackError, checkpoint, parse_pack_header,
};

/// Expected coordinates supplied by the caller's independently verified pack.
/// These fields authorize nothing; every framing coordinate is checked against
/// the bytes read before a completion receipt is returned.
#[derive(Clone, Copy, Debug)]
pub struct ExistingPackBinding {
    pub checksum: ObjectId,
    pub sha256: [u8; 32],
    pub object_count: u32,
    pub bytes: usize,
}

/// Complete envelope and byte-framing evidence only. Native object identities,
/// types, delta dependencies and graph disclosure remain the caller's proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingPackBundleReceipt {
    format: ObjectFormat,
    pack_checksum: ObjectId,
    object_count: u32,
    prerequisite_count: usize,
    external_object_count: usize,
    pack_bytes: usize,
    header_bytes: usize,
    bundle_bytes: usize,
    bundle_sha256: [u8; 32],
}

impl ExistingPackBundleReceipt {
    #[must_use]
    pub const fn format(&self) -> ObjectFormat {
        self.format
    }
    #[must_use]
    pub const fn pack_checksum(&self) -> ObjectId {
        self.pack_checksum
    }
    #[must_use]
    pub const fn object_count(&self) -> u32 {
        self.object_count
    }
    #[must_use]
    pub const fn prerequisite_count(&self) -> usize {
        self.prerequisite_count
    }
    #[must_use]
    pub const fn external_object_count(&self) -> usize {
        self.external_object_count
    }
    #[must_use]
    pub const fn pack_bytes(&self) -> usize {
        self.pack_bytes
    }
    #[must_use]
    pub const fn header_bytes(&self) -> usize {
        self.header_bytes
    }
    #[must_use]
    pub const fn bundle_bytes(&self) -> usize {
        self.bundle_bytes
    }
    #[must_use]
    pub const fn bundle_sha256(&self) -> [u8; 32] {
        self.bundle_sha256
    }
}

/// Check only bounded envelope coordinates, without reading or writing pack
/// bytes. A selecting caller can reject an optional representation that cannot
/// fit the header plus pack envelope before it starts a different encoder.
/// Success grants no native-object, payload-integrity or completion evidence.
pub fn check_existing_pack_bundle_envelope(
    format: ObjectFormat,
    references: &[BundleReference],
    head: Option<ObjectId>,
    prerequisites: &[ObjectId],
    selected: &[ObjectId],
    external: &BTreeMap<ObjectId, ObjectType>,
    binding: ExistingPackBinding,
    limits: &StreamFullBundleLimits,
    deadline: &mut impl Deadline,
) -> Result<(), StreamFullBundleError> {
    let mut control = Control {
        deadline,
        cancelled: false,
    };
    prepare_envelope(
        format,
        references,
        head,
        prerequisites,
        selected,
        external,
        binding,
        limits,
        &mut control,
    )?;
    checkpoint(&mut control)?;
    Ok(())
}

struct Envelope {
    header: Vec<u8>,
    prerequisite_count: usize,
    bundle_bytes: usize,
}

fn prepare_envelope(
    format: ObjectFormat,
    references: &[BundleReference],
    head: Option<ObjectId>,
    prerequisites: &[ObjectId],
    selected: &[ObjectId],
    external: &BTreeMap<ObjectId, ObjectType>,
    binding: ExistingPackBinding,
    limits: &StreamFullBundleLimits,
    control: &mut impl Deadline,
) -> Result<Envelope, StreamFullBundleError> {
    checkpoint(control)?;
    let ids = selected_ids(format, selected, limits, control)?;
    let boundary = prerequisite_ids(format, prerequisites, &ids, external, control)?;
    if binding.checksum.algorithm() != format
        || binding.object_count as usize != ids.len()
        || binding.bytes < 12 + format.digest_len()
    {
        return Err(FullBundleError::Invalid("existing pack coordinates").into());
    }
    if binding.bytes > limits.pack.max_input_bytes {
        return Err(FullBundleError::Limit("pack bytes").into());
    }
    let header = header(
        format,
        references,
        head,
        &boundary,
        &ids,
        external,
        limits.envelope,
        control,
    )?;
    let bundle_bytes = header
        .len()
        .checked_add(binding.bytes)
        .filter(|bytes| *bytes <= limits.envelope.max_bundle_bytes)
        .ok_or(FullBundleError::Limit("bundle bytes"))?;
    Ok(Envelope {
        header,
        prerequisite_count: boundary.len(),
        bundle_bytes,
    })
}

/// Frame an existing full or prerequisite-scoped pack without changing its
/// entries. Selected/external identities and ref syntax are bounded and checked
/// before any output. Their association with the actual native pack objects is
/// NOT established here: the caller must supply that independent evidence.
///
/// The original source must end exactly at `binding.bytes`. Both checksums,
/// count and EOF must match before the trailer is emitted and a receipt exists.
/// Output may contain tentative partial bytes on any failure. Blocking I/O
/// deadlines, sink cleanup, flush and eventual publication belong to its owner.
pub fn write_existing_pack_bundle_stream<R: Read + ?Sized, W: Write + ?Sized>(
    format: ObjectFormat,
    references: &[BundleReference],
    head: Option<ObjectId>,
    prerequisites: &[ObjectId],
    selected: &[ObjectId],
    external: &BTreeMap<ObjectId, ObjectType>,
    binding: ExistingPackBinding,
    limits: &StreamFullBundleLimits,
    deadline: &mut impl Deadline,
    input: &mut R,
    output: &mut W,
) -> Result<ExistingPackBundleReceipt, StreamFullBundleError> {
    let mut control = Control {
        deadline,
        cancelled: false,
    };
    let Envelope {
        header,
        prerequisite_count,
        bundle_bytes,
    } = prepare_envelope(
        format,
        references,
        head,
        prerequisites,
        selected,
        external,
        binding,
        limits,
        &mut control,
    )?;
    let header_bytes = header.len();
    let mut fixed = [0; 12];
    read_exact(input, &mut fixed, &mut control)?;
    if parse_pack_header(&fixed, &limits.pack)?.object_count != binding.object_count {
        return Err(FullBundleError::Invalid("existing pack count").into());
    }
    let mut emitter = Output {
        writer: output,
        native: NativeHash::new(format),
        sha256: Sha256Hasher::new(),
        bytes: 0,
        header_bytes,
        pack_limit: limits.pack.max_input_bytes,
        bundle_limit: limits.envelope.max_bundle_bytes,
    };
    emitter.emit(&header, false, &mut control)?;
    let mut raw_hash = Sha256Hasher::new();
    raw_hash.update(&fixed);
    emitter.emit(&fixed, true, &mut control)?;
    let mut remaining = binding.bytes - 12 - format.digest_len();
    let mut buffer = [0; CHUNK_BYTES];
    while remaining != 0 {
        let count = remaining.min(buffer.len());
        read_exact(input, &mut buffer[..count], &mut control)?;
        raw_hash.update(&buffer[..count]);
        emitter.emit(&buffer[..count], true, &mut control)?;
        remaining -= count;
    }
    let mut trailer = [0; 32];
    let trailer = &mut trailer[..format.digest_len()];
    read_exact(input, trailer, &mut control)?;
    raw_hash.update(trailer);
    if trailer != binding.checksum.as_bytes() || emitter.native.clone().finish() != binding.checksum
    {
        return Err(PackError::TrailerChecksumMismatch.into());
    }
    if raw_hash.finish() != binding.sha256 {
        return Err(FullBundleError::Invalid("existing pack strong binding").into());
    }
    if read_some(input, &mut [0; 1], &mut control)? != 0 {
        return Err(PackError::TrailingPackData.into());
    }
    emitter.emit(trailer, false, &mut control)?;
    checkpoint(&mut control)?;
    if emitter.bytes != bundle_bytes {
        return Err(FullBundleError::Invalid("existing bundle byte count").into());
    }
    Ok(ExistingPackBundleReceipt {
        format,
        pack_checksum: binding.checksum,
        object_count: binding.object_count,
        prerequisite_count,
        external_object_count: external.len(),
        pack_bytes: binding.bytes,
        header_bytes,
        bundle_bytes,
        bundle_sha256: emitter.sha256.finish(),
    })
}

fn read_exact(
    input: &mut (impl Read + ?Sized),
    mut bytes: &mut [u8],
    control: &mut impl Deadline,
) -> Result<(), StreamFullBundleError> {
    while !bytes.is_empty() {
        let count = read_some(input, bytes, control)?;
        if count == 0 {
            return Err(
                io::Error::new(io::ErrorKind::UnexpectedEof, "existing pack ended early").into(),
            );
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}

fn read_some(
    input: &mut (impl Read + ?Sized),
    bytes: &mut [u8],
    control: &mut impl Deadline,
) -> Result<usize, StreamFullBundleError> {
    loop {
        checkpoint(control)?;
        let result = input.read(bytes);
        checkpoint(control)?;
        let count = match result {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "existing pack reader returned an invalid count",
            )
            .into());
        }
        return Ok(count);
    }
}

#[cfg(test)]
mod tests;
