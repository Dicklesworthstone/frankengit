//! Retain one prepared candidate under another exact bundle advertisement.
//!
//! Only the bounded transport header is allocated. The pack remains borrowed
//! and byte-identical, so a controller can retain both CI and target artifacts
//! without another pack-sized buffer. This is envelope transformation, not
//! object verification, ref admission, or permission to publish a candidate.

use std::io::Write;

use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_types::RefName;

use super::stream::StreamFullBundleError;
use super::{FullBundleError, FullBundleInput, FullBundleLimits};
use crate::{Deadline, ObjectFormat, ObjectId, checkpoint};

const CHUNK_BYTES: usize = 16 * 1024;

/// A single exact advertisement and an unchanged borrowed pack. Prerequisites
/// remain sorted native identities; their informational comments are normalized.
#[derive(Debug)]
pub struct RetargetedBundle<'a> {
    header: Vec<u8>,
    pack: &'a [u8],
}

impl<'a> RetargetedBundle<'a> {
    /// Require exactly the expected ref and candidate, no HEAD advertisement,
    /// and the candidate's native hash domain. Both input and output obey the
    /// same independent header and total-byte bounds, including a longer ref.
    /// Parsing accepts the existing bounded incremental prerequisite profile.
    pub fn parse(
        bytes: &'a [u8],
        expected_reference: &RefName,
        destination: &RefName,
        expected_commit: ObjectId,
        limits: FullBundleLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, FullBundleError> {
        let input = FullBundleInput::parse_incremental(bytes, limits, deadline)?;
        if input.format() != expected_commit.algorithm() {
            return Err(FullBundleError::FormatMismatch);
        }
        if expected_commit.is_zero()
            || !destination.as_bytes().starts_with(b"refs/")
            || input.head().is_some()
            || input.references().len() != 1
            || input.references()[0].name() != expected_reference
            || *input.references()[0].target() != expected_commit
        {
            return Err(FullBundleError::Invalid(
                "single candidate bundle coordinates differ",
            ));
        }
        let pack = input.pack_bytes();
        let maximum = limits.max_header_bytes.min(
            limits
                .max_bundle_bytes
                .checked_sub(pack.len())
                .ok_or(FullBundleError::Limit("retargeted bundle bytes"))?,
        );
        let mut header = Vec::new();
        append(
            &mut header,
            match input.format() {
                ObjectFormat::Sha1 => b"# v2 git bundle\n",
                ObjectFormat::Sha256 => b"# v3 git bundle\n@object-format=sha256\n",
            },
            maximum,
        )?;
        for prerequisite in input.prerequisites() {
            checkpoint(deadline)?;
            append(
                &mut header,
                format!("-{prerequisite} canonical parent\n").as_bytes(),
                maximum,
            )?;
        }
        append(
            &mut header,
            format!("{expected_commit} ").as_bytes(),
            maximum,
        )?;
        append(&mut header, destination.as_bytes(), maximum)?;
        append(&mut header, b"\n\n", maximum)?;
        checkpoint(deadline)?;
        Ok(Self { header, pack })
    }

    #[must_use]
    pub fn header_bytes(&self) -> &[u8] {
        &self.header
    }

    #[must_use]
    pub const fn pack_bytes(&self) -> &'a [u8] {
        self.pack
    }

    #[must_use]
    pub fn byte_len(&self) -> usize {
        // parse bounds the sum by max_bundle_bytes before constructing Self.
        self.header.len() + self.pack.len()
    }

    /// Commit to the exact transformed envelope and original pack, checking
    /// cancellation between bounded hashing chunks. No combined buffer exists.
    pub fn sha256(&self, deadline: &mut impl Deadline) -> Result<[u8; 32], FullBundleError> {
        let mut hash = Sha256Hasher::new();
        for bytes in [&self.header[..], self.pack] {
            for chunk in bytes.chunks(CHUNK_BYTES) {
                checkpoint(deadline)?;
                hash.update(chunk);
            }
        }
        checkpoint(deadline)?;
        Ok(hash.finish())
    }

    /// Write tentative bytes with bounded cancellation checkpoints. The caller
    /// owns output I/O deadlines, private staging, sync and final publication.
    /// I/O failure or cancellation may follow partial output; neither is a
    /// complete artifact or evidence that a related repository write rolled back.
    pub fn write_to<W: Write + ?Sized>(
        &self,
        output: &mut W,
        deadline: &mut impl Deadline,
    ) -> Result<(), StreamFullBundleError> {
        for bytes in [&self.header[..], self.pack] {
            for chunk in bytes.chunks(CHUNK_BYTES) {
                checkpoint(deadline)?;
                output.write_all(chunk)?;
            }
        }
        checkpoint(deadline)?;
        Ok(())
    }

    /// Materialize only when the consumer requires one contiguous transport.
    /// Streaming artifact consumers should use write_to instead.
    pub fn into_vec(mut self, deadline: &mut impl Deadline) -> Result<Vec<u8>, FullBundleError> {
        checkpoint(deadline)?;
        self.header
            .try_reserve_exact(self.pack.len())
            .map_err(|_| FullBundleError::Limit("retargeted bundle allocation"))?;
        for chunk in self.pack.chunks(CHUNK_BYTES) {
            checkpoint(deadline)?;
            self.header.extend_from_slice(chunk);
        }
        checkpoint(deadline)?;
        Ok(self.header)
    }
}

fn append(header: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<(), FullBundleError> {
    if header
        .len()
        .checked_add(bytes.len())
        .is_none_or(|len| len > maximum)
    {
        return Err(FullBundleError::Limit("retargeted bundle header or bytes"));
    }
    header
        .try_reserve_exact(bytes.len())
        .map_err(|_| FullBundleError::Limit("retargeted header allocation"))?;
    header.extend_from_slice(bytes);
    Ok(())
}
