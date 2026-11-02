//! Optional raw custody from the original native verification pass. A replay
//! of a mutable source file cannot mint this receipt or any member commitment.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, BufReader, Cursor, Read};

use fgit_crypto::{DigestHasher, IdentityDomain, Sha256Hasher};
use fgit_pack::{
    NativeChecksumVerifier, PackLimits, StreamPackError, StreamPackEvent, StreamPackReceipt,
    parse_pack_header, read_streamed_pack_chunks, read_verified_pack_owned,
};
use fgit_types::{GitHashAlgorithm, GitOid};

use super::super::{BundleVerifyError, BundleVerifyLimits, ObjectKind, checkpoint};
use super::resolve::Inventory;
use super::storage::{CHUNK_BYTES, io_error};
use crate::received_pack::placement::PlacementBoundPack;
use crate::received_pack::{ReceivedPackCache, StreamedCaptureReservation, VerifiedReceivedObject};

struct Raw {
    bytes: Vec<u8>,
    expected: usize,
    reservation: StreamedCaptureReservation,
}

struct Tee<'a, R> {
    inner: R,
    raw: Option<Raw>,
    enabled: &'a Cell<bool>,
}

impl<'a, R> Tee<'a, R> {
    fn new(
        inner: R,
        cache: &ReceivedPackCache,
        bytes: usize,
        objects: usize,
        enabled: &'a Cell<bool>,
    ) -> Self {
        let raw = (|| {
            let reservation = cache.reserve_streamed_capture(bytes, objects)?;
            let mut raw = Vec::new();
            if raw.try_reserve_exact(bytes).is_err() || raw.capacity() != bytes {
                return None;
            }
            Some(Raw {
                bytes: raw,
                expected: bytes,
                reservation,
            })
        })();
        enabled.set(raw.is_some());
        Self {
            inner,
            raw,
            enabled,
        }
    }
}

impl<R: Read> Read for Tee<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(output)?;
        if count > output.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid pack input read count",
            ));
        }
        if !self.enabled.get() {
            self.raw.take();
        }
        if let Some(raw) = &mut self.raw {
            if count > raw.expected.saturating_sub(raw.bytes.len()) {
                self.enabled.set(false);
                self.raw.take();
            } else {
                raw.bytes.extend_from_slice(&output[..count]);
            }
        }
        Ok(count)
    }
}

/// Complete raw framing under its original allocation reservation. Native
/// identity, typed graph and selected-placement joins still have to succeed.
pub(super) struct CapturedInput {
    raw: Raw,
    receipt: StreamPackReceipt,
    inflated: usize,
}

pub(super) fn inflation_limit(cache: &ReceivedPackCache, limits: &PackLimits) -> usize {
    cache
        .max_bytes()
        .min(PackLimits::default().max_total_expanded_bytes)
        .min(limits.max_total_expanded_bytes)
}

/// `reader` is already at the pack boundary in the native verification pass.
/// Its buffered bytes are consumed once. A twelve-byte stack prefix permits a
/// count-aware reservation before allocating raw custody, then goes through
/// the original native reader unchanged along with the remaining source.
pub(super) fn read<R: BufRead>(
    reader: &mut R,
    format: GitHashAlgorithm,
    pack_bytes: u64,
    limits: &PackLimits,
    maximum_blob_bytes: usize,
    cache: Option<&ReceivedPackCache>,
    live: &mut impl FnMut() -> bool,
    mut sink: impl FnMut(StreamPackEvent<'_>) -> Result<(), BundleVerifyError>,
) -> Result<(StreamPackReceipt, Option<CapturedInput>), BundleVerifyError> {
    checkpoint(live)?;
    let eligible = cache.and_then(|cache| {
        let bytes = usize::try_from(pack_bytes).ok()?;
        (bytes != 0 && bytes <= cache.capture_limit()).then_some((cache, bytes))
    });
    let Some((cache, bytes)) = eligible else {
        let result =
            read_streamed_pack_chunks(reader, format, limits, maximum_blob_bytes, live, sink);
        checkpoint(live)?;
        return result.map(|receipt| (receipt, None)).map_err(stream_error);
    };
    let mut prefix = [0; 12];
    // The underlying error remains authoritative input failure. No optional
    // allocation error can change this source read or manufacture success.
    reader
        .read_exact(&mut prefix)
        .map_err(|error| io_error("read bundle pack header", error))?;
    checkpoint(live)?;
    let header = parse_pack_header(&prefix, limits).map_err(BundleVerifyError::Pack)?;
    let enabled = Cell::new(false);
    let tee = Tee::new(
        Cursor::new(prefix).chain(reader),
        cache,
        bytes,
        header.object_count as usize,
        &enabled,
    );
    let mut input = BufReader::with_capacity(CHUNK_BYTES, tee);
    let mut inflated = 0usize;
    let maximum_inflated = inflation_limit(cache, limits);
    let result = read_streamed_pack_chunks(
        &mut input,
        format,
        limits,
        maximum_blob_bytes,
        live,
        |event| {
            if let StreamPackEvent::Begin(start) = &event {
                inflated = inflated.saturating_add(start.header.declared_size);
                if inflated > maximum_inflated
                    || start.header.declared_size > limits.max_object_bytes
                {
                    enabled.set(false);
                }
            }
            sink(event)
        },
    );
    checkpoint(live)?;
    let receipt = result.map_err(stream_error)?;
    let tee = input.into_inner();
    if !enabled.get() {
        return Ok((receipt, None));
    }
    let Some(raw) = tee.raw else {
        return Ok((receipt, None));
    };
    if raw.bytes.len() != raw.expected
        || receipt.pack_bytes() != raw.expected as u64
        || receipt.header() != header
    {
        return Ok((receipt, None));
    }
    let mut hash = Sha256Hasher::new();
    for chunk in raw.bytes.chunks(CHUNK_BYTES) {
        checkpoint(live)?;
        hash.update(chunk);
    }
    if hash.finish() != receipt.pack_sha256() {
        return Ok((receipt, None));
    }
    checkpoint(live)?;
    Ok((
        receipt.clone(),
        Some(CapturedInput {
            raw,
            receipt,
            inflated,
        }),
    ))
}

fn stream_error(error: StreamPackError<BundleVerifyError>) -> BundleVerifyError {
    match error {
        StreamPackError::Io(error) => io_error("read bundle pack", error),
        StreamPackError::Pack(error) => BundleVerifyError::Pack(error),
        StreamPackError::Sink(error) => error,
    }
}

/// Native resolution metadata and independent strong payload commitments for
/// every actual raw entry. All fields remain private to this completed verifier.
pub(super) struct VerifiedCapture {
    input: CapturedInput,
    objects: Vec<VerifiedReceivedObject>,
    offsets: BTreeMap<u64, GitOid>,
    commitments: BTreeMap<GitOid, [u8; 32]>,
}

impl CapturedInput {
    /// Reject a representation that cannot fit the optional resident parser
    /// before the graph phase performs extra strong commitment hashing.
    pub(super) fn eligible(
        &self,
        inventory: &Inventory,
        limits: &BundleVerifyLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<bool, BundleVerifyError> {
        checkpoint(live)?;
        if self.receipt.header().object_count as usize != inventory.entries.len() {
            return Ok(false);
        }
        for entry in &inventory.entries {
            checkpoint(live)?;
            if !entry
                .resolved
                .is_some_and(|object| object.span.length() <= limits.pack.max_object_bytes)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn verified(
        self,
        inventory: &Inventory,
        commitments: BTreeMap<GitOid, [u8; 32]>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Option<VerifiedCapture>, BundleVerifyError> {
        checkpoint(live)?;
        if commitments.len() != inventory.entries.len() {
            return Ok(None);
        }
        let mut objects = Vec::new();
        if objects.try_reserve_exact(inventory.entries.len()).is_err() {
            return Ok(None);
        }
        let mut offsets = BTreeMap::new();
        for entry in &inventory.entries {
            checkpoint(live)?;
            let Some(object) = entry.resolved else {
                return Ok(None);
            };
            if !commitments.contains_key(&object.id) {
                return Ok(None);
            }
            objects.push(VerifiedReceivedObject {
                id: object.id,
                kind: object.kind,
                bytes: object.span.length(),
            });
            offsets.insert(entry.offset, object.id);
        }
        objects.sort_unstable_by_key(|object| object.id);
        checkpoint(live)?;
        Ok(Some(VerifiedCapture {
            input: self,
            objects,
            offsets,
            commitments,
        }))
    }
}

impl VerifiedCapture {
    pub(super) fn prepare(
        self,
        cache: &ReceivedPackCache,
        uploaded: &BTreeSet<GitOid>,
        limits: &PackLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Option<PlacementBoundPack>, BundleVerifyError> {
        checkpoint(live)?;
        // Mapped fetches may deliberately omit raw pack members. A borrowed
        // original is not an uploaded placement either. Never widen either set.
        for object in &self.objects {
            checkpoint(live)?;
            if !uploaded.contains(&object.id) {
                return Ok(None);
            }
        }
        let maximum_inflated = inflation_limit(cache, limits);
        if self.input.inflated > maximum_inflated {
            return Ok(None);
        }
        let mut parser = limits.clone();
        parser.max_input_bytes = parser.max_input_bytes.min(cache.capture_limit());
        parser.max_total_expanded_bytes = maximum_inflated;
        parser.max_object_bytes = parser.max_object_bytes.min(maximum_inflated);
        // One bundle contains one pack. Its sole optional second pass retains
        // bounded entry programs, never an unbounded expanded native inventory.
        let parsed = read_verified_pack_owned(
            self.input.raw.bytes,
            self.input.receipt.format(),
            &parser,
            live,
            &NativeChecksumVerifier,
            cache.capture_limit(),
        );
        checkpoint(live)?;
        let Ok(pack) = parsed else {
            return Ok(None);
        };
        if pack.header != self.input.receipt.header()
            || pack.trailer != self.input.receipt.trailer()
        {
            return Ok(None);
        }
        let pending = cache.prepare_streamed_verified(
            &pack,
            self.objects.into_iter(),
            &self.offsets,
            limits,
            live,
            self.input.raw.reservation,
        );
        checkpoint(live)?;
        Ok(pending
            .ok()
            .flatten()
            .map(|pending| PlacementBoundPack::new(pending, self.commitments)))
    }
}

pub(super) fn strong_hasher(kind: ObjectKind, length: usize) -> Option<Sha256Hasher> {
    let header = format!("{} {length}\0", kind.label());
    let bytes = (length as u64).checked_add(header.len() as u64)?;
    let mut hash = Sha256Hasher::new();
    hash.update(&fgit_crypto::internal_id_preimage_header(
        IdentityDomain::GitPayloadCommitment,
        fgit_crypto::GIT_PAYLOAD_SCHEMA,
        bytes,
    ));
    hash.update(header.as_bytes());
    Some(hash)
}
