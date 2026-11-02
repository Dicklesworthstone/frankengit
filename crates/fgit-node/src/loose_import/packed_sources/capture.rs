//! Optional representation custody from the SAME bytes the import verified.
//! Cache admission never rereads a mutable source path or replaces native,
//! graph, index, placement or canonical import validation.

use super::{ImportControl, ImportedPack, LooseGitImportRefusal, Member};
use crate::received_pack::{ReceivedPackCache, StreamedCaptureReservation, VerifiedReceivedObject};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_pack::{NativeChecksumVerifier, PackLimits, StreamPackReceipt, read_verified_pack_owned};
use fgit_types::GitOid;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};

struct Raw {
    bytes: Vec<u8>,
    expected: usize,
    reservation: StreamedCaptureReservation,
    valid: bool,
}

/// A bounded, optional tee. Its read outcome is always the original reader's:
/// an allocation/capacity/capture failure only disables optional retention.
pub(super) struct Tee<'a, R> {
    inner: R,
    raw: Option<Raw>,
    enabled: &'a Cell<bool>,
}

impl<'a, R> Tee<'a, R> {
    pub(super) fn new(
        inner: R,
        cache: Option<&ReceivedPackCache>,
        length: u64,
        objects: usize,
        enabled: &'a Cell<bool>,
    ) -> Self {
        let raw = (|| {
            let length = usize::try_from(length).ok()?;
            let reservation = cache?.reserve_streamed_capture(length, objects)?;
            let mut bytes = Vec::new();
            if bytes.try_reserve_exact(length).is_err() || bytes.capacity() != length {
                return None;
            }
            Some(Raw {
                bytes,
                expected: length,
                reservation,
                valid: true,
            })
        })();
        enabled.set(raw.is_some());
        Self {
            inner,
            raw,
            enabled,
        }
    }

    pub(super) fn is_capturing(&self) -> bool {
        self.raw.is_some()
    }

    /// Called only after exact stream EOF, idx/trailer agreement and native
    /// resolution of every row. The full-byte digest binds the optional tee to
    /// that original reader receipt, independently of a SHA-1 pack trailer.
    pub(super) fn verified(
        self,
        receipt: StreamPackReceipt,
        resolved: &BTreeMap<u64, Member>,
        inflated: u64,
        commitments: Option<BTreeMap<GitOid, [u8; 32]>>,
        control: &ImportControl<'_>,
    ) -> Result<Option<Captured>, LooseGitImportRefusal> {
        control.checkpoint()?;
        if !self.enabled.get() {
            return Ok(None);
        }
        let Some(raw) = self.raw else { return Ok(None) };
        let Some(commitments) = commitments else {
            return Ok(None);
        };
        if !raw.valid
            || raw.bytes.len() != raw.expected
            || receipt.pack_bytes() != raw.expected as u64
            || receipt.header().object_count as usize != resolved.len()
            || commitments.len() != resolved.len()
        {
            return Ok(None);
        }
        let mut digest = Sha256Hasher::new();
        for chunk in raw.bytes.chunks(super::IO_CHUNK_BYTES) {
            control.checkpoint()?;
            digest.update(chunk);
        }
        if digest.finish() != receipt.pack_sha256() {
            return Ok(None);
        }
        let mut objects = Vec::new();
        if objects.try_reserve_exact(resolved.len()).is_err() {
            return Ok(None);
        }
        let mut ids = BTreeMap::new();
        for (offset, member) in resolved {
            control.checkpoint()?;
            objects.push(VerifiedReceivedObject {
                id: member.id,
                kind: member.kind,
                bytes: member.handle.length(),
            });
            ids.insert(*offset, member.id);
        }
        objects.sort_unstable_by_key(|object| object.id);
        control.checkpoint()?;
        Ok(Some(Captured {
            raw,
            receipt,
            objects,
            ids,
            inflated,
            commitments,
        }))
    }
}

impl<R: Read> Read for Tee<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        if !self.enabled.get() {
            self.raw.take();
        }
        if let Some(raw) = &mut self.raw
            && raw.valid
        {
            if count > raw.expected.saturating_sub(raw.bytes.len()) {
                raw.valid = false;
                raw.bytes.clear();
            } else {
                // The exact raw allocation and conservative metadata charge
                // were reserved before the first source byte was copied.
                raw.bytes.extend_from_slice(&buffer[..count]);
            }
        }
        Ok(count)
    }
}

pub(super) fn inflation_limit(cache: Option<&ReceivedPackCache>, limits: &PackLimits) -> usize {
    cache.map_or(0, |cache| {
        cache
            .max_bytes()
            .min(PackLimits::default().max_total_expanded_bytes)
            .min(limits.max_total_expanded_bytes)
    })
}

pub(super) struct Captured {
    raw: Raw,
    receipt: StreamPackReceipt,
    objects: Vec<VerifiedReceivedObject>,
    ids: BTreeMap<u64, GitOid>,
    inflated: u64,
    commitments: BTreeMap<GitOid, [u8; 32]>,
}

impl Captured {
    pub(super) fn prepare(
        self,
        cache: &ReceivedPackCache,
        selected: &BTreeSet<GitOid>,
        limits: &PackLimits,
        remaining_inflation: &mut usize,
        control: &ImportControl<'_>,
    ) -> Result<Option<ImportedPack>, LooseGitImportRefusal> {
        control.checkpoint()?;
        // Placement's final strong collision check covers only the accepted
        // closure. A verified but unreachable pack member cannot borrow that
        // check; skip its entire representation rather than widen placement.
        for object in &self.objects {
            control.checkpoint()?;
            if !selected.contains(&object.id) {
                return Ok(None);
            }
        }
        let Ok(inflated) = usize::try_from(self.inflated) else {
            return Ok(None);
        };
        if inflated > *remaining_inflation {
            return Ok(None);
        }
        // This second pass inflates entry programs, never reconstructed delta
        // results. Keep its resident ceiling separate from a multi-GiB import
        // profile. Every candidate spends the same operation-wide allowance.
        let mut parser_limits = limits.clone();
        parser_limits.max_input_bytes = parser_limits.max_input_bytes.min(cache.capture_limit());
        parser_limits.max_total_expanded_bytes = *remaining_inflation;
        parser_limits.max_object_bytes = parser_limits.max_object_bytes.min(*remaining_inflation);
        *remaining_inflation -= inflated;
        let parsed = read_verified_pack_owned(
            self.raw.bytes,
            self.receipt.format(),
            &parser_limits,
            &mut control.cpu_probe(),
            &NativeChecksumVerifier,
            cache.capture_limit(),
        );
        control.checkpoint()?;
        let pack = match parsed {
            Ok(pack) => pack,
            Err(_) => {
                // The parser has no partial-work receipt. A failure spends
                // the rest of optional inflation rather than resetting it.
                *remaining_inflation = 0;
                return Ok(None);
            }
        };
        if pack.header != self.receipt.header() || pack.trailer != self.receipt.trailer() {
            return Ok(None);
        }
        let pending = cache.prepare_streamed_verified(
            &pack,
            self.objects.into_iter(),
            &self.ids,
            limits,
            &mut control.cpu_probe(),
            self.raw.reservation,
        );
        control.checkpoint()?;
        // Shape/allocation/capacity failures are optional misses. A checkpoint
        // above propagates the import's sticky original cancellation/budget.
        Ok(pending
            .ok()
            .flatten()
            .map(|pending| ImportedPack::new(pending, self.commitments)))
    }
}
