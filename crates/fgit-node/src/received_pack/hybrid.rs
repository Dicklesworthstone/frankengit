//! Preserve verified entry representations while encoding uncovered objects.
//!
//! The retained subset is closed over its own selected bases and explicitly
//! proven client-held bases. The new native run is self-contained. Concatenating
//! their entry runs therefore introduces no cross-run delta edge or duplicate
//! object. Original checksums are verified while copying into private scratch;
//! one new header/trailer is promoted only after both complete runs verify.

use super::composition::NativeHasher;
use super::{ReceivedPackCache, ReceivedPackPayload, ReceivedPackReceipt, check, selective};
use crate::pack_spool::{PackSpool, SpooledPack, SpoolTemporary};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_git_object::ObjectType;
use fgit_pack::{
    PackArtifactSink, PackError, PackLimits, PackOrderKey, PackWriteError, PackWriteReceipt,
};
use fgit_types::GitOid;
use std::io;
use std::path::Path;

/// Provenance of one exact selected pack assembled from two disjoint sets.
/// The native component's frozen profile describes only its newly encoded
/// entries, never the output order or compression of the complete hybrid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridPackReceipt {
    checksum: GitOid,
    sha256: [u8; 32],
    object_count: u32,
    output_bytes: usize,
    total_object_bytes: usize,
    reused: ReceivedPackReceipt,
    written: PackWriteReceipt,
}

impl HybridPackReceipt {
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        if self.reused.external_base_count() == 0 {
            "received-pack-hybrid-v1"
        } else {
            "received-pack-hybrid-thin-v1"
        }
    }

    #[must_use]
    pub const fn checksum(&self) -> GitOid {
        self.checksum
    }

    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    #[must_use]
    pub const fn object_count(&self) -> u32 {
        self.object_count
    }

    #[must_use]
    pub const fn output_bytes(&self) -> usize {
        self.output_bytes
    }

    #[must_use]
    pub const fn total_object_bytes(&self) -> usize {
        self.total_object_bytes
    }

    /// Native-verification and representation evidence for only the reused subset.
    #[must_use]
    pub const fn reused(&self) -> &ReceivedPackReceipt {
        &self.reused
    }

    /// Frozen native-writer evidence for only the newly encoded subset.
    #[must_use]
    pub const fn written(&self) -> &PackWriteReceipt {
        &self.written
    }

    #[must_use]
    pub const fn source_pack_count(&self) -> usize {
        self.reused.source_pack_count()
    }

    #[must_use]
    pub const fn external_base_count(&self) -> usize {
        self.reused.external_base_count()
    }
}

/// Private custody and exact complement of a caller-authorized selection.
pub(crate) struct PartialReceivedPack {
    received: ReceivedPackPayload,
    missing: Vec<PackOrderKey>,
    native_limits: PackLimits,
    original_limits: PackLimits,
    total_entry_bytes: usize,
}

pub(super) fn prepare(
    cache: &ReceivedPackCache,
    keys: &[PackOrderKey],
    limits: &PackLimits,
    held: &[(GitOid, ObjectType)],
    live: &mut impl FnMut() -> bool,
) -> Result<Option<PartialReceivedPack>, PackWriteError> {
    let Some(selection) = selective::partial(cache, keys, limits, held, live)? else {
        return Ok(None);
    };
    let receipt = selection.received.receipt();
    let framing = 12 + receipt.checksum().algorithm().digest_len();
    let Some(run_bytes) = receipt.output_bytes().checked_sub(framing) else {
        return Ok(None);
    };
    let mut native_limits = limits.clone();
    let Some(output_bytes) = limits.max_input_bytes.checked_sub(run_bytes) else {
        return Ok(None);
    };
    // Native object totals and inflated delta-program totals are independent
    // bounds. Reserving their maximum leaves room for either native form.
    let Some(expanded) = limits.max_total_expanded_bytes.checked_sub(
        receipt.total_object_bytes().max(selection.total_entry_bytes),
    ) else {
        return Ok(None);
    };
    let Some(entries) = limits.max_entries.checked_sub(receipt.object_count()) else {
        return Ok(None);
    };
    if output_bytes < framing || selection.missing.len() > entries as usize {
        return Ok(None);
    }
    native_limits.max_input_bytes = output_bytes;
    native_limits.max_total_expanded_bytes = expanded;
    native_limits.max_entries = entries;
    check(live)?;
    Ok(Some(PartialReceivedPack {
        received: selection.received,
        missing: selection.missing,
        native_limits,
        original_limits: limits.clone(),
        total_entry_bytes: selection.total_entry_bytes,
    }))
}

impl PartialReceivedPack {
    pub(crate) fn missing_keys(&self) -> &[PackOrderKey] {
        &self.missing
    }

    pub(crate) const fn native_limits(&self) -> &PackLimits {
        &self.native_limits
    }

    #[cfg(test)]
    pub(crate) fn received(&self) -> &ReceivedPackReceipt {
        self.received.receipt()
    }

    /// Join only the native writer's exact missing-key run. The caller uses
    /// the returned limits, a non-thin profile and no external native bases.
    /// Neither source artifact becomes externally consumable through this
    /// operation until its original checksum and the new trailer complete.
    pub(crate) fn finish(
        mut self,
        mut native: SpooledPack,
        written: PackWriteReceipt,
        root: &Path,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(SpooledPack, HybridPackReceipt), PackWriteError> {
        check(live)?;
        let reused = self.received.receipt().clone();
        let format = reused.checksum().algorithm();
        let framing = 12 + format.digest_len();
        if written.profile.thin {
            return Err(PackWriteError::ThinBasesNotPermitted);
        }
        if written.checksum.algorithm() != format
            || written.object_count as usize != self.missing.len()
            || written.compression.len() != self.missing.len()
            || written.output_bytes < framing
            || written.output_bytes > self.native_limits.max_input_bytes
            || written.total_object_bytes > self.native_limits.max_total_expanded_bytes
            || written.profile.max_delta_depth > self.native_limits.max_delta_depth
        {
            return Err(PackWriteError::CompressionReceiptMismatch);
        }
        let mut native_entry_bytes = 0usize;
        for member in &written.compression {
            check(live)?;
            if member.input_bytes > self.native_limits.max_object_bytes {
                return Err(PackError::ObjectSizeLimit {
                    actual: member.input_bytes,
                    limit: self.native_limits.max_object_bytes,
                }
                .into());
            }
            native_entry_bytes = native_entry_bytes
                .checked_add(member.input_bytes)
                .ok_or(PackError::IntegerOverflow {
                    context: "hybrid native entry bytes",
                })?;
        }
        let total_entries = self.total_entry_bytes.checked_add(native_entry_bytes).ok_or(
            PackError::IntegerOverflow {
                context: "hybrid inflated entry bytes",
            },
        )?;
        if total_entries > self.original_limits.max_total_expanded_bytes {
            return Err(PackError::TotalExpandedLimit {
                actual: total_entries,
                limit: self.original_limits.max_total_expanded_bytes,
            }
            .into());
        }
        let object_count = reused.object_count().checked_add(written.object_count).ok_or(
            PackError::IntegerOverflow {
                context: "hybrid entry count",
            },
        )?;
        let total_object_bytes = reused
            .total_object_bytes()
            .checked_add(written.total_object_bytes)
            .ok_or(PackError::IntegerOverflow {
                context: "hybrid object bytes",
            })?;
        let output_bytes = reused
            .output_bytes()
            .checked_add(written.output_bytes - framing)
            .ok_or(PackError::IntegerOverflow {
                context: "hybrid output bytes",
            })?;
        if object_count > self.original_limits.max_entries
            || total_object_bytes > self.original_limits.max_total_expanded_bytes
            || output_bytes > self.original_limits.max_input_bytes
        {
            return Err(PackWriteError::CompressionReceiptMismatch);
        }
        let mut header = *b"PACK\0\0\0\x02\0\0\0\0";
        header[8..].copy_from_slice(&object_count.to_be_bytes());
        let mut spool = PackSpool::new(root);
        let mut temporary = spool.create_temporary()?;
        let result: Result<HybridPackReceipt, PackWriteError> = (|| {
            let mut output = Output {
                spool: &mut spool,
                temporary: &mut temporary,
                native: NativeHasher::new(format),
                strong: Sha256Hasher::new(),
                length: 0,
                maximum: output_bytes,
            };
            output.emit(&header)?;
            copy_run(
                |maximum| self.received.next_chunk(maximum),
                reused.checksum(),
                Some(reused.sha256()),
                reused.object_count(),
                reused.output_bytes(),
                &mut output,
                live,
            )?;
            copy_run(
                |maximum| native.next_chunk(maximum),
                written.checksum,
                None,
                written.object_count,
                written.output_bytes,
                &mut output,
                live,
            )?;
            check(live)?;
            let (checksum, sha256) = output.finish()?;
            check(live)?;
            spool.promote_temporary(&mut temporary)?;
            Ok(HybridPackReceipt {
                checksum,
                sha256,
                object_count,
                output_bytes,
                total_object_bytes,
                reused,
                written,
            })
        })();
        // This drops either the unpromoted private file or the empty holder
        // left by promotion. Cancellation and every refusal leave no payload.
        spool.abort_temporary(temporary);
        let receipt = result?;
        let pack = spool.into_promoted().ok_or(PackWriteError::PromotionRefused)?;
        Ok((pack, receipt))
    }
}

struct Output<'a, 'root> {
    spool: &'a mut PackSpool<'root>,
    temporary: &'a mut SpoolTemporary,
    native: NativeHasher,
    strong: Sha256Hasher,
    length: usize,
    maximum: usize,
}

impl Output<'_, '_> {
    fn emit(&mut self, bytes: &[u8]) -> Result<(), PackWriteError> {
        let next = self.length.checked_add(bytes.len()).ok_or(
            PackError::IntegerOverflow {
                context: "hybrid streamed output",
            },
        )?;
        if next > self.maximum {
            return Err(PackWriteError::OutputLimit {
                attempted: next,
                limit: self.maximum,
            });
        }
        self.spool.write_temporary(self.temporary, bytes)?;
        self.native.update(bytes);
        self.strong.update(bytes);
        self.length = next;
        Ok(())
    }

    fn finish(mut self) -> Result<(GitOid, [u8; 32]), PackWriteError> {
        let checksum = self.native.finish();
        if self.length.checked_add(checksum.as_bytes().len()) != Some(self.maximum) {
            return Err(PackWriteError::TemporaryReadRefused);
        }
        self.spool.write_temporary(self.temporary, checksum.as_bytes())?;
        self.strong.update(checksum.as_bytes());
        Ok((checksum, self.strong.finish()))
    }
}

/// Verify each original frame while copying only its entry run. The offset of
/// every native OFS entry and its base changes by the same constant. Retained
/// selective entries use REF deltas, so they require no offset adjustment.
fn copy_run(
    mut read: impl FnMut(usize) -> io::Result<Option<Vec<u8>>>,
    checksum: GitOid,
    sha256: Option<&[u8; 32]>,
    count: u32,
    length: usize,
    output: &mut Output<'_, '_>,
    live: &mut impl FnMut() -> bool,
) -> Result<(), PackWriteError> {
    let trailer_at = length
        .checked_sub(checksum.as_bytes().len())
        .filter(|length| *length >= 12)
        .ok_or(PackWriteError::TemporaryReadRefused)?;
    let mut original = NativeHasher::new(checksum.algorithm());
    let mut strong = Sha256Hasher::new();
    let mut header = [0u8; 12];
    let mut offset = 0usize;
    loop {
        check(live)?;
        let chunk = read(super::HASH_CHUNK_BYTES)
            .map_err(|_| PackWriteError::TemporaryReadRefused)?;
        check(live)?;
        let Some(bytes) = chunk else { break };
        let end = offset
            .checked_add(bytes.len())
            .filter(|end| *end <= length)
            .ok_or(PackWriteError::TemporaryReadRefused)?;
        if bytes.is_empty() || bytes.len() > super::HASH_CHUNK_BYTES {
            return Err(PackWriteError::TemporaryReadRefused);
        }
        strong.update(&bytes);
        if offset < trailer_at {
            original.update(&bytes[..end.min(trailer_at) - offset]);
        }
        if offset < 12 {
            header[offset..end.min(12)].copy_from_slice(&bytes[..end.min(12) - offset]);
        }
        let start = offset.max(12);
        let stop = end.min(trailer_at);
        if start < stop {
            output.emit(&bytes[start - offset..stop - offset])?;
        }
        if end > trailer_at {
            let start = offset.max(trailer_at);
            if bytes[start - offset..] != checksum.as_bytes()[start - trailer_at..end - trailer_at] {
                return Err(PackError::TrailerChecksumMismatch.into());
            }
        }
        offset = end;
    }
    if offset != length
        || header[..8] != *b"PACK\0\0\0\x02"
        || header[8..] != count.to_be_bytes()
    {
        return Err(PackWriteError::TemporaryReadRefused);
    }
    if original.finish() != checksum || sha256.is_some_and(|expected| strong.finish() != *expected) {
        return Err(PackError::TrailerChecksumMismatch.into());
    }
    check(live)?;
    Ok(())
}
