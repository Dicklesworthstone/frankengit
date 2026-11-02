//! Optional transport custody after an exact typed visible-graph selection.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};

use fgit_pack::full_bundle::stream::StreamFullBundleLimits;
use fgit_pack::full_bundle::stream::existing::{
    ExistingPackBinding, check_existing_pack_bundle_envelope, write_existing_pack_bundle_stream,
};
use fgit_pack::{BundleReference, PackError};
use fgit_types::GitOid;

use super::incremental::Selection;
use super::{NodeWorkspaceRefusal, StreamBundleExportReceipt, StreamBundleExportRefusal};
use crate::received_pack::ReceivedPackPayload;
use crate::{MaterializedAdmission, OneNode};

/// A miss writes nothing. After a hit starts framing, all output remains
/// tentative and any failure terminates export instead of appending a fallback.
pub(super) fn try_write(
    node: &OneNode,
    materialized: &MaterializedAdmission,
    references: &[BundleReference],
    head: Option<GitOid>,
    prerequisites: &[GitOid],
    selection: &Selection,
    limits: &StreamFullBundleLimits,
    live: &mut impl FnMut() -> bool,
    output: &mut (impl Write + ?Sized),
) -> Result<Option<StreamBundleExportReceipt>, StreamBundleExportRefusal> {
    checkpoint(live)?;
    if selection.keys.is_empty() || node.received_pack_cache().max_bytes() == 0 {
        return Ok(None);
    }
    let mut held = Vec::new();
    if held.try_reserve_exact(selection.external.len()).is_err() {
        return Ok(None);
    }
    let mut held_ids = BTreeSet::new();
    for (id, kind) in &selection.external {
        checkpoint(live)?;
        held.push((*id, *kind));
        held_ids.insert(*id);
    }
    // Keep the stricter buffered-object envelope for this optional path. A
    // larger streamed-blob allowance can still use the ordinary encoder on a
    // miss; it never increases a cache parser's resident allocation limit.
    let select = |live: &mut _| {
        node.received_pack_cache().try_reuse_with_held(
            &selection.keys,
            &limits.pack,
            true,
            &held,
            live,
        )
    };
    let first = select(live);
    checkpoint(live)?;
    let mut payload = match first {
        Ok(payload) => payload,
        Err(_) => return Ok(None),
    };
    if payload.is_none() {
        let restored = node.restore_received_pack_custody(
            materialized,
            &selection.keys,
            &held_ids,
            &limits.pack,
            live,
        );
        checkpoint(live)?;
        if let Err(error) = restored {
            // This helper's only fatal optional-work error is a stopped
            // request. Preserve it even if a future implementation returns it
            // without invoking our sticky deadline probe itself.
            if matches!(&error, crate::NodePackMaterializationRefusal::Pack(error)
                if matches!(error.as_ref(), fgit_pack::PackWriteError::Pack(PackError::DeadlineExceeded)))
            {
                return Err(NodeWorkspaceRefusal::BundleGraph(Box::new(error)).into());
            }
            return Ok(None);
        }
        let restored = select(live);
        checkpoint(live)?;
        payload = match restored {
            Ok(payload) => payload,
            Err(_) => return Ok(None),
        };
    }
    let Some(payload) = payload else {
        return Ok(None);
    };
    let received = payload.receipt().clone();
    if received.total_object_bytes() != selection.total_object_bytes
        || received.object_count() as usize != selection.objects.len()
        || (prerequisites.is_empty() && received.external_base_count() != 0)
    {
        return Ok(None);
    }
    let binding = ExistingPackBinding {
        checksum: received.checksum(),
        sha256: *received.sha256(),
        object_count: received.object_count(),
        bytes: received.output_bytes(),
    };
    // An eligible raw pack can be larger than a freshly compressed pack.
    // Include the exact header before choosing it, so an envelope miss still
    // gives the ordinary encoder its chance without any appended output.
    let envelope = check_existing_pack_bundle_envelope(
        node.object_format,
        references,
        head,
        prerequisites,
        &selection.objects,
        &selection.external,
        binding,
        limits,
        live,
    );
    checkpoint(live)?;
    if envelope.is_err() {
        return Ok(None);
    }
    let framing = write_existing_pack_bundle_stream(
        node.object_format,
        references,
        head,
        prerequisites,
        &selection.objects,
        &selection.external,
        binding,
        limits,
        live,
        &mut PayloadReader(payload),
        output,
    )
    .map_err(StreamBundleExportRefusal::Stream)?;
    checkpoint(live)?;
    Ok(Some(StreamBundleExportReceipt::from_received(
        received, framing,
    )))
}

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), StreamBundleExportRefusal> {
    if live() {
        Ok(())
    } else {
        Err(StreamBundleExportRefusal::Stream(
            PackError::DeadlineExceeded.into(),
        ))
    }
}

/// The payload pins immutable verified custody. Each read copies at most the
/// framer's fixed input chunk and never joins the compressed pack in memory.
struct PayloadReader(ReceivedPackPayload);
impl Read for PayloadReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let Some(bytes) = self.0.next_chunk(output.len())? else {
            return Ok(0);
        };
        output[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
}
