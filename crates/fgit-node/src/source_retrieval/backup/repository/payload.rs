//! Archive payload ownership: blobs stream; only bounded Git metadata buffers.
use std::io::Read;

use fgit_crypto::GitObjectKind;
use fgit_treefs::integrity::ObjectGraphAudit;

use super::archive::{MAX_OBJECT_BYTES, stream::RecordHeader};

/// Read metadata only after its independent buffered limit has passed. The
/// final read requires the archive reader's authenticated EOF before use.
pub(super) fn metadata(header: RecordHeader, input: &mut dyn Read) -> Result<Vec<u8>, String> {
    if header.kind == GitObjectKind::Blob {
        return Err("blob payload requires streaming custody".into());
    }
    let length = usize::try_from(header.length)
        .ok()
        .filter(|length| *length <= MAX_OBJECT_BYTES)
        .ok_or("repository backup metadata object-byte limit")?;
    let mut body = Vec::new();
    body.try_reserve_exact(length)
        .map_err(|_| "repository backup metadata allocation refused")?;
    body.resize(length, 0);
    input.read_exact(&mut body).map_err(|e| e.to_string())?;
    let mut probe = [0];
    if input.read(&mut probe).map_err(|e| e.to_string())? != 0 {
        return Err("repository backup metadata exceeded its declared length".into());
    }
    Ok(body)
}

/// Return buffered metadata for optional exact readback comparison. Blobs are
/// independently native-hashed by the graph and leave no object-sized buffer.
pub(super) fn observe(
    graph: &mut ObjectGraphAudit,
    header: RecordHeader,
    input: &mut dyn Read,
    max_blob_bytes: u64,
    live: &mut impl FnMut() -> bool,
) -> Result<Option<Vec<u8>>, String> {
    if header.kind == GitObjectKind::Blob {
        let length = usize::try_from(header.length)
            .map_err(|_| "backup blob length is not representable on this host")?;
        let maximum = usize::try_from(max_blob_bytes)
            .map_err(|_| "backup blob limit is not representable on this host")?;
        graph
            .observe_blob_stream(
                header.oid,
                length,
                maximum,
                &mut |out| input.read(out),
                live,
            )
            .map_err(|e| e.to_string())?;
        Ok(None)
    } else {
        let body = metadata(header, input)?;
        graph
            .observe(header.oid, header.kind, &body, live)
            .map_err(|e| e.to_string())?;
        Ok(Some(body))
    }
}

#[cfg(test)]
mod tests;
