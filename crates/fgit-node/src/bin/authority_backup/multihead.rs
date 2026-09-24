//! Explicit all-heads operator profile. The ordinary single-head command and
//! FGSRC001 source archive keep their existing format and default behavior.
#[cfg(test)]
use std::fs;
use std::path::Path;

use fgit_authority::StoreInstanceId;
use fgit_authority_fsqlite::{
    MultiHeadLimits, decode_multi_head_snapshot, encode_multi_head_snapshot,
};

use super::{MAX_BYTES, hex, publish_new, quote, regular, require_absent, sha256, with_store};

#[path = "multihead_restore.rs"]
mod recovery;

pub fn export(input: &Path, destination: &Path) -> Result<String, String> {
    regular(input)?;
    require_absent(destination)?;
    let (bytes, bodies, heads, issuance, instance) = with_store(
        input,
        StoreInstanceId::from_raw(0),
        true,
        |runtime, store, cx| {
            let limits = MultiHeadLimits::default();
            let snapshot = runtime
                .block_on(store.export_multi_head_portable(cx, limits))
                .map_err(|error| error.to_string())?;
            let bytes = encode_multi_head_snapshot(&snapshot, limits, store.limits())
                .map_err(|error| error.to_string())?;
            if bytes.len() > MAX_BYTES {
                return Err("serialized all-heads backup exceeds 64 MiB".into());
            }
            // Exercise the destination's actual envelope, not just our writer.
            let decoded =
                decode_multi_head_snapshot(&bytes, limits, store.limits()).map_err(|error| {
                    format!("all-heads export exceeds restore codec envelope: {error}")
                })?;
            if decoded != snapshot {
                return Err("all-heads encoding changed the captured snapshot".into());
            }
            Ok((
                bytes,
                snapshot.bodies.len(),
                snapshot.heads.len(),
                snapshot.issuance.len(),
                snapshot.instance,
            ))
        },
    )?;
    let hash = hex(&sha256(&bytes));
    // with_store has awaited both store close and runtime drain before this link.
    publish_new(destination, &bytes)?;
    Ok(format!(
        concat!(
            "{{\"type\":\"authority_multi_head_backup_export\",\"schema_version\":1,",
            "\"format\":\"authority-export-v2\",\"sha256\":{},\"bytes\":{},",
            "\"bodies\":{},\"heads\":{},\"issuance_rows\":{},\"source_instance\":{},",
            "\"complete\":true,\"store_closed\":true,\"runtime_drained\":true,",
            "\"git_objects_included\":false,\"signature_verified\":false,\"authority_changed\":false}}"
        ),
        quote(&hash),
        bytes.len(),
        bodies,
        heads,
        issuance,
        instance
    ))
}

pub fn restore(
    input: &Path,
    destination: &Path,
    expected: [u8; 32],
    instance: StoreInstanceId,
) -> Result<String, String> {
    recovery::execute(input, destination, expected, instance, false)
}

/// Only the explicit all-heads resume command can adopt an owned restore root.
pub fn resume(
    input: &Path,
    destination: &Path,
    expected: [u8; 32],
    instance: StoreInstanceId,
) -> Result<String, String> {
    recovery::execute(input, destination, expected, instance, true)
}

#[cfg(test)]
#[path = "multihead_tests.rs"]
mod tests;
