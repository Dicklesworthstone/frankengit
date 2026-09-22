//! Explicit all-heads operator profile. The ordinary single-head command and
//! FGSRC001 source archive keep their existing format and default behavior.
use std::fs;
use std::path::Path;

use fgit_authority::{AuthorityLimits, StoreInstanceId};
use fgit_authority_fsqlite::{
    MultiHeadLimits, decode_multi_head_snapshot, encode_multi_head_snapshot,
};

use super::{
    MAX_BYTES, hex, parent, publish_new, quote, read_backup, regular, require_absent,
    sha256, sync_directory, with_store,
};

pub(super) fn export(input: &Path, destination: &Path) -> Result<String, String> {
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
            let decoded = decode_multi_head_snapshot(&bytes, limits, store.limits())
                .map_err(|error| format!("all-heads export exceeds restore codec envelope: {error}"))?;
            if decoded != snapshot {
                return Err("all-heads encoding changed the captured snapshot".into());
            }
            Ok((bytes, snapshot.bodies.len(), snapshot.heads.len(),
                snapshot.issuance.len(), snapshot.instance))
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
        quote(&hash), bytes.len(), bodies, heads, issuance, instance
    ))
}

pub(super) fn restore(input: &Path, destination: &Path, expected: [u8; 32],
    instance: StoreInstanceId,
) -> Result<String, String> {
    require_absent(destination)?;
    let bytes = read_backup(input)?;
    if sha256(&bytes) != expected {
        return Err("backup checksum mismatch; no destination created".into());
    }
    let limits = MultiHeadLimits::default();
    let snapshot = decode_multi_head_snapshot(&bytes, limits, AuthorityLimits::default())
        .map_err(|error| format!("invalid all-heads backup; no destination created: {error}"))?;
    if snapshot.instance == instance.raw() {
        return Err("destination instance must differ from source; no destination created".into());
    }
    // Complete format, lineage and capacity checks precede ALL destination writes.
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(destination)
        .map_err(|error| format!("cannot create new restore directory: {error}"))?;
    let path = destination.join("authority.fsqlite");
    let imported = with_store(&path, instance, false, |runtime, store, cx| {
        if store.instance_id() != instance {
            return Err("restore destination instance changed before import".into());
        }
        let receipts = runtime.block_on(store.import_multi_head_portable(cx, &snapshot, limits))
            .map_err(|error| format!("all-heads import did not confirm completion: {error}"))?;
        let checked = runtime.block_on(store.verify_multi_head_import(cx, &snapshot, limits))
            .map_err(|error| format!("all-heads import committed; whole-image verification failed: {error}"))?;
        if checked != receipts || receipts.len() != snapshot.heads.len() {
            return Err("all-heads import committed; publication receipts disagree with the complete image".into());
        }
        Ok(receipts)
    }).map_err(|error| format!(
        "{error}; restore directory retained at {}; do not infer success or non-commit from its presence",
        destination.display()
    ))?;
    // Read the persisted image through a NEW connection/runtime. Do not reimport
    // to make a missing row or a missing secondary head appear to verify.
    regular(&path).map_err(|error| format!("all-heads import committed; reopen refused: {error}"))?;
    with_store(&path, instance, true, |runtime, store, cx| {
        if store.instance_id() != instance {
            return Err("restored store has the wrong instance on reopen".into());
        }
        let checked = runtime.block_on(store.verify_multi_head_import(cx, &snapshot, limits))
            .map_err(|error| error.to_string())?;
        if checked != imported {
            return Err("reopened all-heads receipts differ from the import".into());
        }
        Ok(())
    }).map_err(|error| format!("all-heads import committed; persisted-image reopen verification failed: {error}"))?;
    sync_directory(destination)
        .map_err(|error| format!("all-heads restore committed and closed; directory sync failed: {error}"))?;
    sync_directory(parent(destination))
        .map_err(|error| format!("all-heads restore committed and closed; parent sync failed: {error}"))?;
    Ok(format!(
        concat!(
            "{{\"type\":\"authority_multi_head_backup_restore\",\"schema_version\":1,",
            "\"format\":\"authority-export-v2\",\"sha256\":{},\"bodies\":{},\"heads\":{},",
            "\"issuance_rows\":{},\"source_instance\":{},\"destination_instance\":{},",
            "\"database\":{},\"complete\":true,\"store_closed\":true,\"runtime_drained\":true,",
            "\"all_heads_verified\":true,\"reopened_and_verified\":true,",
            "\"source_tokens_preserved\":false,\"git_objects_restored\":false,",
            "\"routing_published\":false,\"signature_verified\":false}}"
        ),
        quote(&hex(&expected)), snapshot.bodies.len(), snapshot.heads.len(), snapshot.issuance.len(),
        snapshot.instance, instance.raw(), quote(&path.to_string_lossy())
    ))
}

#[cfg(test)]
#[path = "multihead_tests.rs"]
mod tests;
