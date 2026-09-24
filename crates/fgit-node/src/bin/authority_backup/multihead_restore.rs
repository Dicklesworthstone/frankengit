//! One complete authority image, private staging, public database last.
//! Retries reconcile actual state; an intent is never a success receipt.
use std::path::Path;

use super::super::{hex, quote, read_backup, regular, require_absent, sha256, with_store};
use fgit_authority::{AuthorityLimits, HeadReadReceipt, StoreInstanceId};
use fgit_authority_fsqlite::{MultiHeadSnapshot, decode_multi_head_snapshot};

#[path = "multihead_state.rs"]
mod state;
use state::Custody;

/// Tests stop at production boundaries; the executable provides a no-op. These
/// are returned interruptions, not an environment-controlled process-kill hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Intent,
    Imported,
    Reopened,
    WalPrepared,
    Published,
    FinalVerified,
    Cleaned,
}

pub(super) fn execute(
    input: &Path,
    root: &Path,
    pin: [u8; 32],
    instance: StoreInstanceId,
    resume: bool,
) -> Result<String, String> {
    execute_with(input, root, pin, instance, resume, |_| Ok(()))
}

fn image(
    root: &Path,
    source: &MultiHeadSnapshot,
    instance: StoreInstanceId,
    import: bool,
    resume: bool,
) -> Result<Vec<HeadReadReceipt>, String> {
    let database = root.join("authority.fsqlite");
    if !import {
        regular(&database)?;
    }
    with_store(&database, instance, !import, |runtime, store, cx| {
        if store.instance_id() != instance {
            return Err("all-heads destination instance disagrees with restore intent".into());
        }
        let imported = if import {
            Some(
                if resume {
                    runtime.block_on(store.resume_multi_head_import(cx, source, Default::default()))
                } else {
                    runtime.block_on(store.import_multi_head_portable(
                        cx,
                        source,
                        Default::default(),
                    ))
                }
                .map_err(|error| format!("all-heads import outcome not confirmed: {error}"))?,
            )
        } else {
            None
        };
        let checked = runtime
            .block_on(store.verify_multi_head_import(cx, source, Default::default()))
            .map_err(|error| format!("all-heads whole-image verification refused: {error}"))?;
        if checked.len() != source.heads.len()
            || imported.as_ref().is_some_and(|prior| *prior != checked)
        {
            return Err("all-heads publication receipts disagree with the complete image".into());
        }
        for receipt in &checked {
            runtime
                .block_on(store.authenticate_head_receipt(cx, receipt))
                .map_err(|error| error.to_string())?;
        }
        Ok(checked)
    })
}

fn execute_with(
    input: &Path,
    root: &Path,
    pin: [u8; 32],
    instance: StoreInstanceId,
    resume: bool,
    mut checkpoint: impl FnMut(Stage) -> Result<(), String>,
) -> Result<String, String> {
    if !resume {
        require_absent(root)?;
    }
    let bytes = read_backup(input)?;
    if sha256(&bytes) != pin {
        return Err("backup checksum mismatch; destination untouched".into());
    }
    let source = decode_multi_head_snapshot(&bytes, Default::default(), AuthorityLimits::default())
        .map_err(|error| format!("invalid all-heads backup; destination untouched: {error}"))?;
    if source.instance == instance.raw() {
        return Err("destination instance must differ from source; destination untouched".into());
    }
    // Keep the exact decoded input, not a path to be reopened after validation.
    drop(bytes);
    let custody = Custody::acquire(root, pin, instance, resume)?;
    let already_published = custody.published()?;
    let outcome = (|| {
        let expected = if already_published {
            // Never reimport/repair an existing public image, even on --resume;
            // only drop a surviving quarantine alias so the engine can open it.
            custody.settle_publication()?;
            image(root, &source, instance, false, false)?
        } else {
            checkpoint(Stage::Intent)?;
            let quarantine = custody.quarantine()?;
            let imported = image(&quarantine, &source, instance, true, resume)?;
            checkpoint(Stage::Imported)?;
            let reopened = image(&quarantine, &source, instance, false, false)?;
            if reopened != imported {
                return Err("quarantined receipts changed across reopen".into());
            }
            checkpoint(Stage::Reopened)?;
            custody.publish(|| checkpoint(Stage::WalPrepared))?;
            imported
        };
        checkpoint(Stage::Published)?;
        let final_image = image(root, &source, instance, false, false)?;
        if final_image != expected {
            return Err("final-location receipts changed across reopen".into());
        }
        checkpoint(Stage::FinalVerified)?;
        custody.cleanup()?;
        checkpoint(Stage::Cleaned)?;
        Ok(())
    })();
    outcome.map_err(|error: String| match custody.published() {
        Ok(false) => format!(
            "{error}; final authority absent; private restore state retained at {}",
            root.display()
        ),
        Ok(true) => format!(
            "{error}; final authority is visible; verification/cleanup incomplete at {}",
            root.display()
        ),
        Err(inspect) => format!(
            "{error}; publication state could not be inspected: {inspect}; preserve {}",
            root.display()
        ),
    })?;
    Ok(format!(
        concat!(
            "{{\"type\":\"authority_multi_head_backup_restore\",\"schema_version\":1,",
            "\"format\":\"authority-export-v2\",\"sha256\":{},\"bodies\":{},\"heads\":{},",
            "\"issuance_rows\":{},\"source_instance\":{},\"destination_instance\":{},",
            "\"database\":{},\"complete\":true,\"store_closed\":true,\"runtime_drained\":true,",
            "\"all_heads_verified\":true,\"reopened_and_verified\":true,\"authority_installed_last\":true,",
            "\"resume_requested\":{},\"already_published\":{},",
            "\"source_tokens_preserved\":false,\"git_objects_restored\":false,",
            "\"routing_published\":false,\"signature_verified\":false}}"
        ),
        quote(&hex(&pin)),
        source.bodies.len(),
        source.heads.len(),
        source.issuance.len(),
        source.instance,
        instance.raw(),
        quote(&root.join("authority.fsqlite").to_string_lossy()),
        resume,
        already_published
    ))
}

#[cfg(test)]
#[path = "multihead_recovery_tests.rs"]
mod tests;
