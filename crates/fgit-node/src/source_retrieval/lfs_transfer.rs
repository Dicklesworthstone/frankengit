//! Pinned native-pointer LFS portability over the existing immutable custody
//! store. These trusted-local host commands own and drain their node runtime.
//! Neither an archive nor a successful payload put publishes repository state.

mod files;
mod options;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::backup::{hex, publish_streamed, quote};
use crate::{NodeConfig, NodeRequestContext, OneNode};
use fgit_authority::HeadReadReceipt;
use fgit_object_fabric::ObjectKind;
#[cfg(test)]
use fgit_object_fabric::artifact::storage::lfs::transfer::Seal;
use fgit_object_fabric::artifact::storage::lfs::transfer::{
    self, Encoder, SourceIdentity, TransferLimits, VerifiedArchive,
};
use fgit_object_fabric::artifact::storage::lfs::{LfsObject, LfsOid, LfsStore, MAX_OBJECT_BYTES};
use fgit_object_fabric::artifact::storage::{ArtifactOperation, ArtifactPut};
use fgit_types::{
    GitHashAlgorithm, HeadGeneration, RepositoryId, RepositoryIncarnationId, TenantId,
};
use options::{Action, Deadline, Options};

#[derive(Clone, Copy, Debug, Default)]
struct ImportProgress {
    attempted: usize,
    created: usize,
    already_present: usize,
}

/// A failed host operation may have retained verified immutable payloads.
/// It never proves that a prior put was rolled back or deletes those payloads.
#[derive(Debug)]
pub struct LfsTransferFailure {
    message: String,
    progress: ImportProgress,
}
impl std::fmt::Display for LfsTransferFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.message)
    }
}
impl std::error::Error for LfsTransferFailure {}

#[must_use]
pub fn error_json(error: &LfsTransferFailure) -> String {
    format!(
        concat!(
            "{{\"type\":\"lfs_transfer_error\",\"schema_version\":1,\"complete\":false,",
            "\"retained_custody_may_exist\":{},\"put_attempts\":{},",
            "\"objects_created\":{},\"objects_already_present\":{},",
            "\"refs_published\":false,\"error\":{}}}"
        ),
        error.progress.attempted != 0,
        error.progress.attempted,
        error.progress.created,
        error.progress.already_present,
        quote(&error.message),
    )
}

/// Run one explicit inventory/export/import operation. This is a synchronous
/// top-level host boundary, not a request handler or an ambient capability.
pub fn run(args: &[String], output: &mut impl Write) -> Result<(), LfsTransferFailure> {
    run_with_timeout(args, output, None)
}

/// A global command time cap only shortens the leaf's absolute deadline.
pub fn run_with_timeout(
    args: &[String],
    output: &mut impl Write,
    timeout: Option<Duration>,
) -> Result<(), LfsTransferFailure> {
    let mut progress = ImportProgress::default();
    run_inner(args, output, timeout, &mut progress)
        .map_err(|message| LfsTransferFailure { message, progress })
}

fn run_inner(
    args: &[String],
    output: &mut impl Write,
    timeout: Option<Duration>,
    progress: &mut ImportProgress,
) -> Result<(), String> {
    if args == ["--help"]
        || (args.len() == 2
            && args[1] == "--help"
            && matches!(args[0].as_str(), "inventory" | "export" | "import"))
    {
        return emit(output, options::USAGE);
    }
    let options = Options::parse(args, timeout)?;
    let deadline = Deadline::new(options.timeout);
    deadline.check()?;
    files::directory(&options.root, false)?;
    let receipt = match options.action {
        Action::Inventory => with_node(&options, |node| {
            let request = node.request_context();
            let inventory = inventory(node, &request, &options, deadline)?;
            revalidate(node, &request, &inventory.receipt, deadline)?;
            inventory_json(&inventory, deadline)
        })?,
        Action::Export => {
            let path = options.archive.as_ref().ok_or("missing archive path")?;
            files::output(path)?;
            let custody = options.custody.as_ref().ok_or("missing custody root")?;
            files::directory(custody, true)?;
            publish_streamed(
                path,
                |file| export(&options, file, deadline),
                || deadline.check(),
            )?
        }
        Action::Import => import(&options, deadline, progress)?,
    };
    deadline.check().map_err(|error| match options.action {
        Action::Export => format!("LFS archive is published; {error}"),
        Action::Import => format!("LFS import may have retained verified custody; {error}; retry the identical archive and target pins"),
        Action::Inventory => error,
    })?;
    emit(output, &receipt).map_err(|e| match options.action {
        Action::Export => format!("LFS archive is published; receipt output failed: {e}"),
        Action::Import => format!("LFS import finished with retained custody; receipt output failed: {e}; retry the identical archive and target pins"),
        Action::Inventory => e,
    })
}

fn emit(output: &mut impl Write, text: &str) -> Result<(), String> {
    writeln!(output, "{text}")
        .and_then(|()| output.flush())
        .map_err(|e| e.to_string())
}

fn with_node<T>(
    options: &Options,
    operation: impl FnOnce(&OneNode) -> Result<T, String>,
) -> Result<T, String> {
    let mut node = OneNode::open_existing(options.config()?).map_err(|e| e.to_string())?;
    let result = node
        .bring_into_service(HeadGeneration::FIRST)
        .map_err(|e| e.to_string())
        .and_then(|()| operation(&node));
    let cleanup = node.shutdown().map_err(|e| e.to_string());
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(format!(
            "LFS operation finished; node shutdown failed: {error}"
        )),
        (Err(error), Err(cleanup)) => Err(format!("{error}; node shutdown also failed: {cleanup}")),
    }
}

struct Inventory {
    source: SourceIdentity,
    receipt: HeadReadReceipt,
    objects: Vec<LfsObject>,
    payload_bytes: u64,
    native_objects: usize,
    native_bytes: u64,
}

fn identity(options: &Options, node: &OneNode, receipt: &HeadReadReceipt) -> SourceIdentity {
    SourceIdentity {
        tenant: options.tenant,
        repository: options.repository,
        incarnation: node.repository_incarnation_id(),
        format: options.format,
        head_generation: receipt.generation().get(),
        head_token: receipt.token().to_opaque_bytes(),
        head_sha256: fgit_crypto::sha256_digest(receipt.body()),
    }
}

fn same_receipt(expected: &HeadReadReceipt, current: &HeadReadReceipt) -> bool {
    expected.key() == current.key()
        && expected.token() == current.token()
        && expected.generation() == current.generation()
        && expected.body() == current.body()
}

fn revalidate(
    node: &OneNode,
    request: &NodeRequestContext,
    expected: &HeadReadReceipt,
    deadline: Deadline,
) -> Result<(), String> {
    deadline.request(request)?;
    let current = node
        .runtime()
        .block_on(node.authenticate_authority_head_in(request))
        .map_err(|e| e.to_string())?;
    deadline.request(request)?;
    if !same_receipt(expected, current.receipt()) {
        return Err("LFS native inventory head moved; retain existing custody and inspect fresh destination pins before retry".into());
    }
    Ok(())
}

/// Header framing chooses a bounded read path only. Every selected object is
/// subsequently verified, so a corrupt advertised kind/length cannot silently
/// remove a pointer from this complete bounded native inventory.
fn inventory(
    node: &OneNode,
    request: &NodeRequestContext,
    options: &Options,
    deadline: Deadline,
) -> Result<Inventory, String> {
    deadline.request(request)?;
    if options
        .incarnation
        .is_some_and(|id| id != node.repository_incarnation_id())
    {
        return Err("LFS destination/source incarnation mismatch".into());
    }
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(request))
        .map_err(|e| e.to_string())?;
    deadline.request(request)?;
    let receipt = selected.authenticated().receipt().clone();
    let source = identity(options, node, &receipt);
    if options
        .head_sha256
        .is_some_and(|pin| pin != source.head_sha256)
    {
        return Err("LFS destination/source head pin mismatch".into());
    }
    let native = selected.selected_closure().closure().objects();
    if native.len() > options.source_objects {
        return Err("LFS native inventory object-count limit".into());
    }
    let mut pointers = BTreeMap::new();
    let mut native_bytes = 0_u64;
    for &oid in native {
        deadline.request(request)?;
        let header = node.git_object_header(oid).map_err(|e| e.to_string())?;
        native_bytes = native_bytes
            .checked_add(header.payload_length)
            .filter(|n| *n <= options.source_bytes)
            .ok_or("LFS native inventory byte limit")?;
        if header.kind == ObjectKind::Blob {
            let mut stream = node
                .open_git_blob_stream(oid, options.source_bytes)
                .map_err(|e| e.to_string())?;
            if stream.declared_length() != header.payload_length {
                return Err("LFS native blob framing changed".into());
            }
            let mut prefix = Vec::with_capacity(1024);
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                deadline.request(request)?;
                let count = stream
                    .read_tentative(&mut buffer)
                    .map_err(|e| e.to_string())?;
                deadline.request(request)?;
                if count == 0 {
                    break;
                }
                let copy = count.min(1024_usize.saturating_sub(prefix.len()));
                prefix.extend_from_slice(&buffer[..copy]);
            }
            observe_pointer(
                &prefix,
                header.payload_length,
                &mut pointers,
                options.limits,
            )?;
        } else {
            let object = node.read_git_object(oid).map_err(|e| e.to_string())?;
            if object.envelope().object_kind() != header.kind
                || object.payload().len() as u64 != header.payload_length
            {
                return Err("LFS native object framing changed".into());
            }
        }
    }
    let objects: Vec<_> = pointers
        .into_iter()
        .map(|(oid, size)| LfsObject { oid, size })
        .collect();
    let payload_bytes = objects
        .iter()
        .try_fold(0_u64, |sum, object| sum.checked_add(object.size))
        .filter(|sum| *sum <= options.limits.max_payload_bytes)
        .ok_or("LFS pointer payload-byte limit")?;
    deadline.request(request)?;
    Ok(Inventory {
        source,
        receipt,
        objects,
        payload_bytes,
        native_objects: native.len(),
        native_bytes,
    })
}

fn observe_pointer(
    prefix: &[u8],
    length: u64,
    objects: &mut BTreeMap<LfsOid, u64>,
    limits: TransferLimits,
) -> Result<(), String> {
    if !prefix.starts_with(b"version https://git-lfs.github.com/spec/") {
        return Ok(());
    }
    if length > 1024 || prefix.len() as u64 != length {
        return Err("unsupported oversized LFS pointer in native inventory".into());
    }
    let pointer = LfsObject::parse_pointer(prefix)
        .map_err(|e| format!("unsupported LFS pointer in native inventory: {e}"))?;
    if pointer.size > limits.max_object_bytes.min(MAX_OBJECT_BYTES) {
        return Err("LFS pointer exceeds per-object payload limit".into());
    }
    if let Some(size) = objects.get(&pointer.oid) {
        if *size != pointer.size {
            return Err("conflicting lengths for one native LFS OID".into());
        }
    } else {
        if objects.len() == limits.max_objects {
            return Err("LFS pointer object-count limit".into());
        }
        objects.insert(pointer.oid, pointer.size);
    }
    Ok(())
}

fn identity_json(source: &SourceIdentity) -> String {
    format!(
        concat!(
            "{{\"tenant_id\":{},\"repository_id\":{},\"incarnation_id\":{},",
            "\"object_format\":{},\"head_generation\":\"{}\",\"head_token\":{},\"head_sha256\":{}}}"
        ),
        quote(&source.tenant.to_string()),
        quote(&source.repository.to_string()),
        quote(&source.incarnation.to_string()),
        quote(source.format.as_str()),
        source.head_generation,
        quote(&hex(&source.head_token)),
        quote(&hex(&source.head_sha256)),
    )
}

fn inventory_json(inventory: &Inventory, deadline: Deadline) -> Result<String, String> {
    let mut out = format!(
        concat!(
            "{{\"type\":\"lfs_inventory\",\"schema_version\":1,\"source\":{},",
            "\"native_objects\":{},\"native_bytes\":{},\"objects\":{},\"payload_bytes\":{},",
            "\"complete\":true,\"scope\":\"authority_selected_native_pointers\",",
            "\"custody_verified\":false,\"head_revalidated\":true,\"node_closed\":true,\"pointers\":["
        ),
        identity_json(&inventory.source),
        inventory.native_objects,
        inventory.native_bytes,
        inventory.objects.len(),
        inventory.payload_bytes,
    );
    for (index, object) in inventory.objects.iter().enumerate() {
        deadline.check()?;
        if index != 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"oid\":{},\"size\":{}}}",
            quote(&object.oid.to_string()),
            object.size
        ));
        if out.len() > 16 * 1024 * 1024 {
            return Err("LFS inventory output limit".into());
        }
    }
    out.push_str("]}");
    Ok(out)
}

fn export(options: &Options, file: &mut File, deadline: Deadline) -> Result<String, String> {
    with_node(options, |node| {
        let request = node.request_context();
        let inventory = inventory(node, &request, options, deadline)?;
        let root = options.custody.as_ref().ok_or("missing LFS custody root")?;
        let store = LfsStore::open(
            root,
            options.tenant,
            options.repository,
            inventory.source.incarnation,
        )
        .map_err(|e| e.to_string())?;
        let live = || deadline.live(&request);
        let operation = ArtifactOperation::new(MAX_OBJECT_BYTES, deadline.remaining()?, &live)
            .map_err(|e| e.to_string())?;
        let mut archive_live = || deadline.live(&request);
        let mut encoder = Encoder::new(
            &mut *file,
            inventory.source,
            inventory.objects.len(),
            inventory.payload_bytes,
            options.limits,
            &mut archive_live,
        )
        .map_err(|e| e.to_string())?;
        for &object in &inventory.objects {
            deadline.request(&request)?;
            let mut payload = store.open_verified(object, &operation).map_err(|e| {
                format!(
                    "LFS source custody missing or invalid for {}: {e}",
                    object.oid
                )
            })?;
            encoder
                .object(object, &mut payload, &mut archive_live)
                .map_err(|e| e.to_string())?;
        }
        let seal = encoder
            .finish(&mut archive_live)
            .map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let verified = transfer::verify(file, seal.digest, options.limits, &mut archive_live)
            .map_err(|e| e.to_string())?;
        if verified.source() != &inventory.source
            || verified.seal() != seal
            || !verified
                .records()
                .iter()
                .map(|r| r.object())
                .eq(inventory.objects.iter().copied())
        {
            return Err("LFS archive changed its exact source selection".into());
        }
        revalidate(node, &request, &inventory.receipt, deadline)?;
        Ok(format!(
            concat!(
                "{{\"type\":\"lfs_export\",\"schema_version\":1,\"source\":{},",
                "\"sha256\":{},\"bytes\":{},\"objects\":{},\"payload_bytes\":{},",
                "\"native_objects\":{},\"native_bytes\":{},\"complete\":true,",
                "\"scope\":\"authority_selected_native_pointers\",\"source_head_revalidated\":true,",
                "\"node_closed\":true,\"refs_published\":false,\"physical_orphans_included\":false}}"
            ),
            identity_json(&inventory.source),
            quote(&hex(&seal.digest)),
            seal.bytes,
            inventory.objects.len(),
            seal.payload_bytes,
            inventory.native_objects,
            inventory.native_bytes,
        ))
    })
}

/// Complete target coverage is established before the first immutable write.
/// Extra source records remain fully verified but are never imported.
fn target_records(
    archive: &VerifiedArchive,
    target: &[LfsObject],
    live: &mut impl FnMut() -> bool,
) -> Result<Vec<usize>, String> {
    let records = archive.records();
    let mut selected = Vec::with_capacity(target.len());
    for object in target {
        if !live() {
            return Err("LFS target coverage cancelled or resource budget exhausted".into());
        }
        let index = records
            .binary_search_by_key(&object.oid, |record| record.object().oid)
            .map_err(|_| "LFS archive does not cover every target native pointer")?;
        if records[index].object() != *object {
            return Err("LFS archive conflicts with a target native pointer length".into());
        }
        selected.push(index);
    }
    Ok(selected)
}

fn import(
    options: &Options,
    deadline: Deadline,
    progress: &mut ImportProgress,
) -> Result<String, String> {
    let root = options.custody.as_ref().ok_or("missing LFS custody root")?;
    let path = options.archive.as_ref().ok_or("missing LFS archive")?;
    files::directory(root, true)?;
    let mut input = files::spool(path, root, options.limits.max_archive_bytes, deadline)?;
    let expected = options
        .archive_sha256
        .ok_or("missing independently trusted LFS archive checksum")?;
    let archive = transfer::verify(&mut input, expected, options.limits, &mut || {
        deadline.check().is_ok()
    })
    .map_err(|e| e.to_string())?;
    with_node(options, |node| {
        let request = node.request_context();
        let target = inventory(node, &request, options, deadline)?;
        let selected = target_records(&archive, &target.objects, &mut || deadline.live(&request))?;
        revalidate(node, &request, &target.receipt, deadline)?;
        let store = LfsStore::open(
            root,
            options.tenant,
            options.repository,
            target.source.incarnation,
        )
        .map_err(|e| e.to_string())?;
        let live = || deadline.live(&request);
        let operation = ArtifactOperation::new(MAX_OBJECT_BYTES, deadline.remaining()?, &live)
            .map_err(|e| e.to_string())?;
        for &index in &selected {
            revalidate(node, &request, &target.receipt, deadline)?;
            let record = &archive.records()[index];
            let object = record.object();
            input
                .seek(SeekFrom::Start(record.payload_offset()))
                .map_err(|e| e.to_string())?;
            let mut body = (&mut input).take(object.size);
            progress.attempted += 1;
            match store.put(object, &mut body, &operation) {
                Ok(ArtifactPut::Created) => progress.created += 1,
                Ok(ArtifactPut::AlreadyPresent) => progress.already_present += 1,
                Err(error) => {
                    return Err(format!(
                        "LFS import stopped at {}; earlier verified custody remains and this put may be retained: {error}; retry the identical archive and destination pins",
                        object.oid
                    ));
                }
            }
            revalidate(node, &request, &target.receipt, deadline)?;
        }
        revalidate(node, &request, &target.receipt, deadline)?;
        let seal = archive.seal();
        Ok(format!(
            concat!(
                "{{\"type\":\"lfs_import\",\"schema_version\":1,\"source\":{},\"target\":{},",
                "\"sha256\":{},\"archive_bytes\":{},\"archive_objects\":{},\"archive_payload_bytes\":{},",
                "\"objects\":{},\"payload_bytes\":{},\"objects_created\":{},\"objects_already_present\":{},",
                "\"unreferenced_objects_skipped\":{},\"unreferenced_payload_bytes_skipped\":{},",
                "\"complete\":true,\"target_pointer_coverage_verified\":true,\"target_head_revalidated\":true,",
                "\"retained_custody\":{},\"node_closed\":true,\"refs_published\":false,\"retention_roots_published\":false}}"
            ),
            identity_json(archive.source()),
            identity_json(&target.source),
            quote(&hex(&seal.digest)),
            seal.bytes,
            archive.records().len(),
            seal.payload_bytes,
            selected.len(),
            target.payload_bytes,
            progress.created,
            progress.already_present,
            archive.records().len() - selected.len(),
            seal.payload_bytes - target.payload_bytes,
            !selected.is_empty(),
        ))
    })
}

#[cfg(test)]
mod tests;
