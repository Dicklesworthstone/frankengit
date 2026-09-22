//! Restore only into a newly reserved root. Its public authority path stays
//! absent until quarantined metadata AND every selected Git object verify.
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fgit_authority::{HeadReadReceipt, StoreInstanceId};
use fgit_crypto::GitObjectKind;
use fgit_node::{NodeConfig, OneNode};
use fgit_object_fabric::ObjectKind as FabricKind;
use fgit_treefs::integrity::{GraphReport, ObjectGraphAudit};

use super::archive::{self, Archive, MAX_ARCHIVE_BYTES};
use super::{limits, live, with_node};
use super::super::{emit, generation, hex, parent, quote, regular, require_absent,
    sha256, sync_directory, with_store};

pub(super) const USAGE: &str = "usage: fg-repository-backup restore <backup-file> <new-storage-root> --trusted-local
         --expected-sha256 <64-lowercase-hex> --destination-instance <positive-integer>

Restores the exact source checkpoint and its complete selected Git graph into
an EMPTY new root. Supply an independently trusted archive checksum and a fresh
store-instance identity distinct from the source. Source CAS tokens are reminted.
No existing repository is overwritten, rewound or merged with the backup.

Decode/checksum/identity checks precede directory creation. Metadata and objects
are then staged under .restore-quarantine; graph/selection, original commitments
and disk readback must verify before authority.fsqlite is published at the root.
The closed database's WAL, if any, is installed BEFORE that database. A remaining
nonempty rollback journal refuses publication. Shared-memory caches are rebuilt.
A fresh reopen is checked before success. Failed/interrupted directories remain
for investigation; existence never implies completion. Do not concurrently open
or modify the reserved root/quarantine. Trusted parent paths are required.

This is SOURCE recovery, not a signed capsule, external-artifact backup, routing
activation or authorization to replay external effects. Review restored outbox
state and external dependencies before serving. The checksum pins exactly one
chosen checkpoint; it does not prove this was the newest source checkpoint.
Exit 0: complete scoped restore after node close; 2: refusal, incomplete operation,
cleanup or receipt I/O failure. A failure after authority publication says so.";

#[derive(Debug)]
struct Options { input: PathBuf, output: PathBuf, expected: [u8; 32], instance: StoreInstanceId }
fn digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("expected SHA-256 must be exactly 64 lowercase hexadecimal characters".into());
    }
    let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    let mut result = [0; 32];
    for (out, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *out = 16 * nibble(pair[0]) + nibble(pair[1]);
    }
    Ok(result)
}
fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() != 8 || args[0] != "restore" || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
        || args[1].is_empty() || args[2].is_empty()
    { return Err(USAGE.into()); }
    let (mut trusted, mut expected, mut instance) = (false, None, None);
    let mut cursor = 3;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        if flag == "--trusted-local" && !trusted { trusted = true; continue; }
        let value = args.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag.as_str() {
            "--expected-sha256" if expected.is_none() => expected = Some(digest(value)?),
            "--destination-instance" if instance.is_none() => {
                if value.starts_with('0') || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("destination instance must be canonical positive decimal".into());
                }
                let number = value.parse::<u64>().ok().filter(|n| *n > 0 && *n <= i64::MAX as u64)
                    .ok_or("destination instance must fit a positive SQL integer")?;
                instance = Some(StoreInstanceId::from_raw(number));
            }
            _ => return Err(format!("unknown or duplicate restore option: {flag}")),
        }
    }
    if !trusted { return Err("restore requires --trusted-local and whole-repository authorization".into()); }
    let output = PathBuf::from(&args[2]);
    if output.file_name().is_none() { return Err("restore requires a new named storage root".into()); }
    Ok(Options { input: args[1].clone().into(), output,
        expected: expected.ok_or("restore requires an independently trusted --expected-sha256")?,
        instance: instance.ok_or("restore requires a new --destination-instance")? })
}
fn read_backup(path: &Path) -> Result<Vec<u8>, String> {
    if regular(path)? > MAX_ARCHIVE_BYTES as u64 { return Err("repository backup input exceeds 64 MiB".into()); }
    let file = File::open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() || opened.len() > MAX_ARCHIVE_BYTES as u64 {
        return Err("repository backup changed into a non-regular or oversized input".into());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(usize::try_from(opened.len()).map_err(|_| "input length overflow")?)
        .map_err(|_| "repository backup input allocation refused")?;
    file.take(MAX_ARCHIVE_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_ARCHIVE_BYTES { return Err("empty or oversized repository backup".into()); }
    Ok(bytes)
}
fn create_private(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|e| format!("cannot reserve new restore directory: {e}"))
}
fn config(root: &Path, archive: &Archive<'_>) -> NodeConfig {
    let id = archive.identity;
    NodeConfig::new(root.to_path_buf(), id.tenant, id.repository)
        .with_object_format(id.format).with_expected_repository_incarnation(id.incarnation)
}
fn graph_from_archive(node: &OneNode, archive: &Archive<'_>, expected: &HeadReadReceipt,
    install: bool,
) -> Result<GraphReport, String> {
    let started = Instant::now();
    let request = node.request_context();
    let selected = node.runtime().block_on(node.materialize_admission_in(&request)).map_err(|e| e.to_string())?;
    live(started, &request)?;
    if selected.authenticated().receipt() != expected {
        return Err("restored authority disagrees with its exact import receipt".into());
    }
    let objects = selected.selected_closure().closure().objects();
    if objects.len() != archive.records.len()
        || objects.iter().zip(&archive.records).any(|(oid, record)| *oid != record.oid)
    { return Err("archive inventory does not equal the authority-selected object set".into()); }
    let mut checkpoint = || live(started, &request).is_ok();
    let mut graph = ObjectGraphAudit::new(objects, archive.identity.format, limits(), &mut checkpoint)
        .map_err(|e| e.to_string())?;
    // Graph/selection validation precedes ALL Git object placement.
    for record in &archive.records {
        graph.observe(record.oid, record.kind, record.payload, &mut checkpoint).map_err(|e| e.to_string())?;
    }
    let report = graph.finish(&selected.snapshot().refs, &mut checkpoint).map_err(|e| e.to_string())?;
    for record in &archive.records {
        live(started, &request)?;
        if install {
            let mut body = Vec::new();
            body.try_reserve_exact(record.payload.len()).map_err(|_| "restore object allocation refused")?;
            body.extend_from_slice(record.payload);
            let stored = node.put_git_object(record.kind, body).map_err(|e| e.to_string())?;
            if stored.identity() != record.oid { return Err("restored object changed identity".into()); }
        }
        let stored = node.read_git_object(record.oid).map_err(|e| e.to_string())?;
        live(started, &request)?;
        let kind = match record.kind {
            GitObjectKind::Commit => FabricKind::Commit, GitObjectKind::Tree => FabricKind::Tree,
            GitObjectKind::Blob => FabricKind::Blob, GitObjectKind::Tag => FabricKind::Tag,
        };
        if stored.envelope().object_kind() != kind || stored.payload() != record.payload {
            return Err(format!("restored object did not read back byte-identically: {}", record.oid));
        }
    }
    let current = node.runtime().block_on(node.authenticate_authority_head_in(&request)).map_err(|e| e.to_string())?;
    live(started, &request)?;
    if current.receipt() != expected { return Err("restored head moved during verification".into()); }
    Ok(report)
}

/// Filesystem phase after the quarantined node has verified and CLOSED. This
/// object owns no authority: it only prepares the already-verified closed image.
/// Dropping it leaves final authority absent. No automatic cleanup deletes evidence.
struct PreparedPublication { quarantine: PathBuf, destination: PathBuf }
impl PreparedPublication {
    fn prepare(quarantine: &Path, destination: &Path) -> Result<Self, String> {
        let database = quarantine.join("authority.fsqlite");
        regular(&database)?;
        require_absent(&destination.join("authority.fsqlite"))?;
        // A successful close is not an excuse to discard uncheckpointed WAL.
        // Hot rollback journals are refused rather than interpreted by this layer.
        match fs::symlink_metadata(quarantine.join("authority.fsqlite-journal")) {
            Ok(metadata) if metadata.is_file() && metadata.len() == 0 => {},
            Ok(_) => return Err("closed restore retained a rollback journal; publication refused".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.to_string()),
        }
        File::open(&database).and_then(|file| file.sync_all()).map_err(|e| e.to_string())?;
        let objects = quarantine.join("objects");
        let target_objects = destination.join("objects");
        require_absent(&target_objects)?;
        let metadata = fs::symlink_metadata(&objects).map_err(|e| e.to_string())?;
        if !metadata.is_dir() { return Err("restore object fabric is not a directory".into()); }
        // Both directories are exclusively owned by this invocation under the
        // newly reserved, trusted root. No archive pathname enters this rename.
        fs::rename(&objects, &target_objects).map_err(|e| e.to_string())?;
        sync_directory(&target_objects).map_err(|e| e.to_string())?;
        let wal = quarantine.join("authority.fsqlite-wal");
        match fs::symlink_metadata(&wal) {
            Ok(metadata) if metadata.is_file() => {
                File::open(&wal).and_then(|file| file.sync_all()).map_err(|e| e.to_string())?;
                fs::hard_link(&wal, destination.join("authority.fsqlite-wal")).map_err(|e| e.to_string())?;
            }
            Ok(_) => return Err("restore WAL is not a regular file".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.to_string()),
        }
        sync_directory(quarantine).map_err(|e| e.to_string())?;
        sync_directory(destination).map_err(|e| e.to_string())?;
        sync_directory(parent(destination)).map_err(|e| e.to_string())?;
        Ok(Self { quarantine: quarantine.to_path_buf(), destination: destination.to_path_buf() })
    }
    fn publish(self) -> Result<(), String> {
        fs::hard_link(self.quarantine.join("authority.fsqlite"), self.destination.join("authority.fsqlite"))
            .map_err(|e| format!("destination authority was not published: {e}"))?;
        sync_directory(&self.destination).map_err(|e| format!("destination authority is visible; sync failed: {e}"))?;
        // Remove only this invocation's private staging tree, never the target.
        fs::remove_dir_all(&self.quarantine).map_err(|e| format!("destination authority is visible; quarantine cleanup failed: {e}"))?;
        sync_directory(&self.destination).map_err(|e| format!("destination authority is visible; cleanup sync failed: {e}"))
    }
}
fn execute(options: &Options) -> Result<String, String> {
    require_absent(&options.output)?;
    let bytes = read_backup(&options.input)?;
    if sha256(&bytes) != options.expected { return Err("backup checksum mismatch; no destination created".into()); }
    let started = Instant::now();
    let archive = archive::decode(&bytes, || {
        if started.elapsed() >= Duration::from_secs(300) { Err("repository backup decode deadline".into()) } else { Ok(()) }
    })?;
    if archive.authority.instance == options.instance.raw() {
        return Err("destination instance must differ from source; no destination created".into());
    }
    create_private(&options.output)?;
    let quarantine = options.output.join(".restore-quarantine");
    let prepared = (|| {
        create_private(&quarantine)?;
        let expected = with_store(&quarantine.join("authority.fsqlite"), options.instance, false, |runtime, store, cx| {
            let head = runtime.block_on(store.import_portable(cx, &archive.authority, Default::default()))
                .map_err(|e| e.to_string())?.ok_or("repository import returned no head")?;
            runtime.block_on(store.authenticate_head_receipt(cx, &head)).map_err(|e| e.to_string())?;
            let source = archive.authority.head.as_ref().ok_or("missing source head")?;
            if head.key().as_bytes() != source.key.as_slice() || head.body() != source.body.as_slice()
                || head.generation().get() != source.generation
            { return Err("repository import changed canonical head bytes".into()); }
            Ok(head)
        })?;
        let graph = with_node(config(&quarantine, &archive), |node|
            graph_from_archive(node, &archive, &expected, true))?;
        // Reopen the closed image and re-read every body before public authority.
        let reopened = with_node(config(&quarantine, &archive), |node|
            graph_from_archive(node, &archive, &expected, false))?;
        if reopened != graph { return Err("restored graph changed across quarantine reopen".into()); }
        let publication = PreparedPublication::prepare(&quarantine, &options.output)?;
        Ok((publication, expected, graph))
    })();
    let (publication, expected, graph) = prepared.map_err(|error: String| format!(
        "{error}; destination authority not published; retained restore state at {}", options.output.display()))?;
    publication.publish()?;
    let reopened = with_node(config(&options.output, &archive), |node|
        graph_from_archive(node, &archive, &expected, false))
        .map_err(|error| format!("destination authority is visible; final reopen verification failed: {error}"))?;
    if reopened != graph { return Err("destination authority is visible; final graph report mismatch".into()); }
    Ok(format!(concat!("{{\"type\":\"repository_source_backup_restore\",\"schema_version\":1,",
        "\"sha256\":{},\"tenant_id\":{},\"repository_id\":{},\"incarnation_id\":{},",
        "\"object_format\":{},\"head_generation\":{},\"objects\":{},\"references\":{},",
        "\"payload_bytes\":{},\"destination_instance\":{},\"complete\":true,",
        "\"scope\":\"authority_and_selected_git_objects\",\"object_graph_verified\":true,",
        "\"original_payload_commitments_verified\":true,\"source_tokens_preserved\":false,",
        "\"reopened_and_verified\":true,\"node_closed\":true,\"routing_published\":false,",
        "\"external_artifacts_restored\":false,\"signature_verified\":false}}"),
        quote(&hex(&options.expected)), quote(&archive.identity.tenant.to_string()),
        quote(&archive.identity.repository.to_string()), quote(&archive.identity.incarnation.to_string()),
        quote(archive.identity.format.as_str()), generation(&archive.authority), graph.objects,
        graph.references, graph.payload_bytes, options.instance.raw()))
}
pub(super) fn run(args: &[String], output: &mut impl Write) -> Result<(), String> {
    if args == ["restore", "--help"] { return emit(output, USAGE); }
    let receipt = execute(&parse(args)?)?;
    emit(output, &receipt).map_err(|error| format!("destination authority is visible and verified; receipt output failed: {error}"))
}

#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;
