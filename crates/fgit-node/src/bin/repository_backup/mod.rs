//! Bounded source-recovery transport: authority rows plus EVERY admitted Git
//! object selected by the exact same authenticated head. No directory inventory
//! or mutable Git repository becomes authoritative. This is not a capsule.
mod archive;
mod restore;

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fgit_authority::{HeadReadReceipt, StoreInstanceId};
use fgit_authority_fsqlite::{ExportBundle, PortableStoreLimits, export_bundle};
use fgit_crypto::GitObjectKind;
use fgit_node::{NodeConfig, NodeRequestContext, OneNode};
use fgit_object_fabric::ObjectKind as FabricKind;
use fgit_treefs::integrity::{GraphLimits, GraphReport, ObjectGraphAudit};
use fgit_types::{GitHashAlgorithm, HeadGeneration, RepositoryId, TenantId};

use super::{emit, hex, publish_new, quote, regular, require_absent, sha256, with_store};
use archive::{Archive, Encoder, Identity, MAX_ARCHIVE_BYTES, MAX_OBJECT_BYTES, MAX_OBJECTS};

pub(super) const USAGE: &str = "usage: fg-repository-backup export <storage-root> <new-backup-file> <tenant-id> <repository-id>
         --trusted-local [--object-format sha1|sha256]

Authority metadata plus every authority-selected Git object, including admitted
history unreachable from current refs. Source head, complete local graph, native
IDs and original independent payload commitments are verified before export.
The head must remain unchanged across metadata capture, graph work and recheck.
No implicit retry, live directory copying, external Git, or remote authorization.

This is a bounded trusted-local SOURCE recovery transport, not a signed capsule
or a full service backup. External artifacts, private keys, runner workspaces,
search indexes and routing are excluded. Stable trusted parent paths required.
Limits: 64 MiB complete transport, 100000 objects, 32 MiB per object, 100000 refs,
1000000 inspected edges and a 300 second node scan. Codec/runtime limits may
refuse earlier. The scan timeout is cooperative, not a blocking-I/O interruption.
Export never overwrites an existing file. Save its SHA-256 independently.";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    destination: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
}
fn parse(args: &[String]) -> Result<Options, String> {
    if !(6..=8).contains(&args.len()) || args[0] != "export"
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
        || args[1].is_empty() || args[2].is_empty()
    { return Err(USAGE.into()); }
    let mut trusted = false;
    let mut format = None;
    let mut cursor = 5;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        match flag.as_str() {
            "--trusted-local" if !trusted => trusted = true,
            "--object-format" if format.is_none() => {
                let value = args.get(cursor).ok_or("missing object format")?;
                cursor += 1;
                format = Some(match value.as_str() {
                    "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256,
                    _ => return Err("object format must be sha1 or sha256".into()),
                });
            }
            _ => return Err(format!("unknown or duplicate repository backup option: {flag}")),
        }
    }
    if !trusted { return Err("repository export requires --trusted-local and whole-repository authorization".into()); }
    let destination = PathBuf::from(&args[2]);
    if destination.file_name().is_none() { return Err("destination must name a new file".into()); }
    Ok(Options { root: args[1].clone().into(), destination,
        tenant: TenantId::from_hex(&args[3]).map_err(|e| e.to_string())?,
        repository: RepositoryId::from_hex(&args[4]).map_err(|e| e.to_string())?,
        format: format.unwrap_or(GitHashAlgorithm::Sha1) })
}
fn limits() -> GraphLimits {
    GraphLimits { max_objects: MAX_OBJECTS, max_object_bytes: MAX_OBJECT_BYTES,
        max_payload_bytes: MAX_ARCHIVE_BYTES as u64, ..Default::default() }
}
fn live(started: Instant, request: &NodeRequestContext) -> Result<(), String> {
    if started.elapsed() >= Duration::from_secs(300) {
        request.cancel();
        return Err("repository backup scan deadline exceeded".into());
    }
    Ok(())
}
/// Require exact token, key, generation AND bytes, not merely the same generation.
fn matches_head(bundle: &ExportBundle, current: &HeadReadReceipt) -> bool {
    bundle.head.as_ref().is_some_and(|head|
        head.key.as_slice() == current.key().as_bytes()
        && head.token.as_slice() == current.token().to_opaque_bytes().as_slice()
        && head.generation == current.generation().get()
        && head.body.as_slice() == current.body())
}
fn with_node<T>(config: NodeConfig, action: impl FnOnce(&OneNode) -> Result<T, String>) -> Result<T, String> {
    let mut node = OneNode::open_existing(config).map_err(|error| error.to_string())?;
    let result = node.bring_into_service(HeadGeneration::FIRST).map_err(|e| e.to_string())
        .and_then(|()| action(&node));
    let cleanup = node.shutdown().map_err(|error| error.to_string());
    match (result, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(format!("repository operation finished but node shutdown failed: {error}")),
        (Err(error), Err(cleanup)) => Err(format!("{error}; node shutdown also failed: {cleanup}")),
    }
}
fn export(options: &Options) -> Result<(Vec<u8>, String), String> {
    let metadata = std::fs::symlink_metadata(&options.root).map_err(|e| e.to_string())?;
    if !metadata.is_dir() { return Err("source root must be an existing directory, not a symlink".into()); }
    let database = options.root.join("authority.fsqlite");
    regular(&database)?;
    let authority = with_store(&database, StoreInstanceId::from_raw(0), true, |runtime, store, cx|
        runtime.block_on(store.export_portable(cx, PortableStoreLimits::default())).map_err(|e| e.to_string()))?;
    let encoded = export_bundle(&authority).map_err(|error| error.to_string())?;
    with_node(NodeConfig::new(options.root.clone(), options.tenant, options.repository)
        .with_object_format(options.format), |node| {
        let started = Instant::now();
        let request = node.request_context();
        let selected = node.runtime().block_on(node.materialize_admission_in(&request)).map_err(|e| e.to_string())?;
        live(started, &request)?;
        if !matches_head(&authority, selected.authenticated().receipt()) {
            return Err("repository head moved after authority capture; no backup published".into());
        }
        let objects = selected.selected_closure().closure().objects();
        let mut checkpoint = || live(started, &request).is_ok();
        let identity = Identity { tenant: options.tenant, repository: options.repository,
            incarnation: node.repository_incarnation_id(), format: options.format };
        let mut output = Encoder::new(identity, &encoded, objects.len())?;
        for &oid in objects {
            live(started, &request)?;
            let object = node.read_git_object(oid).map_err(|error| format!("backup object {oid}: {error}"))?;
            live(started, &request)?;
            let kind = match object.envelope().object_kind() {
                FabricKind::Commit => GitObjectKind::Commit, FabricKind::Tree => GitObjectKind::Tree,
                FabricKind::Blob => GitObjectKind::Blob, FabricKind::Tag => GitObjectKind::Tag,
                FabricKind::Internal => return Err("non-Git object in selected source closure".into()),
            };
            output.object(oid, kind, object.payload(), &object.envelope().payload_commitment())?;
        }
        let bytes = output.finish()?;
        // Exercise the same hostile-input envelope the destination uses. There
        // must never be a successful export that our own decoder cannot read.
        let decoded = archive::decode(&bytes, || live(started, &request))?;
        if decoded.identity != identity || decoded.authority != authority || decoded.records.len() != objects.len() {
            return Err("repository backup transport changed its source snapshot".into());
        }
        let mut graph = ObjectGraphAudit::new(objects, options.format, limits(), &mut checkpoint)
            .map_err(|error| error.to_string())?;
        for record in &decoded.records {
            graph.observe(record.oid, record.kind, record.payload, &mut checkpoint).map_err(|error| error.to_string())?;
        }
        let report = graph.finish(&selected.snapshot().refs, &mut checkpoint).map_err(|error| error.to_string())?;
        let current = node.runtime().block_on(node.authenticate_authority_head_in(&request)).map_err(|e| e.to_string())?;
        live(started, &request)?;
        if !matches_head(&authority, current.receipt()) {
            return Err("repository head moved during backup; no backup published".into());
        }
        let receipt = receipt(&decoded, report, sha256(&bytes), bytes.len());
        Ok((bytes, receipt))
    })
}
fn receipt(archive: &Archive<'_>, graph: GraphReport, digest: [u8; 32], size: usize) -> String {
    format!(concat!("{{\"type\":\"repository_source_backup_export\",\"schema_version\":1,",
        "\"sha256\":{},\"bytes\":{},\"tenant_id\":{},\"repository_id\":{},\"incarnation_id\":{},",
        "\"object_format\":{},\"head_generation\":{},\"objects\":{},\"references\":{},",
        "\"payload_bytes\":{},\"local_edges\":{},\"external_gitlinks\":{},",
        "\"complete\":true,\"scope\":\"authority_and_selected_git_objects\",",
        "\"object_graph_verified\":true,\"original_payload_commitments_verified\":true,",
        "\"source_head_revalidated\":true,\"node_closed\":true,\"signature_verified\":false,",
        "\"external_artifacts_included\":false,\"physical_orphans_included\":false}}"),
        quote(&hex(&digest)), size, quote(&archive.identity.tenant.to_string()),
        quote(&archive.identity.repository.to_string()), quote(&archive.identity.incarnation.to_string()),
        quote(archive.identity.format.as_str()), super::generation(&archive.authority),
        graph.objects, graph.references, graph.payload_bytes, graph.local_edges, graph.external_gitlinks)
}
pub(super) fn run(args: &[String], output: &mut impl Write) -> Result<(), String> {
    if args == ["--help"] { emit(output, USAGE)?; return emit(output, restore::USAGE); }
    if args.first().is_some_and(|arg| arg == "restore") { return restore::run(args, output); }
    if args == ["export", "--help"] { return emit(output, USAGE); }
    let options = parse(args)?;
    require_absent(&options.destination)?;
    let (bytes, receipt) = export(&options)?;
    publish_new(&options.destination, &bytes)?;
    emit(output, &receipt).map_err(|error| format!("repository backup published; receipt output failed: {error}"))
}

#[cfg(test)]
mod tests;
