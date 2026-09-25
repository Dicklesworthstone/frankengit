//! Bounded source recovery: authority rows plus EVERY Git object selected by
//! the same head. Payload bytes stream through a private, unpublished file.
mod archive;
mod input;
mod profile;
mod restore;

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

use fgit_authority::{HeadReadReceipt, StoreInstanceId};
use fgit_authority_fsqlite::{ExportBundle, PortableStoreLimits, export_bundle};
use fgit_crypto::GitObjectKind;
use crate::{NodeConfig, OneNode};
use fgit_object_fabric::ObjectKind as FabricKind;
use fgit_treefs::integrity::{GraphLimits, GraphReport, ObjectGraphAudit};
use fgit_types::{GitHashAlgorithm, HeadGeneration, RepositoryId, TenantId};

use super::{emit, hex, publish_streamed, quote, regular, require_absent, with_store};
use archive::stream::{Seal, StreamDecoder, StreamEncoder, StreamHeader, TransferLimits};
use archive::{Identity, MAX_OBJECT_BYTES, MAX_OBJECTS};
use profile::{Profile, ProfileFlags};

pub const USAGE: &str = "usage: fg backup export <storage-root> <new-backup-file> <tenant-id> <repository-id>
         --trusted-local [--object-format sha1|sha256]
         [--max-archive-bytes <1..1099511627776>] [--timeout-secs <1..86400>]

Authority metadata plus every authority-selected Git object, including admitted
history unreachable from current refs. Source head, complete local graph, native
IDs and original independent payload commitments are verified before export.
The head must remain unchanged across metadata capture, graph work and recheck.
No implicit retry, live directory copying, external Git, or remote authorization.

This is a bounded trusted-local SOURCE recovery transport, not a signed capsule
or a full service backup. External artifacts, private keys, runner workspaces,
search indexes and routing are excluded. Stable trusted parent paths required.
Default archive budget: 1 GiB; default operation deadline: 300 seconds.
Independent bounds: 100000 objects, 32 MiB per object, 100000 refs and
1000000 inspected edges. Authority metadata retains its separate 64 MiB bound.
Codec/runtime limits may refuse earlier. The deadline covers all passes, is
cooperative, and cannot interrupt a blocking filesystem call.
Export streams payloads through one object buffer and verifies the staged file.
Export never overwrites an existing file. Save its SHA-256 independently.";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    destination: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    profile: Profile,
}
fn parse(args: &[String]) -> Result<Options, String> {
    if !(6..=12).contains(&args.len())
        || args[0] != "export"
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
        || args[1].is_empty()
        || args[2].is_empty()
    {
        return Err(USAGE.into());
    }
    let mut trusted = false;
    let mut format = None;
    let mut profile = ProfileFlags::default();
    let mut cursor = 5;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        match flag.as_str() {
            "--trusted-local" if !trusted => trusted = true,
            "--object-format" if format.is_none() => {
                let value = args.get(cursor).ok_or("missing object format")?;
                cursor += 1;
                format = Some(match value.as_str() {
                    "sha1" => GitHashAlgorithm::Sha1,
                    "sha256" => GitHashAlgorithm::Sha256,
                    _ => return Err("object format must be sha1 or sha256".into()),
                });
            }
            "--max-archive-bytes" | "--timeout-secs" => {
                let value = args
                    .get(cursor)
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                cursor += 1;
                profile.set(flag, value)?;
            }
            _ => {
                return Err(format!(
                    "unknown or duplicate repository backup option: {flag}"
                ));
            }
        }
    }
    if !trusted {
        return Err(
            "repository export requires --trusted-local and whole-repository authorization".into(),
        );
    }
    let destination = PathBuf::from(&args[2]);
    if destination.file_name().is_none() {
        return Err("destination must name a new file".into());
    }
    Ok(Options {
        root: args[1].clone().into(),
        destination,
        tenant: TenantId::from_hex(&args[3]).map_err(|e| e.to_string())?,
        repository: RepositoryId::from_hex(&args[4]).map_err(|e| e.to_string())?,
        format: format.unwrap_or(GitHashAlgorithm::Sha1),
        profile: profile.finish(),
    })
}
fn limits(transfer: TransferLimits) -> GraphLimits {
    GraphLimits {
        max_objects: MAX_OBJECTS,
        max_object_bytes: MAX_OBJECT_BYTES,
        max_payload_bytes: transfer.max_archive_bytes,
        ..Default::default()
    }
}
/// Require exact token, key, generation AND bytes, not merely the same generation.
fn matches_head(bundle: &ExportBundle, current: &HeadReadReceipt) -> bool {
    bundle.head.as_ref().is_some_and(|head| {
        head.key.as_slice() == current.key().as_bytes()
            && head.token.as_slice() == current.token().to_opaque_bytes().as_slice()
            && head.generation == current.generation().get()
            && head.body.as_slice() == current.body()
    })
}
fn with_node<T>(
    config: NodeConfig,
    action: impl FnOnce(&OneNode) -> Result<T, String>,
) -> Result<T, String> {
    let mut node = OneNode::open_existing(config).map_err(|error| error.to_string())?;
    let result = node
        .bring_into_service(HeadGeneration::FIRST)
        .map_err(|e| e.to_string())
        .and_then(|()| action(&node));
    let cleanup = node.shutdown().map_err(|error| error.to_string());
    match (result, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(format!(
            "repository operation finished but node shutdown failed: {error}"
        )),
        (Err(error), Err(cleanup)) => Err(format!("{error}; node shutdown also failed: {cleanup}")),
    }
}
fn export(options: &Options, file: &mut File) -> Result<String, String> {
    let deadline = options.profile.start();
    let metadata = std::fs::symlink_metadata(&options.root).map_err(|e| e.to_string())?;
    if !metadata.is_dir() {
        return Err("source root must be an existing directory, not a symlink".into());
    }
    let database = options.root.join("authority.fsqlite");
    regular(&database)?;
    let authority = with_store(
        &database,
        StoreInstanceId::from_raw(0),
        true,
        |runtime, store, cx| {
            runtime
                .block_on(store.export_portable(cx, PortableStoreLimits::default()))
                .map_err(|e| e.to_string())
        },
    )?;
    let encoded = export_bundle(&authority).map_err(|error| error.to_string())?;
    deadline.check()?;
    let result = with_node(
        NodeConfig::new(options.root.clone(), options.tenant, options.repository)
            .with_object_format(options.format)
            .with_runtime_budgets(options.profile.node_budgets()?),
        |node| {
            let request = node.request_context();
            let selected = node
                .runtime()
                .block_on(node.materialize_admission_in(&request))
                .map_err(|e| e.to_string())?;
            deadline.in_request(&request)?;
            if !matches_head(&authority, selected.authenticated().receipt()) {
                return Err(
                    "repository head moved after authority capture; no backup published".into(),
                );
            }
            let objects = selected.selected_closure().closure().objects();
            let identity = Identity {
                tenant: options.tenant,
                repository: options.repository,
                incarnation: node.repository_incarnation_id(),
                format: options.format,
            };
            let mut io_live = || deadline.in_request(&request);
            let mut output = StreamEncoder::new(
                &mut *file,
                identity,
                &encoded,
                objects.len(),
                options.profile.transfer,
                &mut io_live,
            )?;
            for &oid in objects {
                io_live()?;
                let object = node
                    .read_git_object(oid)
                    .map_err(|error| format!("backup object {oid}: {error}"))?;
                io_live()?;
                let kind = match object.envelope().object_kind() {
                    FabricKind::Commit => GitObjectKind::Commit,
                    FabricKind::Tree => GitObjectKind::Tree,
                    FabricKind::Blob => GitObjectKind::Blob,
                    FabricKind::Tag => GitObjectKind::Tag,
                    FabricKind::Internal => {
                        return Err("non-Git object in selected source closure".into());
                    }
                };
                output.object(
                    oid,
                    kind,
                    object.payload(),
                    &object.envelope().payload_commitment(),
                    &mut io_live,
                )?;
            }
            let written = output.finish(&mut io_live)?;
            file.seek(SeekFrom::Start(0))
                .map_err(|e| format!("backup verification seek failed: {e}"))?;
            // Read the actual staged bytes, not a second encoding or source buffer.
            // Their checksum must equal the writer's digest and EOF must be exact.
            let mut decoded =
                StreamDecoder::new(&mut *file, options.profile.transfer, &mut io_live)?;
            if decoded.header().identity != identity
                || decoded.header().authority != authority
                || decoded.header().objects != objects.len()
            {
                return Err("repository backup transport changed its source snapshot".into());
            }
            let mut checkpoint = || deadline.in_request(&request).is_ok();
            let mut graph = ObjectGraphAudit::new(
                objects,
                options.format,
                limits(options.profile.transfer),
                &mut checkpoint,
            )
            .map_err(|error| error.to_string())?;
            while let Some(record) = decoded.record(&mut io_live)? {
                graph
                    .observe(record.oid, record.kind, record.payload, &mut checkpoint)
                    .map_err(|error| error.to_string())?;
            }
            let (header, verified) = decoded.finish(written.digest, &mut io_live)?;
            if verified != written {
                return Err("repository backup staged length changed".into());
            }
            let report = graph
                .finish(&selected.snapshot().refs, &mut checkpoint)
                .map_err(|error| error.to_string())?;
            let current = node
                .runtime()
                .block_on(node.authenticate_authority_head_in(&request))
                .map_err(|e| e.to_string())?;
            io_live()?;
            if !matches_head(&authority, current.receipt()) {
                return Err("repository head moved during backup; no backup published".into());
            }
            Ok(receipt(&header, report, verified))
        },
    )?;
    deadline.check()?;
    Ok(result)
}
fn receipt(archive: &StreamHeader, graph: GraphReport, seal: Seal) -> String {
    format!(
        concat!(
            "{{\"type\":\"repository_source_backup_export\",\"schema_version\":1,",
            "\"sha256\":{},\"bytes\":{},\"tenant_id\":{},\"repository_id\":{},\"incarnation_id\":{},",
            "\"object_format\":{},\"head_generation\":{},\"objects\":{},\"references\":{},",
            "\"payload_bytes\":{},\"local_edges\":{},\"external_gitlinks\":{},",
            "\"complete\":true,\"scope\":\"authority_and_selected_git_objects\",",
            "\"object_graph_verified\":true,\"original_payload_commitments_verified\":true,",
            "\"source_head_revalidated\":true,\"node_closed\":true,\"signature_verified\":false,",
            "\"external_artifacts_included\":false,\"physical_orphans_included\":false}}"
        ),
        quote(&hex(&seal.digest)),
        seal.bytes,
        quote(&archive.identity.tenant.to_string()),
        quote(&archive.identity.repository.to_string()),
        quote(&archive.identity.incarnation.to_string()),
        quote(archive.identity.format.as_str()),
        super::generation(&archive.authority),
        graph.objects,
        graph.references,
        graph.payload_bytes,
        graph.local_edges,
        graph.external_gitlinks
    )
}
pub fn run(args: &[String], output: &mut impl Write) -> Result<(), String> {
    if args == ["--help"] {
        emit(output, USAGE)?;
        emit(output, restore::USAGE)?;
        return emit(output, restore::verify::USAGE);
    }
    if args.first().is_some_and(|arg| arg == "verify") {
        return restore::verify::run(args, output);
    }
    if args.first().is_some_and(|arg| arg == "restore") {
        return restore::run(args, output);
    }
    if args == ["export", "--help"] {
        return emit(output, USAGE);
    }
    let options = parse(args)?;
    require_absent(&options.destination)?;
    let receipt = publish_streamed(&options.destination, |file| export(&options, file))?;
    emit(output, &receipt)
        .map_err(|error| format!("repository backup published; receipt output failed: {error}"))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod publication_tests;
