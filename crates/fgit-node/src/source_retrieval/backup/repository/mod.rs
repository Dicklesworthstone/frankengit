//! Bounded source recovery: authority rows plus EVERY Git object selected by
//! the same head. Payload bytes stream through a private, unpublished file.
mod approval;
mod archive;
mod attest;
mod blob_io;
mod checkpoint;
mod donor;
mod input;
mod lfs;
mod payload;
mod profile;
mod reconstruct;
#[cfg(unix)]
mod recovery_io;
mod replication;
mod restore;
mod selection;

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::{NodeConfig, NodeRequestContext, OneNode};
use fgit_authority::{HeadReadReceipt, StoreInstanceId};
use fgit_authority_fsqlite::{ExportBundle, PortableStoreLimits, export_bundle};
use fgit_crypto::GitObjectKind;
use fgit_object_fabric::ObjectKind as FabricKind;
use fgit_treefs::integrity::{GraphLimits, GraphReport, ObjectGraphAudit};
use fgit_types::{GitHashAlgorithm, GitOid, HeadGeneration, RepositoryId, TenantId};

use super::{emit, hex, publish_streamed, quote, regular, require_absent, with_store};
use archive::stream::{Seal, StreamDecoder, StreamEncoder, StreamHeader, TransferLimits};
use archive::{Identity, MAX_OBJECT_BYTES};
use profile::{Deadline, Profile, ProfileFlags};
use std::time::Duration;

/// An independently pinned optional payload companion. Its source identity and
/// complete inventory are checked against the source archive, not a directory.
#[derive(Clone, Debug)]
struct LfsInput {
    path: PathBuf,
    expected: [u8; 32],
}

#[derive(Default)]
struct LfsInputFlags {
    path: Option<PathBuf>,
    expected: Option<[u8; 32]>,
}
impl LfsInputFlags {
    fn accepts(flag: &str) -> bool {
        matches!(flag, "--lfs-archive" | "--expected-lfs-sha256")
    }

    fn set(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--lfs-archive" if self.path.is_none() && !value.is_empty() => {
                self.path = Some(PathBuf::from(value));
            }
            "--expected-lfs-sha256" if self.expected.is_none() => {
                self.expected = Some(restore::digest(value)?);
            }
            _ => return Err(format!("invalid or duplicate LFS companion option: {flag}")),
        }
        Ok(())
    }

    fn finish(self) -> Result<Option<LfsInput>, String> {
        match (self.path, self.expected) {
            (None, None) => Ok(None),
            (Some(path), Some(expected)) => Ok(Some(LfsInput { path, expected })),
            _ => Err("--lfs-archive and --expected-lfs-sha256 are required together".into()),
        }
    }
}

#[derive(Debug)]
struct LfsExport {
    root: PathBuf,
    output: PathBuf,
}

pub const USAGE: &str =
    "usage: fg backup export <storage-root> <new-backup-file> <tenant-id> <repository-id>
         --trusted-local [--object-format sha1|sha256]
         [--max-archive-bytes <1..1099511627776>] [--timeout-secs <1..86400>]
         [--max-blob-bytes <1..1099511627776>]
         [--max-objects <1..1000000>]
         [--lfs-root <existing-custody-root> --lfs-output <new-companion-file>]
         [--donor-backup <file> --donor-sha256 <64-lowercase-hex>
          --donor-scratch <new-private-root> --donor-verification-instance <positive-integer>
          [--donor-max-ancestry-hops <1..65536>]]

Authority metadata plus every authority-selected Git object, including admitted
history unreachable from current refs. Source head, complete local graph, native
IDs and original independent payload commitments are verified before export.
When authority selects retained outcome leaves, their exact manifest/envelopes
travel in FGSRC002 and are verified without history fallback. Only the current
or nearest selected root is included; original capsule/root identities survive.
The head must remain unchanged across metadata capture, graph work and recheck.
No implicit retry, live directory copying, external Git, or remote authorization.

This is a bounded trusted-local SOURCE recovery transport, not a signed capsule
or a full service backup. By default external artifacts are excluded. Explicit
paired LFS options include only the complete native pointer-selected payload set.
Other external artifacts, private keys, runner workspaces,
search indexes and routing are excluded. Stable trusted parent paths required.
Default archive budget: 1 GiB; default operation deadline: 300 seconds.
An explicit leading fg --timeout-secs cap narrows the selected leaf timeout.
The complete Git inventory defaults to 100000 objects; --max-objects selects
an explicit allowance through 1000000. It never truncates the selected set.
Independent bounds: 32 MiB per metadata object, 100000 refs and
1000000 inspected edges. Authority metadata retains its separate 64 MiB bound.
Retained checkpoint transport is separately bounded at 32 MiB; its existing
16 MiB reconstructed segment and 8 MiB manifest limits cannot be widened here.
Codec/runtime limits may refuse earlier. The deadline covers all passes, is
cooperative, and cannot interrupt a blocking filesystem call.
Blobs default to 32 MiB; --max-blob-bytes selects a separate streaming allowance.
Export streams blobs in bounded chunks and independently verifies the staged file.
Export never overwrites an existing file. Save its SHA-256 independently.

--lfs-root and --lfs-output are optional together and require a Unix host.
LFS selection scans every admitted Git blob in the exact source snapshot,
including retained history. Unsupported/conflicting pointers and missing or
corrupt selected payloads refuse; unrelated custody objects are not included.
The existing FGSRC source and FGLF companion formats remain separate. Retain
both SHA-256 checksums independently. --max-archive-bytes bounds each file;
--max-objects also bounds distinct LFS objects. LFS payloads retain their native
512 MiB per-object limit; --max-blob-bytes applies only to Git blob bodies.
Both streams are verified before the source node closes. Publication is
create-only, companion first and source second, not an atomic two-file operation.
A later failure may leave the verified companion; inspect both named outputs
before retry. The receipt reports the exact companion checksum and inventory.
LFS companion export cannot be combined with donor-assisted export options.

An explicit donor uses a separately retained archive SHA-256 plus complete native
authority/inventory/graph verification. Its exact head must be an ancestor of
the current capture in the same tenant/repository/incarnation/object format.
Selected donor objects supply their original verified payload commitments;
newer objects still come from the live source. The current authority, inventory
and checkpoint are never replaced by the donor's older snapshot. Donor overlap
is selected before local reads, so missing/corrupt old objects can be exported.
No live object is repaired or rewritten. A new ordinary archive is the output.
Donor, output and verification scratch must be physically separate from one
another and the live source. Unix directory identity profile; stable trusted
parents required. Ancestry defaults to 4096 hops. All passes share one deadline.";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    destination: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    profile: Profile,
    donor: Option<donor::Options>,
    lfs: Option<LfsExport>,
}
fn parse(args: &[String]) -> Result<Options, String> {
    if !(6..=30).contains(&args.len())
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
    let mut donor = donor::Flags::default();
    let (mut lfs_root, mut lfs_output) = (None, None);
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
            "--max-archive-bytes" | "--max-blob-bytes" | "--max-objects" | "--timeout-secs" => {
                let value = args
                    .get(cursor)
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                cursor += 1;
                profile.set(flag, value)?;
            }
            "--lfs-root" | "--lfs-output" => {
                let value = args
                    .get(cursor)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                cursor += 1;
                let slot = if flag == "--lfs-root" {
                    &mut lfs_root
                } else {
                    &mut lfs_output
                };
                if slot.replace(PathBuf::from(value)).is_some() {
                    return Err(format!("duplicate LFS companion option: {flag}"));
                }
            }
            _ if donor::Flags::accepts(flag) => {
                let value = args
                    .get(cursor)
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                cursor += 1;
                donor.set(flag, value)?;
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
    let lfs = match (lfs_root, lfs_output) {
        (None, None) => None,
        (Some(root), Some(output)) if output.file_name().is_some() => {
            Some(LfsExport { root, output })
        }
        _ => return Err("--lfs-root and a named --lfs-output are required together".into()),
    };
    let donor = donor.finish()?;
    if donor.is_some() && lfs.is_some() {
        return Err("donor-assisted export and LFS companion export cannot be combined".into());
    }
    Ok(Options {
        root: args[1].clone().into(),
        destination,
        tenant: TenantId::from_hex(&args[3]).map_err(|e| e.to_string())?,
        repository: RepositoryId::from_hex(&args[4]).map_err(|e| e.to_string())?,
        format: format.unwrap_or(GitHashAlgorithm::Sha1),
        profile: profile.finish(),
        donor,
        lfs,
    })
}
fn limits(transfer: TransferLimits) -> GraphLimits {
    GraphLimits {
        max_objects: transfer.max_objects,
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
fn export(
    options: &Options,
    file: &mut File,
    deadline: Deadline,
    donor: Option<&mut donor::Prepared>,
    lfs_file: Option<&mut File>,
) -> Result<String, String> {
    deadline.check()?;
    let metadata = std::fs::symlink_metadata(&options.root).map_err(|e| e.to_string())?;
    if !metadata.is_dir() {
        return Err("source root must be an existing directory, not a symlink".into());
    }
    let database = options.root.join("authority.fsqlite");
    regular(&database)?;
    deadline.check()?;
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
            .with_selected_pack_blob_limit(
                usize::try_from(options.profile.transfer.max_blob_bytes)
                    .map_err(|_| "backup blob limit is not representable on this host")?,
            )
            .with_runtime_budgets(options.profile.node_budgets()?),
        |node| {
            let request = node.session_request_context_with_timeout(deadline.remaining()?);
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
            if objects.len() > options.profile.transfer.max_objects {
                return Err("repository backup object-count limit".into());
            }
            let retained =
                checkpoint::CheckpointEvidence::capture(node, &request, &selected, deadline)?;
            let identity = Identity {
                tenant: options.tenant,
                repository: options.repository,
                incarnation: node.repository_incarnation_id(),
                format: options.format,
            };
            let mut io_live = || deadline.in_request(&request);
            let mut output = StreamEncoder::with_checkpoint(
                &mut *file,
                identity,
                &encoded,
                objects.len(),
                retained.as_ref(),
                options.profile.transfer,
                &mut io_live,
            )?;
            let provenance = if let Some(donor) = donor {
                Some(donor.write_selected(
                    donor::SourceSnapshot {
                        node,
                        request: &request,
                        captured: selected.authenticated().receipt(),
                        objects,
                    },
                    &mut output,
                    deadline,
                    |oid, output| {
                        encode_local_object(
                            node,
                            &request,
                            oid,
                            options.profile.transfer,
                            deadline,
                            output,
                        )
                    },
                )?)
            } else {
                for &oid in objects {
                    encode_local_object(
                        node,
                        &request,
                        oid,
                        options.profile.transfer,
                        deadline,
                        &mut output,
                    )?;
                }
                None
            };
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
                || decoded.header().checkpoint != retained
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
            while decoded.visit_record(&mut io_live, |header, body| {
                payload::observe(
                    &mut graph,
                    header,
                    body,
                    options.profile.transfer.max_blob_bytes,
                    &mut checkpoint,
                )?;
                Ok(())
            })? {}
            let (header, verified) = decoded.finish(written.digest, &mut io_live)?;
            if verified != written {
                return Err("repository backup staged length changed".into());
            }
            let report = graph
                .finish(&selected.snapshot().refs, &mut checkpoint)
                .map_err(|error| error.to_string())?;
            if let Some(evidence) = &header.checkpoint {
                evidence.verify(node, &request, &selected, deadline, false)?;
            }
            let lfs_receipt = match (&options.lfs, lfs_file) {
                (Some(companion), Some(lfs_file)) => {
                    // The inventory comes from the complete, graph-verified
                    // source archive, including historical admitted pointers.
                    // Recheck the same open source file on every pass.
                    let mut source = input::PinnedArchive::from_reader(
                        &mut *file,
                        written.digest,
                        options.profile.transfer,
                        deadline,
                    )?;
                    let inventory =
                        lfs::Inventory::collect(&mut source, deadline, options.profile.transfer)?;
                    Some(lfs::export(
                        &companion.root,
                        &header,
                        &inventory,
                        lfs_file,
                        options.profile.transfer,
                        deadline,
                    )?)
                }
                (None, None) => None,
                _ => return Err("LFS companion staging disagrees with export options".into()),
            };
            let current = node
                .runtime()
                .block_on(node.authenticate_authority_head_in(&request))
                .map_err(|e| e.to_string())?;
            io_live()?;
            if !matches_head(&authority, current.receipt()) {
                return Err("repository head moved during backup; no backup published".into());
            }
            let mut report = receipt(&header, report, verified, provenance.as_ref());
            if let Some(lfs) = lfs_receipt {
                report.pop();
                report.push_str(&lfs.fields());
                report.push_str(",\"lfs_payloads_included\":true}");
            }
            Ok(report)
        },
    )?;
    deadline.check()?;
    Ok(result)
}
fn encode_local_object<W: Write>(
    node: &OneNode,
    request: &NodeRequestContext,
    oid: GitOid,
    transfer: TransferLimits,
    deadline: Deadline,
    output: &mut StreamEncoder<W>,
) -> Result<(), String> {
    let mut live = || deadline.in_request(request);
    live()?;
    // Header reads select the bounded path only; they establish no payload
    // authenticity. Both paths still verify the actual body through exact EOF.
    let header = node
        .git_object_header(oid)
        .map_err(|error| error.to_string())?;
    if header.kind == FabricKind::Blob {
        let mut body =
            blob_io::BlobReader::open(node, oid, transfer.max_blob_bytes, deadline, request)?;
        output.object_stream(
            oid,
            GitObjectKind::Blob,
            body.length(),
            &body.commitment(),
            &mut body,
            &mut live,
        )
    } else {
        if header.payload_length > MAX_OBJECT_BYTES as u64 {
            return Err("repository backup metadata object-byte limit".into());
        }
        let object = node
            .read_git_object(oid)
            .map_err(|error| format!("backup object {oid}: {error}"))?;
        live()?;
        let kind = match object.envelope().object_kind() {
            FabricKind::Commit => GitObjectKind::Commit,
            FabricKind::Tree => GitObjectKind::Tree,
            FabricKind::Tag => GitObjectKind::Tag,
            FabricKind::Blob | FabricKind::Internal => {
                return Err("selected backup object changed its Git kind".into());
            }
        };
        output.object(
            oid,
            kind,
            object.payload(),
            &object.envelope().payload_commitment(),
            &mut live,
        )
    }
}

fn receipt(
    archive: &StreamHeader,
    graph: GraphReport,
    seal: Seal,
    donor: Option<&donor::Provenance>,
) -> String {
    format!(
        concat!(
            "{{\"type\":\"repository_source_backup_export\",\"schema_version\":1,",
            "\"sha256\":{},\"bytes\":{},\"tenant_id\":{},\"repository_id\":{},\"incarnation_id\":{},",
            "\"object_format\":{},\"head_generation\":{},\"objects\":{},\"references\":{},",
            "\"payload_bytes\":{},\"local_edges\":{},\"external_gitlinks\":{},",
            "\"complete\":true,\"scope\":\"authority_and_selected_git_objects\",",
            "\"object_graph_verified\":true,\"original_payload_commitments_verified\":true,",
            "\"source_head_revalidated\":true,\"node_closed\":true,\"signature_verified\":false,",
            "\"external_artifacts_included\":false,\"physical_orphans_included\":false{}{}}}"
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
        graph.external_gitlinks,
        checkpoint::receipt(archive.checkpoint.as_ref()),
        donor.map_or_else(String::new, donor::Provenance::receipt_fields),
    )
}
pub fn run(args: &[String], output: &mut impl Write) -> Result<(), String> {
    run_with_timeout(args, output, None)
}

/// Stage both files before completing either export. The inner companion is
/// published only after the source node closes and its exact head recheck has
/// passed. Source publication follows. These are two create-only files, not an
/// atomic pair: a later failure explicitly retains the verified companion.
fn build_export(
    options: &Options,
    source_file: &mut File,
    deadline: Deadline,
    donor: Option<&mut donor::Prepared>,
) -> Result<String, String> {
    if let Some(lfs) = &options.lfs {
        publish_streamed(
            &lfs.output,
            |lfs_file| export(options, source_file, deadline, donor, Some(lfs_file)),
            || deadline.check(),
        )
    } else {
        export(options, source_file, deadline, donor, None)
    }
}

pub(super) fn run_with_timeout(
    args: &[String],
    output: &mut impl Write,
    timeout: Option<Duration>,
) -> Result<(), String> {
    if args == ["--help"] {
        emit(output, USAGE)?;
        emit(output, restore::USAGE)?;
        emit(output, restore::verify::USAGE)?;
        emit(output, attest::USAGE)?;
        emit(output, reconstruct::USAGE)?;
        emit(output, selection::USAGE)?;
        emit(output, replication::USAGE)?;
        return emit(output, approval::witness::USAGE);
    }
    if args.first().is_some_and(|arg| arg == "replicate") {
        return replication::run(args, output, timeout);
    }
    if args.first().is_some_and(|arg| arg == "witness") {
        return approval::witness::run(args, output, timeout);
    }
    if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "verify-selected" | "recover"))
    {
        return selection::run(args, output, timeout);
    }
    if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "catalog" | "reconstruct"))
    {
        return reconstruct::run(args, output, timeout);
    }
    if args.first().is_some_and(|arg| arg == "attest") {
        return attest::run(args, output, timeout);
    }
    if args.first().is_some_and(|arg| arg == "verify") {
        return restore::verify::run(args, output, timeout);
    }
    if args.first().is_some_and(|arg| arg == "restore") {
        return restore::run(args, output, timeout);
    }
    if args == ["export", "--help"] {
        return emit(output, USAGE);
    }
    let mut options = parse(args)?;
    options.profile = options.profile.with_timeout_cap(timeout)?;
    let deadline = options.profile.start();
    deadline.check()?;
    require_absent(&options.destination)?;
    if let Some(lfs) = &options.lfs {
        require_absent(&lfs.output)?;
        // Resolve existing parents to catch relative and symlink aliases even
        // though neither output file exists yet.
        let source_parent = super::parent(&options.destination)
            .canonicalize()
            .map_err(|e| e.to_string())?;
        let lfs_parent = super::parent(&lfs.output)
            .canonicalize()
            .map_err(|e| e.to_string())?;
        if source_parent.join(
            options
                .destination
                .file_name()
                .ok_or("missing source filename")?,
        ) == lfs_parent.join(lfs.output.file_name().ok_or("missing LFS filename")?)
        {
            return Err("source archive and LFS companion require distinct output files".into());
        }
    }
    let publication = if let Some(donor) = &options.donor {
        let (mut prepared, separation) = donor.prepare(
            &options.root,
            &options.destination,
            (options.tenant, options.repository, options.format),
            options.profile,
            deadline,
        )?;
        publish_streamed(
            &options.destination,
            |file| {
                separation.check(|| deadline.check())?;
                let receipt = build_export(&options, file, deadline, Some(&mut prepared))?;
                separation.check(|| deadline.check())?;
                Ok(receipt)
            },
            || separation.check(|| deadline.check()),
        )
    } else {
        publish_streamed(
            &options.destination,
            |file| build_export(&options, file, deadline, None),
            || deadline.check(),
        )
    };
    let receipt = publication.map_err(|error| {
        if let Some(lfs) = &options.lfs {
            format!("{error}; paired export may have retained its verified LFS companion at {}; inspect both output paths before retry", lfs.output.display())
        } else {
            error
        }
    })?;
    emit(output, &receipt)
        .map_err(|error| format!("repository backup published; receipt output failed: {error}"))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod publication_tests;

#[cfg(test)]
mod inventory_tests;
