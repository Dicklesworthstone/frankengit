//! The native catalog/recovery driver. Every payload pass shares its original
//! approval, deadline and read ledger; only verified private bytes are linked.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{ErrorKind, Seek, SeekFrom};
use std::path::PathBuf;

use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_treefs::integrity::GraphReport;

use super::super::super::{hex, quote, require_absent};
use super::super::approval::VerifiedApproval;
use super::super::archive::stream::Seal;
use super::super::attest::filesystem::Stage;
use super::super::input::PinnedArchive;
use super::super::profile::Deadline;
use super::super::restore::verify::verify_pinned_in;
use super::catalog::{self, CHUNK_BYTES, Catalog, MAX_CATALOG_BYTES};
use super::io::{BUFFER_BYTES, Checkpoint, Control, Metered, ReadFailure, Source, SourceFailure};
use super::{MAX_READ_BYTES, MAX_REPLICAS, Operation, Options, Receipt};

pub(super) fn execute_with_checkpoints(
    options: &Options,
    deadline: Deadline,
    mut checkpoint: impl FnMut(Checkpoint) -> Result<(), String>,
) -> Result<Receipt, String> {
    deadline.check()?;
    options.profile.transfer.validate()?;
    if options.max_read_bytes == 0 || options.max_read_bytes > MAX_READ_BYTES {
        return Err("backup aggregate payload-read allowance is outside its finite profile".into());
    }
    if (options.operation == Operation::Reconstruct && options.replicas.is_empty())
        || options.replicas.len() > MAX_REPLICAS
        || (options.operation == Operation::Catalog && !options.replicas.is_empty())
    {
        return Err(
            "backup reconstruction requires 1..64 explicit copies; catalog takes one archive"
                .into(),
        );
    }
    // Authenticate and retain meaning once, before examining catalog/replicas
    // or reserving output/scratch. No path, hash hint or source selects trust.
    let approval = options.approval.authenticate(
        options.expected,
        options.profile.transfer.max_archive_bytes,
        deadline,
    )?;
    let control = Control::new(&approval, deadline, options.max_read_bytes, &mut checkpoint);
    let original = approval.artifact_seal();
    // Healthy catalog = 3 native passes + 1 catalog pass; healthy recovery =
    // 1 source pass + 3 native passes. EOF probes returning zero are free.
    control.reserve(4 * original.bytes)?;
    require_absent(&options.output)?;
    require_absent(&options.scratch)?;
    match options.operation {
        Operation::Catalog => create_catalog(options, deadline, &approval, &control),
        Operation::Reconstruct => reconstruct(options, deadline, &approval, &control),
    }
}

fn native_preflight(
    options: &Options,
    deadline: Deadline,
    approval: &VerifiedApproval,
    control: &Control<'_>,
    file: File,
) -> Result<GraphReport, String> {
    control.checkpoint(Checkpoint::BeforeVerification)?;
    let archive = PinnedArchive::from_reader(
        Metered {
            input: file,
            control,
        },
        options.expected,
        options.profile.transfer,
        deadline,
    )?;
    approval.match_archive(archive.header(), archive.seal())?;
    let verified = verify_pinned_in(
        archive,
        &options.scratch,
        options.instance,
        options.profile,
        deadline,
    )?;
    approval.match_archive(verified.header(), verified.seal())?;
    control.checkpoint(Checkpoint::AfterVerification)?;
    Ok(verified.graph())
}

fn create_catalog(
    options: &Options,
    deadline: Deadline,
    approval: &VerifiedApproval,
    control: &Control<'_>,
) -> Result<Receipt, String> {
    let original = approval.artifact_seal();
    control.check()?;
    let mut source =
        Source::open(&options.input, original.bytes).map_err(SourceFailure::message)?;
    if source.length() != original.bytes {
        return Err("catalog creation requires the complete original approved archive".into());
    }
    let file = source.file.try_clone().map_err(|error| error.to_string())?;
    let graph = native_preflight(options, deadline, approval, control, file)?;
    source.check().map_err(SourceFailure::message)?;
    source
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut catalog = Catalog::new(original)?;
    let mut whole = Sha256Hasher::new();
    let mut buffer = [0; BUFFER_BYTES];
    let mut at = 0_u64;
    while at < original.bytes {
        let end = original.bytes.min(at + CHUNK_BYTES);
        let mut chunk = Sha256Hasher::new();
        while at < end {
            let maximum = (end - at).min(buffer.len() as u64) as usize;
            let count = read_payload(control, &mut source.file, &mut buffer[..maximum])?;
            if count == 0 {
                return Err("backup catalog source became short".into());
            }
            chunk.update(&buffer[..count]);
            whole.update(&buffer[..count]);
            at += count as u64;
        }
        catalog.push(chunk.finish())?;
    }
    if read_payload(control, &mut source.file, &mut buffer[..1])? != 0
        || whole.finish() != original.digest
    {
        return Err(
            "backup catalog source changed from its original signed digest or length".into(),
        );
    }
    source.check().map_err(SourceFailure::message)?;
    control.check()?;
    let bytes = catalog.encode()?;
    let mut stage = Stage::reserve(&options.output, deadline)?;
    let result = (|| {
        control.write_all(stage.file(), &bytes)?;
        // Freeze inode/content metadata before readback. Publication later
        // compares against this same fence, never a post-validation re-freeze.
        stage.synchronize_content(bytes.len() as u64, deadline)?;
        readback_catalog(stage.file(), &bytes, control)?;
        control.checkpoint(Checkpoint::BeforePublication)?;
        stage.publish(|| control.check())?;
        Ok(receipt(options, approval, control, graph, &catalog, &[]))
    })();
    result.map_err(|error| stage.failure(error))
}

fn read_payload(
    control: &Control<'_>,
    file: &mut File,
    buffer: &mut [u8],
) -> Result<usize, String> {
    loop {
        match control.read(file, buffer) {
            Err(ReadFailure::Io(error)) if error.kind() == ErrorKind::Interrupted => {}
            result => return result.map_err(ReadFailure::message),
        }
    }
}

fn read_catalog(
    options: &Options,
    original: Seal,
    control: &Control<'_>,
) -> Result<Catalog, String> {
    control.check()?;
    let mut source =
        Source::open(&options.input, MAX_CATALOG_BYTES as u64).map_err(SourceFailure::message)?;
    let expected = catalog::encoded_length(original)?;
    if source.length() != expected as u64 {
        return Err(
            "backup catalog length disagrees with original authenticated range count".into(),
        );
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected)
        .map_err(|_| "backup catalog input allocation refused")?;
    bytes.resize(expected, 0);
    let mut at = 0;
    while at < expected {
        let count = control.metadata_read(&mut source.file, &mut bytes[at..])?;
        if count == 0 {
            return Err("backup catalog was truncated while reading".into());
        }
        at += count;
    }
    if control.metadata_read(&mut source.file, &mut [0; 1])? != 0 {
        return Err("backup catalog has trailing bytes".into());
    }
    source.check().map_err(SourceFailure::message)?;
    control.check()?;
    Catalog::parse(&bytes, original)
}

fn readback_catalog(file: &mut File, expected: &[u8], control: &Control<'_>) -> Result<(), String> {
    control.check()?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut at = 0;
    let mut buffer = [0; BUFFER_BYTES];
    loop {
        let count = control.metadata_read(file, &mut buffer)?;
        if count == 0 {
            break;
        }
        if expected.get(at..at + count) != Some(&buffer[..count]) {
            return Err("backup catalog staging readback changed".into());
        }
        at += count;
    }
    if at != expected.len() {
        return Err("backup catalog staging readback became short".into());
    }
    control.check()
}

struct Replica {
    path: PathBuf,
    source: Option<Source>,
    chunks_used: usize,
    chunks_rejected: usize,
    unavailable: Option<String>,
}

fn open_replicas(
    options: &Options,
    original: Seal,
    control: &Control<'_>,
) -> Result<Vec<Replica>, String> {
    let mut replicas = Vec::with_capacity(options.replicas.len());
    let mut identities = BTreeSet::new();
    for path in &options.replicas {
        control.check()?;
        let (source, unavailable) = match Source::open(path, original.bytes) {
            Ok(source) => {
                if !identities.insert(source.identity()) {
                    return Err("backup replicas must name distinct underlying files".into());
                }
                (Some(source), None)
            }
            Err(SourceFailure::Unavailable(error)) => (None, Some(error)),
            Err(SourceFailure::Fatal(error)) => return Err(error),
        };
        replicas.push(Replica {
            path: path.clone(),
            source,
            chunks_used: 0,
            chunks_rejected: 0,
            unavailable,
        });
    }
    control.check()?;
    Ok(replicas)
}

fn reconstruct(
    options: &Options,
    deadline: Deadline,
    approval: &VerifiedApproval,
    control: &Control<'_>,
) -> Result<Receipt, String> {
    let original = approval.artifact_seal();
    let catalog = read_catalog(options, original, control)?;
    let mut replicas = open_replicas(options, original, control)?;
    let mut stage = Stage::reserve(&options.output, deadline)?;
    let result = (|| {
        let mut buffer = [0; BUFFER_BYTES];
        for chunk in 0..catalog.count() {
            let start = chunk as u64 * CHUNK_BYTES;
            let end = original.bytes.min(start + CHUNK_BYTES);
            let mut accepted = false;
            for (index, replica) in replicas.iter_mut().enumerate() {
                control.check()?;
                let Some(source) = replica.source.as_mut() else {
                    continue;
                };
                if source.length() < end {
                    replica.chunks_rejected += 1;
                    continue;
                }
                // Failed attempts consume the same ledger. Before each one,
                // reserve the remaining source ranges plus three native scans.
                control.reserve(4 * original.bytes - start)?;
                match copy_candidate(
                    source,
                    stage.file(),
                    start,
                    end,
                    catalog.hash(chunk),
                    control,
                    &mut buffer,
                ) {
                    Ok(true) => {
                        replica.chunks_used += 1;
                        control.checkpoint(Checkpoint::ChunkAccepted {
                            chunk,
                            replica: index,
                        })?;
                        accepted = true;
                        break;
                    }
                    Ok(false) => replica.chunks_rejected += 1,
                    Err(SourceFailure::Unavailable(error)) => {
                        replica.chunks_rejected += 1;
                        replica.unavailable = Some(error);
                        // A changed/short descriptor is never reconsidered.
                        replica.source = None;
                    }
                    Err(SourceFailure::Fatal(error)) => return Err(error),
                }
            }
            if !accepted {
                return Err(format!(
                    "no surviving approved byte range for backup chunk {chunk}"
                ));
            }
        }
        // This is a custody fence, not a content proof. The same frozen file
        // must then pass full pin, decoding, original commitments and graph.
        stage.synchronize_content(original.bytes, deadline)?;
        let file = stage
            .file()
            .try_clone()
            .map_err(|error| error.to_string())?;
        let graph = native_preflight(options, deadline, approval, control, file)?;
        control.checkpoint(Checkpoint::BeforePublication)?;
        stage.publish(|| control.check())?;
        Ok(receipt(
            options, approval, control, graph, &catalog, &replicas,
        ))
    })();
    result.map_err(|error| stage.failure(error))
}

fn copy_candidate(
    source: &mut Source,
    output: &mut File,
    start: u64,
    end: u64,
    expected: &[u8; 32],
    control: &Control<'_>,
    buffer: &mut [u8],
) -> Result<bool, SourceFailure> {
    control.check().map_err(SourceFailure::Fatal)?;
    source.check()?;
    source
        .file
        .seek(SeekFrom::Start(start))
        .map_err(SourceFailure::from_io)?;
    output
        .seek(SeekFrom::Start(start))
        .map_err(|error| SourceFailure::Fatal(format!("backup staging seek failed: {error}")))?;
    let mut hash = Sha256Hasher::new();
    let mut at = start;
    while at < end {
        let maximum = (end - at).min(buffer.len() as u64) as usize;
        let count = match control.read(&mut source.file, &mut buffer[..maximum]) {
            Ok(0) => {
                return Err(SourceFailure::Unavailable(
                    "source became short while reading a range".into(),
                ));
            }
            Ok(count) => count,
            Err(ReadFailure::Io(error)) if error.kind() == ErrorKind::Interrupted => continue,
            Err(ReadFailure::Io(error)) => return Err(SourceFailure::from_io(error)),
            Err(ReadFailure::Gate(error)) => return Err(SourceFailure::Fatal(error)),
        };
        hash.update(&buffer[..count]);
        control
            .write_all(output, &buffer[..count])
            .map_err(SourceFailure::Fatal)?;
        at += count as u64;
    }
    source.check()?;
    control.check().map_err(SourceFailure::Fatal)?;
    Ok(&hash.finish() == expected)
}

fn receipt(
    options: &Options,
    approval: &VerifiedApproval,
    control: &Control<'_>,
    graph: GraphReport,
    catalog: &Catalog,
    replicas: &[Replica],
) -> Receipt {
    let sources = replicas
        .iter()
        .map(|replica| {
            format!(
                "{{\"path\":{},\"chunks_used\":{},\"chunks_rejected\":{},\"unavailable\":{}}}",
                quote(&replica.path.display().to_string()),
                replica.chunks_used,
                replica.chunks_rejected,
                replica
                    .unavailable
                    .as_deref()
                    .map_or_else(|| "null".into(), quote),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Receipt {
        json: format!(
            concat!(
                "{{\"type\":{},\"schema_version\":1,\"complete\":true,\"publication_state\":\"durable\",",
                "\"output\":{},\"sha256\":{},\"archive_bytes\":{},\"chunk_bytes\":{},\"chunks\":{},",
                "\"native_content_verified\":true,\"archive_bytes_authenticated\":true,",
                "\"object_graph_verified\":true,\"original_payload_commitments_verified\":true,",
                "\"authority_import_verified\":true,\"node_closed\":true,\"scratch_removed\":true,",
                "\"objects\":{},\"references\":{},\"payload_bytes\":{},\"verification_instance\":{},",
                "\"payload_bytes_read\":{},\"payload_read_calls\":{},\"maximum_read_bytes\":{},\"payload_read_budget\":{},",
                "\"replicas\":[{}],\"approval\":{},\"new_signature_created\":false,",
                "\"catalog_is_authority\":false,\"newest_checkpoint_verified\":false,",
                "\"complete_capsule_verified\":false,\"external_artifacts_verified\":false,",
                "\"destination_authority_published\":false,\"routing_published\":false}}"
            ),
            quote(match options.operation {
                Operation::Catalog => "repository_backup_chunk_catalog_created",
                Operation::Reconstruct => "repository_backup_reconstructed",
            }),
            quote(&options.output.display().to_string()),
            quote(&hex(&catalog.archive.digest)),
            catalog.archive.bytes,
            CHUNK_BYTES,
            catalog.count(),
            graph.objects,
            graph.references,
            graph.payload_bytes,
            options.instance.raw(),
            control.bytes_read(),
            control.read_calls(),
            BUFFER_BYTES,
            options.max_read_bytes,
            sources,
            approval.receipt_json(),
        ),
    }
}
