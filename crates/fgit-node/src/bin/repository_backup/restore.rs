//! Restore into a new root, or resume only its exact checksum-bound intent.
//! Public authority stays absent until metadata AND every selected object verify.
#[path = "resume.rs"]
mod resume;

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use fgit_authority::{HeadReadReceipt, StoreInstanceId};
use fgit_authority_fsqlite::ExportBundle;
use fgit_crypto::GitObjectKind;
use fgit_node::{NodeConfig, OneNode};
use fgit_object_fabric::ObjectKind as FabricKind;
use fgit_treefs::integrity::{GraphReport, ObjectGraphAudit};

use super::super::{
    emit, generation, hex, parent, quote, regular, require_absent, sync_directory, with_store,
};
use super::archive::{Record, stream::StreamHeader};
use super::input::PinnedArchive;
use super::profile::{Deadline, Profile, ProfileFlags};
use super::{limits, with_node};

pub(super) const USAGE: &str =
    "usage: fg-repository-backup restore <backup-file> <storage-root> --trusted-local
         --expected-sha256 <64-lowercase-hex> --destination-instance <positive-integer>
         [--resume] [--max-archive-bytes <1..1099511627776>] [--timeout-secs <1..86400>]

By default reserve an EMPTY new root. --resume requires an existing restore intent
for the SAME independently trusted checksum and destination instance. It accepts
only empty/rolled-back authority or the exact complete imported snapshot. An
already published copy is verified read-only; newer or different state refuses.
No existing repository is overwritten, rewound, merged, or silently repaired.
Source CAS tokens are reminted only on first import, never on an exact retry.

Checksum and streamed identity checks precede directory creation. All later
passes rehash the same open input against that pin; payload memory does not grow
with archive size. Default archive budget: 1 GiB; authority metadata: 64 MiB.
The 300 second default deadline is shared across ALL passes of one invocation.
An explicit resume gets a new bounded attempt, not an unbounded automatic retry.

Metadata and objects are staged under .restore-quarantine. Graph/selection,
original commitments and disk readback verify before final authority publication.
Moved object storage and WAL return to quarantine before an unpublished resume
opens the database. Conflicting locations refuse. Authority is still installed
last, and the final image is reopened and verified before success or cleanup.

The immutable .restore-intent and OS-locked .restore-lock remain for retries.
The lock excludes other cooperating restore commands, not running node services.
Do not serve or concurrently modify the root/quarantine. Trusted parent paths
are required. Legacy interrupted roots without an intent cannot be resumed.
Deadlines cannot interrupt blocking I/O. Failed state is retained, not deleted.

This is SOURCE recovery, not a signed capsule, external-artifact backup, routing
activation or authorization to replay external effects. Review restored outbox
state and external dependencies before serving. The checksum pins one chosen
checkpoint; it does not prove this was the newest source checkpoint.
Exit 0: complete scoped restore after node close; 2: refusal, incomplete operation,
cleanup or receipt I/O failure. A failure after authority publication says so.";

#[derive(Debug)]
struct Options {
    input: PathBuf,
    output: PathBuf,
    expected: [u8; 32],
    instance: StoreInstanceId,
    profile: Profile,
    resume: bool,
}
fn digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
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
    if !(8..=13).contains(&args.len())
        || args[0] != "restore"
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
        || args[1].is_empty()
        || args[2].is_empty()
    {
        return Err(USAGE.into());
    }
    let (mut trusted, mut expected, mut instance, mut resume) = (false, None, None, false);
    let mut profile = ProfileFlags::default();
    let mut cursor = 3;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        if flag == "--trusted-local" && !trusted {
            trusted = true;
            continue;
        }
        if flag == "--resume" {
            if resume {
                return Err("duplicate --resume".into());
            }
            resume = true;
            continue;
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag.as_str() {
            "--expected-sha256" if expected.is_none() => expected = Some(digest(value)?),
            "--destination-instance" if instance.is_none() => {
                if value.starts_with('0') || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("destination instance must be canonical positive decimal".into());
                }
                let number = value
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0 && i64::try_from(*n).is_ok())
                    .ok_or("destination instance must fit a positive SQL integer")?;
                instance = Some(StoreInstanceId::from_raw(number));
            }
            "--max-archive-bytes" | "--timeout-secs" => profile.set(flag, value)?,
            _ => return Err(format!("unknown or duplicate restore option: {flag}")),
        }
    }
    if !trusted {
        return Err("restore requires --trusted-local and whole-repository authorization".into());
    }
    let output = PathBuf::from(&args[2]);
    if output.file_name().is_none() {
        return Err("restore requires a named storage root".into());
    }
    Ok(Options {
        input: args[1].clone().into(),
        output,
        expected: expected.ok_or("restore requires an independently trusted --expected-sha256")?,
        instance: instance.ok_or("restore requires a --destination-instance")?,
        profile: profile.finish(),
        resume,
    })
}
fn create_private(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|e| format!("cannot reserve new restore directory: {e}"))
}
fn config(root: &Path, archive: &StreamHeader, profile: Profile) -> Result<NodeConfig, String> {
    let id = archive.identity;
    Ok(
        NodeConfig::new(root.to_path_buf(), id.tenant, id.repository)
            .with_object_format(id.format)
            .with_expected_repository_incarnation(id.incarnation)
            .with_runtime_budgets(profile.node_budgets()?),
    )
}
fn verify_stored(node: &OneNode, record: &Record<'_>) -> Result<(), String> {
    let stored = node
        .read_git_object(record.oid)
        .map_err(|e| e.to_string())?;
    let kind = match record.kind {
        GitObjectKind::Commit => FabricKind::Commit,
        GitObjectKind::Tree => FabricKind::Tree,
        GitObjectKind::Blob => FabricKind::Blob,
        GitObjectKind::Tag => FabricKind::Tag,
    };
    if stored.envelope().object_kind() != kind || stored.payload() != record.payload {
        return Err(format!(
            "restored object did not read back byte-identically: {}",
            record.oid
        ));
    }
    Ok(())
}
fn graph_from_archive(
    node: &OneNode,
    archive: &mut PinnedArchive,
    expected: &HeadReadReceipt,
    install: bool,
    profile: Profile,
    deadline: Deadline,
) -> Result<GraphReport, String> {
    deadline.check()?;
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .map_err(|e| e.to_string())?;
    deadline.in_request(&request)?;
    if selected.authenticated().receipt() != expected {
        return Err("restored authority disagrees with its exact import receipt".into());
    }
    let objects = selected.selected_closure().closure().objects();
    if objects.len() != archive.header().objects {
        return Err("archive inventory does not equal the authority-selected object set".into());
    }
    let mut checkpoint = || deadline.in_request(&request).is_ok();
    let mut graph = ObjectGraphAudit::new(
        objects,
        archive.header().identity.format,
        limits(profile.transfer),
        &mut checkpoint,
    )
    .map_err(|e| e.to_string())?;
    // Graph/selection validation and a complete checksum pass precede ALL object
    // placement. The graph checks exact sorted IDs, not only inventory counts.
    archive.scan(deadline, |record| {
        deadline.in_request(&request)?;
        graph
            .observe(record.oid, record.kind, record.payload, &mut checkpoint)
            .map_err(|e| e.to_string())?;
        if !install {
            verify_stored(node, &record)?;
        }
        deadline.in_request(&request)
    })?;
    let report = graph
        .finish(&selected.snapshot().refs, &mut checkpoint)
        .map_err(|e| e.to_string())?;
    if install {
        archive.scan(deadline, |record| {
            deadline.in_request(&request)?;
            // Even a changed file cannot cause an out-of-selection placement
            // before this pass's final checksum notices the mutation.
            if !objects.contains(&record.oid) {
                return Err("archive inventory changed before placement".into());
            }
            let mut body = Vec::new();
            body.try_reserve_exact(record.payload.len())
                .map_err(|_| "restore object allocation refused")?;
            body.extend_from_slice(record.payload);
            let stored = node
                .put_git_object(record.kind, body)
                .map_err(|e| e.to_string())?;
            if stored.identity() != record.oid {
                return Err("restored object changed identity".into());
            }
            verify_stored(node, &record)?;
            deadline.in_request(&request)
        })?;
    }
    let current = node
        .runtime()
        .block_on(node.authenticate_authority_head_in(&request))
        .map_err(|e| e.to_string())?;
    deadline.in_request(&request)?;
    if current.receipt() != expected {
        return Err("restored head moved during verification".into());
    }
    Ok(report)
}

/// Filesystem phase after the quarantined node has verified and CLOSED. This
/// object owns no authority: it only prepares the already-verified closed image.
/// Dropping it leaves final authority absent. Cleanup waits for final verification.
struct PreparedPublication {
    quarantine: PathBuf,
    destination: PathBuf,
}
impl PreparedPublication {
    fn prepare(quarantine: &Path, destination: &Path) -> Result<Self, String> {
        let database = quarantine.join("authority.fsqlite");
        regular(&database)?;
        require_absent(&destination.join("authority.fsqlite"))?;
        // A successful close is not an excuse to discard uncheckpointed WAL.
        // Hot rollback journals are refused rather than interpreted by this layer.
        match fs::symlink_metadata(quarantine.join("authority.fsqlite-journal")) {
            Ok(metadata) if metadata.is_file() && metadata.len() == 0 => {}
            Ok(_) => {
                return Err(
                    "closed restore retained a rollback journal; publication refused".into(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        File::open(&database)
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())?;
        let objects = quarantine.join("objects");
        let target_objects = destination.join("objects");
        require_absent(&target_objects)?;
        let metadata = fs::symlink_metadata(&objects).map_err(|e| e.to_string())?;
        if !metadata.is_dir() {
            return Err("restore object fabric is not a directory".into());
        }
        // Both directories are exclusively owned by this invocation under the
        // newly reserved, trusted root. No archive pathname enters this rename.
        fs::rename(&objects, &target_objects).map_err(|e| e.to_string())?;
        sync_directory(&target_objects).map_err(|e| e.to_string())?;
        let wal = quarantine.join("authority.fsqlite-wal");
        match fs::symlink_metadata(&wal) {
            Ok(metadata) if metadata.is_file() => {
                File::open(&wal)
                    .and_then(|file| file.sync_all())
                    .map_err(|e| e.to_string())?;
                let target_wal = destination.join("authority.fsqlite-wal");
                require_absent(&target_wal)?;
                // One location per closed WAL lets an interrupted resume put
                // it back beside its database before asking the engine to open.
                fs::rename(&wal, &target_wal).map_err(|e| e.to_string())?;
            }
            Ok(_) => return Err("restore WAL is not a regular file".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        sync_directory(quarantine).map_err(|e| e.to_string())?;
        sync_directory(destination).map_err(|e| e.to_string())?;
        sync_directory(parent(destination)).map_err(|e| e.to_string())?;
        Ok(Self {
            quarantine: quarantine.to_path_buf(),
            destination: destination.to_path_buf(),
        })
    }
    /// The no-replace link is the visibility boundary. The quarantine alias is
    /// then dropped: fsqlite >= 0.4 refuses to open a database path with more
    /// than one hard link, and the verified image is the same file at the
    /// destination. A crash between the two is settled on resume.
    fn publish(self) -> Result<(), String> {
        fs::hard_link(
            self.quarantine.join("authority.fsqlite"),
            self.destination.join("authority.fsqlite"),
        )
        .map_err(|e| format!("destination authority was not published: {e}"))?;
        sync_directory(&self.destination)
            .map_err(|e| format!("destination authority is visible; sync failed: {e}"))?;
        fs::remove_file(self.quarantine.join("authority.fsqlite")).map_err(|e| {
            format!("destination authority is visible; quarantine alias removal failed: {e}")
        })?;
        sync_directory(&self.quarantine)
            .map_err(|e| format!("destination authority is visible; quarantine sync failed: {e}"))
    }
}

fn authority_image(
    root: &Path,
    source: &ExportBundle,
    options: &Options,
    read_only: bool,
    deadline: Deadline,
) -> Result<HeadReadReceipt, String> {
    let database = root.join("authority.fsqlite");
    if read_only {
        regular(&database)?;
    }
    with_store(
        &database,
        options.instance,
        read_only,
        |runtime, store, cx| {
            deadline.check()?;
            if store.instance_id() != options.instance {
                return Err("restore database instance disagrees with its intent".into());
            }
            let head = if read_only {
                runtime.block_on(store.verify_portable_import(cx, source, Default::default()))
            } else if options.resume {
                runtime.block_on(store.resume_portable_import(cx, source, Default::default()))
            } else {
                runtime.block_on(store.import_portable(cx, source, Default::default()))
            }
            .map_err(|e| e.to_string())?
            .ok_or("repository import returned no head")?;
            runtime
                .block_on(store.authenticate_head_receipt(cx, &head))
                .map_err(|e| e.to_string())?;
            let source = source.head.as_ref().ok_or("missing source head")?;
            if head.key().as_bytes() != source.key.as_slice()
                || head.body() != source.body.as_slice()
                || head.generation().get() != source.generation
            {
                return Err("repository import changed canonical head bytes".into());
            }
            deadline.check()?;
            Ok(head)
        },
    )
}

/// Production boundaries exercised by deterministic interruption tests. The
/// command supplies a no-op observer; no environment-controlled fault hook exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Intent,
    Authority,
    Objects,
    QuarantineVerified,
    DataPrepared,
    Published,
    FinalVerified,
    Cleaned,
}
fn execute(options: &Options) -> Result<String, String> {
    execute_with_checkpoints(options, |_| Ok(()))
}
fn execute_with_checkpoints(
    options: &Options,
    mut checkpoint: impl FnMut(Stage) -> Result<(), String>,
) -> Result<String, String> {
    let deadline = options.profile.start();
    if !options.resume {
        require_absent(&options.output)?;
    }
    let mut archive = PinnedArchive::open(
        &options.input,
        options.expected,
        options.profile.transfer,
        deadline,
    )?;
    if archive.header().authority.instance == options.instance.raw() {
        return Err("destination instance must differ from source; no destination created".into());
    }
    deadline.check()?;
    let intent = if options.resume {
        resume::Intent::open(&options.output, options.expected, options.instance)?
    } else {
        resume::Intent::reserve(&options.output, options.expected, options.instance)?
    };
    let already_published = intent.published()?;
    let (expected, prior_graph) = if already_published {
        // Drop a crash-surviving quarantine alias before any engine reopen.
        intent.settle_publication()?;
        let expected = authority_image(
            &options.output,
            &archive.header().authority,
            options,
            true,
            deadline,
        )
        .map_err(|e| {
            format!("destination authority is visible; resume verification refused: {e}")
        })?;
        (expected, None)
    } else {
        let prepared = (|| {
            checkpoint(Stage::Intent)?;
            let quarantine = intent.quarantine()?;
            let expected = authority_image(
                &quarantine,
                &archive.header().authority,
                options,
                false,
                deadline,
            )?;
            checkpoint(Stage::Authority)?;
            let graph = with_node(
                config(&quarantine, archive.header(), options.profile)?,
                |node| {
                    graph_from_archive(
                        node,
                        &mut archive,
                        &expected,
                        true,
                        options.profile,
                        deadline,
                    )
                },
            )?;
            checkpoint(Stage::Objects)?;
            let reopened = with_node(
                config(&quarantine, archive.header(), options.profile)?,
                |node| {
                    graph_from_archive(
                        node,
                        &mut archive,
                        &expected,
                        false,
                        options.profile,
                        deadline,
                    )
                },
            )?;
            if reopened != graph {
                return Err("restored graph changed across quarantine reopen".into());
            }
            checkpoint(Stage::QuarantineVerified)?;
            deadline.check()?;
            let publication = PreparedPublication::prepare(&quarantine, &options.output)?;
            checkpoint(Stage::DataPrepared)?;
            deadline.check()?;
            Ok((publication, expected, graph))
        })();
        let (publication, expected, graph) = prepared.map_err(|error: String| {
            format!(
                "{error}; destination authority not published; retained restore state at {}",
                options.output.display()
            )
        })?;
        publication.publish()?;
        (expected, Some(graph))
    };
    checkpoint(Stage::Published).map_err(|e| format!("destination authority is visible; {e}"))?;
    let graph = with_node(
        config(&options.output, archive.header(), options.profile)?,
        |node| {
            graph_from_archive(
                node,
                &mut archive,
                &expected,
                false,
                options.profile,
                deadline,
            )
        },
    )
    .map_err(|error| {
        format!("destination authority is visible; final reopen verification failed: {error}")
    })?;
    if prior_graph.is_some_and(|prior| prior != graph) {
        return Err("destination authority is visible; final graph report mismatch".into());
    }
    checkpoint(Stage::FinalVerified)
        .map_err(|e| format!("destination authority is visible; {e}"))?;
    intent.cleanup()?;
    checkpoint(Stage::Cleaned).map_err(|e| format!("destination authority is visible; {e}"))?;
    let header = archive.header();
    Ok(format!(
        concat!(
            "{{\"type\":\"repository_source_backup_restore\",\"schema_version\":1,",
            "\"sha256\":{},\"tenant_id\":{},\"repository_id\":{},\"incarnation_id\":{},",
            "\"object_format\":{},\"head_generation\":{},\"objects\":{},\"references\":{},",
            "\"payload_bytes\":{},\"destination_instance\":{},\"complete\":true,",
            "\"scope\":\"authority_and_selected_git_objects\",\"object_graph_verified\":true,",
            "\"original_payload_commitments_verified\":true,\"source_tokens_preserved\":false,",
            "\"reopened_and_verified\":true,\"node_closed\":true,\"routing_published\":false,",
            "\"external_artifacts_restored\":false,\"signature_verified\":false,",
            "\"archive_bytes\":{},\"streaming\":true,\"resume_requested\":{},\"already_published\":{}}}"
        ),
        quote(&hex(&options.expected)),
        quote(&header.identity.tenant.to_string()),
        quote(&header.identity.repository.to_string()),
        quote(&header.identity.incarnation.to_string()),
        quote(header.identity.format.as_str()),
        generation(&header.authority),
        graph.objects,
        graph.references,
        graph.payload_bytes,
        options.instance.raw(),
        archive.seal().bytes,
        options.resume,
        already_published
    ))
}
pub(super) fn run(args: &[String], output: &mut impl Write) -> Result<(), String> {
    if args == ["restore", "--help"] {
        return emit(output, USAGE);
    }
    let options = parse(args)?;
    let receipt = execute(&options)?;
    emit(output, &receipt)
        .map_err(|error| format!("repository restore completed; receipt output failed: {error}"))
}

#[cfg(test)]
#[path = "resume_engine_tests.rs"]
mod resume_engine_tests;
#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;
