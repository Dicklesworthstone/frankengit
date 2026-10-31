//! Recovery preflight through the real metadata backend and canonical graph.
//! Only bounded authority metadata is imported; Git payloads stay in the archive.
use super::super::approval::ApprovalFlags;
use super::super::archive::stream::{Seal, StreamHeader};
use super::super::input::PinnedArchive;
use super::super::profile::{Deadline, Profile, ProfileFlags};
use super::{
    ArchiveGraphMode, Options, approval_receipt_fields, authenticate_approval, authority_image,
    check_approval_current, config, create_private, digest, emit, generation, graph_from_archive,
    hex, match_approval, quote, require_absent, sync_directory, with_node,
};
use fgit_authority::StoreInstanceId;
use fgit_treefs::integrity::GraphReport;
use std::fs::{self, File};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

pub(in super::super) const USAGE: &str =
    "usage: fg backup verify <backup-file> <new-scratch-root> --trusted-local
         --expected-sha256 <64-lowercase-hex> --verification-instance <positive-integer>
         [--max-archive-bytes <1..1099511627776>] [--timeout-secs <1..86400>]
         [--max-blob-bytes <1..1099511627776>]
         [--max-objects <1..1000000>]
         [--approval <DSSE-file> --trust-key <SPKI-public-PEM>
          --tenant-id <hex> --repository-id <hex> --incarnation-id <hex>
          --object-format sha1|sha256 --minimum-head-generation <positive-u64>]

Approval options are all-or-none. Signed mode authenticates the exact external
key/namespace/floor and signed digest/size/lifetime before creating scratch.
--expected-sha256 remains independently required. The native archive header must
match those signed declarations; signatures do not replace native graph checks.

Verify the independently pinned archive, portable authority image, exact selected
Git inventory, required-kind graph and original payload commitments BEFORE a
restore. This uses the SAME backend/materializer/graph checks as restore, without
copying Git payloads or publishing authority at the scratch root. No source node
is needed. Metadata lives only in a private .verify-quarantine child.
FGSRC002 also verifies its bounded retained outcome evidence against the exact
authority-selected root through a read-only archive view; no leaves are placed.
Legacy FGSRC001 does not claim retained checkpoint preservation.

The scratch root must be absent under a stable trusted parent. Never serve or
concurrently modify it. Success closes the node and removes this invocation's
scratch state; failure after creation retains it for diagnosis. Existing paths
are never reused or removed. There is no --resume for verification.

All passes share one deadline and one open checksum-pinned archive. Default:
1 GiB archive, 300 seconds; metadata retains its independent 64 MiB bound.
Blobs default to 32 MiB; --max-blob-bytes selects a separate streaming allowance.
Commit, tree and tag bodies keep their independent 32 MiB metadata limit.
The complete Git inventory defaults to 100000 objects. --max-objects permits
up to 1000000 without widening authority, graph-edge, reference or byte limits.
An explicit leading fg --timeout-secs cap narrows the selected leaf timeout.
This verifies SOURCE recovery inputs, not destination disk readback, the newest
full backup checkpoint, a complete signed capsule, external artifacts, routing or external-effect replay.
Exit 0: complete scoped preflight and cleanup; 2: refusal, incomplete verification,
cleanup failure or receipt-output failure.";

fn parse(args: &[String]) -> Result<Options, String> {
    if !(8..=30).contains(&args.len())
        || args[0] != "verify"
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
        || args[1].is_empty()
        || args[2].is_empty()
    {
        return Err(USAGE.into());
    }
    let (mut trusted, mut expected, mut instance) = (false, None, None);
    let mut profile = ProfileFlags::default();
    let mut approval = ApprovalFlags::default();
    let mut cursor = 3;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        if flag == "--trusted-local" && !trusted {
            trusted = true;
            continue;
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag.as_str() {
            "--expected-sha256" if expected.is_none() => expected = Some(digest(value)?),
            "--verification-instance" if instance.is_none() => {
                if value.is_empty()
                    || value.starts_with('0')
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err("verification instance must be canonical positive decimal".into());
                }
                let number = value
                    .parse::<u64>()
                    .ok()
                    .filter(|number| *number > 0 && i64::try_from(*number).is_ok())
                    .ok_or("verification instance must fit a positive SQL integer")?;
                instance = Some(StoreInstanceId::from_raw(number));
            }
            "--max-archive-bytes" | "--max-blob-bytes" | "--max-objects" | "--timeout-secs" => {
                profile.set(flag, value)?;
            }
            _ if ApprovalFlags::accepts(flag) => approval.set(flag, value)?,
            _ => return Err(format!("unknown or duplicate verification option: {flag}")),
        }
    }
    if !trusted {
        return Err(
            "verification requires --trusted-local and whole-repository authorization".into(),
        );
    }
    let output = PathBuf::from(&args[2]);
    if output.file_name().is_none() {
        return Err("verification requires a named new scratch root".into());
    }
    Ok(Options {
        input: args[1].clone().into(),
        output,
        expected: expected
            .ok_or("verification requires an independently trusted --expected-sha256")?,
        instance: instance.ok_or("verification requires a --verification-instance")?,
        profile: profile.finish(),
        resume: false,
        approval: approval.finish()?,
    })
}

/// Deterministic observation points for tests, never environment-controlled hooks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    AuthorityClosed,
    GraphCheckedAndNodeClosed,
}
fn execute(options: &Options) -> Result<String, String> {
    execute_with_checkpoints(options, |_| Ok(()))
}
fn execute_with_checkpoints(
    options: &Options,
    checkpoint: impl FnMut(Stage) -> Result<(), String>,
) -> Result<String, String> {
    if options.resume {
        return Err("verification cannot resume or reuse existing scratch state".into());
    }
    let deadline = options.profile.start();
    let approval = authenticate_approval(options, deadline)?;
    require_absent(&options.output)?;
    // No directory exists until the original checksum, framing, native IDs and
    // independent payload commitments have all passed against one opened input.
    let archive = PinnedArchive::open(
        &options.input,
        options.expected,
        options.profile.transfer,
        deadline,
    )?;
    let verified =
        verify_pinned_with_checkpoints(archive, options, approval.as_ref(), deadline, checkpoint)?;
    let archive = &verified.archive;
    let graph = verified.graph;
    let header = archive.header();
    Ok(format!(
        concat!(
            "{{\"type\":\"repository_source_backup_verify\",\"schema_version\":1,",
            "\"sha256\":{},\"archive_bytes\":{},\"tenant_id\":{},\"repository_id\":{},",
            "\"incarnation_id\":{},\"object_format\":{},\"head_generation\":{},",
            "\"objects\":{},\"references\":{},\"payload_bytes\":{},\"local_edges\":{},",
            "\"external_gitlinks\":{},\"verification_instance\":{},\"complete\":true,",
            "\"scope\":\"authority_and_selected_git_objects\",\"object_graph_verified\":true,",
            "\"original_payload_commitments_verified\":true,\"authority_import_verified\":true,",
            "\"git_payloads_written\":false,\"destination_authority_published\":false,",
            "\"node_closed\":true,\"scratch_removed\":true,\"destination_readback_verified\":false,",
            "\"newest_checkpoint_verified\":false,\"signature_verified\":{}{},",
            "\"external_artifacts_verified\":false,\"routing_published\":false{}}}"
        ),
        quote(&hex(&options.expected)),
        archive.seal().bytes,
        quote(&header.identity.tenant.to_string()),
        quote(&header.identity.repository.to_string()),
        quote(&header.identity.incarnation.to_string()),
        quote(header.identity.format.as_str()),
        generation(&header.authority),
        graph.objects,
        graph.references,
        graph.payload_bytes,
        graph.local_edges,
        graph.external_gitlinks,
        options.instance.raw(),
        approval.is_some(),
        approval_receipt_fields(approval.as_ref()),
        super::super::checkpoint::receipt(header.checkpoint.as_ref()),
    ))
}

/// Only complete native authority/selection/graph verification constructs this
/// result. It retains the original descriptor, pin and limits for later rechecks.
/// It is content evidence, never canonical authorization or a signed capsule.
pub(in super::super) struct VerifiedSourceArchive<R = File> {
    archive: PinnedArchive<R>,
    graph: GraphReport,
}

impl<R: Read + Seek> VerifiedSourceArchive<R> {
    pub(in super::super) fn header(&self) -> &StreamHeader {
        self.archive.header()
    }

    pub(in super::super) fn seal(&self) -> Seal {
        self.archive.seal()
    }

    pub(in super::super) const fn graph(&self) -> GraphReport {
        self.graph
    }

    /// Reverify the original bytes through exact EOF without renewing the
    /// invocation's deadline or reopening the caller's input pathname.
    pub(in super::super) fn recheck(&mut self, deadline: Deadline) -> Result<(), String> {
        self.archive.scan_stream(deadline, |header, input| {
            let buffer_bytes = (header.length.min(64 * 1024) as usize).max(1);
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(buffer_bytes)
                .map_err(|_| "backup recheck buffer allocation refused")?;
            buffer.resize(buffer_bytes, 0);
            loop {
                deadline.check()?;
                if input.read(&mut buffer).map_err(|error| error.to_string())? == 0 {
                    return deadline.check();
                }
            }
        })
    }
}

/// The same real preflight used by `verify`, available to native composition
/// without parsing a receipt or spawning another command. No input is reopened.
pub(in super::super) fn verify_pinned_in<R: Read + Seek>(
    archive: PinnedArchive<R>,
    scratch: &Path,
    instance: StoreInstanceId,
    profile: Profile,
    deadline: Deadline,
) -> Result<VerifiedSourceArchive<R>, String> {
    let options = Options {
        input: PathBuf::new(),
        output: scratch.to_path_buf(),
        expected: archive.seal().digest,
        instance,
        profile,
        resume: false,
        approval: None,
    };
    verify_pinned_with_checkpoints(archive, &options, None, deadline, |_| Ok(()))
}

fn verify_pinned_with_checkpoints<R: Read + Seek>(
    mut archive: PinnedArchive<R>,
    options: &Options,
    approval: Option<&super::VerifiedApproval>,
    deadline: Deadline,
    mut checkpoint: impl FnMut(Stage) -> Result<(), String>,
) -> Result<VerifiedSourceArchive<R>, String> {
    deadline.check()?;
    require_absent(&options.output)?;
    match_approval(approval, &archive, deadline)?;
    if archive.header().authority.instance == options.instance.raw() {
        return Err("verification instance must differ from source; no scratch created".into());
    }
    deadline.check()?;
    create_private(&options.output)?;
    let quarantine = options.output.join(".verify-quarantine");
    let verified = (|| {
        create_private(&quarantine)?;
        let expected = authority_image(
            &quarantine,
            &archive.header().authority,
            options,
            false,
            deadline,
        )?;
        checkpoint(Stage::AuthorityClosed)?;
        let graph = with_node(
            config(&quarantine, archive.header(), options.profile)?,
            |node| {
                graph_from_archive(
                    node,
                    &mut archive,
                    &expected,
                    ArchiveGraphMode::Preflight,
                    options.profile,
                    deadline,
                )
            },
        )?;
        checkpoint(Stage::GraphCheckedAndNodeClosed)?;
        check_approval_current(approval, deadline)?;
        // There is deliberately no PreparedPublication and no restore intent.
        // This command cannot publish a root or authorize a later resume.
        require_absent(&options.output.join("authority.fsqlite"))?;
        Ok(graph)
    })();
    let graph = verified.map_err(|error: String| {
        format!(
            "{error}; no destination authority published; retained verification scratch at {}",
            options.output.display(),
        )
    })?;
    // Both store and node have explicitly closed. Remove only the fresh private
    // tree this invocation created, never a caller's pre-existing directory.
    fs::remove_dir_all(&options.output).map_err(|error| {
        format!(
            "archive verified but scratch cleanup failed at {}: {error}",
            options.output.display(),
        )
    })?;
    sync_directory(super::parent(&options.output)).map_err(|error| {
        format!("archive verified and scratch removed; parent sync failed: {error}")
    })?;
    Ok(VerifiedSourceArchive { archive, graph })
}

pub(in super::super) fn run(
    args: &[String],
    output: &mut impl Write,
    timeout: Option<std::time::Duration>,
) -> Result<(), String> {
    if args == ["verify", "--help"] {
        return emit(output, USAGE);
    }
    let mut options = parse(args)?;
    options.profile = options.profile.with_timeout_cap(timeout)?;
    let receipt = execute(&options)?;
    emit(output, &receipt).map_err(|error| {
        format!("archive verified and scratch removed; receipt output failed: {error}")
    })
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
