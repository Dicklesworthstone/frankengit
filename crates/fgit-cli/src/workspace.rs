//! The explicit local-operator TreeFS tool workflow. No repository ref write.

mod invocation;

use fgit_node::{
    NodeConfig, OneNode, WorkspaceBatchJob, WorkspaceHostTelemetry, WorkspaceInputSharing,
    WorkspaceToolResult,
};
use fgit_runner::sparse_workspace::SharedInputCacheStats;
use fgit_schema::json::{self, Value as JsonValue};
use fgit_types::{
    GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId,
};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const USAGE: &str = "usage: fg workspace run <storage-root> <tenant-id> <repository-id> <ref> <private-parent> <workspace-id-hex> <new-bundle-name> --trusted-local --read <top-level-path> [--read ...] [--write <exact-output-path> ...] [--shared-inputs copy|prefer-reflink|require-reflink] --author 'Name <email>' --timestamp <unix-seconds> --message <text> [--timeout-secs <1..3600>] [--expected-head <snapshot-token>] [--expected-commit <native-oid>] -- /absolute/tool [args...]";
const BATCH_USAGE: &str = "usage: fg workspace run-batch <storage-root> <tenant-id> <repository-id> <ref> <private-parent> --trusted-local --read <top-level-path> [--read ...] [--shared-inputs copy|prefer-reflink|require-reflink] [--timeout-secs <1..3600>] [--expected-head <snapshot-token>] [--expected-commit <native-oid>] --spec <batch-spec-json>";
const MAX_SPEC_BYTES: usize = json::MAX_INPUT;
const MAX_BATCH_JOBS: usize = 64;
static TEMPORARY: AtomicU64 = AtomicU64::new(0);

struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    reference: RefName,
    expected_head: Option<RepositoryAuthorityHeadId>,
    expected_commit: Option<GitOid>,
    parent: PathBuf,
    workspace: [u8; 16],
    destination: PathBuf,
    reads: Vec<Vec<u8>>,
    writes: Vec<Vec<u8>>,
    sharing: WorkspaceInputSharing,
    author: String,
    timestamp: u64,
    message: String,
    timeout: Duration,
    program: String,
    arguments: Vec<String>,
}

pub fn run(arguments: &[String]) -> Result<(), String> {
    if arguments.first().is_some_and(|arg| arg == "recover") {
        return invocation::recover(arguments);
    }
    if arguments.first().is_some_and(|arg| arg == "run-batch") {
        return run_batch(arguments);
    }
    let options = parse(arguments)?;
    ensure_bundle_absent(&options.destination)?;
    let signals = fgit_node::TerminationSignals::install()
        .map_err(|error| format!("workspace signal registration failed: {error}"))?;
    let mut node = OneNode::open_existing(NodeConfig::new(
        options.storage.clone(),
        options.tenant,
        options.repository,
    ))
    .map_err(|error| error.to_string())?;
    let mut monitor_cleanup = None;
    let mut invocation = None;
    let operation = (|| {
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|error| error.to_string())?;
        node.bring_into_service(head.receipt().generation())
            .map_err(|error| error.to_string())?;
        let request = fgit_cli::command_request_context(&node);
        let mut command = Command::new(&options.program);
        command.args(&options.arguments);
        let (result, cleanup) = signals
            .run_request(node.runtime(), &request, |request| {
                let (claimed, head, commit) = invocation::reserve(&node, request, &options)?;
                invocation = Some(claimed);
                node.runtime()
                    .block_on(node.run_trusted_workspace_tool_shared_at_in(
                        request,
                        &options.reference,
                        (Some(head), Some(commit)),
                        options.workspace,
                        &options.parent,
                        &options.reads,
                        &options.writes,
                        options.sharing,
                        &mut command,
                        options.timeout,
                        (
                            &options.author,
                            options.timestamp,
                            options.message.as_bytes(),
                        ),
                    ))
                    .map_err(|error| error.to_string())
            })
            .map_err(|error| error.to_string())?;
        monitor_cleanup = cleanup.err().map(|error| error.to_string());
        result.map_err(|error| error.to_string())
    })();
    let node_cleanup = node.shutdown().err().map(|error| error.to_string());
    let result = match settled_result(operation, monitor_cleanup, node_cleanup) {
        Ok(result) => result,
        Err(error) => {
            if let Some(claimed) = invocation {
                if let Err(record) = claimed.fail(&error) {
                    return Err(format!("{error}; terminal custody unresolved: {record}"));
                }
            }
            return Err(error);
        }
    };
    let invocation = invocation.ok_or("workspace completed without invocation custody")?;
    let receipt = finalize_candidate_output(&options, &result, invocation)?;
    writeln!(std::io::stdout().lock(), "{receipt}").map_err(|error| {
        format!(
            "bundle is published at {}; receipt output failed: {error}",
            options.destination.display()
        )
    })
}

fn run_batch(arguments: &[String]) -> Result<(), String> {
    let batch = parse_batch(arguments)?;
    for item in &batch {
        ensure_bundle_absent(&item.destination)?;
    }
    let first = batch.first().ok_or(BATCH_USAGE)?;
    let signals = fgit_node::TerminationSignals::install()
        .map_err(|error| format!("workspace signal registration failed: {error}"))?;
    let mut node = OneNode::open_existing(NodeConfig::new(
        first.storage.clone(),
        first.tenant,
        first.repository,
    ))
    .map_err(|error| error.to_string())?;
    let mut monitor_cleanup = None;
    let mut invocations = None;
    let operation = (|| {
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|error| error.to_string())?;
        node.bring_into_service(head.receipt().generation())
            .map_err(|error| error.to_string())?;
        let request = fgit_cli::command_request_context(&node);
        let mut jobs = batch
            .iter()
            .map(|opt| {
                let mut command = Command::new(&opt.program);
                command.args(&opt.arguments);
                WorkspaceBatchJob {
                    workspace_id: opt.workspace,
                    output_paths: opt.writes.clone(),
                    command,
                    author: opt.author.clone(),
                    timestamp: opt.timestamp,
                    message: opt.message.as_bytes().to_vec(),
                }
            })
            .collect::<Vec<_>>();
        let (result, cleanup) = signals
            .run_request(node.runtime(), &request, |request| {
                let (claimed, head, commit) = invocation::reserve_batch(&node, request, &batch)?;
                invocations = Some(claimed);
                node.runtime()
                    .block_on(node.run_trusted_workspace_batch_at_in(
                        request,
                        &first.reference,
                        (Some(head), Some(commit)),
                        &first.parent,
                        &first.reads,
                        first.sharing,
                        first.timeout,
                        &mut jobs,
                    ))
                    .map_err(|error| error.to_string())
            })
            .map_err(|error| error.to_string())?;
        monitor_cleanup = cleanup.err().map(|error| error.to_string());
        result.map_err(|error| error.to_string())
    })();
    let node_cleanup = node.shutdown().err().map(|error| error.to_string());
    let batch_result = match settled_result(operation, monitor_cleanup, node_cleanup) {
        Ok(result) => result,
        Err(error) => {
            if let Some(claimed_list) = invocations {
                let mut custody_errors = Vec::new();
                for claimed in claimed_list {
                    if let Err(record) = claimed.fail(&error) {
                        custody_errors.push(record.to_string());
                    }
                }
                if !custody_errors.is_empty() {
                    return Err(format!(
                        "{error}; terminal custody unresolved: {}",
                        custody_errors.join(", ")
                    ));
                }
            }
            return Err(error);
        }
    };
    let invocations = invocations.ok_or("workspace batch completed without invocation custody")?;
    if batch_result.results.len() != batch.len() || invocations.len() != batch.len() {
        return Err("workspace batch result length mismatch".to_owned());
    }
    let first_result = batch_result
        .results
        .first()
        .ok_or("empty workspace batch result")?;
    let format = match first_result.object_format {
        GitHashAlgorithm::Sha1 => "sha1",
        GitHashAlgorithm::Sha256 => "sha256",
    };
    let source_commit = first_result.source_commit.to_string();
    let source_rcr = first_result.source_rcr.to_string();
    let mut job_receipts = Vec::with_capacity(batch.len());
    for ((options, result), invocation) in batch
        .iter()
        .zip(batch_result.results.iter())
        .zip(invocations)
    {
        job_receipts.push(finalize_candidate_output(options, result, invocation)?);
    }
    let batch_receipt = format!(
        "{{\"type\":\"workspace_batch\",\"published_to_repository\":false,\"object_format\":\"{format}\",\"sharing_mode\":\"{}\",\"source_commit\":\"{source_commit}\",\"source_rcr\":\"{source_rcr}\",\"cache\":{},\"jobs\":[{}]}}",
        batch_result.sharing_mode.as_str(),
        cache_stats_json(&batch_result.cache_stats),
        job_receipts.join(","),
    );
    writeln!(std::io::stdout().lock(), "{batch_receipt}")
        .map_err(|error| format!("batch bundles published; receipt output failed: {error}"))
}

fn ensure_bundle_absent(destination: &Path) -> Result<(), String> {
    match fs::symlink_metadata(destination) {
        Ok(_) => Err("bundle destination already exists; no tool was run".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect bundle destination: {error}")),
    }
}

fn finalize_candidate_output(
    options: &Options,
    result: &WorkspaceToolResult,
    invocation: invocation::Invocation,
) -> Result<String, String> {
    let format = match result.object_format {
        GitHashAlgorithm::Sha1 => "sha1",
        GitHashAlgorithm::Sha256 => "sha256",
    };
    // Standard Git bundle v3: the receiver must already possess the source
    // commit and its reachable objects. No promisor filter or thin delta is
    // claimed. Native object construction/compression remains in fgit-pack.
    let mut header = format!(
        "# v3 git bundle\n@object-format={format}\n-{} TreeFS source prerequisite\n{} ",
        result.source_commit, result.candidate_commit
    )
    .into_bytes();
    header.extend_from_slice(options.reference.as_bytes());
    header.extend_from_slice(b"\n\n");

    let changed = result
        .changed_paths
        .iter()
        .map(|path| quote(&hex(path)))
        .collect::<Vec<_>>()
        .join(",");
    let mut receipt = format!(
        "{{\"type\":\"workspace_candidate\",\"published_to_repository\":false,\"object_format\":\"{format}\",\"workspace_id\":\"{}\",\"source_commit\":\"{}\",\"source_rcr\":\"{}\",\"candidate_commit\":\"{}\",\"root_tree\":\"{}\",\"objects\":{},\"changed_paths_hex\":[{}],\"bundle\":{},\"host_telemetry\":{}}}",
        hex(&options.workspace),
        result.source_commit,
        result.source_rcr,
        result.candidate_commit,
        result.root_tree,
        result.object_count,
        changed,
        quote(&options.destination.to_string_lossy()),
        telemetry_json(&result.telemetry),
    );
    receipt.pop();
    receipt.push_str(&format!(
        ",\"invocation_directory\":{},\"request_sha256\":\"{}\"}}",
        quote(&invocation.directory.to_string_lossy()),
        hex(&invocation.request_id)
    ));
    let terminal = invocation
        .complete(&header, result.pack_bytes(), receipt.as_bytes())
        .map_err(|error| format!("candidate custody unresolved; do not rerun the tool: {error}"))?;
    publish_bundle(&options.destination, &header, result.pack_bytes())?;
    receipt.pop();
    receipt.push_str(&format!(",\"terminal_sha256\":\"{}\"}}", hex(&terminal)));
    Ok(receipt)
}

fn telemetry_json(telemetry: &WorkspaceHostTelemetry) -> String {
    format!(
        concat!(
            "{{\"profile\":\"linux-openat2-v2\",\"sharing_mode\":\"{}\",",
            "\"reflink_supported\":{},\"copied_bytes\":{},\"shared_host_bytes\":{},",
            "\"metadata_bytes\":{},\"imported_bytes\":{},\"created_entries\":{},",
            "\"imported_entries\":{},\"removed_entries\":{},\"seeded_bytes\":{},",
            "\"cloned_bytes\":{},\"fallback_bytes\":{},\"creation_ns\":{},",
            "\"execution_ns\":{},\"cleanup_ns\":{}}}"
        ),
        telemetry.sharing_mode.as_str(),
        telemetry.reflink_supported,
        telemetry.copied_bytes,
        telemetry.shared_host_bytes,
        telemetry.metadata_bytes,
        telemetry.imported_bytes,
        telemetry.created_entries,
        telemetry.imported_entries,
        telemetry.removed_entries,
        telemetry.seeded_bytes,
        telemetry.cloned_bytes,
        telemetry.fallback_bytes,
        telemetry.creation_ns,
        telemetry.execution_ns,
        telemetry.cleanup_ns,
    )
}

fn cache_stats_json(stats: &SharedInputCacheStats) -> String {
    format!(
        concat!(
            "{{\"profile\":\"verified-reflink-or-copy-v1\",\"cache_closed\":true,",
            "\"reflink_supported\":{},\"resident_bytes\":{},\"resident_entries\":{},",
            "\"seeded_bytes\":{},\"seeded_entries\":{},\"probe_entries\":{},",
            "\"cloned_bytes\":{},\"clone_operations\":{},\"fallback_bytes\":{},",
            "\"fallback_files\":{},\"unsupported_files\":{},\"capacity_files\":{}}}"
        ),
        stats.reflink_supported,
        stats.resident_bytes,
        stats.resident_entries,
        stats.seeded_bytes,
        stats.seeded_entries,
        stats.probe_entries,
        stats.cloned_bytes,
        stats.clone_operations,
        stats.fallback_bytes,
        stats.fallback_files,
        stats.unsupported_files,
        stats.capacity_files,
    )
}

/// Completion must not conceal observer or node cleanup, nor erase the original
/// operation refusal. No bundle is written until all three owners have settled.
fn settled_result<T>(
    operation: Result<T, String>,
    monitor: Option<String>,
    node: Option<String>,
) -> Result<T, String> {
    let mut cleanup = Vec::new();
    if let Some(error) = monitor {
        cleanup.push(format!("signal observer cleanup failed: {error}"));
    }
    if let Some(error) = node {
        cleanup.push(format!("node shutdown failed: {error}"));
    }
    match (operation, cleanup.is_empty()) {
        (Ok(result), true) => Ok(result),
        (Err(error), true) => Err(error),
        (Ok(_), false) => Err(format!(
            "candidate prepared but bundle not published; {}",
            cleanup.join("; ")
        )),
        (Err(error), false) => Err(format!("{error}; {}", cleanup.join("; "))),
    }
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 10 || arguments[0] != "run" {
        return Err(USAGE.to_owned());
    }
    let boundary = arguments[8..]
        .iter()
        .position(|arg| arg == "--")
        .map(|index| index + 8)
        .ok_or_else(|| USAGE.to_owned())?;
    if boundary + 1 >= arguments.len() {
        return Err(USAGE.to_owned());
    }
    let tenant = TenantId::from_hex(&arguments[2]).map_err(|e| e.to_string())?;
    let repository = RepositoryId::from_hex(&arguments[3]).map_err(|e| e.to_string())?;
    let reference = RefName::try_new(arguments[4].as_bytes()).map_err(|e| e.to_string())?;
    let workspace = workspace_id(&arguments[6])?;
    validate_bundle_filename(&arguments[7], std::slice::from_ref(&arguments[6]))?;
    let parent = PathBuf::from(&arguments[5]);
    let destination = parent.join(&arguments[7]);
    let (mut reads, mut writes) = (Vec::new(), Vec::new());
    let (mut author, mut timestamp, mut message, mut timeout) = (None, None, None, None);
    let (mut expected_head, mut expected_commit) = (None, None);
    let mut sharing = None;
    let mut trusted = false;
    let mut cursor = 8;
    while cursor < boundary {
        let flag = arguments[cursor].as_str();
        cursor += 1;
        if flag == "--trusted-local" {
            if trusted {
                return Err("duplicate --trusted-local".to_owned());
            }
            trusted = true;
            continue;
        }
        let value = arguments
            .get(cursor)
            .filter(|_| cursor < boundary)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag {
            "--expected-head" => set_once(
                &mut expected_head,
                super::commit_replay::parse_head(value)?,
                flag,
            )?,
            "--expected-commit" => set_once(
                &mut expected_commit,
                super::publication_support::parse_oid(value)?,
                flag,
            )?,
            "--read" => reads.push(value.as_bytes().to_vec()),
            "--write" => writes.push(value.as_bytes().to_vec()),
            "--shared-inputs" => set_once(&mut sharing, parse_sharing(value)?, flag)?,
            "--author" => set_once(&mut author, value.clone(), flag)?,
            "--message" => set_once(&mut message, value.clone(), flag)?,
            "--timestamp" => set_once(&mut timestamp, number(value)?, flag)?,
            "--timeout-secs" => set_once(&mut timeout, number(value)?, flag)?,
            _ => return Err(format!("unknown workspace option {flag}")),
        }
    }
    if !trusted {
        return Err("--trusted-local is required: this command runs with host-user privileges, not in a hostile-code sandbox".to_owned());
    }
    if reads.is_empty() || reads.len() > 1024 || writes.len() > 10_000 {
        return Err("invalid read/output count".to_owned());
    }
    let seconds = timeout.unwrap_or(60);
    if seconds == 0 || seconds > 3600 {
        return Err("timeout must be 1..3600 seconds".to_owned());
    }
    Ok(Options {
        storage: arguments[1].clone().into(),
        tenant,
        repository,
        reference,
        expected_head,
        expected_commit,
        parent,
        workspace,
        destination,
        reads,
        writes,
        sharing: sharing.unwrap_or(WorkspaceInputSharing::PreferReflink),
        author: author.ok_or("--author is required")?,
        timestamp: timestamp.ok_or("--timestamp is required")?,
        message: message.ok_or("--message is required")?,
        timeout: Duration::from_secs(seconds),
        program: arguments[boundary + 1].clone(),
        arguments: arguments[boundary + 2..].to_vec(),
    })
}

fn parse_batch(arguments: &[String]) -> Result<Vec<Options>, String> {
    if arguments.len() < 10 || arguments[0] != "run-batch" {
        return Err(BATCH_USAGE.to_owned());
    }
    let tenant = TenantId::from_hex(&arguments[2]).map_err(|e| e.to_string())?;
    let repository = RepositoryId::from_hex(&arguments[3]).map_err(|e| e.to_string())?;
    let reference = RefName::try_new(arguments[4].as_bytes()).map_err(|e| e.to_string())?;
    let parent = PathBuf::from(&arguments[5]);
    let mut reads = Vec::new();
    let (mut expected_head, mut expected_commit) = (None, None);
    let (mut sharing, mut timeout, mut spec_path) = (None, None, None);
    let mut trusted = false;
    let mut cursor = 6;
    while cursor < arguments.len() {
        let flag = arguments[cursor].as_str();
        cursor += 1;
        if flag == "--trusted-local" {
            if trusted {
                return Err("duplicate --trusted-local".to_owned());
            }
            trusted = true;
            continue;
        }
        let value = arguments
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag {
            "--expected-head" => set_once(
                &mut expected_head,
                super::commit_replay::parse_head(value)?,
                flag,
            )?,
            "--expected-commit" => set_once(
                &mut expected_commit,
                super::publication_support::parse_oid(value)?,
                flag,
            )?,
            "--read" => reads.push(value.as_bytes().to_vec()),
            "--shared-inputs" => set_once(&mut sharing, parse_sharing(value)?, flag)?,
            "--timeout-secs" => set_once(&mut timeout, number(value)?, flag)?,
            "--spec" => set_once(&mut spec_path, PathBuf::from(value), flag)?,
            _ => return Err(format!("unknown workspace batch option {flag}")),
        }
    }
    if !trusted {
        return Err("--trusted-local is required: this command runs with host-user privileges, not in a hostile-code sandbox".to_owned());
    }
    if reads.is_empty() || reads.len() > 1024 {
        return Err("invalid read count".to_owned());
    }
    let seconds = timeout.unwrap_or(60);
    if seconds == 0 || seconds > 3600 {
        return Err("timeout must be 1..3600 seconds".to_owned());
    }
    let spec_path = spec_path.ok_or("--spec is required")?;
    let spec_bytes = read_spec_file(&spec_path)?;
    parse_batch_spec_bytes(
        &spec_bytes,
        PathBuf::from(&arguments[1]),
        tenant,
        repository,
        reference,
        expected_head,
        expected_commit,
        parent,
        reads,
        sharing.unwrap_or(WorkspaceInputSharing::PreferReflink),
        Duration::from_secs(seconds),
    )
}

fn read_spec_file(path: &Path) -> Result<Vec<u8>, String> {
    let named = fs::symlink_metadata(path).map_err(|e| format!("cannot inspect --spec: {e}"))?;
    if !named.is_file() || named.nlink() != 1 {
        return Err("--spec must name a regular non-symlink file".to_owned());
    }
    if named.len() > MAX_SPEC_BYTES as u64 {
        return Err("--spec exceeds finite JSON input limit".to_owned());
    }
    let file = File::open(path).map_err(|e| format!("cannot open --spec: {e}"))?;
    let actual = file
        .metadata()
        .map_err(|e| format!("cannot stat --spec: {e}"))?;
    if (actual.dev(), actual.ino(), actual.len()) != (named.dev(), named.ino(), named.len()) {
        return Err("--spec changed during open".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(MAX_SPEC_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read --spec: {e}"))?;
    if bytes.len() > MAX_SPEC_BYTES || bytes.len() as u64 != actual.len() {
        return Err("--spec changed or exceeds finite JSON input limit".to_owned());
    }
    Ok(bytes)
}

fn parse_batch_spec_bytes(
    spec_bytes: &[u8],
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    reference: RefName,
    expected_head: Option<RepositoryAuthorityHeadId>,
    expected_commit: Option<GitOid>,
    parent: PathBuf,
    reads: Vec<Vec<u8>>,
    sharing: WorkspaceInputSharing,
    timeout: Duration,
) -> Result<Vec<Options>, String> {
    let root =
        json::parse(spec_bytes).map_err(|e| format!("invalid workspace batch spec JSON: {e}"))?;
    let root_obj = root
        .object()
        .ok_or("workspace batch spec must be a JSON object")?;
    if root_obj.keys().any(|key| key != "jobs") {
        return Err("workspace batch spec contains unknown top-level field".to_owned());
    }
    let Some(JsonValue::Array(jobs)) = root_obj.get("jobs") else {
        return Err("workspace batch spec requires a jobs array".to_owned());
    };
    if jobs.is_empty() || jobs.len() > MAX_BATCH_JOBS {
        return Err("workspace batch spec requires 1..64 jobs".to_owned());
    }
    let mut raw_ids = Vec::with_capacity(jobs.len());
    for entry in jobs {
        let obj = entry
            .object()
            .ok_or("workspace batch job must be a JSON object")?;
        let id_text = obj
            .get("workspace_id")
            .and_then(JsonValue::text)
            .ok_or("workspace batch job requires workspace_id")?;
        raw_ids.push(id_text.to_owned());
    }
    let mut seen_ids = BTreeSet::new();
    let mut seen_bundles = BTreeSet::new();
    let mut parsed = Vec::with_capacity(jobs.len());
    for entry in jobs {
        let obj = entry
            .object()
            .ok_or("workspace batch job must be a JSON object")?;
        for key in obj.keys() {
            if !matches!(
                key.as_str(),
                "workspace_id"
                    | "bundle"
                    | "writes"
                    | "author"
                    | "timestamp"
                    | "message"
                    | "program"
                    | "args"
            ) {
                return Err(format!("unknown workspace batch job field {key}"));
            }
        }
        let id_text = obj
            .get("workspace_id")
            .and_then(JsonValue::text)
            .ok_or("workspace batch job requires workspace_id")?;
        let id = workspace_id(id_text)?;
        if !seen_ids.insert(id) {
            return Err("duplicate workspace_id in batch spec".to_owned());
        }
        let bundle_name = obj
            .get("bundle")
            .and_then(JsonValue::text)
            .ok_or("workspace batch job requires bundle")?;
        validate_bundle_filename(bundle_name, &raw_ids)?;
        if !seen_bundles.insert(bundle_name.to_owned()) {
            return Err("duplicate bundle filename in batch spec".to_owned());
        }
        let writes = match obj.get("writes") {
            Some(JsonValue::Array(items)) => {
                if items.len() > 10_000 {
                    return Err("workspace batch job exceeds output limit".to_owned());
                }
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    let path = item
                        .text()
                        .ok_or("workspace batch job writes must be strings")?;
                    out.push(path.as_bytes().to_vec());
                }
                out
            }
            None => Vec::new(),
            Some(_) => return Err("workspace batch job writes must be an array".to_owned()),
        };
        let author = obj
            .get("author")
            .and_then(JsonValue::text)
            .ok_or("workspace batch job requires author")?
            .to_owned();
        let timestamp = obj
            .get("timestamp")
            .and_then(JsonValue::unsigned)
            .ok_or("workspace batch job requires unsigned timestamp")?;
        let message = obj
            .get("message")
            .and_then(JsonValue::text)
            .ok_or("workspace batch job requires message")?
            .to_owned();
        let program = obj
            .get("program")
            .and_then(JsonValue::text)
            .ok_or("workspace batch job requires program")?
            .to_owned();
        let arguments = match obj.get("args") {
            Some(JsonValue::Array(items)) => {
                if items.len() > 128 {
                    return Err("workspace batch job exceeds argument limit".to_owned());
                }
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    let arg = item
                        .text()
                        .ok_or("workspace batch job args must be strings")?;
                    out.push(arg.to_owned());
                }
                out
            }
            None => Vec::new(),
            Some(_) => return Err("workspace batch job args must be an array".to_owned()),
        };
        parsed.push(Options {
            storage: storage.clone(),
            tenant,
            repository,
            reference: reference.clone(),
            expected_head,
            expected_commit,
            parent: parent.clone(),
            workspace: id,
            destination: parent.join(bundle_name),
            reads: reads.clone(),
            writes,
            sharing,
            author,
            timestamp,
            message,
            timeout,
            program,
            arguments,
        });
    }
    Ok(parsed)
}

fn validate_bundle_filename(bundle: &str, workspace_hexes: &[String]) -> Result<(), String> {
    let name = Path::new(bundle);
    if name.file_name() != Some(name.as_os_str())
        || bundle.is_empty()
        || workspace_hexes
            .iter()
            .any(|ws| bundle == format!("workspace-{ws}"))
    {
        return Err(
            "bundle name must be one new filename distinct from every workspace slot".to_owned(),
        );
    }
    Ok(())
}

fn parse_sharing(value: &str) -> Result<WorkspaceInputSharing, String> {
    match value {
        "prefer-reflink" => Ok(WorkspaceInputSharing::PreferReflink),
        "require-reflink" => Ok(WorkspaceInputSharing::RequireReflink),
        "copy" => Ok(WorkspaceInputSharing::Copy),
        _ => Err(format!(
            "invalid --shared-inputs value {value}; expected copy, prefer-reflink, or require-reflink"
        )),
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate {name}"));
    }
    *slot = Some(value);
    Ok(())
}
fn number(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("expected unsigned decimal integer".to_owned());
    }
    value.parse().map_err(|_| "integer exceeds u64".to_owned())
}
fn workspace_id(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("workspace identity must be 32 lowercase hexadecimal characters".to_owned());
    }
    let mut id = [0; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(id)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Body first; atomically create the final name without replacing any file.
/// The caller-owned private parent is the same one validated by the host
/// workspace adapter. A post-link failure reports that output is visible.
fn publish_bundle(destination: &Path, header: &[u8], pack: &[u8]) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or("bundle destination has no parent")?;
    let directory = File::open(parent).map_err(|e| e.to_string())?;
    let (temporary, mut file) = (0..16)
        .find_map(|_| {
            let path = parent.join(format!(
                ".fg-bundle-{}-{}.tmp",
                std::process::id(),
                TEMPORARY.fetch_add(1, Ordering::Relaxed)
            ));
            if path == destination {
                return None;
            }
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => Some(Ok((path, file))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error.to_string())),
            }
        })
        .ok_or("cannot reserve a private bundle temporary")??;
    let mut visible = false;
    let written = (|| -> std::io::Result<()> {
        file.write_all(header)?;
        file.write_all(pack)?;
        file.sync_all()?;
        fs::hard_link(&temporary, destination)?;
        visible = true;
        fs::remove_file(&temporary)?;
        directory.sync_all()
    })();
    if let Err(error) = written {
        let cleanup = match fs::remove_file(&temporary) {
            Ok(()) => String::new(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => format!(
                "; temporary {} also could not be removed: {e}",
                temporary.display()
            ),
        };
        return Err(format!(
            "bundle {} at {}: {error}{cleanup}",
            if visible {
                "is visible but finalization failed"
            } else {
                "was not published"
            },
            destination.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        [
            "run",
            "node",
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "refs/heads/main",
            "/private/workspaces",
            "33333333333333333333333333333333",
            "candidate.bundle",
            "--trusted-local",
            "--read",
            "src",
            "--write",
            "src/lib.rs",
            "--author",
            "Test <test@example.invalid>",
            "--timestamp",
            "0",
            "--message",
            "workspace candidate",
            "--",
            "/usr/bin/true",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn exact_source_flags_are_parsed_before_tool_arguments_and_duplicate_pins_refuse() {
        for width in [40, 64] {
            let mut input = args();
            let at = input.iter().position(|s| s == "--").unwrap();
            input.splice(
                at..at,
                [
                    "--expected-commit".into(),
                    "a".repeat(width),
                    "--expected-head".into(),
                    format!("alg:2:{}", "bb".repeat(32)),
                ],
            );
            let options = parse(&input).unwrap();
            assert_eq!(
                options.expected_commit.unwrap().to_string(),
                "a".repeat(width)
            );
            assert!(options.expected_head.is_some());
            let at = input.iter().position(|s| s == "--").unwrap();
            input.splice(at..at, ["--expected-commit".into(), "a".repeat(width)]);
            assert!(parse(&input).is_err());
        }
        for (flag, bad) in [
            ("--expected-commit", "bogus"),
            ("--expected-head", "alg:2:bad"),
        ] {
            let mut input = args();
            let at = input.iter().position(|s| s == "--").unwrap();
            input.splice(at..at, [flag.into(), bad.into()]);
            assert!(parse(&input).is_err());
        }
        let mut input = args();
        input.extend([
            "--expected-commit".into(),
            "this-is-a-literal-tool-argument".into(),
        ]);
        assert!(parse(&input).unwrap().expected_commit.is_none());
    }

    #[test]
    fn shared_inputs_policy_parses_and_rejects_duplicates_or_unknown_modes() {
        assert_eq!(
            parse(&args()).unwrap().sharing,
            WorkspaceInputSharing::PreferReflink
        );
        for (raw, expected) in [
            ("copy", WorkspaceInputSharing::Copy),
            ("prefer-reflink", WorkspaceInputSharing::PreferReflink),
            ("require-reflink", WorkspaceInputSharing::RequireReflink),
        ] {
            let mut input = args();
            let at = input.iter().position(|s| s == "--").unwrap();
            input.splice(at..at, ["--shared-inputs".into(), raw.into()]);
            assert_eq!(parse(&input).unwrap().sharing, expected);
            let at = input.iter().position(|s| s == "--").unwrap();
            input.splice(at..at, ["--shared-inputs".into(), raw.into()]);
            assert!(parse(&input).is_err());
        }
        let mut bad = args();
        let at = bad.iter().position(|s| s == "--").unwrap();
        bad.splice(at..at, ["--shared-inputs".into(), "fuse".into()]);
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn batch_spec_parses_distinct_jobs_and_rejects_collisions_or_unknown_fields() {
        let parse_spec = |raw: &str| {
            parse_batch_spec_bytes(
                raw.as_bytes(),
                PathBuf::from("node"),
                TenantId::from_bytes([0x11; 16]),
                RepositoryId::from_bytes([0x22; 16]),
                RefName::try_new(b"refs/heads/main").unwrap(),
                None,
                None,
                PathBuf::from("/private/workspaces"),
                vec![b"src".to_vec()],
                WorkspaceInputSharing::PreferReflink,
                Duration::from_secs(30),
            )
        };
        let valid = r#"{
            "jobs": [
                {
                    "workspace_id": "01010101010101010101010101010101",
                    "bundle": "first.bundle",
                    "writes": ["src/a.rs"],
                    "author": "Test <test@example.invalid>",
                    "timestamp": 1,
                    "message": "job 1\n",
                    "program": "/usr/bin/true",
                    "args": ["--one"]
                },
                {
                    "workspace_id": "02020202020202020202020202020202",
                    "bundle": "second.bundle",
                    "writes": ["src/b.rs"],
                    "author": "Test <test@example.invalid>",
                    "timestamp": 2,
                    "message": "job 2\n",
                    "program": "/usr/bin/true"
                }
            ]
        }"#;
        let jobs = parse_spec(valid).unwrap();
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].arguments, vec!["--one"]);
        assert!(jobs[1].arguments.is_empty());

        let dup_id = valid.replace(
            "02020202020202020202020202020202",
            "01010101010101010101010101010101",
        );
        assert!(parse_spec(&dup_id).is_err());

        let dup_bundle = valid.replace("second.bundle", "first.bundle");
        assert!(parse_spec(&dup_bundle).is_err());

        let slot_collision = valid.replace(
            "second.bundle",
            "workspace-01010101010101010101010101010101",
        );
        assert!(parse_spec(&slot_collision).is_err());

        let unknown = r#"{"jobs":[],"extra":1}"#;
        assert!(parse_spec(unknown).is_err());
    }

    #[test]
    fn no_bundle_result_escapes_failed_monitor_or_node_cleanup() {
        assert_eq!(settled_result(Ok(7), None, None).unwrap(), 7);
        assert_eq!(
            settled_result::<()>(Err("original refusal".into()), None, None).unwrap_err(),
            "original refusal"
        );
        for (monitor, node) in [
            (Some("monitor".into()), None),
            (None, Some("node".into())),
            (Some("monitor".into()), Some("node".into())),
        ] {
            let error = settled_result(Ok(7), monitor.clone(), node.clone()).unwrap_err();
            assert!(error.contains("candidate prepared but bundle not published"));
            let error = settled_result::<()>(
                Err("original refusal".into()),
                monitor.clone(),
                node.clone(),
            )
            .unwrap_err();
            assert!(error.starts_with("original refusal"));
            if monitor.is_some() {
                assert!(error.contains("signal observer cleanup failed: monitor"));
            }
            if node.is_some() {
                assert!(error.contains("node shutdown failed: node"));
            }
        }
    }

    #[test]
    fn complete_invocation_parses_without_running_anything() {
        let options = parse(&args()).unwrap();
        assert_eq!(options.reads, vec![b"src".to_vec()]);
        assert_eq!(options.writes, vec![b"src/lib.rs".to_vec()]);
        assert_eq!(options.timestamp, 0);
        assert_eq!(options.program, "/usr/bin/true");
        assert_eq!(
            options.destination,
            PathBuf::from("/private/workspaces/candidate.bundle")
        );
    }
    #[test]
    fn trust_opt_in_and_non_escaping_output_are_required() {
        let mut untrusted = args();
        untrusted.retain(|arg| arg != "--trusted-local");
        assert!(parse(&untrusted).is_err());
        for bad in ["../escape", "/outside", ".", "..", "sub/output"] {
            let mut escaped = args();
            escaped[7] = bad.to_owned();
            assert!(parse(&escaped).is_err(), "{bad}");
        }
        assert!(parse(&args()).is_ok());
    }
    #[test]
    fn arguments_after_the_separator_remain_tool_arguments() {
        let mut values = args();
        values.extend(["--message".to_owned(), "do not parse this".to_owned()]);
        assert_eq!(
            parse(&values).unwrap().arguments,
            vec!["--message", "do not parse this"]
        );
        assert_eq!(quote("a\n\"b\\é"), "\"a\\u000a\\\"b\\\\é\"");
    }
}
