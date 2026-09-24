#![forbid(unsafe_code)]
//! Trusted-local integrity audit of one authenticated, immutable object set.
//! Physical residue is never used to discover canonical objects.

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fgit_node::source_retrieval::integrity::{
    GraphAuditQuery, GraphAuditRefusal, GraphLimits, GraphRefusal, GraphReport,
};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{
    CANONICAL_CODEC_VERSION, GitHashAlgorithm, GitOid, HeadGeneration, RepositoryAuthorityHeadId,
    RepositoryId, TenantId,
};

use super::publication_support::{quote, set_once};

const MIB: u64 = 1024 * 1024;
const MAX_OBJECTS: usize = 1_000_000;
const MAX_REFERENCES: usize = 1_000_000;
const MAX_EDGES: usize = 8_000_000;
const MAX_BYTES: u64 = 16 * 1024 * MIB;
const USAGE: &str = "usage: fg fsck <storage-root> <tenant-id> <repository-id> --trusted-local
  [--object-format sha1|sha256] [--expected-generation <non-zero>]
  [--expected-head <algorithm-qualified-snapshot-token>]
  [--max-objects <1..1000000>] [--max-bytes <1..17179869184>]
  [--max-object-bytes <1..268435456>] [--timeout-secs <1..3600>]
  [--max-edges <1..8000000> | --objects-only]

Verify EVERY object in the authenticated authority-selected closure, including
admitted history no longer reachable from current refs. Native Git identity and
the independent payload commitment are checked by the existing object fabric.
By default, also verify complete local graph connectivity, commit/tree/tag edge
types, branch target kinds, and acyclicity. Gitlinks are external data, never
local traversal edges, and still count against the edge budget. Imported legacy
syntax is preserved; this is not strict Git fsck or signature verification.
--objects-only explicitly selects the older byte-integrity/membership audit;
its receipt says object_graph_verified=false, never an implicit fallback.

Every current reference must belong to the selected closure. The exact authority
basis is revalidated after the scan; movement refuses rather than mixing snapshots.
--expected-generation fences the initial observation. For exact identity, pass
a previous receipt's snapshot_token as --expected-head; both fences must match.
This local operator command can inspect hidden refs and requires explicit
whole-repository authorization via --trusted-local. It does not discover orphan
files, repair storage, change refs, follow symlinks/submodules, or run external Git.
Defaults: 100000 objects, 1000000 inspected edges, 512 MiB total payload,
32 MiB per object, 300 seconds; at most 1000000 references in graph mode.
The per-object ceiling is enforced before allocation; the total counts verified
payload bytes, not physical I/O. A failing scan may read one additional bounded
object before refusing. The scan timeout is checked between operations; it does
not interrupt a blocking filesystem call. Inherited runtime budgets may stop
work earlier. Revalidation is an observation, not a lock against later writes.
No success receipt is emitted before all checks and node shutdown complete.
Exit 0: complete scoped audit; 2: invalid input, incomplete audit, or output error.";

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    expected_generation: Option<u64>,
    expected_head: Option<RepositoryAuthorityHeadId>,
    objects_only: bool,
    max_edges: usize,
    limits: Limits,
}

#[derive(Clone, Copy, Debug)]
struct Limits {
    objects: usize,
    bytes: u64,
    object_bytes: u64,
    seconds: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            objects: 100_000,
            bytes: 512 * MIB,
            object_bytes: 32 * MIB,
            seconds: 300,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Limit(&'static str),
    Deadline,
    Source(String),
    Object { oid: GitOid, detail: String },
    ReferenceOutsideClosure(GitOid),
    ObjectFormat(GitOid),
    Generation { expected: u64, observed: u64 },
    ExpectedHead,
    SnapshotChanged,
    Graph(GraphRefusal),
    NodeGraph(String),
}

impl Display for Refusal {
    fn fmt(&self, out: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(field) => write!(out, "audit_limit_exceeded: {field}"),
            Self::Deadline => out.write_str("audit_deadline_exceeded"),
            Self::Source(detail) => write!(out, "authority_read_failed: {detail}"),
            Self::Object { oid, detail } => write!(out, "object_read_failed: {oid}: {detail}"),
            Self::ReferenceOutsideClosure(oid) => {
                write!(out, "reference_outside_selected_closure: {oid}")
            }
            Self::ObjectFormat(oid) => write!(out, "object_format_mismatch: {oid}"),
            Self::Generation { expected, observed } => write!(
                out,
                "authority_generation_mismatch: expected {expected}, observed {observed}"
            ),
            Self::ExpectedHead => {
                out.write_str("authority_head_mismatch: expected snapshot is not current")
            }
            Self::SnapshotChanged => out.write_str("authority_snapshot_changed: restart the audit"),
            Self::Graph(error) => Display::fmt(error, out),
            Self::NodeGraph(detail) => write!(out, "node_graph_audit_failed: {detail}"),
        }
    }
}

impl std::error::Error for Refusal {}

#[derive(Debug, PartialEq, Eq)]
struct Report {
    head: RepositoryAuthorityHeadId,
    generation: u64,
    closure_root: String,
    references: usize,
    objects: usize,
    payload_bytes: u64,
    graph: Option<GraphReport>,
}

fn positive(text: &str, maximum: u64, field: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{field} requires a positive decimal integer"));
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && *value <= maximum)
        .ok_or_else(|| format!("{field} must be in 1..={maximum}"))
}

fn parse_head(text: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let (algorithm, digest) = text
        .strip_prefix("alg:")
        .and_then(|value| value.split_once(':'))
        .ok_or("expected an algorithm-qualified snapshot_token")?;
    if algorithm.starts_with('0') {
        return Err("snapshot algorithm must be canonical positive decimal".into());
    }
    let code = positive(algorithm, u64::from(u16::MAX), "snapshot algorithm")?;
    let algorithm =
        DigestAlgorithmId::try_new(u16::try_from(code).map_err(|_| "snapshot algorithm overflow")?)
            .map_err(|_| "invalid snapshot algorithm")?;
    if digest.is_empty()
        || digest.len() > 128
        || digest.len() % 2 != 0
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("snapshot digest must be bounded lowercase hex".into());
    }
    let nibble = |byte: u8| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    let bytes = digest
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| 16 * nibble(pair[0]) + nibble(pair[1]))
        .collect::<Vec<_>>();
    let digest = DigestBytes::try_new(&bytes).map_err(|_| "invalid snapshot digest width")?;
    Ok(RepositoryAuthorityHeadId::from_digest(
        algorithm,
        CANONICAL_CODEC_VERSION,
        digest,
    ))
}

fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    let digest = id
        .digest()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("alg:{}:{digest}", id.algorithm().code_point())
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4
        || args.len() > 20
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
        || args[0].is_empty()
    {
        return Err(USAGE.into());
    }
    let mut trusted = None;
    let mut format = None;
    let mut generation = None;
    let mut head = None;
    let mut objects = None;
    let mut bytes = None;
    let mut object_bytes = None;
    let mut seconds = None;
    let mut objects_only = None;
    let mut edges = None;
    let mut cursor = 3;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        if flag == "--trusted-local" {
            set_once(&mut trusted, true, flag)?;
            continue;
        }
        if flag == "--objects-only" {
            set_once(&mut objects_only, true, flag)?;
            continue;
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag.as_str() {
            "--object-format" => {
                let value = match value.as_str() {
                    "sha1" => GitHashAlgorithm::Sha1,
                    "sha256" => GitHashAlgorithm::Sha256,
                    _ => return Err("object format must be sha1 or sha256".into()),
                };
                set_once(&mut format, value, flag)?;
            }
            "--expected-generation" => {
                set_once(&mut generation, positive(value, u64::MAX, flag)?, flag)?;
            }
            "--expected-head" => set_once(&mut head, parse_head(value)?, flag)?,
            "--max-objects" => set_once(
                &mut objects,
                positive(value, MAX_OBJECTS as u64, flag)? as usize,
                flag,
            )?,
            "--max-bytes" => set_once(&mut bytes, positive(value, MAX_BYTES, flag)?, flag)?,
            "--max-object-bytes" => {
                set_once(&mut object_bytes, positive(value, 256 * MIB, flag)?, flag)?;
            }
            "--timeout-secs" => set_once(&mut seconds, positive(value, 3600, flag)?, flag)?,
            "--max-edges" => set_once(
                &mut edges,
                positive(value, MAX_EDGES as u64, flag)? as usize,
                flag,
            )?,
            _ => return Err(format!("unsupported fsck option: {flag}")),
        }
    }
    if trusted != Some(true) {
        return Err(
            "fsck requires --trusted-local and authorization to inspect the entire repository"
                .into(),
        );
    }
    if objects_only.is_some() && edges.is_some() {
        return Err("--max-edges cannot be combined with --objects-only".into());
    }
    let defaults = Limits::default();
    Ok(Options {
        storage: PathBuf::from(&args[0]),
        tenant: TenantId::from_hex(&args[1]).map_err(|error| error.to_string())?,
        repository: RepositoryId::from_hex(&args[2]).map_err(|error| error.to_string())?,
        format: format.unwrap_or(GitHashAlgorithm::Sha1),
        expected_generation: generation,
        expected_head: head,
        objects_only: objects_only.unwrap_or(false),
        max_edges: edges.unwrap_or(GraphLimits::default().max_edges),
        limits: Limits {
            objects: objects.unwrap_or(defaults.objects),
            bytes: bytes.unwrap_or(defaults.bytes),
            object_bytes: object_bytes.unwrap_or(defaults.object_bytes),
            seconds: seconds.unwrap_or(defaults.seconds),
        },
    })
}

fn live(started: Instant, seconds: u64) -> Result<(), Refusal> {
    if started.elapsed() >= Duration::from_secs(seconds) {
        Err(Refusal::Deadline)
    } else {
        Ok(())
    }
}

fn check_fences(
    options: &Options,
    head: RepositoryAuthorityHeadId,
    generation: u64,
) -> Result<(), Refusal> {
    if let Some(expected) = options.expected_generation
        && expected != generation
    {
        return Err(Refusal::Generation {
            expected,
            observed: generation,
        });
    }
    if options
        .expected_head
        .is_some_and(|expected| expected != head)
    {
        return Err(Refusal::ExpectedHead);
    }
    Ok(())
}

/// The reader is a verified-whole-read boundary, not a source of unchecked
/// payloads. Only the node fabric implements that boundary in the command.
fn check_objects(
    objects: &BTreeSet<GitOid>,
    format: GitHashAlgorithm,
    limits: Limits,
    mut read: impl FnMut(GitOid) -> Result<u64, String>,
    mut checkpoint: impl FnMut() -> Result<(), Refusal>,
) -> Result<u64, Refusal> {
    if objects.len() > limits.objects {
        return Err(Refusal::Limit("max-objects"));
    }
    let mut bytes = 0_u64;
    for &oid in objects {
        checkpoint()?;
        if oid.algorithm() != format || oid.is_zero() {
            return Err(Refusal::ObjectFormat(oid));
        }
        let read = read(oid);
        checkpoint()?;
        let size = read.map_err(|detail| Refusal::Object { oid, detail })?;
        if size > limits.object_bytes {
            return Err(Refusal::Limit("max-object-bytes"));
        }
        bytes = bytes
            .checked_add(size)
            .filter(|total| *total <= limits.bytes)
            .ok_or(Refusal::Limit("max-bytes"))?;
    }
    checkpoint()?;
    Ok(bytes)
}

fn graph_error(error: GraphAuditRefusal) -> Refusal {
    match error {
        GraphAuditRefusal::Graph(GraphRefusal::Limit("objects")) => Refusal::Limit("max-objects"),
        GraphAuditRefusal::Graph(GraphRefusal::Limit("object bytes")) => {
            Refusal::Limit("max-object-bytes")
        }
        GraphAuditRefusal::Graph(GraphRefusal::Limit("payload bytes")) => {
            Refusal::Limit("max-bytes")
        }
        GraphAuditRefusal::Graph(GraphRefusal::Limit("edges")) => Refusal::Limit("max-edges"),
        GraphAuditRefusal::Graph(error) => Refusal::Graph(error),
        GraphAuditRefusal::ExpectedHead => Refusal::ExpectedHead,
        GraphAuditRefusal::ExpectedGeneration { expected, observed } => {
            Refusal::Generation { expected, observed }
        }
        GraphAuditRefusal::SnapshotChanged => Refusal::SnapshotChanged,
        GraphAuditRefusal::Deadline => Refusal::Deadline,
        other => Refusal::NodeGraph(other.to_string()),
    }
}

fn inspect_graph(node: &OneNode, options: &Options) -> Result<Report, Refusal> {
    let query = GraphAuditQuery {
        expected_head: options.expected_head,
        expected_generation: options
            .expected_generation
            .map(HeadGeneration::try_new)
            .transpose()
            .map_err(|_| Refusal::Limit("expected generation"))?,
        limits: GraphLimits {
            max_objects: options.limits.objects,
            max_references: MAX_REFERENCES,
            max_edges: options.max_edges,
            max_object_bytes: usize::try_from(options.limits.object_bytes)
                .map_err(|_| Refusal::Limit("max-object-bytes"))?,
            max_payload_bytes: options.limits.bytes,
        },
        timeout: Duration::from_secs(options.limits.seconds),
    };
    let request = node.request_context();
    let report = node
        .runtime()
        .block_on(node.audit_selected_object_graph_local_in(&request, query))
        .map_err(graph_error)?;
    let graph = *report.graph();
    Ok(Report {
        head: report.head(),
        generation: report.generation().get(),
        closure_root: report.closure_root().to_string(),
        references: graph.references,
        objects: graph.objects,
        payload_bytes: graph.payload_bytes,
        graph: Some(graph),
    })
}

fn inspect(node: &OneNode, options: &Options) -> Result<Report, Refusal> {
    if !options.objects_only {
        return inspect_graph(node, options);
    }
    let started = Instant::now();
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .map_err(|error| Refusal::Source(error.to_string()))?;
    let generation = selected.authenticated().receipt().generation().get();
    let head = selected.basis().id();
    check_fences(options, head, generation)?;
    let objects = selected.selected_closure().closure().objects();
    for oid in selected.snapshot().refs.values() {
        live(started, options.limits.seconds)?;
        if !objects.contains(oid) {
            return Err(Refusal::ReferenceOutsideClosure(*oid));
        }
    }
    let payload_bytes = check_objects(
        objects,
        options.format,
        options.limits,
        |oid| {
            node.read_git_object(oid)
                .map(|object| object.payload().len() as u64)
                .map_err(|error| error.to_string())
        },
        || live(started, options.limits.seconds),
    )?;
    let current = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .map_err(|error| Refusal::Source(error.to_string()))?;
    live(started, options.limits.seconds)?;
    if current.basis() != selected.basis()
        || current.selected_closure() != selected.selected_closure()
    {
        return Err(Refusal::SnapshotChanged);
    }
    Ok(Report {
        head,
        generation,
        closure_root: selected.selected_closure().root().to_string(),
        references: selected.snapshot().refs.len(),
        objects: objects.len(),
        payload_bytes,
        graph: None,
    })
}

pub fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        emit(&mut std::io::stdout().lock(), USAGE)?;
        return Ok(0);
    }
    let options = parse(args)?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format)
            .with_max_object_bytes(options.limits.object_bytes),
    )
    .map_err(|error| format!("cannot open fsck node: {error}"))?;
    let result = node
        .bring_into_service(HeadGeneration::FIRST)
        .map_err(|error| Refusal::Source(error.to_string()))
        .and_then(|()| inspect(&node, &options));
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    finish(&mut std::io::stdout().lock(), &options, result, cleanup)
}

fn emit(output: &mut impl Write, text: &str) -> Result<(), String> {
    writeln!(output, "{text}")
        .and_then(|()| output.flush())
        .map_err(|error| format!("fsck receipt output incomplete: {error}"))
}

fn graph_receipt(options: &Options, report: &Report) -> Result<String, String> {
    match report.graph {
        None if options.objects_only => Ok(concat!(
            "\"object_graph_verified\":false,\"graph_profile\":null,",
            "\"local_edges_verified\":null,\"external_gitlinks\":null,\"graph_acyclic\":null"
        )
        .into()),
        Some(graph)
            if !options.objects_only
                && graph.objects == report.objects
                && graph.references == report.references
                && graph.payload_bytes == report.payload_bytes =>
        {
            Ok(format!(
                concat!(
                    "\"object_graph_verified\":true,\"graph_profile\":\"native-closure-v1\",",
                    "\"local_edges_verified\":{},\"external_gitlinks\":{},\"graph_acyclic\":true"
                ),
                graph.local_edges, graph.external_gitlinks
            ))
        }
        _ => Err(
            "no complete integrity report returned; graph profile or accounting mismatch".into(),
        ),
    }
}

fn finish(
    output: &mut impl Write,
    options: &Options,
    result: Result<Report, Refusal>,
    cleanup: Option<String>,
) -> Result<u8, String> {
    match (result, cleanup) {
        (Ok(report), None) => {
            let graph = graph_receipt(options, &report)?;
            emit(
                output,
                &format!(
                    concat!(
                        "{{\"type\":\"repository_fsck\",\"schema_version\":1,",
                        "\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},",
                        "\"authority_generation\":{},\"references_checked\":{},\"objects_verified\":{},",
                        "\"payload_bytes_verified\":{},\"authority_head\":{},\"snapshot_token\":{},",
                        "\"selected_closure_root\":{},\"scope\":\"authority_selected_objects\",",
                        "\"complete\":true,{},\"head_revalidated\":true,",
                        "\"physical_orphans_scanned\":false,\"repository_changed\":false,\"node_closed\":true}}"
                    ),
                    quote(&options.tenant.to_string()),
                    quote(&options.repository.to_string()),
                    quote(options.format.as_str()),
                    report.generation,
                    report.references,
                    report.objects,
                    report.payload_bytes,
                    quote(&report.head.to_string()),
                    quote(&head_token(report.head)),
                    quote(&report.closure_root),
                    graph
                ),
            )?;
            Ok(0)
        }
        (result, cleanup) => {
            let check = result
                .err()
                .map_or_else(String::new, |error| format!("; audit: {error}"));
            let close = cleanup.map_or_else(String::new, |error| format!("; shutdown: {error}"));
            Err(format!(
                "no complete integrity report returned{check}{close}"
            ))
        }
    }
}

#[cfg(test)]
mod tests;
