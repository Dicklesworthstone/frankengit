//! Native authority-bound task reads through the concrete Beads adapter.
//! Local operator sponsorship does not grant autonomous task or repository
//! writes. Task text is returned explicitly as untrusted data.

mod options;
pub mod process;

use fgit_agent::beads::{
    BEADS_PROFILE, BeadsReadSource, BeadsRefusal, BeadsTaskRecord, BeadsTransport,
};
use fgit_agent::{AuthorityReadReceipt, ClassSet, IntentRun, LogicalTime, OperationClass, RunId};
use fgit_crypto::sha256_digest;
use fgit_node::{
    GitDaemonSessionTimeout, NodeConfig, NodeRequestContext, OneNode, TerminationSignals,
};
use fgit_resource::{Grade, ResourceVector};
use fgit_schema::json::{self, Value, number, object, text};
use std::io::Write;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const USAGE: &str =
    "usage: fg agent task show <storage-root> <tenant-id> <repository-id> <exact-beads-id>
  --trusted-local --sponsor <principal-id>
  --beads-root <absolute-beads-directory> --br <absolute-br-0.7.6-executable>
  [--object-format sha1|sha256] [--expires-after-secs <1..300>]
  [--max-output-bytes <1..8388608>]

Authenticates the current repository authority head, opens a bounded read-only
IntentRun, and reads exactly one task from an explicitly selected Beads database.
Returns the exact source commitment, native unclaimed-task snapshot when
available, retained claim history, and untrusted Beads document as JSON.
The operator authorizes both local reads and execution of the trusted br binary.
No task is claimed, released, imported, exported, or activated by this command.
Global --timeout-secs may shorten the shared 30-second default lifetime.
Exit 0: complete requested task read; exit 2: refusal, no task document on stdout.";

struct Clock {
    origin: Instant,
    logical_origin: u64,
    deadline: Instant,
    expiry: LogicalTime,
}

impl Clock {
    fn start(lifetime: Duration) -> Result<Self, String> {
        let origin = Instant::now();
        let logical_origin = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
            .ok_or("agent task clock is outside its supported epoch")?;
        let nanos = u64::try_from(lifetime.as_nanos()).map_err(|_| "task lifetime overflow")?;
        let expiry = logical_origin
            .checked_add(nanos)
            .ok_or("task expiry overflow")?;
        let deadline = origin
            .checked_add(lifetime)
            .ok_or("task deadline overflow")?;
        Ok(Self {
            origin,
            logical_origin,
            deadline,
            expiry: LogicalTime::new(expiry),
        })
    }

    fn now(&self) -> LogicalTime {
        LogicalTime::new(
            self.logical_origin.saturating_add(
                u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX),
            ),
        )
    }

    fn check(&self, request: &NodeRequestContext) -> Result<(), String> {
        if !request.is_live() || Instant::now() >= self.deadline || self.now() >= self.expiry {
            Err("agent task request cancelled or its time/resource budget expired".into())
        } else {
            Ok(())
        }
    }
}

/// The explicit `fg agent task show` host. Output is buffered until signal
/// observation, the external child, and the native node have all settled.
pub fn run(arguments: &[String]) -> Result<u8, String> {
    run_with(arguments, &mut std::io::stdout().lock())
}

fn run_with(arguments: &[String], output: &mut impl Write) -> Result<u8, String> {
    if arguments == ["--help"] || arguments == ["show", "--help"] {
        writeln!(output, "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let Some((operation, args)) = arguments.split_first() else {
        return Err(USAGE.into());
    };
    if operation != "show" {
        return Err(USAGE.into());
    }
    let options = options::parse(args)?;
    let lifetime = options.timeout.min(crate::command_timeout_duration());
    let clock = Clock::start(lifetime)?;
    let signals = TerminationSignals::install().map_err(|error| error.to_string())?;
    let node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| error.to_string())?;
    let request = node.command_request_context(Some(
        GitDaemonSessionTimeout::try_new(lifetime).map_err(|error| error.to_string())?,
    ));
    let operation = signals
        .run_request(node.runtime(), &request, |request| {
            read_task(&node, request, &clock, &options)
        })
        .map_err(|error| error.to_string())
        .and_then(|(operation, cleanup)| match (operation, cleanup) {
            (Ok(document), Ok(())) => Ok(document),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => {
                Err(format!("agent task signal monitor cleanup failed: {error}"))
            }
            (Err(error), Err(cleanup)) => {
                Err(format!("{error}; monitor cleanup failed: {cleanup}"))
            }
        });
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let document = match (operation, cleanup) {
        (Ok(document), None) => document,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("agent task node shutdown failed: {error}")),
        (Err(error), Some(cleanup)) => {
            return Err(format!("{error}; node shutdown failed: {cleanup}"));
        }
    };
    output
        .write_all(document.as_bytes())
        .map_err(|error| error.to_string())?;
    if document.len() < options.maximum {
        output.write_all(b"\n").map_err(|error| error.to_string())?;
    }
    output.flush().map_err(|error| error.to_string())?;
    Ok(0)
}

fn read_task(
    node: &OneNode,
    request: &NodeRequestContext,
    clock: &Clock,
    options: &options::Options,
) -> Result<String, String> {
    clock.check(request)?;
    let authenticated = node
        .runtime()
        .block_on(node.authenticate_authority_head_in(request))
        .map_err(|error| error.to_string())?;
    let authority = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        clock.now(),
        sha256_digest(b"frankengit/native-agent-beads-read/v1"),
    )
    .map_err(|error| error.to_string())?;
    clock.check(request)?;
    let live = || request.is_live();
    let now = || clock.now();
    let mut transport = process::BeadsProcess::open(
        &options.program,
        &options.beads_root,
        clock.deadline,
        &live,
        &now,
    )
    .map_err(|error| format!("Beads process profile refused: {error:?}"))?;
    let root = transport
        .root()
        .to_str()
        .ok_or("Beads root is not UTF-8")?
        .to_owned();
    let scope = ClassSet::from_classes(&[
        OperationClass::ReadCanonicalObject,
        OperationClass::ReadDerivedGeneration,
    ]);
    let budget =
        ResourceVector::single(Grade::Bytes, fgit_agent::beads::MAX_BEADS_JSON_BYTES as u64)
            .with(Grade::EgressBytes, options.maximum as u64);
    let seed = IntentRun::new_authenticated(
        RunId::new(0),
        authority.clone(),
        scope,
        budget,
        clock.expiry,
    )
    .map_err(|error| error.to_string())?;
    let mut identity = Vec::from(b"frankengit/agent-beads-read-run/v1\0".as_slice());
    identity.extend_from_slice(
        seed.commitment()
            .map_err(|error| error.to_string())?
            .as_bytes(),
    );
    identity.extend_from_slice(options.sponsor.as_bytes());
    for value in [root.as_bytes(), options.task.as_bytes()] {
        identity.extend_from_slice(&(value.len() as u64).to_be_bytes());
        identity.extend_from_slice(value);
    }
    let digest = sha256_digest(&identity);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    let run = IntentRun::new_authenticated(
        RunId::new(u128::from_be_bytes(id)),
        authority.clone(),
        scope,
        budget,
        clock.expiry,
    )
    .map_err(|error| error.to_string())?;
    let bytes = transport
        .show(&options.task, BeadsReadSource::Database)
        .map_err(|error| format!("Beads task read refused: {error:?}"))?;
    clock.check(request)?;
    let record = BeadsTaskRecord::parse_show_json(&options.task, &bytes)
        .map_err(|error| error.to_string())?;
    let observed = clock.now();
    let (snapshot, unavailable) = match record.unclaimed_snapshot(&authority, observed) {
        Ok(snapshot) => (
            object([
                ("snapshot_id", text(hex(snapshot.snapshot_id().as_bytes()))),
                ("task_id", text(snapshot.task_id().to_string())),
                ("generation", text(hex(snapshot.generation()))),
                (
                    "authority_read_receipt_id",
                    text(hex(snapshot.authority_read_receipt_id().as_bytes())),
                ),
            ]),
            Value::Null,
        ),
        Err(error @ (BeadsRefusal::NotOpenUnassigned | BeadsRefusal::ExistingHistory)) => {
            (Value::Null, text(error.to_string()))
        }
        Err(error) => return Err(error.to_string()),
    };
    let source = record
        .document_json(fgit_agent::beads::MAX_BEADS_JSON_BYTES)
        .map_err(|error| error.to_string())?;
    let source = json::parse_with(
        source.as_bytes(),
        json::Limits {
            input: fgit_agent::beads::MAX_BEADS_JSON_BYTES,
            depth: 16,
            nodes: 65_536,
            items: 4096,
            string: fgit_agent::beads::MAX_BEADS_JSON_BYTES,
        },
    )
    .map_err(str::to_owned)?;
    let result = object([
        ("type", text("agent_task")),
        ("schema_version", number(1)),
        ("profile", text(BEADS_PROFILE)),
        ("complete", Value::Bool(true)),
        ("read_only", Value::Bool(true)),
        ("publication_authorized", Value::Bool(false)),
        ("task_claim_activation_authorized", Value::Bool(false)),
        (
            "sponsor",
            object([
                ("principal_id", text(options.sponsor.to_string())),
                ("authentication", text("operator-asserted")),
                ("authorization_host", text("trusted-local-cli")),
            ]),
        ),
        (
            "run",
            object([
                ("id", text(run.run_id().to_string())),
                (
                    "commitment",
                    text(hex(run
                        .commitment()
                        .map_err(|error| error.to_string())?
                        .as_bytes())),
                ),
                ("expires_at_logical_time", number(clock.expiry.value())),
                ("persistence", text("invocation-only")),
            ]),
        ),
        (
            "authority_receipt",
            object([
                (
                    "receipt_id",
                    text(hex(authority
                        .receipt_id()
                        .map_err(|error| error.to_string())?
                        .as_bytes())),
                ),
                ("head_id", text(authority.authority_head_id().to_string())),
                (
                    "generation",
                    number(authority.authority_head_generation().get()),
                ),
                ("repository_id", text(authority.repository_id().to_string())),
            ]),
        ),
        (
            "observation",
            object([
                ("beads_root", text(root)),
                ("beads_id", text(record.id())),
                ("source", text("database")),
                ("raw_response_sha256", text(hex(&sha256_digest(&bytes)))),
                ("observed_at_logical_time", number(observed.value())),
            ]),
        ),
        ("unclaimed_snapshot", snapshot),
        ("unclaimed_snapshot_unavailable", unavailable),
        ("untrusted_task_document", source),
    ])
    .encode(options.maximum)
    .map_err(str::to_owned)?;
    clock.check(request)?;
    Ok(result)
}

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(ALPHABET[(byte >> 4) as usize] as char);
        result.push(ALPHABET[(byte & 15) as usize] as char);
    }
    result
}

pub fn error_json(error: &str) -> String {
    object([
        ("type", text("agent_task_error")),
        ("schema_version", number(1)),
        ("complete", Value::Bool(false)),
        ("error", text(error)),
    ])
    .encode(64 * 1024)
    .unwrap_or_else(|_| "{\"type\":\"agent_task_error\",\"error\":\"response_limit\"}".into())
}
