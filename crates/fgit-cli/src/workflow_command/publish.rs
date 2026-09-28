//! Publish one exact saved job observation through canonical node admission.
//! Argument parsing is complete before journal or repository I/O. Saved custody
//! supplies evidence bytes; the local operator authenticates the publisher.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Component, PathBuf};

use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{Digest, DigestAlgorithm, DigestBytes};
use fgit_forge::event::workflow_check::{NativeWorkflowCheck, WorkflowCheckConclusion};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, PrincipalId, RefName, RepositoryId, RepositoryIncarnationId,
    TenantId, TxId,
};

use crate::publication_support::{describe, quote, write_terminal_receipt};

// This CLI selects one fact within the existing 128-fact journal batch profile.
const MAX_FACT_INDEX: u64 = 127;
const USAGE: &str = "\
usage: fg workflow publish <storage-root> <tenant-id> <repository-id> <ref>
  --trusted-local --run-directory <absolute-private-run-directory>
  --journal-id <64-lowercase-hex-original-attempt-marker-sha256>
  --batch <64-lowercase-hex> --fact-index <0..127>
  --principal-id <32-lowercase-hex> --idempotency-key <nonempty-key>
  [--minimum-pin <bytes>:<tail-sha256>] [--expected-incarnation <id>]
  [--object-format sha1|sha256] [--ref-hex] [--timeout-ms <1..60000>]

Select a completed job from `fg workflow recover`. The original private marker,
journal batch and exact referenced evidence are verified before publication.
Retain the original journal ID and any minimum pin independently of storage.
The selected branch must currently name the job's actual executed commit.

This records an authenticated local operator's observation and its forge delivery
obligation in one canonical decision. Local success remains action_required;
these observations cannot satisfy required successful checks. The command does
not run scripts, change refs, acknowledge the journal, or remove saved history.
It needs no final report and can publish a completed job from an interrupted run.

Linux only; the run directory must be stable, private (0700) and operator-owned.
The cooperative pre-admission read timeout defaults to 30000 ms. Canonical
admission and shutdown retain the node's own finite runtime budgets.

Keep the original principal, key, branch, journal ID, batch and fact on retry.
A retry returns its original decision even after source movement. Receipts name
historical outcomes; they do not assert that the source is still current.
Stdout contains one JSON receipt without raw evidence, after node shutdown.
Exit 0: committed observation; 3: canonical refusal; 2: input, unavailable/unknown
outcome, cleanup or output error. A nonzero exit is not proof of non-commit.";

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    reference: RefName,
    format: GitHashAlgorithm,
    directory: PathBuf,
    journal: Digest,
    batch: Digest,
    fact_index: usize,
    minimum: Option<(u64, Digest)>,
    principal: PrincipalId,
    key: IdempotencyKey,
    incarnation: Option<RepositoryIncarnationId>,
    timeout_ms: u64,
}

pub(super) fn run(arguments: &[String], output: &mut impl Write) -> Result<u8, String> {
    if arguments == ["publish", "--help"] {
        writeln!(output, "{USAGE}")
            .and_then(|()| output.flush())
            .map_err(|error| format!("workflow publication help output failed: {error}"))?;
        return Ok(0);
    }
    let options = parse(arguments)?;
    #[cfg(target_os = "linux")]
    {
        execute(options, output)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err("saved workflow publication requires Linux; no fallback is selected".to_owned())
    }
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 5
        || arguments.len() > 40
        || arguments.first().map(String::as_str) != Some("publish")
    {
        return Err(USAGE.to_owned());
    }
    if arguments
        .iter()
        .any(|arg| arg.len() > 4096 || arg.contains('\0'))
        || arguments.iter().map(String::len).sum::<usize>() > 32 * 1024
    {
        return Err("workflow publication arguments exceed the bounded local profile".to_owned());
    }
    if arguments[1].is_empty() {
        return Err("storage root must contain 1..4096 bytes".to_owned());
    }
    fixed_hex(&arguments[2], 16)?;
    fixed_hex(&arguments[3], 16)?;
    let tenant = TenantId::from_hex(&arguments[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[3]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new();
    let mut cursor = 5;
    while cursor < arguments.len() {
        let flag = arguments[cursor].as_str();
        cursor += 1;
        if matches!(flag, "--trusted-local" | "--ref-hex") {
            if flags.insert(flag, "").is_some() {
                return Err(format!("duplicate {flag}"));
            }
            continue;
        }
        if !matches!(
            flag,
            "--run-directory"
                | "--journal-id"
                | "--batch"
                | "--fact-index"
                | "--principal-id"
                | "--idempotency-key"
                | "--minimum-pin"
                | "--expected-incarnation"
                | "--object-format"
                | "--timeout-ms"
        ) {
            return Err(format!("unknown workflow publication option {flag:?}"));
        }
        let value = arguments
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        if flags.insert(flag, value.as_str()).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    if !flags.contains_key("--trusted-local") {
        return Err(
            "--trusted-local is mandatory: an authorized local operator reports this observation"
                .to_owned(),
        );
    }
    let required = |flag: &str| {
        flags
            .get(flag)
            .copied()
            .ok_or_else(|| format!("missing {flag}"))
    };
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".to_owned()),
    };
    let reference = if flags.contains_key("--ref-hex") {
        super::unhex(&arguments[4], 4096)?
    } else {
        arguments[4].as_bytes().to_vec()
    };
    let reference = RefName::try_new(&reference).map_err(|_| "invalid reference bytes")?;
    if !reference.as_bytes().starts_with(b"refs/heads/") {
        return Err("workflow publication requires an exact branch under refs/heads/".to_owned());
    }
    let directory = absolute_directory(required("--run-directory")?)?;
    let journal = digest(required("--journal-id")?)?;
    let batch = digest(required("--batch")?)?;
    let fact_index = decimal(required("--fact-index")?, 0, MAX_FACT_INDEX)? as usize;
    let principal_text = required("--principal-id")?;
    fixed_hex(principal_text, 16)?;
    let principal = PrincipalId::from_hex(principal_text).map_err(|_| "invalid principal ID")?;
    let key = required("--idempotency-key")?;
    if key.is_empty() {
        return Err("idempotency key must not be empty".to_owned());
    }
    let key = IdempotencyKey::new(key.as_bytes().to_vec())
        .map_err(|_| "idempotency key exceeds its byte bound")?;
    let minimum = flags
        .get("--minimum-pin")
        .map(|text| pin(text))
        .transpose()?;
    let incarnation = flags
        .get("--expected-incarnation")
        .map(|text| {
            fixed_hex(text, 16)?;
            RepositoryIncarnationId::from_hex(text).map_err(|_| "invalid incarnation ID".to_owned())
        })
        .transpose()?;
    let timeout_ms = flags
        .get("--timeout-ms")
        .map_or(Ok(30_000), |text| decimal(text, 1, 60_000))?;
    Ok(Options {
        storage: arguments[1].clone().into(),
        tenant,
        repository,
        reference,
        format,
        directory,
        journal,
        batch,
        fact_index,
        minimum,
        principal,
        key,
        incarnation,
        timeout_ms,
    })
}

fn fixed_hex(value: &str, length: usize) -> Result<Vec<u8>, String> {
    let bytes = super::unhex(value, length)?;
    if bytes.len() != length {
        return Err(format!(
            "expected {} lowercase hexadecimal digits",
            length * 2
        ));
    }
    Ok(bytes)
}

fn digest(value: &str) -> Result<Digest, String> {
    let bytes = fixed_hex(value, 32)?;
    Ok(Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&bytes).map_err(|_| "invalid SHA-256 digest")?,
    ))
}

fn pin(value: &str) -> Result<(u64, Digest), String> {
    let (length, tail) = value
        .split_once(':')
        .ok_or("minimum pin must be <byte-length>:<sha256>")?;
    Ok((decimal(length, 72, 4 * 1024 * 1024 * 1024)?, digest(tail)?))
}

fn decimal(value: &str, minimum: u64, maximum: u64) -> Result<u64, String> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("expected canonical unsigned decimal".to_owned());
    }
    let number = value
        .parse::<u64>()
        .map_err(|_| "unsigned decimal overflow")?;
    if !(minimum..=maximum).contains(&number) {
        return Err("value is outside the bounded publication profile".to_owned());
    }
    Ok(number)
}

fn absolute_directory(value: &str) -> Result<PathBuf, String> {
    let directory = PathBuf::from(value);
    if value.is_empty()
        || value.ends_with('/')
        || !directory.is_absolute()
        || directory.file_name().is_none()
        || directory
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(
            "run directory must be absolute, without parent traversal or a trailing slash"
                .to_owned(),
        );
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn execute(options: Options, output: &mut impl Write) -> Result<u8, String> {
    use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};

    let started = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(options.timeout_ms);
    let live = || started.elapsed() < timeout;
    // Complete bounded, non-consuming custody intake before opening authority.
    // The helper binds the original marker, retained batch, fact and exact body.
    let record = OneNode::trusted_workflow_check_record(
        &options.directory,
        (options.tenant, options.repository, options.journal),
        options.minimum,
        options.batch,
        options.fact_index,
        options.reference.clone(),
        &live,
    )
    .map_err(|error| operation_error(&error.to_string(), false, None))?;
    if record.source_commit.algorithm() != options.format {
        return Err(operation_error(
            "saved source commit and repository object format disagree",
            false,
            None,
        ));
    }
    let observation = NativeWorkflowCheck {
        actor: options.principal,
        record,
    };
    let session = LoopbackReceiveSession::authenticated(options.principal, options.key.clone());
    if !live() {
        return Err(operation_error("pre-admission read timeout", false, None));
    }
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| {
        operation_error(&format!("cannot open workflow node: {error}"), false, None)
    })?;
    let incarnation = node.repository_incarnation_id();
    let mut entered_admission = false;
    let operation = (|| {
        if options
            .incarnation
            .is_some_and(|expected| expected != incarnation)
        {
            return Err("repository incarnation changed".to_owned());
        }
        if !live() {
            return Err("pre-admission read timeout".to_owned());
        }
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|error| format!("cannot authenticate repository authority: {error}"))?;
        if let Err(error) = node.bring_into_service(head.receipt().generation()) {
            // The native publisher recovers exact terminal outcomes before its
            // mandatory intake gates. A new-intake failure must not mask one.
            eprintln!(
                "workflow publication intake unavailable ({error}); only existing outcome recovery may succeed"
            );
        }
        if !live() {
            return Err("pre-admission read timeout".to_owned());
        }
        let request = node.request_context();
        entered_admission = true;
        node.runtime()
            .block_on(node.admit_trusted_workflow_check_in(
                &request,
                &session,
                &observation.record,
                Default::default(),
            ))
            .map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match operation {
        Ok((tx, terminal)) => finish(
            output,
            &options,
            incarnation,
            &observation,
            tx,
            &terminal,
            cleanup.as_deref(),
        ),
        Err(error) => Err(operation_error(
            &error,
            entered_admission,
            cleanup.as_deref(),
        )),
    }
}

fn operation_error(error: &str, entered_admission: bool, cleanup: Option<&str>) -> String {
    let cleanup = cleanup.map_or_else(String::new, |error| {
        format!("; node shutdown also failed: {error}")
    });
    if entered_admission {
        format!(
            "workflow publication returned no terminal outcome: {error}{cleanup}; this is not evidence of non-commit. Reconcile by retrying the identical principal, idempotency key, branch bytes, journal ID, batch and fact; do not rerun the workflow or replace the key"
        )
    } else {
        format!(
            "workflow publication failed before admission: {error}{cleanup}; this invocation submitted no observation, but does not determine any earlier invocation's outcome. Preserve the original saved attempt; do not rerun the workflow"
        )
    }
}

fn finish(
    output: &mut impl Write,
    options: &Options,
    incarnation: RepositoryIncarnationId,
    observation: &NativeWorkflowCheck,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    let receipt = receipt(options, incarnation, observation, tx, terminal, cleanup);
    if let Err(error) = write_terminal_receipt(output, &receipt, tx, terminal) {
        return Err(cleanup.map_or(error.clone(), |cleanup| {
            format!("{error}; node shutdown also failed: {cleanup}")
        }));
    }
    if let Some(error) = cleanup {
        return Err(format!(
            "{}; node shutdown failed: {error}",
            describe(tx, terminal)
        ));
    }
    Ok(match terminal.outcome {
        DecisionOutcome::Committed { .. } => 0,
        DecisionOutcome::Refused { .. } => 3,
    })
}

fn receipt(
    options: &Options,
    incarnation: RepositoryIncarnationId,
    observation: &NativeWorkflowCheck,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> String {
    let (outcome, rcr, refusal, code, committed) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            quote(&repository_commit_id.to_string()),
            "null".to_owned(),
            "null".to_owned(),
            true,
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            "null".to_owned(),
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
            false,
        ),
    };
    let record = &observation.record;
    let conclusion = match record.conclusion {
        WorkflowCheckConclusion::ActionRequired => "action_required",
        WorkflowCheckConclusion::Failure => "failure",
        WorkflowCheckConclusion::Cancelled => "cancelled",
        WorkflowCheckConclusion::TimedOut => "timed_out",
    };
    format!(
        concat!(
            "{{\"type\":\"workflow_check_publication\",\"schema_version\":1,\"trusted_local\":true,",
            "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"principal_id\":{},",
            "\"object_format\":{},\"check_id\":{},\"job\":{},\"source_ref_hex\":{},\"source_commit\":{},",
            "\"run_id\":{},\"attempt_id\":{},\"graph_root\":{},\"conclusion\":{},",
            "\"journal_id\":{},\"batch_sha256\":{},\"fact_index\":{},",
            "\"evidence_sha256\":{},\"evidence_bytes\":{},\"evidence_payload_included\":false,",
            "\"tx_id\":{},\"outcome\":{},\"decision_sequence\":{},\"command_committed\":{},",
            "\"repository_commit_id\":{},\"refusal_record_id\":{},\"refusal_code\":{},",
            "\"scope\":\"trusted_workflow_observations\",\"merge_permission\":null,",
            "\"authoritative_check\":false,\"execution_retried\":false,\"journal_acknowledged\":false,",
            "\"refs_changed\":false,\"historical_outcome\":true,\"current_refs_asserted\":false,",
            "\"delivery_acknowledged\":null,\"node_closed\":{},\"cleanup_error\":{}}}"
        ),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(&incarnation.to_string()),
        quote(&options.principal.to_string()),
        quote(options.format.as_str()),
        quote(&observation.id().to_string()),
        quote(&record.job),
        quote(&hex(record.source_ref.as_bytes())),
        quote(&record.source_commit.to_string()),
        quote(&hex(&record.run_id)),
        quote(&hex(&record.attempt_id)),
        quote(&hex(&record.graph_root)),
        quote(conclusion),
        quote(&hex(options.journal.bytes().as_bytes())),
        quote(&hex(options.batch.bytes().as_bytes())),
        options.fact_index,
        quote(&hex(&fgit_crypto::sha256_digest(&record.evidence))),
        record.evidence.len(),
        quote(&tx.to_string()),
        quote(outcome),
        quote(&terminal.decision_sequence.get().to_string()),
        committed,
        rcr,
        refusal,
        code,
        cleanup.is_none(),
        cleanup.map_or_else(|| "null".to_owned(), quote),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "publish/tests.rs"]
mod tests;
