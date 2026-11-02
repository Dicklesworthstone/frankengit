//! Exact unpublished PR checks reuse retained job custody and native metadata
//! admission. An original terminal is recovered before any bundle-file access.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use fgit_authority::TerminalOutcome;
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::event::workflow_check::candidate::NativeCandidateWorkflowCheck;
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_types::{DecisionOutcome, GitOid, PolicyEpoch, RefName, RepositoryIncarnationId, TxId};

use super::publish;
use crate::publication_support::{describe, quote, read_bundle, write_terminal_receipt};

const MAX_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
const USAGE: &str =
    "usage: fg workflow publish-candidate <storage-root> <tenant-id> <repository-id> <target-ref>
  --trusted-local --run-directory <absolute-private-run-directory>
  --journal-id <64-lowercase-hex-original-attempt-marker-sha256>
  --batch <64-lowercase-hex> --fact-index <0..127>
  --principal-id <32-lowercase-hex> --idempotency-key <original-key>
  --expected-incarnation <32-lowercase-hex>
  --pull-request <number> --expected-pull-request-version <version>
  --expected-policy-epoch <epoch> --source-ref <refs/heads/source>
  --expected-source-tip <oid> --expected-target-tip <oid>
  --merge-base <oid> --candidate-commit <oid>
  --bundle <stable-local-file> --bundle-sha256 <independently-retained-64-lowercase-hex>
  [--source-ref-hex <hex> instead of --source-ref] [--ref-hex]
  [--minimum-pin <bytes>:<tail-sha256>] [--object-format sha1|sha256]
  [--timeout-ms <1..60000>]

Publish one completed job from the original trusted-local workflow journal for
the exact native PR candidate. The bundle must be a bounded regular artifact
whose independently retained SHA-256 matches; admission validates the actual
merge, squash or fast-forward shape and every original PR/ref/policy coordinate.
This does not run scripts, stage candidate objects, move refs, approve reviews,
acknowledge custody, or authorize a merge. Configured candidate-check protection
independently selects the publisher, workflow graph and job.

The original journal marker, batch, fact, subject, digest, publisher and key must
remain identical on retry. Exact canonical outcome recovery happens before
opening the bundle file, so a committed/refused check remains recoverable after
the file disappears or its source moves. A missing result is not non-commit.
The original execution authority head is provenance, not a current-head lease.

Linux only. The private journal directory and local artifact must be stable and
operator-controlled. The pre-admission read timeout defaults to 30000 ms;
native admission and shutdown retain their own finite budgets. Stdout is one
JSON receipt after node shutdown. Exit 0: committed; 3: canonical refusal;
2: input, unavailable/unknown outcome, cleanup or receipt-output failure.";

#[derive(Debug)]
struct Options {
    publication: publish::Options,
    subject: ReviewSubject,
    candidate: CandidateBinding,
    bundle: PathBuf,
    bundle_sha256: [u8; 32],
}

pub(super) fn run(arguments: &[String], output: &mut impl Write) -> Result<u8, String> {
    if arguments == ["publish-candidate", "--help"] {
        writeln!(output, "{USAGE}")
            .and_then(|()| output.flush())
            .map_err(|error| format!("candidate check publication help failed: {error}"))?;
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
        Err("saved candidate check publication requires Linux; no fallback is selected".into())
    }
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 5
        || arguments.len() > 72
        || arguments.first().map(String::as_str) != Some("publish-candidate")
        || arguments
            .iter()
            .any(|value| value.len() > 4096 || value.contains('\0'))
        || arguments.iter().map(String::len).sum::<usize>() > 64 * 1024
    {
        return Err(USAGE.into());
    }
    let mut ordinary = arguments[..5].to_vec();
    ordinary[0] = "publish".into();
    let mut selected = BTreeMap::new();
    let mut cursor = 5;
    while cursor < arguments.len() {
        let flag = arguments[cursor].as_str();
        cursor += 1;
        if matches!(flag, "--trusted-local" | "--ref-hex") {
            ordinary.push(flag.into());
            continue;
        }
        let value = arguments
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        if matches!(
            flag,
            "--pull-request"
                | "--expected-pull-request-version"
                | "--expected-policy-epoch"
                | "--source-ref"
                | "--source-ref-hex"
                | "--expected-source-tip"
                | "--expected-target-tip"
                | "--merge-base"
                | "--candidate-commit"
                | "--bundle"
                | "--bundle-sha256"
        ) {
            if selected.insert(flag, value.as_str()).is_some() {
                return Err(format!("duplicate {flag}"));
            }
        } else {
            ordinary.extend([flag.to_owned(), value.clone()]);
        }
    }
    let publication = publish::parse(&ordinary)?;
    if publication.incarnation.is_none() {
        return Err("--expected-incarnation is mandatory for candidate check publication".into());
    }
    let get = |flag: &str| {
        selected
            .get(flag)
            .copied()
            .ok_or_else(|| format!("missing {flag}"))
    };
    let positive = |flag: &str| publish::decimal(get(flag)?, 1, u64::MAX);
    let native = |flag: &str| {
        let value = get(flag)?;
        publish::fixed_hex(value, publication.format.digest_len())?;
        let id =
            GitOid::from_hex(publication.format, value).map_err(|_| "invalid native object ID")?;
        if id.is_zero() {
            return Err("zero is not a candidate coordinate".to_owned());
        }
        Ok(id)
    };
    let source = match (
        selected.get("--source-ref"),
        selected.get("--source-ref-hex"),
    ) {
        (Some(value), None) => value.as_bytes().to_vec(),
        (None, Some(value)) => super::unhex(value, fgit_types::MAX_REF_NAME_LEN)?,
        _ => return Err("supply exactly one --source-ref or --source-ref-hex".into()),
    };
    let subject = ReviewSubject {
        pull_request: PullRequestNumber::try_new(positive("--pull-request")?)
            .ok_or("invalid pull request number")?,
        pull_request_version: AggregateVersion::try_new(positive(
            "--expected-pull-request-version",
        )?)
        .ok_or("invalid pull request version")?,
        policy_epoch: PolicyEpoch::try_new(positive("--expected-policy-epoch")?)
            .map_err(|_| "invalid policy epoch")?,
        source_ref: RefName::try_new(&source).map_err(|_| "invalid source branch bytes")?,
        target_ref: publication.reference.clone(),
        source_tip: native("--expected-source-tip")?,
        target_tip: native("--expected-target-tip")?,
    };
    let candidate = CandidateBinding {
        merge_base: native("--merge-base")?,
        commit: native("--candidate-commit")?,
    };
    candidate
        .validate(&subject)
        .map_err(|_| "invalid exact PR candidate coordinates")?;
    let bundle = get("--bundle")?;
    if bundle.is_empty() {
        return Err("--bundle requires a stable local file path".into());
    }
    let bundle_sha256 = publish::fixed_hex(get("--bundle-sha256")?, 32)?
        .try_into()
        .map_err(|_| "invalid bundle SHA-256")?;
    Ok(Options {
        publication,
        subject,
        candidate,
        bundle: bundle.into(),
        bundle_sha256,
    })
}

fn verify_bundle_digest(
    bytes: &[u8],
    expected: [u8; 32],
    live: &dyn Fn() -> bool,
) -> Result<(), String> {
    let mut hash = Sha256Hasher::new();
    for chunk in bytes.chunks(16 * 1024) {
        if !live() {
            return Err("candidate bundle intake timed out".into());
        }
        hash.update(chunk);
    }
    if !live() {
        return Err("candidate bundle intake timed out".into());
    }
    if hash.finish() != expected {
        return Err("candidate bundle differs from the independently retained SHA-256".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn execute(options: Options, output: &mut impl Write) -> Result<u8, String> {
    use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};

    let original = &options.publication;
    let started = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(original.timeout_ms);
    let live = || started.elapsed() < timeout;
    let record = OneNode::trusted_candidate_workflow_check_record(
        &original.directory,
        (original.tenant, original.repository, original.journal),
        original.minimum,
        original.batch,
        original.fact_index,
        options.subject.clone(),
        options.candidate,
        options.bundle_sha256,
        &live,
    )
    .map_err(|error| publish::operation_error(&error.to_string(), false, None))?;
    if record.check.source_commit.algorithm() != original.format {
        return Err(publish::operation_error(
            "saved candidate and object format disagree",
            false,
            None,
        ));
    }
    let observation = NativeCandidateWorkflowCheck {
        actor: original.principal,
        record,
    };
    let session = LoopbackReceiveSession::authenticated(original.principal, original.key.clone());
    if !live() {
        return Err(publish::operation_error(
            "pre-admission read timeout",
            false,
            None,
        ));
    }
    let mut node = OneNode::open_existing(
        NodeConfig::new(
            original.storage.clone(),
            original.tenant,
            original.repository,
        )
        .with_object_format(original.format),
    )
    .map_err(|error| {
        publish::operation_error(&format!("cannot open workflow node: {error}"), false, None)
    })?;
    let incarnation = node.repository_incarnation_id();
    let mut entered_admission = false;
    let operation = (|| {
        if original.incarnation != Some(incarnation) {
            return Err("repository incarnation changed".to_owned());
        }
        if !live() {
            return Err("pre-admission read timeout".to_owned());
        }
        let request = fgit_cli::command_request_context(&node);
        // This lookup creates no seal and never reads the bundle. The retained
        // digest, complete subject and original evidence reconstruct the request.
        if let Some((tx, terminal)) = node
            .runtime()
            .block_on(node.recover_trusted_candidate_workflow_check_in(
                &request,
                &session,
                &observation.record,
            ))
            .map_err(|error| error.to_string())?
        {
            return Ok((tx, terminal, true));
        }
        let bundle = read_bundle(&options.bundle, MAX_BUNDLE_BYTES)?;
        verify_bundle_digest(&bundle, options.bundle_sha256, &live)?;
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|error| format!("cannot authenticate repository authority: {error}"))?;
        if let Err(error) = node.bring_into_service(head.receipt().generation()) {
            eprintln!(
                "candidate check intake unavailable ({error}); only an existing outcome may recover"
            );
        }
        if !live() {
            return Err("pre-admission read timeout".to_owned());
        }
        entered_admission = true;
        node.runtime()
            .block_on(node.admit_trusted_candidate_workflow_check_in(
                &request,
                &session,
                &observation.record,
                &bundle,
                Default::default(),
            ))
            .map(|(tx, terminal)| (tx, terminal, false))
            .map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match operation {
        Ok((tx, terminal, recovered)) => finish(
            output,
            &options,
            incarnation,
            &observation,
            tx,
            &terminal,
            recovered,
            cleanup.as_deref(),
        ),
        Err(error) => Err(publish::operation_error(
            &error,
            entered_admission,
            cleanup.as_deref(),
        )),
    }
}

fn finish(
    output: &mut impl Write,
    options: &Options,
    incarnation: RepositoryIncarnationId,
    observation: &NativeCandidateWorkflowCheck,
    tx: TxId,
    terminal: &TerminalOutcome,
    recovered: bool,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    let receipt = receipt(
        options,
        incarnation,
        observation,
        tx,
        terminal,
        recovered,
        cleanup,
    );
    write_terminal_receipt(output, &receipt, tx, terminal).map_err(|error| {
        cleanup.map_or(error.clone(), |cleanup| {
            format!("{error}; node shutdown also failed: {cleanup}")
        })
    })?;
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
    observation: &NativeCandidateWorkflowCheck,
    tx: TxId,
    terminal: &TerminalOutcome,
    recovered: bool,
    cleanup: Option<&str>,
) -> String {
    let record = &observation.record;
    let subject = &record.subject;
    let extension = format!(
        concat!(
            ",\"subject_kind\":\"unpublished_pr_candidate\",\"objects_staged\":false,\"outcome_recovered\":{},",
            "\"bundle_sha256\":{},\"candidate\":{{\"merge_base\":{},\"commit\":{}}},",
            "\"subject\":{{\"pull_request\":{},\"pull_request_version\":{},\"policy_epoch\":{},",
            "\"source_ref_hex\":{},\"target_ref_hex\":{},\"source_tip\":{},\"target_tip\":{}}}"
        ),
        recovered,
        quote(&hex(&record.bundle_sha256)),
        quote(&record.candidate.merge_base.to_string()),
        quote(&record.candidate.commit.to_string()),
        subject.pull_request.get(),
        subject.pull_request_version.get(),
        subject.policy_epoch.get(),
        quote(&hex(subject.source_ref.as_bytes())),
        quote(&hex(subject.target_ref.as_bytes())),
        quote(&subject.source_tip.to_string()),
        quote(&subject.target_tip.to_string())
    );
    publish::record_receipt(
        &options.publication,
        incarnation,
        &record.check,
        observation.id(),
        tx,
        terminal,
        cleanup,
        "candidate_workflow_check_publication",
        &extension,
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "publish_candidate/tests.rs"]
mod tests;
