//! Trusted-local exact-version fast-forward publication through the native node.
//! All semantic coordinates are supplied before opening storage. There is no
//! fetch, branch-tip refresh, Git subprocess, candidate synthesis, or force path.

mod options;
#[cfg(test)]
mod tests;

use std::io::Write;

use fgit_authority::TerminalOutcome;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, TxId};

use crate::publication_support::{describe, quote, write_terminal_receipt};
use options::Options;

const USAGE: &str = "\
usage: fg pr fast-forward <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local --principal <id> --idempotency-key <key>
  --expected-version <positive PR version>
  (--source-ref <branch> | --source-ref-hex <bytes>) --expected-source <oid>
  (--target-ref <branch> | --target-ref-hex <bytes>) --expected-target <oid>
  [--object-format sha1|sha256]

The exact source tip must already be admitted and descend from the exact target.
Success moves that target and marks this PR merged in ONE canonical decision.
Mandatory repository protection still applies. This is not a review approval,
force push, squash, rebase, two-parent merge, or automatic fallback to one.
No title, body, author, merge commit, bundle, or latest-tip lookup is needed.

Keep the original principal, key, PR version, branch bytes and tips on retry.
A retry returns its original decision even after the PR or target has changed.
Receipts describe historical outcomes, not a fresh assertion of current refs.
Exit 0: canonical commit; 3: canonical refusal; 2: input, unavailable/unknown
outcome, cleanup or output error. A nonzero process exit is not proof of rollback.
Only an authorized local operator may use --trusted-local; no remote grant is added.";

pub(super) fn run(arguments: &[String], output: &mut impl Write) -> Result<u8, String> {
    if arguments == ["--help"] {
        writeln!(output, "{USAGE}")
            .and_then(|()| output.flush())
            .map_err(|error| format!("fast-forward help output failed: {error}"))?;
        return Ok(0);
    }
    // Parse and validate the COMPLETE command before any repository I/O.
    let options = options::parse(arguments)?;
    let session = LoopbackReceiveSession::authenticated(options.principal, options.key.clone());
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| {
        format!(
            "cannot open fast-forward node: {error}; this invocation did not reach merge admission"
        )
    })?;
    let incarnation = node.repository_incarnation_id().to_string();
    let mut entered_admission = false;
    let outcome = (|| {
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|error| format!("cannot authenticate repository authority: {error}"))?;
        if let Err(error) = node.bring_into_service(head.receipt().generation()) {
            // Do not hide a historical decision behind new-intake state. The
            // native driver recovers the exact seal first; undecided requests
            // still encounter its own mandatory intake and policy gates.
            eprintln!(
                "fast-forward intake unavailable ({error}); only existing outcome recovery may succeed"
            );
        }
        let request = node.request_context();
        entered_admission = true;
        node.runtime()
            .block_on(node.fast_forward_pull_request_durable_in(
                &request,
                &session,
                options.number,
                options.version,
                &options.source_ref,
                options.source,
                &options.target_ref,
                options.target,
                Default::default(),
                Default::default(),
            ))
            .map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match outcome {
        Ok((tx, terminal)) => finish(
            output,
            &options,
            &incarnation,
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
            "fast-forward returned no terminal outcome: {error}{cleanup}; this is not evidence of non-commit. Preserve and reconcile the ORIGINAL principal, idempotency key, PR version, branch bytes and native tips; never refresh them or substitute another merge method on retry"
        )
    } else {
        format!(
            "fast-forward failed before merge admission: {error}{cleanup}; this invocation submitted no merge, but does not determine any earlier invocation's outcome"
        )
    }
}

fn finish(
    output: &mut impl Write,
    options: &Options,
    incarnation: &str,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    // A lost stdout or failed shutdown cannot turn a known canonical decision
    // into an unknown outcome. Preserve its identity in both receipt and error.
    let receipt = receipt(options, incarnation, tx, terminal, cleanup);
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
    incarnation: &str,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> String {
    let (outcome, commit, refusal, code, exit) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            quote(&repository_commit_id.to_string()),
            "null".to_owned(),
            "null".to_owned(),
            0,
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            "null".to_owned(),
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
            3,
        ),
    };
    format!(
        concat!(
            "{{\"type\":\"pull_request_fast_forward_publication\",\"schema_version\":1,",
            "\"method\":\"fast-forward-only/v1\",\"trusted_local\":true,",
            "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"principal_id\":{},",
            "\"object_format\":{},\"number\":{},\"expected_version\":{},",
            "\"source_ref_hex\":{},\"target_ref_hex\":{},\"expected_source\":{},\"expected_target\":{},",
            "\"tx_id\":{},\"outcome\":{},\"decision_sequence\":{},",
            "\"repository_commit_id\":{},\"refusal_record_id\":{},\"refusal_code\":{},",
            "\"atomic\":true,\"coupled_pr_and_ref\":true,\"git_objects_created\":false,",
            "\"historical_outcome\":true,\"current_refs_asserted\":false,\"delivery_acknowledged\":null,",
            "\"decision_exit_code\":{},\"cleanup_error\":{}}}"
        ),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(incarnation),
        quote(&options.principal.to_string()),
        quote(options.format.as_str()),
        quote(&options.number.get().to_string()),
        quote(&options.version.get().to_string()),
        quote(&hex(options.source_ref.as_bytes())),
        quote(&hex(options.target_ref.as_bytes())),
        quote(&options.source.to_string()),
        quote(&options.target.to_string()),
        quote(&tx.to_string()),
        quote(outcome),
        quote(&terminal.decision_sequence.get().to_string()),
        commit,
        refusal,
        code,
        exit,
        cleanup.map_or_else(|| "null".to_owned(), quote),
    )
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
