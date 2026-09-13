//! Explicit trusted-local publication of a reviewed rebase artifact.
mod options;
#[cfg(test)]
mod tests;

use crate::commit_replay::hex;
use crate::publication_support::{describe, quote, read_bundle, write_terminal_receipt};
use fgit_authority::{TerminalOutcome, MAX_IDEMPOTENCY_KEY_BYTES};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, TxId};
use options::{KeyInput, Options};
use std::io::{Read, Write};

const USAGE: &str = "usage: fg rebase apply <storage-root> <tenant-id> <repository-id> <source-ref> <bundle>
  --trusted-local --allow-rewrite --principal <id>
  (--idempotency-key <exact-text> | --key-stdin)
  --expected-source <old-source-oid> --expected-onto <onto-oid>
  --expected-commit <independently-reviewed-candidate-oid> [--source-ref-hex]

Publishes one reviewed linear series in an atomic expected-old ref transaction.
The expected SOURCE tip is the lease; ONTO is the sole bundle prerequisite.
--allow-rewrite is explicit operator consent, not a policy bypass or force bit.
Preparation receipts are not authorization. No tip is inferred from the artifact.
The 128 MiB artifact must be a stable regular file under your control. Both native
hash domains and zero-commit series are supported. PR metadata is not rewritten.
Stdin keys contain 1..256 exact bytes, including any newline; keys are never printed.
Retry identical inputs/key or use fg outcome after an interrupted response.
Exit 0: committed; 3: canonical refusal; 2: input, infrastructure or cleanup error.";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let options = options::parse(args)?;
    let key = match &options.key {
        KeyInput::Bytes(bytes) => bytes.clone(),
        KeyInput::Stdin => read_key(&mut std::io::stdin().lock())?,
    };
    let bundle = read_bundle(&options.bundle, 128 * 1024 * 1024)?;
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant,
        options.repository).with_object_format(options.source.algorithm()))
        .map_err(|error| format!("cannot open rebase node: {error}"))?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        let admitted = node.runtime().block_on(node.apply_rebase_bundle_durable_in(
            &request, options.principal, &key, &options.reference, options.source,
            options.onto, options.candidate, &bundle,
        )).map_err(|error| error.to_string())?;
        let Some(first) = admitted.commands.first() else {
            return Err("admission returned no terminal rebase command".to_owned());
        };
        if !admitted.session.atomic || admitted.commands.len() != 1
            || admitted.session.tx_ids != vec![first.tx_id] {
            return Err(format!("inconsistent rebase receipt; {}", describe(first.tx_id, &first.terminal)));
        }
        Ok((first.tx_id, first.terminal))
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match result {
        Ok((tx, terminal)) => finish(&mut std::io::stdout().lock(), &options, tx, &terminal, cleanup.as_deref()),
        Err(error) => {
            let cleanup = cleanup.map_or_else(String::new, |error| format!("; node shutdown also failed: {error}"));
            Err(format!("rebase application did not return a complete receipt: {error}{cleanup}; an error is not evidence of non-commit. Use fg outcome with the original principal/key or retry identical source/onto/candidate inputs; do not change the key"))
        }
    }
}

fn read_key(input: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    input.take((MAX_IDEMPOTENCY_KEY_BYTES + 1) as u64).read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read bounded rebase key: {error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err("rebase key must contain 1..256 exact bytes".into());
    }
    Ok(bytes)
}

fn finish(output: &mut impl Write, options: &Options, tx: TxId, terminal: &TerminalOutcome,
    cleanup: Option<&str>) -> Result<u8, String> {
    let (state, exit, rcr, code, refusal) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } =>
            ("committed", 0, quote(&repository_commit_id.to_string()), "null".into(), "null".into()),
        DecisionOutcome::Refused { code, refusal_record_id } =>
            ("refused", 3, "null".into(), quote(&format!("{code:?}")), quote(&refusal_record_id.to_string())),
    };
    let receipt = format!(concat!("{{\"type\":\"rebase_publication\",\"schema_version\":1,\"atomic\":true,",
        "\"outcome\":{},\"command_committed\":{},\"tx_id\":{},\"decision_sequence\":{},",
        "\"repository_commit_id\":{rcr},\"refusal_code\":{code},\"refusal_record_id\":{refusal},",
        "\"tenant_id\":{},\"repository_id\":{},\"principal_id\":{},\"object_format\":{},",
        "\"source_reference_hex\":{},\"expected_source\":{},\"expected_onto\":{},\"expected_commit\":{},",
        "\"delivery_acknowledged\":null,\"node_closed\":{},\"cleanup_error\":{}}}"),
        quote(state), exit == 0, quote(&tx.to_string()), terminal.decision_sequence.get(),
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(&options.principal.to_string()),
        quote(options.source.algorithm().as_str()), quote(&hex(options.reference.as_bytes())),
        quote(&options.source.to_string()), quote(&options.onto.to_string()), quote(&options.candidate.to_string()),
        cleanup.is_none(), cleanup.map_or_else(|| "null".into(), quote), rcr=rcr, code=code, refusal=refusal);
    if let Err(error) = write_terminal_receipt(output, &receipt, tx, terminal) {
        return Err(cleanup.map_or(error.clone(), |cleanup| format!("{error}; node shutdown also failed: {cleanup}")));
    }
    if let Some(error) = cleanup {
        return Err(format!("{}; node shutdown failed: {error}", describe(tx, terminal)));
    }
    Ok(exit)
}
