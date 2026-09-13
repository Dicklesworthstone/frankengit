//! Native patch preparation and separately reviewed ordinary workspace admission.
mod options;

use std::io::{Read, Write};
use fgit_authority::{IdempotencyKey, TerminalOutcome, MAX_IDEMPOTENCY_KEY_BYTES};
use fgit_node::{NodeConfig, OneNode, WorkspacePatchCandidate};
use fgit_types::{DecisionOutcome, HeadGeneration, TxId};
use crate::merge_apply::preparation::{publish_new_bundle, require_absent};
use crate::publication_support::{describe, quote, read_bundle, write_terminal_receipt};
use options::{Operation, Options, hex};

const USAGE: &str = "usage: fg patch prepare <storage-root> <tenant-id> <repository-id> <branch-ref> <patch-file> <new-bundle>
  --trusted-local --profile exact-v1 --workspace-id <32-hex> --expected-base <native-commit-id>
  --author <name-and-email> [--committer <name-and-email>] --timestamp <unix-seconds>
  (--message <text> | --message-file <raw-file>) [--ref-hex]
  [--max-files <n>] [--max-hunks <n>] [--max-input-bytes <n>] [--max-output-bytes <n>]

usage: fg patch apply <storage-root> <tenant-id> <repository-id> <branch-ref> <reviewed-bundle>
  --trusted-local --principal <id> (--idempotency-key <key> | --key-stdin)
  --expected-base <native-commit-id> --expected-commit <independently-reviewed-id> [--ref-hex]

exact-v1 accepts ordinary Git unified text patches for regular files: exact
hunk offsets/context, additions/deletions, executable-bit changes, quoted raw
paths and final-newline markers. Supplied index names must match both verified
blob identities. No fuzzy matching, strip option, rename/copy, binary patch,
symlink/gitlink, hook, host tool or external driver is run. All files succeed
or no bundle is produced. No-change input refuses instead of making an empty
commit. Unmodified siblings and all unrelated refs/forge state are preserved.

Preparation never moves refs; its bundle is incremental against expected-base.
Inspect it with fg workspace inspect before applying. Apply consumes the saved
bundle, not a patch recipe. It verifies the reviewed commit through production
quarantine and ordinary expected-old admission; there is no force bypass.
These are trusted local-owner commands, not remote authentication endpoints.
--ref-hex decodes the positional reference as exact lowercase hex. Stdin keys
are bounded exact bytes, including newlines, and never appear in receipts.
Exit 0: prepared/committed; 3: canonical refusal; 2: input/infrastructure/output error.";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] || args == ["prepare", "--help"] || args == ["apply", "--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let mut options = options::parse(args)?;
    let (input, key) = match &mut options.operation {
        Operation::Prepare { patch, output, metadata, message_file, limits, .. } => {
            if let Some(path) = message_file { metadata.message = read_bundle(path, 64 * 1024)?; }
            metadata.validate().map_err(|error| error.to_string())?;
            let input = read_bundle(patch, limits.max_patch_bytes)?;
            // Syntax/path/aggregate limits are checked before opening the node.
            fgit_forge::patch::UnifiedPatch::parse(&input, *limits, &|| false)
                .map_err(|error| error.to_string())?;
            require_absent(output)?;
            (input, None)
        }
        Operation::Apply { bundle, key, .. } => {
            let bytes = match key {
                options::Key::Bytes(bytes) => bytes.clone(),
                options::Key::Stdin => read_key(&mut std::io::stdin().lock())?,
            };
            IdempotencyKey::new(bytes.clone()).map_err(|_| "invalid bounded idempotency key")?;
            (read_bundle(bundle, 128 * 1024 * 1024)?, Some(bytes))
        }
    };
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant,
        options.repository).with_object_format(options.base.algorithm())).map_err(|error| error.to_string())?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        match &options.operation {
            Operation::Prepare { workspace_id, metadata, limits, .. } => node.runtime().block_on(
                node.prepare_trusted_patch_in(&request, &options.reference, options.base, *workspace_id,
                    &input, metadata, *limits)).map(Completed::Prepared).map_err(|error| error.to_string()),
            Operation::Apply { principal, candidate, .. } => {
                let key = key.as_deref().ok_or("patch publication key missing")?;
                let admitted = node.runtime().block_on(node.apply_workspace_bundle_durable_in(
                    &request, *principal, key, &options.reference, options.base, *candidate, &input))
                    .map_err(|error| error.to_string())?;
                let [command] = admitted.commands.as_slice() else {
                    return Err("unexpected publication outcome count; do not infer non-commit".into());
                };
                if !admitted.session.atomic || admitted.session.tx_ids != vec![command.tx_id] {
                    return Err(format!("unexpected publication mapping; {}", describe(command.tx_id, &command.terminal)));
                }
                Ok(Completed::Applied(command.tx_id, command.terminal))
            }
        }
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match result {
        Ok(Completed::Prepared(candidate)) => {
            if let Some(error) = cleanup { return Err(format!("node shutdown failed: {error}; no bundle was published")); }
            let Operation::Prepare { output, .. } = &options.operation else { return Err("patch operation mismatch".into()); };
            let receipt = prepared_receipt(&options, &candidate)?;
            publish_new_bundle(output, candidate.bundle_bytes())?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{receipt}").and_then(|()| stdout.flush()).map_err(|error|
                format!("complete patch bundle is visible at {}; receipt output failed: {error}; repository state was not changed", output.display()))?;
            Ok(0)
        }
        Ok(Completed::Applied(tx, terminal)) => finish_applied(&mut std::io::stdout().lock(),
            &options, tx, &terminal, cleanup.as_deref()),
        Err(error) => {
            let cleanup = cleanup.map_or_else(String::new, |error| format!("; node shutdown also failed: {error}"));
            match options.operation {
                Operation::Prepare { .. } => Err(format!("patch preparation failed: {error}{cleanup}; no bundle was published")),
                Operation::Apply { .. } => Err(format!("no terminal patch outcome returned: {error}{cleanup}; this is not evidence of non-commit. Retry the identical saved bundle, principal, key and expected IDs, or use fg outcome; do not regenerate the patch or change the key")),
            }
        }
    }
}

enum Completed { Prepared(WorkspacePatchCandidate), Applied(TxId, TerminalOutcome) }
fn read_key(input: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    input.take((MAX_IDEMPOTENCY_KEY_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_IDEMPOTENCY_KEY_BYTES { return Err("key must contain 1..256 exact bytes".into()); }
    Ok(bytes)
}
fn prepared_receipt(options: &Options, candidate: &WorkspacePatchCandidate) -> Result<String, String> {
    if options.base != candidate.source_commit || options.base.algorithm() != candidate.object_format
        || candidate.candidate_commit.algorithm() != candidate.object_format
        || candidate.root_tree.algorithm() != candidate.object_format
        || candidate.candidate_commit == candidate.source_commit || candidate.bundle_bytes().is_empty()
    { return Err("inconsistent patch candidate; no bundle was published".into()); }
    let paths = candidate.paths.iter().map(|path| {
        let old = path.old_blob.map_or_else(|| "null".into(), |id| quote(&id.to_string()));
        let new = path.new_blob.map_or_else(|| "null".into(), |id| quote(&id.to_string()));
        let mode = path.new_mode.map_or_else(|| "null".into(), |mode| quote(&format!("{mode:o}")));
        format!("{{\"path_hex\":{},\"old_blob\":{old},\"new_blob\":{new},\"new_mode\":{mode},\"hunks\":{}}}", quote(&hex(&path.path)), path.hunks)
    }).collect::<Vec<_>>().join(",");
    Ok(format!(concat!("{{\"type\":\"patch_preparation\",\"schema_version\":1,\"profile\":\"exact-v1\",",
        "\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"reference_hex\":{},",
        "\"source_commit\":{},\"source_rcr\":{},\"candidate_commit\":{},\"root_tree\":{},",
        "\"patch_sha256\":{},\"bundle_sha256\":{},\"bundle_bytes\":{},\"pack_objects\":{},",
        "\"paths\":[{}],\"published_to_repository\":false,\"node_closed\":true}}"),
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(candidate.object_format.as_str()),
        quote(&hex(options.reference.as_bytes())), quote(&candidate.source_commit.to_string()), quote(&candidate.source_rcr.to_string()),
        quote(&candidate.candidate_commit.to_string()), quote(&candidate.root_tree.to_string()), quote(&hex(&candidate.patch_sha256)),
        quote(&hex(&fgit_crypto::sha256_digest(candidate.bundle_bytes()))), candidate.bundle_bytes().len(), candidate.object_count, paths))
}
fn finish_applied(output: &mut impl Write, options: &Options, tx: TxId,
    terminal: &TerminalOutcome, cleanup: Option<&str>) -> Result<u8, String> {
    let Operation::Apply { principal, candidate, .. } = &options.operation else { return Err("patch receipt operation mismatch".into()); };
    let (outcome, exit, rcr, refusal, refusal_record) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => ("committed", 0, quote(&repository_commit_id.to_string()), "null".to_owned(), "null".to_owned()),
        DecisionOutcome::Refused { code, refusal_record_id } => ("refused", 3, "null".to_owned(), quote(&format!("{code:?}")), quote(&refusal_record_id.to_string())),
    };
    let receipt = format!(concat!("{{\"type\":\"patch_publication\",\"schema_version\":1,\"outcome\":{},",
        "\"published_to_repository\":{},\"tx_id\":{},\"decision_sequence\":{},\"repository_commit_id\":{},\"refusal_code\":{},\"refusal_record_id\":{},",
        "\"tenant_id\":{},\"repository_id\":{},\"principal_id\":{},\"reference_hex\":{},\"expected_base\":{},",
        "\"candidate_commit\":{},\"node_closed\":{},\"cleanup_error\":{}}}"),
        quote(outcome), exit == 0, quote(&tx.to_string()), terminal.decision_sequence.get(), rcr, refusal, refusal_record,
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(&principal.to_string()),
        quote(&hex(options.reference.as_bytes())), quote(&options.base.to_string()), quote(&candidate.to_string()),
        cleanup.is_none(), cleanup.map_or_else(|| "null".to_owned(), quote));
    if let Err(error) = write_terminal_receipt(output, &receipt, tx, terminal) {
        return Err(cleanup.map_or(error.clone(), |cleanup| format!("{error}; node shutdown also failed: {cleanup}")));
    }
    if let Some(error) = cleanup { return Err(format!("{}; node shutdown failed: {error}", describe(tx, terminal))); }
    Ok(exit)
}

#[cfg(test)]
mod tests;
