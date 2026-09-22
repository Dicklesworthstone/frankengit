//! Native first-commit preparation and separately reviewed absent-branch publication.
mod options;
use super::options::hex;
use crate::merge_apply::preparation::{publish_new_bundle, require_absent};
use crate::publication_support::{describe, quote, read_bundle, write_terminal_receipt};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::initial_commit::InitialCommitPlan;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, RepositoryAuthorityHeadId, TxId};
use options::{Operation, Options};
use std::io::{Read, Write};

const USAGE: &str = "usage: fg patch prepare-initial <storage-root> <tenant-id> <repository-id> <branch-ref> <creation-patch> <new-bundle>
  --trusted-local --profile exact-v1 [--object-format sha1|sha256] [--ref-hex]
  --author <name-and-email> [--committer <name-and-email>] --timestamp <unix-seconds>
  (--message <text> | --message-file <raw-file>)
  [--max-files <n>] [--max-hunks <n>] [--max-input-bytes <n>] [--max-output-bytes <n>]

usage: fg patch apply-initial <storage-root> <tenant-id> <repository-id> <branch-ref> <reviewed-bundle>
  --trusted-local --principal <id> (--idempotency-key <key> | --key-stdin)
  --expected-commit <independently-reviewed-native-id> [--ref-hex]

Start with fg init, then prepare creation-only exact hunks for regular files.
The candidate has zero parents and includes its complete native object closure.
An absent independent-history branch may also be created in a nonempty repository.
No fake base commit, host checkout, external Git, force, or HEAD change is used.
Preparation is read-only. Review the candidate identity before applying its saved
bundle. Apply atomically requires branch absence and enforces current policy.
A creation patch must contain at least one file (which may be empty). Symlinks,
gitlinks, deletion/modification, rename/copy and binary-patch encoding refuse.
The output byte budget includes every unique blob, tree and commit body.
Artifact files are create-only. Stdin keys are bounded and byte-exact, including
newlines, and are never printed. Retry identical inputs and key or use fg outcome.
These are trusted-local-owner commands, not remote or agent authentication.
Exit 0: prepared/committed; 3: canonical refusal; 2: input/infrastructure/output error.";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args.len() == 2 && args[1] == "--help" {
        return writeln!(std::io::stdout().lock(), "{USAGE}")
            .map(|()| 0)
            .map_err(|e| e.to_string());
    }
    let mut options = options::parse(args)?;
    let (input, session) = match &mut options.operation {
        Operation::Prepare {
            input,
            output,
            metadata,
            message_file,
            limits,
        } => {
            if let Some(path) = message_file {
                metadata.message = read_bundle(path, 64 * 1024)?;
            }
            metadata.validate().map_err(|e| e.to_string())?;
            let input = read_bundle(input, limits.max_patch_bytes)?;
            let patch = fgit_forge::patch::UnifiedPatch::parse(&input, *limits, &|| false)
                .map_err(|e| e.to_string())?;
            if patch
                .files()
                .iter()
                .any(|file| file.change() != fgit_forge::patch::FileChange::Create)
            {
                return Err("initial patch may only create regular files".into());
            }
            require_absent(output)?;
            (input, None)
        }
        Operation::Apply {
            input,
            principal,
            key,
            ..
        } => {
            let key = key_bytes(key, &mut std::io::stdin().lock())?;
            let session = LoopbackReceiveSession::authenticated(
                *principal,
                IdempotencyKey::new(key).map_err(|e| e.to_string())?,
            );
            (read_bundle(input, 128 * 1024 * 1024)?, Some(session))
        }
    };
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|e| e.to_string())?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|e| e.to_string())?;
        let request = node.request_context();
        match &options.operation {
            Operation::Prepare {
                metadata, limits, ..
            } => {
                let (head, plan, bundle) = node
                    .runtime()
                    .block_on(node.prepare_trusted_initial_patch_in(
                        &request,
                        &options.reference,
                        &input,
                        metadata,
                        *limits,
                        None,
                    ))
                    .map_err(|e| e.to_string())?;
                let count = bundle.pack_receipt().object_count;
                Ok(Completed::Prepared(head, plan, bundle.into_bytes(), count))
            }
            Operation::Apply { candidate, .. } => {
                let session = session
                    .as_ref()
                    .ok_or("initial publication session missing")?;
                let result = node
                    .runtime()
                    .block_on(node.apply_initial_patch_bundle_durable_in(
                        &request,
                        session,
                        &options.reference,
                        *candidate,
                        &input,
                        Default::default(),
                    ))
                    .map_err(|e| e.to_string())?;
                let [command] = result.commands.as_slice() else {
                    return Err("initial publication returned no single terminal result; do not infer non-commit".into());
                };
                if !result.session.atomic || result.session.tx_ids != vec![command.tx_id] {
                    return Err(format!(
                        "inconsistent initial publication mapping; {}",
                        describe(command.tx_id, &command.terminal)
                    ));
                }
                Ok(Completed::Applied(command.tx_id, command.terminal))
            }
        }
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    match result {
        Ok(Completed::Prepared(head, plan, bytes, count)) => {
            if let Some(error) = cleanup {
                return Err(format!(
                    "initial preparation shutdown failed: {error}; no bundle file published"
                ));
            }
            let Operation::Prepare { output, .. } = &options.operation else {
                return Err("initial operation mismatch".into());
            };
            let receipt = prepared_receipt(&options, head, &plan, &bytes, count)?;
            publish_new_bundle(output, &bytes)?;
            writeln!(std::io::stdout().lock(),"{receipt}").and_then(|()|std::io::stdout().flush())
                .map_err(|e|format!("complete initial bundle was created but receipt output failed: {e}; repository state was not changed"))?;
            Ok(0)
        }
        Ok(Completed::Applied(tx, terminal)) => finish_applied(
            &mut std::io::stdout().lock(),
            &options,
            tx,
            &terminal,
            cleanup.as_deref(),
        ),
        Err(error) => {
            let cleanup =
                cleanup.map_or_else(String::new, |e| format!("; node shutdown also failed: {e}"));
            match &options.operation {
                Operation::Prepare { .. } => Err(format!(
                    "initial preparation failed: {error}{cleanup}; no bundle file published"
                )),
                Operation::Apply { .. } => Err(format!(
                    "initial publication returned no terminal outcome: {error}{cleanup}; this is not evidence of non-commit. Retry identical inputs/key or use fg outcome; do not change the scoped retry key"
                )),
            }
        }
    }
}
enum Completed {
    Prepared(RepositoryAuthorityHeadId, InitialCommitPlan, Vec<u8>, u32),
    Applied(TxId, TerminalOutcome),
}
fn key_bytes(key: &options::Key, input: &mut impl Read) -> Result<Vec<u8>, String> {
    match key {
        options::Key::Bytes(bytes) => Ok(bytes.clone()),
        options::Key::Stdin => super::read_key(input),
    }
}
fn prepared_receipt(
    options: &Options,
    head: RepositoryAuthorityHeadId,
    plan: &InitialCommitPlan,
    bytes: &[u8],
    count: u32,
) -> Result<String, String> {
    if plan.object_format != options.format
        || plan.commit.algorithm() != options.format
        || plan.commit.is_zero()
        || plan.tree.algorithm() != options.format
        || bytes.is_empty()
        || count as usize != plan.objects.len()
    {
        return Err("inconsistent initial candidate; no bundle was published".into());
    }
    let files = plan
        .files
        .iter()
        .map(|f| {
            format!(
                "{{\"path_hex\":{},\"blob\":{},\"mode\":{},\"bytes\":{}}}",
                quote(&hex(&f.path)),
                quote(&f.blob.to_string()),
                quote(&format!("{:o}", f.mode)),
                f.bytes
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        concat!(
            "{{\"type\":\"initial_commit_preparation\",\"schema_version\":1,\"profile\":\"exact-v1\",",
            "\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"reference_hex\":{},\"source_head\":{},",
            "\"expected_absent\":true,\"parent_count\":0,\"candidate_commit\":{},\"root_tree\":{},",
            "\"patch_sha256\":{},\"bundle_sha256\":{},\"bundle_bytes\":{},\"pack_objects\":{},\"files\":[{}],",
            "\"published_to_repository\":false,\"node_closed\":true}}"
        ),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(options.format.as_str()),
        quote(&hex(options.reference.as_bytes())),
        quote(&head.to_string()),
        quote(&plan.commit.to_string()),
        quote(&plan.tree.to_string()),
        quote(&hex(&plan.patch_sha256)),
        quote(&hex(&fgit_crypto::sha256_digest(bytes))),
        bytes.len(),
        count,
        files
    ))
}
fn finish_applied(
    output: &mut impl Write,
    options: &Options,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    let Operation::Apply {
        principal,
        candidate,
        ..
    } = &options.operation
    else {
        return Err("initial receipt operation mismatch".into());
    };
    let (outcome, exit, rcr, refusal, record) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            0,
            quote(&repository_commit_id.to_string()),
            "null".into(),
            "null".into(),
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            3,
            "null".into(),
            quote(&format!("{code:?}")),
            quote(&refusal_record_id.to_string()),
        ),
    };
    let receipt = format!(
        concat!(
            "{{\"type\":\"initial_commit_publication\",\"schema_version\":1,\"atomic\":true,\"expected_absent\":true,",
            "\"outcome\":{},\"published_to_repository\":{},\"tx_id\":{},\"decision_sequence\":{},\"repository_commit_id\":{},\"refusal_code\":{},\"refusal_record_id\":{},",
            "\"tenant_id\":{},\"repository_id\":{},\"principal_id\":{},\"object_format\":{},\"reference_hex\":{},\"candidate_commit\":{},",
            "\"node_closed\":{},\"cleanup_error\":{}}}"
        ),
        quote(outcome),
        exit == 0,
        quote(&tx.to_string()),
        terminal.decision_sequence.get(),
        rcr,
        refusal,
        record,
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(&principal.to_string()),
        quote(options.format.as_str()),
        quote(&hex(options.reference.as_bytes())),
        quote(&candidate.to_string()),
        cleanup.is_none(),
        cleanup.map_or_else(|| "null".into(), quote)
    );
    if let Err(error) = write_terminal_receipt(output, &receipt, tx, terminal) {
        return Err(cleanup.map_or(error.clone(), |e| {
            format!("{error}; node shutdown also failed: {e}")
        }));
    }
    if let Some(error) = cleanup {
        return Err(format!(
            "{}; node shutdown failed: {error}",
            describe(tx, terminal)
        ));
    }
    Ok(exit)
}

#[cfg(test)]
mod tests;
