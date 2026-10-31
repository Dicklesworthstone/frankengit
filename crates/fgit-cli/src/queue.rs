//! Canonical queue management, candidate preparation and guarded atomic landing.
mod candidate;
mod options;
mod output;
#[cfg(test)]
mod tests;

use crate::publication_support::{describe, write_terminal_receipt};
use fgit_authority::TerminalOutcome;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode, PreparedQueueHeadBundle};
use fgit_types::{DecisionOutcome, HeadGeneration, RepositoryIncarnationId, TxId};
use options::{Operation, Options};
use std::io::Write;

const USAGE: &str = "\
usage: fg queue show <storage-root> <tenant-id> <repository-id> <queue-number> --trusted-local
  [--expected-head <snapshot-token>] [--expected-incarnation <id>] [--object-format sha1|sha256]
usage: fg queue list <storage-root> <tenant-id> <repository-id> --trusted-local
  [--limit <1..100>] [--after <queue-number> --expected-head <snapshot-token>]
  [--expected-incarnation <id>] [--object-format sha1|sha256]

usage: fg queue <enqueue|dequeue|reorder> <storage-root> <tenant-id> <repository-id> <queue-number>
  --trusted-local --principal <id> --expected-incarnation <id> --idempotency-key <key>
  --expected-version <0-for-first-enqueue> --target-ref <refs/heads/branch>
  [--object-format sha1|sha256]
  enqueue: --pull-request <number> --expected-pull-version <positive-version>
           --source-ref <refs/heads/source> --expected-source-tip <oid> --expected-target-tip <oid>
           [--priority <0..4294967295>]
  dequeue: --pull-request <number> --reason <withdrawn|conflict|check-failed|base-moved|evicted|admin-override>
  reorder: --entry <pull-request-number> ... (the complete nonempty order, at most 1024 entries)

usage: fg queue land <storage-root> <tenant-id> <repository-id> <queue-number>
  --trusted-local --principal <id> --expected-incarnation <id> --idempotency-key <key>
  --expected-version <positive-version> --expected-policy-epoch <positive-epoch>
  --pull-request <number> --expected-pull-version <positive-version>
  --source-ref <refs/heads/source> --target-ref <refs/heads/target>
  --expected-source-tip <oid> --expected-target-tip <oid> [--object-format sha1|sha256]

usage: fg queue prepare <storage-root> <tenant-id> <repository-id> <queue-number>
  --trusted-local --expected-incarnation <id> --expected-version <positive-version>
  --expected-policy-epoch <positive-epoch> --pull-request <number> --expected-pull-version <version>
  --source-ref <refs/heads/source> --target-ref <refs/heads/target>
  --expected-source-tip <oid> --expected-target-tip <oid>
  --profile path-v1|exact-renames-v1 --author <name-and-email> [--committer <name-and-email>]
  --timestamp <unix-seconds> --message <message> --output-bundle <new-file>
  [--object-format sha1|sha256]

usage: fg queue land-candidate <storage-root> <tenant-id> <repository-id> <queue-number>
  --trusted-local --principal <id> --expected-incarnation <id> --idempotency-key <key>
  --expected-version <positive-version> --expected-policy-epoch <positive-epoch>
  --pull-request <number> --expected-pull-version <positive-version>
  --source-ref <refs/heads/source> --target-ref <refs/heads/target>
  --expected-source-tip <oid> --expected-target-tip <oid>
  --merge-base <oid> --expected-commit <reviewed-oid> --bundle <candidate-file>
  [--object-format sha1|sha256]

Queue numbers and target branches remain bound after their first enqueue.
Enqueue checks the current open PR, exact PR version and both compared branch tips.
Higher priorities enter first; equal priorities enter FIFO. Reorder preserves its explicit order.
All changes publish canonical forge events under the exact queue predecessor and original client key.
Retry the identical command and key after a lost response, or use fg outcome; never refresh retry versions.
Receipts describe that terminal decision; use show for the latest queue state.
Enqueue, dequeue and reorder change queue metadata only.
Land requires the exact queue-head PR and performs FastForwardOnly native merge admission,
including current review, required-check and protected-ref rules. The target ref, PR merge
and queue completion publish atomically; the queue advances twice and the PR once.
Land accepts existing commit objects; it does not synthesize merge commits or run checks.
Prepare constructs a two-parent candidate for the exact queue head at one authenticated
snapshot. It writes a new bundle only for a clean merge and does not publish repository state.
Land-candidate validates the supplied two-parent commit and exact candidate evidence before
atomically moving the target, merging the PR and completing the queue head. No method fallback.
This is a trusted local operator interface. It does not authenticate a remote user.
Exit 0: committed/read/prepared; 3: canonical refusal; 4: queue absent;
5: preparation conflicts; 2: input/infrastructure/output error.";

pub fn run(args: &[String]) -> Result<u8, String> {
    run_to(args, &mut std::io::stdout().lock())
}

fn run_to(args: &[String], out: &mut impl Write) -> Result<u8, String> {
    if args == ["--help"]
        || (args.len() == 2
            && args[1] == "--help"
            && matches!(
                args[0].as_str(),
                "show"
                    | "list"
                    | "enqueue"
                    | "dequeue"
                    | "reorder"
                    | "land"
                    | "prepare"
                    | "land-candidate"
            ))
    {
        write_read(out, USAGE)?;
        return Ok(0);
    }
    let options = options::parse(args)?;
    let bundle = match &options.operation {
        Operation::Prepare(preparation) => {
            crate::merge_apply::preparation::require_absent(&preparation.output)?;
            None
        }
        Operation::LandCandidate { bundle, .. } => Some(crate::publication_support::read_bundle(
            bundle,
            candidate::MAX_BUNDLE_BYTES,
        )?),
        _ => None,
    };
    let mut configuration =
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format);
    if let Some(incarnation) = options.incarnation {
        configuration = configuration.with_expected_repository_incarnation(incarnation);
    }
    let mut node = OneNode::open_existing(configuration)
        .map_err(|error| format!("cannot open queue node: {error}"))?;
    let incarnation = node.repository_incarnation_id();
    let service = node
        .bring_into_service(HeadGeneration::FIRST)
        .map_err(|error| error.to_string());
    let request = fgit_cli::command_request_context(&node);
    let result: Result<Completed, String> = match &options.operation {
        Operation::Mutate {
            principal,
            key,
            command,
        } => {
            // Exact outcome recovery precedes new-publication eligibility in
            // the node API, including when current service intake refuses.
            let session = LoopbackReceiveSession::authenticated(*principal, key.clone());
            node.runtime()
                .block_on(node.admit_queue_durable_in(
                    &request,
                    &session,
                    command,
                    Default::default(),
                ))
                .map(|(tx, outcome)| Completed::Mutation(tx, outcome))
                .map_err(|error| match service {
                    Ok(()) => error.to_string(),
                    Err(service) => format!("{error}; service intake also refused: {service}"),
                })
        }
        Operation::Land {
            principal,
            key,
            command,
        } => {
            let session = LoopbackReceiveSession::authenticated(*principal, key.clone());
            node.runtime()
                .block_on(node.land_queue_head_durable_in(
                    &request,
                    &session,
                    command,
                    Default::default(),
                ))
                .map(|(tx, outcome)| Completed::Mutation(tx, outcome))
                .map_err(|error| match service {
                    Ok(()) => error.to_string(),
                    Err(service) => format!("{error}; service intake also refused: {service}"),
                })
        }
        Operation::LandCandidate {
            principal,
            key,
            command,
            ..
        } => {
            let session = LoopbackReceiveSession::authenticated(*principal, key.clone());
            node.runtime()
                .block_on(node.land_queue_head_bundle_durable_in(
                    &request,
                    &session,
                    command,
                    bundle.as_deref().unwrap_or_default(),
                    Default::default(),
                ))
                .map(|(tx, outcome)| Completed::Mutation(tx, outcome))
                .map_err(|error| match service {
                    Ok(()) => error.to_string(),
                    Err(service) => format!("{error}; service intake also refused: {service}"),
                })
        }
        Operation::Prepare(preparation) => service.and_then(|()| {
            node.runtime()
                .block_on(node.prepare_queue_head_bundle_with_profile_in(
                    &request,
                    preparation.number,
                    preparation.expected_version,
                    &preparation.subject,
                    &Default::default(),
                    &preparation.metadata,
                    Default::default(),
                    preparation.profile,
                ))
                .map(|artifact| Completed::Prepared(Box::new(artifact)))
                .map_err(|error| error.to_string())
        }),
        Operation::Show {
            number,
            expected_head,
        } => service.and_then(|()| {
            node.runtime()
                .block_on(node.read_queue_in(
                    &request,
                    &Default::default(),
                    *number,
                    *expected_head,
                ))
                .map_err(|error| error.to_string())
                .and_then(|page| {
                    let report = output::show(
                        &options,
                        incarnation,
                        *number,
                        page.source_head,
                        page.queue.as_ref(),
                    )?;
                    Ok(Completed::Read(
                        report,
                        if page.queue.is_some() { 0 } else { 4 },
                    ))
                })
        }),
        Operation::List {
            after,
            limit,
            expected_head,
        } => service.and_then(|()| {
            node.runtime()
                .block_on(node.read_queues_in(
                    &request,
                    &Default::default(),
                    *after,
                    *limit,
                    *expected_head,
                ))
                .map_err(|error| error.to_string())
                .and_then(|page| {
                    output::list(
                        &options,
                        incarnation,
                        page.source_head,
                        &page.queues,
                        page.next_after,
                    )
                })
                .map(|report| Completed::Read(report, 0))
        }),
    };
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match result {
        Ok(Completed::Mutation(tx, terminal)) => finish(
            out,
            &options,
            incarnation,
            tx,
            &terminal,
            cleanup.as_deref(),
        ),
        Ok(Completed::Read(report, exit)) => {
            if let Some(error) = cleanup {
                return Err(format!("queue read shutdown failed: {error}"));
            }
            write_read(out, &report)?;
            Ok(exit)
        }
        Ok(Completed::Prepared(artifact)) => {
            if let Some(error) = cleanup {
                return Err(format!(
                    "queue preparation shutdown failed: {error}; no candidate bundle was published"
                ));
            }
            candidate::finish(out, &options, incarnation, &artifact)
        }
        Err(error) => {
            let cleanup = cleanup.map_or_else(String::new, |error| {
                format!("; node shutdown also failed: {error}")
            });
            if matches!(
                &options.operation,
                Operation::Mutate { .. } | Operation::Land { .. } | Operation::LandCandidate { .. }
            ) {
                Err(format!(
                    "no terminal queue outcome returned: {error}{cleanup}; this is not evidence of non-commit. Recover with fg outcome using the same principal and key, or retry the identical command, incarnation, versions and tips. Do not replace the key or refresh the expected versions"
                ))
            } else {
                Err(format!(
                    "queue read failed: {error}{cleanup}; no complete result returned"
                ))
            }
        }
    }
}

enum Completed {
    Mutation(TxId, TerminalOutcome),
    Read(String, u8),
    Prepared(Box<PreparedQueueHeadBundle>),
}

fn finish(
    out: &mut impl Write,
    options: &Options,
    incarnation: RepositoryIncarnationId,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    let report =
        output::publication(options, incarnation, tx, terminal, cleanup).map_err(|error| {
            format!(
                "{}; receipt rendering failed: {error}; cleanup: {cleanup:?}",
                describe(tx, terminal)
            )
        })?;
    write_terminal_receipt(out, &report, tx, terminal)
        .map_err(|error| format!("{error}; cleanup: {cleanup:?}"))?;
    if let Some(error) = cleanup {
        return Err(format!(
            "{}; node shutdown failed: {error}",
            describe(tx, terminal)
        ));
    }
    Ok(
        if matches!(terminal.outcome, DecisionOutcome::Committed { .. }) {
            0
        } else {
            3
        },
    )
}

fn write_read(out: &mut impl Write, text: &str) -> Result<(), String> {
    writeln!(out, "{text}")
        .and_then(|()| out.flush())
        .map_err(|error| format!("queue output failed: {error}; no complete result returned"))
}
