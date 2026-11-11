#![forbid(unsafe_code)]
//! Trusted-local maintenance of authority-bound outcome and full repository checkpoints.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use fgit_node::outcome_checkpoint::{
    MAX_REPOSITORY_CHECKPOINT_BYTES, MAX_REPOSITORY_CHECKPOINT_OBJECTS, OutcomeCheckpointLimits,
    OutcomeCheckpointReceipt, RepositoryCheckpointLimits, RepositoryCheckpointReceipt,
};
use fgit_node::{GitDaemonSessionTimeout, NodeConfig, OneNode};
use fgit_types::{
    HeadGeneration, RepositoryAuthorityHeadId, RepositoryCapsuleId, RepositoryId, TenantId,
};

use super::fsck::{head_token, parse_head};
use super::publication_support::quote;

const USAGE: &str =
    "usage: fg checkpoint outcomes <storage-root> <tenant-id> <repository-id> --trusted-local
  [--expected-head <snapshot-token>] [--max-decisions <1..65536>]
  [--max-bytes <1..16777216>] [--timeout-secs <1..3600>]
       fg checkpoint repository <storage-root> <tenant-id> <repository-id> --trusted-local
  [--expected-head <snapshot-token>] [--expected-generation <1..18446744073709551615>]
  [--max-decisions <1..65536>] [--max-bytes <1..16777216>]
  [--max-objects <1..1000000>] [--max-blob-bytes <1..1099511627776>]
  [--max-payload-bytes <1..1099511627776>] [--timeout-secs <1..3600>]

Build and verify retained terminal-outcome leaves, then bind their checkpoint
through an exact-predecessor authority-head replacement. The repository's
persisted SHA-1 or SHA-256 format is inferred. Source refs, forge state, and
terminal transaction outcomes stay unchanged. Repeating at an already
checkpointed head verifies the retained evidence and returns published=false.
--expected-head is an exact fence; a stale token refuses instead of retargeting.

Defaults: 65536 decisions, 16 MiB retained leaf payload, 300 seconds. Limits
apply to the cumulative retained set, including an already selected checkpoint.
The maintenance request uses the shorter of this deadline and a leading global
fg --timeout-secs policy. Each invocation has one deadline, not one per stage.

This trusted-local operation requires authority over the entire repository.
`outcomes` uses capsule profile DecisionHistoryWithAdmissionClosureV1 (terminal
outcomes and cumulative admitted-object membership; object payloads still
require another source). `repository` uses FullClosure and additionally verifies
every admitted Git object in fabric before root-last capsule activation.
Neither prunes history, collects garbage, or removes every history limit.

Exit 0: a verified checkpoint receipt after successful node shutdown.
Exit 2: invalid input, refusal, incomplete shutdown, or receipt output failure.
A missing receipt or timeout does not prove non-publication. Inspect current
authority before retrying; keep an original --expected-head fence if supplied.";

const REPOSITORY_USAGE: &str =
    "usage: fg checkpoint repository <storage-root> <tenant-id> <repository-id> --trusted-local
  [--expected-head <snapshot-token>] [--expected-generation <1..18446744073709551615>]
  [--max-decisions <1..65536>] [--max-bytes <1..16777216>]
  [--max-objects <1..1000000>] [--max-blob-bytes <1..1099511627776>]
  [--max-payload-bytes <1..1099511627776>] [--timeout-secs <1..3600>]

Build and verify a FullClosure RepositoryCapsule over the authenticated
authority head, cumulative retained outcomes, cumulative admitted-object
closure, and every admitted Git object in fabric, then activate the capsule
root-last through an exact-predecessor authority-head CAS. Repeating at an
already checkpointed FullClosure head re-verifies the capsule, outcome leaves,
and Git object graph and returns published=false.

--expected-head and --expected-generation are exact fences; a stale head or
generation refuses instead of retargeting.

Defaults: 65536 decisions, 16 MiB retained leaf payload, 100000 Git objects,
32 MiB per streamed blob, 1 GiB aggregate Git payload, 300 seconds.

Exit 0: a verified repository_checkpoint receipt after successful node shutdown.
Exit 2: invalid input, refusal, incomplete shutdown, or receipt output failure.
A missing receipt or timeout does not prove non-publication. Inspect current
authority before retrying; keep any original --expected-head/--expected-generation fence.";

#[derive(Debug)]
enum Scope {
    Outcomes(OutcomeCheckpointLimits),
    Repository(RepositoryCheckpointLimits),
}

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    scope: Scope,
    timeout: Duration,
}

#[derive(Clone, Debug)]
enum Receipt {
    Outcomes(OutcomeCheckpointReceipt),
    Repository(RepositoryCheckpointReceipt),
}

impl Receipt {
    const fn published(&self) -> bool {
        match self {
            Self::Outcomes(receipt) => receipt.published,
            Self::Repository(receipt) => receipt.published,
        }
    }

    const fn published_head(&self) -> RepositoryAuthorityHeadId {
        match self {
            Self::Outcomes(receipt) => receipt.published_head,
            Self::Repository(receipt) => receipt.published_head,
        }
    }

    const fn capsule_id(&self) -> RepositoryCapsuleId {
        match self {
            Self::Outcomes(receipt) => receipt.capsule_id,
            Self::Repository(receipt) => receipt.capsule_id,
        }
    }
}

fn positive(value: &str, maximum: u64, field: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{field} requires a positive decimal integer"));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && *value <= maximum)
        .ok_or_else(|| format!("{field} must be in 1..={maximum}"))
}

fn parse(args: &[String]) -> Result<Options, String> {
    let subcommand = args.first().map(String::as_str);
    let max_args = match subcommand {
        Some("outcomes") => 13,
        Some("repository") => 21,
        _ => return Err(USAGE.into()),
    };
    let usage = if subcommand == Some("repository") {
        REPOSITORY_USAGE
    } else {
        USAGE
    };
    if args.len() < 4
        || args.len() > max_args
        || args[1].is_empty()
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err(usage.into());
    }
    let mut timeout = Duration::from_secs(300);
    let mut seen = BTreeSet::new();
    let mut at = 4;
    let scope = if subcommand == Some("outcomes") {
        let mut limits = OutcomeCheckpointLimits::default();
        while let Some(flag) = args.get(at) {
            if !seen.insert(flag.as_str()) {
                return Err(format!("duplicate option: {flag}"));
            }
            at += 1;
            if flag == "--trusted-local" {
                continue;
            }
            let value = args
                .get(at)
                .ok_or_else(|| format!("missing value for {flag}"))?;
            at += 1;
            match flag.as_str() {
                "--expected-head" => limits.expected_head = Some(parse_head(value)?),
                "--max-decisions" => {
                    limits.max_decisions = positive(value, 65_536, flag)? as usize;
                }
                "--max-bytes" => {
                    limits.max_archive_bytes = positive(value, 16 * 1024 * 1024, flag)?;
                }
                "--timeout-secs" => timeout = Duration::from_secs(positive(value, 3600, flag)?),
                _ => return Err(format!("unsupported checkpoint option: {flag}")),
            }
        }
        if !seen.contains("--trusted-local") {
            return Err(
                "checkpoint outcomes requires --trusted-local and authority over the entire repository"
                    .into(),
            );
        }
        Scope::Outcomes(limits)
    } else {
        let mut limits = RepositoryCheckpointLimits::default();
        while let Some(flag) = args.get(at) {
            if !seen.insert(flag.as_str()) {
                return Err(format!("duplicate option: {flag}"));
            }
            at += 1;
            if flag == "--trusted-local" {
                continue;
            }
            let value = args
                .get(at)
                .ok_or_else(|| format!("missing value for {flag}"))?;
            at += 1;
            match flag.as_str() {
                "--expected-head" => limits.expected_head = Some(parse_head(value)?),
                "--expected-generation" => {
                    let generation = positive(value, u64::MAX, flag)?;
                    limits.expected_generation =
                        Some(HeadGeneration::try_new(generation).map_err(|e| e.to_string())?);
                }
                "--max-decisions" => {
                    limits.max_decisions = positive(value, 65_536, flag)? as usize;
                }
                "--max-bytes" => {
                    limits.max_archive_bytes = positive(value, 16 * 1024 * 1024, flag)?;
                }
                "--max-objects" => {
                    limits.max_objects =
                        positive(value, MAX_REPOSITORY_CHECKPOINT_OBJECTS as u64, flag)? as usize;
                }
                "--max-blob-bytes" => {
                    limits.max_blob_bytes = positive(value, MAX_REPOSITORY_CHECKPOINT_BYTES, flag)?;
                }
                "--max-payload-bytes" => {
                    limits.max_payload_bytes =
                        positive(value, MAX_REPOSITORY_CHECKPOINT_BYTES, flag)?;
                }
                "--timeout-secs" => timeout = Duration::from_secs(positive(value, 3600, flag)?),
                _ => return Err(format!("unsupported checkpoint option: {flag}")),
            }
        }
        if !seen.contains("--trusted-local") {
            return Err(
                "checkpoint repository requires --trusted-local and authority over the entire repository"
                    .into(),
            );
        }
        Scope::Repository(limits)
    };
    Ok(Options {
        storage: PathBuf::from(&args[1]),
        tenant: TenantId::from_hex(&args[2]).map_err(|error| error.to_string())?,
        repository: RepositoryId::from_hex(&args[3]).map_err(|error| error.to_string())?,
        scope,
        timeout,
    })
}

fn select_timeout(
    local: Duration,
    global: Option<Duration>,
) -> Result<GitDaemonSessionTimeout, String> {
    GitDaemonSessionTimeout::try_new(global.map_or(local, |global| local.min(global)))
        .map_err(|error| error.to_string())
}

pub fn run(arguments: &[String]) -> Result<u8, String> {
    if arguments == ["--help"] || arguments == ["outcomes", "--help"] {
        let mut output = std::io::stdout().lock();
        return writeln!(output, "{USAGE}")
            .and_then(|()| output.flush())
            .map(|()| 0)
            .map_err(|error| format!("checkpoint help output failed: {error}"));
    }
    if arguments == ["repository", "--help"] {
        let mut output = std::io::stdout().lock();
        return writeln!(output, "{REPOSITORY_USAGE}")
            .and_then(|()| output.flush())
            .map(|()| 0)
            .map_err(|error| format!("checkpoint help output failed: {error}"));
    }
    let options = parse(arguments)?;
    let timeout = select_timeout(
        options.timeout,
        fgit_cli::command_timeout_override_duration(),
    )?;
    // Leave the object format unpinned: existing native storage owns it.
    let mut config = NodeConfig::new(options.storage.clone(), options.tenant, options.repository);
    if let Scope::Repository(limits) = options.scope {
        let max_blob = usize::try_from(limits.max_blob_bytes)
            .map_err(|_| "--max-blob-bytes is not representable on this host".to_owned())?;
        config = config.with_selected_pack_blob_limit(max_blob);
    }
    let mut node = OneNode::open_existing(config).map_err(|error| error.to_string())?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|error| error.to_string())?;
        let request = node.command_request_context(Some(timeout));
        match options.scope {
            Scope::Outcomes(limits) => node
                .runtime()
                .block_on(node.checkpoint_outcomes_in(&request, limits))
                .map(Receipt::Outcomes)
                .map_err(|error| error.to_string()),
            Scope::Repository(limits) => node
                .runtime()
                .block_on(node.checkpoint_repository_in(&request, limits))
                .map(Receipt::Repository)
                .map_err(|error| error.to_string()),
        }
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    finish(
        &mut std::io::stdout().lock(),
        &options,
        result,
        cleanup.as_deref(),
    )
}

fn render(options: &Options, receipt: &Receipt) -> String {
    match receipt {
        Receipt::Outcomes(receipt) => format!(
            concat!(
                "{{\"type\":\"outcome_checkpoint\",\"schema_version\":1,",
                "\"tenant_id\":{},\"repository_id\":{},",
                "\"source_head\":{},\"published_head\":{},\"authority_generation\":{},",
                "\"capsule_id\":{},\"checkpoint_root\":{},",
                "\"decisions\":{},\"leaf_objects\":{},\"leaf_bytes\":{},\"published\":{},",
                "\"scope\":\"outcome_index_maintenance\",\"backup_profile\":{},",
                "\"complete\":true,\"node_closed\":true}}"
            ),
            quote(&options.tenant.to_string()),
            quote(&options.repository.to_string()),
            quote(&head_token(receipt.source_head)),
            quote(&head_token(receipt.published_head)),
            receipt.generation.get(),
            quote(&receipt.capsule_id.to_string()),
            quote(&receipt.checkpoint_root.to_string()),
            receipt.decisions,
            receipt.leaf_objects,
            receipt.leaf_bytes,
            receipt.published,
            quote(receipt.backup_profile),
        ),
        Receipt::Repository(receipt) => format!(
            concat!(
                "{{\"type\":\"repository_checkpoint\",\"schema_version\":1,",
                "\"tenant_id\":{},\"repository_id\":{},",
                "\"source_head\":{},\"published_head\":{},\"authority_generation\":{},",
                "\"capsule_id\":{},\"checkpoint_root\":{},\"object_closure_root\":{},",
                "\"decisions\":{},\"leaf_objects\":{},\"leaf_bytes\":{},",
                "\"objects\":{},\"references\":{},\"payload_bytes\":{},",
                "\"local_edges\":{},\"external_gitlinks\":{},\"published\":{},",
                "\"scope\":\"repository_full_closure\",\"backup_profile\":{},",
                "\"complete\":true,\"node_closed\":true}}"
            ),
            quote(&options.tenant.to_string()),
            quote(&options.repository.to_string()),
            quote(&head_token(receipt.source_head)),
            quote(&head_token(receipt.published_head)),
            receipt.generation.get(),
            quote(&receipt.capsule_id.to_string()),
            quote(&receipt.checkpoint_root.to_string()),
            quote(&receipt.object_closure_root.to_string()),
            receipt.decisions,
            receipt.leaf_objects,
            receipt.leaf_bytes,
            receipt.objects,
            receipt.references,
            receipt.payload_bytes,
            receipt.local_edges,
            receipt.external_gitlinks,
            receipt.published,
            quote(receipt.backup_profile),
        ),
    }
}

fn observed(receipt: &Receipt) -> String {
    format!(
        "{} at authority head {} (capsule {})",
        if receipt.published() {
            "checkpoint activation was observed"
        } else {
            "an already selected checkpoint was verified; no new activation was needed"
        },
        head_token(receipt.published_head()),
        receipt.capsule_id(),
    )
}

fn finish(
    output: &mut impl Write,
    options: &Options,
    result: Result<Receipt, String>,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    let receipt = match result {
        Ok(receipt) => receipt,
        Err(error) => {
            return Err(format!(
                "no checkpoint receipt returned: {error}{}; this does not prove non-publication. Inspect current authority before retrying; retain any original --expected-head fence",
                cleanup.map_or_else(String::new, |error| format!(
                    "; node shutdown also failed: {error}"
                )),
            ));
        }
    };
    // Shutdown or a failed stdout cannot erase the authority observation.
    // A complete success record is emitted only after shutdown succeeded.
    if let Some(error) = cleanup {
        return Err(format!(
            "{}; node shutdown failed: {error}; no complete receipt emitted",
            observed(&receipt),
        ));
    }
    writeln!(output, "{}", render(options, &receipt))
        .and_then(|()| output.flush())
        .map_err(|error| format!("{}; receipt output failed: {error}", observed(&receipt),))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_schema::json::{self, Value};
    use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
    use fgit_types::{CANONICAL_CODEC_VERSION, Digest, RepositoryCapsuleId};

    fn args(extra: &[&str]) -> Vec<String> {
        let mut values = [
            "outcomes",
            "node",
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "--trusted-local",
        ]
        .map(str::to_owned)
        .to_vec();
        values.extend(extra.iter().map(|value| (*value).to_owned()));
        values
    }

    fn repo_args(extra: &[&str]) -> Vec<String> {
        let mut values = [
            "repository",
            "node",
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "--trusted-local",
        ]
        .map(str::to_owned)
        .to_vec();
        values.extend(extra.iter().map(|value| (*value).to_owned()));
        values
    }

    #[test]
    fn parser_accepts_bounded_maintenance_and_exact_head() {
        let defaults = parse(&args(&[])).unwrap();
        let Scope::Outcomes(default_limits) = defaults.scope else {
            panic!("expected outcomes scope");
        };
        assert_eq!(default_limits.max_decisions, 65_536);
        assert_eq!(default_limits.max_archive_bytes, 16 * 1024 * 1024);
        assert_eq!(defaults.timeout, Duration::from_secs(300));
        assert!(default_limits.expected_head.is_none());
        let token = format!("alg:1:{}", "ab".repeat(32));
        let options = parse(&args(&[
            "--max-decisions",
            "1",
            "--max-bytes",
            "16777216",
            "--timeout-secs",
            "3600",
            "--expected-head",
            &token,
        ]))
        .unwrap();
        let Scope::Outcomes(limits) = options.scope else {
            panic!("expected outcomes scope");
        };
        assert_eq!(limits.max_decisions, 1);
        assert_eq!(options.timeout, Duration::from_secs(3600));
        assert_eq!(head_token(limits.expected_head.unwrap()), token);

        let repo_defaults = parse(&repo_args(&[])).unwrap();
        let Scope::Repository(repo_limits) = repo_defaults.scope else {
            panic!("expected repository scope");
        };
        assert_eq!(repo_limits.max_objects, 100_000);
        assert_eq!(repo_limits.max_blob_bytes, 32 * 1024 * 1024);
        assert_eq!(repo_limits.max_payload_bytes, 1024 * 1024 * 1024);
        assert!(repo_limits.expected_generation.is_none());
        let repo_options = parse(&repo_args(&[
            "--expected-head",
            &token,
            "--expected-generation",
            "9",
            "--max-objects",
            "1000000",
            "--max-blob-bytes",
            "67108864",
            "--max-payload-bytes",
            "2147483648",
        ]))
        .unwrap();
        let Scope::Repository(repo_limits) = repo_options.scope else {
            panic!("expected repository scope");
        };
        assert_eq!(head_token(repo_limits.expected_head.unwrap()), token);
        assert_eq!(repo_limits.expected_generation.unwrap().get(), 9);
        assert_eq!(repo_limits.max_objects, 1_000_000);
        assert_eq!(repo_limits.max_blob_bytes, 64 * 1024 * 1024);
        assert_eq!(repo_limits.max_payload_bytes, 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn parser_refuses_untrusted_duplicate_unbounded_and_malformed_options() {
        let mut missing = args(&[]);
        missing.pop();
        assert!(
            parse(&missing)
                .unwrap_err()
                .contains("requires --trusted-local")
        );
        let mut missing_repo = repo_args(&[]);
        missing_repo.pop();
        assert!(
            parse(&missing_repo)
                .unwrap_err()
                .contains("requires --trusted-local")
        );
        for extra in [
            vec!["--trusted-local"],
            vec!["--max-decisions", "0"],
            vec!["--max-decisions", "65537"],
            vec!["--max-decisions", "1", "--max-decisions", "2"],
            vec!["--max-bytes", "0"],
            vec!["--max-bytes", "16777217"],
            vec!["--max-bytes", "18446744073709551616"],
            vec!["--timeout-secs", "0"],
            vec!["--timeout-secs", "3601"],
            vec!["--timeout-secs", "1.5"],
            vec!["--timeout-secs", "+1"],
            vec!["--expected-head", "unqualified"],
            vec!["--expected-head", "alg:01:abcd"],
            vec!["--max-decisions"],
            vec!["--prune", "true"],
            vec!["--object-format", "sha1"],
            vec!["--max-objects", "10"],
        ] {
            assert!(parse(&args(&extra)).is_err(), "{extra:?}");
        }
        for extra in [
            vec!["--trusted-local"],
            vec!["--expected-generation", "0"],
            vec!["--max-objects", "0"],
            vec!["--max-objects", "1000001"],
            vec!["--max-blob-bytes", "0"],
            vec!["--max-blob-bytes", "1099511627777"],
            vec!["--max-payload-bytes", "0"],
            vec!["--max-payload-bytes", "1099511627777"],
        ] {
            assert!(parse(&repo_args(&extra)).is_err(), "{extra:?}");
        }
        let mut oversized = args(&[]);
        oversized[1] = "x".repeat(8193);
        assert!(parse(&oversized).is_err());
        let mut bad_command = args(&[]);
        bad_command[0] = "unknown".into();
        assert!(parse(&bad_command).is_err());
    }

    #[test]
    fn local_timeout_cannot_override_a_shorter_global_deadline() {
        let local = Duration::from_secs(300);
        for (global, expected) in [
            (None, local),
            (Some(Duration::from_secs(3600)), local),
            (Some(Duration::from_millis(1)), Duration::from_millis(1)),
        ] {
            assert_eq!(select_timeout(local, global).unwrap().duration(), expected);
        }
    }

    fn receipt(published: bool) -> Receipt {
        let source_head = parse_head(&format!("alg:1:{}", "12".repeat(32))).unwrap();
        let published_head = if published {
            parse_head(&format!("alg:1:{}", "34".repeat(32))).unwrap()
        } else {
            source_head
        };
        let algorithm = DigestAlgorithmId::try_new(1).unwrap();
        let bytes = DigestBytes::try_new(&[0x56; 32]).unwrap();
        Receipt::Outcomes(OutcomeCheckpointReceipt {
            source_head,
            published_head,
            generation: HeadGeneration::try_new(3).unwrap(),
            capsule_id: RepositoryCapsuleId::from_digest(algorithm, CANONICAL_CODEC_VERSION, bytes),
            checkpoint_root: Digest::new(algorithm, bytes),
            backup_profile: "decision_history_with_admission_closure_v1",
            decisions: 7,
            leaf_objects: 1,
            leaf_bytes: 1024,
            published,
        })
    }

    fn repository_receipt(published: bool) -> Receipt {
        let source_head = parse_head(&format!("alg:1:{}", "12".repeat(32))).unwrap();
        let published_head = if published {
            parse_head(&format!("alg:1:{}", "34".repeat(32))).unwrap()
        } else {
            source_head
        };
        let algorithm = DigestAlgorithmId::try_new(1).unwrap();
        let bytes = DigestBytes::try_new(&[0x56; 32]).unwrap();
        let closure_bytes = DigestBytes::try_new(&[0x78; 32]).unwrap();
        Receipt::Repository(RepositoryCheckpointReceipt {
            source_head,
            published_head,
            generation: HeadGeneration::try_new(4).unwrap(),
            capsule_id: RepositoryCapsuleId::from_digest(algorithm, CANONICAL_CODEC_VERSION, bytes),
            checkpoint_root: Digest::new(algorithm, bytes),
            object_closure_root: Digest::new(algorithm, closure_bytes),
            backup_profile: "full_closure",
            decisions: 7,
            leaf_objects: 1,
            leaf_bytes: 1024,
            objects: 12,
            references: 3,
            payload_bytes: 4096,
            local_edges: 9,
            external_gitlinks: 0,
            published,
        })
    }

    struct BrokenOutput {
        fail_flush: bool,
    }
    impl Write for BrokenOutput {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if self.fail_flush {
                Ok(data.len())
            } else {
                Err(std::io::Error::other("broken write"))
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("broken flush"))
        }
    }

    #[test]
    fn completion_receipt_binds_observed_authority_after_shutdown() {
        let options = parse(&args(&[])).unwrap();
        for published in [false, true] {
            let receipt = receipt(published);
            let mut output = Vec::new();
            assert_eq!(
                finish(&mut output, &options, Ok(receipt.clone()), None),
                Ok(0)
            );
            let value = json::parse(&output).unwrap();
            let fields = value.object().unwrap();
            assert_eq!(fields["published"], Value::Bool(published));
            assert_eq!(fields["complete"], Value::Bool(true));
            assert_eq!(fields["node_closed"], Value::Bool(true));
            assert_eq!(
                fields["backup_profile"].text(),
                Some("decision_history_with_admission_closure_v1")
            );
            assert_eq!(
                fields["published_head"].text(),
                Some(head_token(receipt.published_head()).as_str())
            );
            assert_eq!(fields["decisions"].unsigned(), Some(7));
        }

        let repo_options = parse(&repo_args(&[])).unwrap();
        for published in [false, true] {
            let receipt = repository_receipt(published);
            let mut output = Vec::new();
            assert_eq!(
                finish(&mut output, &repo_options, Ok(receipt.clone()), None),
                Ok(0)
            );
            let value = json::parse(&output).unwrap();
            let fields = value.object().unwrap();
            assert_eq!(fields["type"].text(), Some("repository_checkpoint"));
            assert_eq!(fields["scope"].text(), Some("repository_full_closure"));
            assert_eq!(fields["backup_profile"].text(), Some("full_closure"));
            assert_eq!(fields["published"], Value::Bool(published));
            assert_eq!(fields["objects"].unsigned(), Some(12));
            assert_eq!(fields["references"].unsigned(), Some(3));
            assert_eq!(fields["payload_bytes"].unsigned(), Some(4096));
            assert_eq!(fields["local_edges"].unsigned(), Some(9));
            assert_eq!(fields["external_gitlinks"].unsigned(), Some(0));
            assert!(fields["object_closure_root"].text().is_some());
        }
    }

    #[test]
    fn cleanup_and_sink_failures_preserve_the_publication_observation() {
        let options = parse(&args(&[])).unwrap();
        for published in [false, true] {
            let receipt = receipt(published);
            let description = observed(&receipt);
            let mut output = Vec::new();
            let error = finish(
                &mut output,
                &options,
                Ok(receipt.clone()),
                Some("containment"),
            )
            .unwrap_err();
            assert!(output.is_empty(), "failed cleanup cannot emit success");
            assert!(error.contains(&description));
            assert!(error.contains("containment"));
            for fail_flush in [false, true] {
                let error = finish(
                    &mut BrokenOutput { fail_flush },
                    &options,
                    Ok(receipt.clone()),
                    None,
                )
                .unwrap_err();
                assert!(error.contains(&description));
                assert!(error.contains("receipt output failed"));
            }
        }
        let mut output = Vec::new();
        let error = finish(
            &mut output,
            &options,
            Err("activation response lost".into()),
            Some("containment"),
        )
        .unwrap_err();
        assert!(output.is_empty());
        assert!(error.contains("activation response lost"));
        assert!(error.contains("containment"));
        assert!(error.contains("does not prove non-publication"));
    }
}
