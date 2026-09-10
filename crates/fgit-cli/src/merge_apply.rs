//! Native merge preparation and independently reviewed artifact publication.
//! Preparation and Ref + Forge + Outbox publication remain separate commands.

pub(crate) mod preparation;

use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::NativeMerge;
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RefName, RepositoryId, TenantId, TxId};
use std::path::PathBuf;

use super::publication_support::{describe, parse_oid, quote, read_bundle, set_once, write_terminal_receipt};

const MAX_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
const USAGE: &str = "usage: fg merge apply <storage-root> <tenant-id> <repository-id> <target-ref> <bundle-path> --trusted-local --principal <principal-id> --idempotency-key <key> --source-ref <branch> --expected-source <oid> --expected-target <oid> --merge-base <oid> --expected-commit <reviewed-oid> --pull-request <number> --expected-version <version; 0=new stream>";

struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    bundle: PathBuf,
    principal: PrincipalId,
    key: Vec<u8>,
    pull_request: PullRequestNumber,
    version: ExpectedVersion,
    version_number: u64,
    pull_request_number: u64,
    merge: NativeMerge,
}

pub(super) fn run(arguments: &[String]) -> Result<(), String> {
    if arguments.first().is_some_and(|argument| argument == "prepare" || argument == "resolve") {
        return preparation::run(arguments);
    }
    if arguments == ["--help"] {
        println!("{}\n\n{}\n\n{USAGE}", preparation::USAGE, preparation::RESOLUTION_USAGE);
        return Ok(());
    }
    if arguments == ["apply", "--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let options = parse(arguments)?;
    let input = read_bundle(&options.bundle, MAX_BUNDLE_BYTES)?;
    let mut node = OneNode::open_existing(NodeConfig::new(
        options.storage.clone(), options.tenant, options.repository,
    ).with_object_format(options.merge.merge_commit.algorithm()))
        .map_err(|error| error.to_string())?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        node.runtime().block_on(node.apply_merge_bundle_durable_in(
            &request, options.principal, &options.key, options.pull_request,
            options.version, &options.merge, &input,
        )).map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let (tx_id, terminal) = match operation {
        Ok(decision) => decision,
        Err(error) => {
            let cleanup = cleanup.as_ref().map_or_else(String::new,
                |error| format!("; node shutdown also failed: {error}"));
            return Err(format!("no terminal outcome returned: {error}{cleanup}; this is not evidence of non-commit. Retry the identical reviewed bundle, principal, key, source/target/base/candidate coordinates and PR version to reconcile; do not recompute a merge or change the key to recover this attempt"));
        }
    };
    let receipt = render_receipt(&options, tx_id, &terminal, cleanup.as_deref());
    if let Err(error) = write_terminal_receipt(&mut std::io::stdout().lock(), &receipt, tx_id, &terminal) {
        return Err(cleanup.as_ref().map_or_else(|| error.clone(),
            |cleanup| format!("{error}; node shutdown also failed: {cleanup}")));
    }
    if let Some(error) = cleanup {
        return Err(format!("{}; node shutdown failed: {error}", describe(tx_id, &terminal)));
    }
    match terminal.outcome {
        DecisionOutcome::Committed { .. } => Ok(()),
        DecisionOutcome::Refused { .. } => Err(describe(tx_id, &terminal)),
    }
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 6 || arguments[0] != "apply" {
        return Err(USAGE.to_owned());
    }
    if arguments.len() > 32 || arguments.iter().any(|arg| arg.len() > 4096) {
        return Err("merge apply arguments exceed the bounded local command profile".to_owned());
    }
    if arguments[1].is_empty() || arguments[5].is_empty() {
        return Err("storage root and reviewed bundle path must be nonempty".to_owned());
    }
    let tenant = TenantId::from_hex(&arguments[2]).map_err(|error| error.to_string())?;
    let repository = RepositoryId::from_hex(&arguments[3]).map_err(|error| error.to_string())?;
    let target_ref = RefName::try_new(arguments[4].as_bytes()).map_err(|error| error.to_string())?;
    let (mut principal, mut key, mut source_ref, mut source_tip) = (None, None, None, None);
    let (mut target_tip, mut base_tip, mut candidate, mut number, mut version) = (None, None, None, None, None);
    let mut trusted = false;
    let mut cursor = 6;
    while cursor < arguments.len() {
        let flag = arguments[cursor].as_str();
        cursor += 1;
        if flag == "--trusted-local" {
            if trusted { return Err("duplicate --trusted-local".to_owned()); }
            trusted = true;
            continue;
        }
        let value = arguments.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag {
            "--principal" => set_once(&mut principal,
                PrincipalId::from_hex(value).map_err(|error| error.to_string())?, flag)?,
            "--idempotency-key" => {
                IdempotencyKey::new(value.as_bytes().to_vec())
                    .map_err(|_| "invalid bounded idempotency key".to_owned())?;
                set_once(&mut key, value.as_bytes().to_vec(), flag)?;
            }
            "--source-ref" => set_once(&mut source_ref,
                RefName::try_new(value.as_bytes()).map_err(|error| error.to_string())?, flag)?,
            "--expected-source" => set_once(&mut source_tip, parse_oid(value)?, flag)?,
            "--expected-target" => set_once(&mut target_tip, parse_oid(value)?, flag)?,
            "--merge-base" => set_once(&mut base_tip, parse_oid(value)?, flag)?,
            "--expected-commit" => set_once(&mut candidate, parse_oid(value)?, flag)?,
            "--pull-request" => set_once(&mut number, decimal(value, flag)?, flag)?,
            "--expected-version" => set_once(&mut version, decimal(value, flag)?, flag)?,
            _ => return Err(format!("unknown merge apply option {flag}; implicit or forced merges are not supported")),
        }
    }
    if !trusted {
        return Err("--trusted-local is required: the local operator authorizes this principal and repository mutation".to_owned());
    }
    let number = number.ok_or("--pull-request is required")?;
    let pull_request = PullRequestNumber::try_new(number).ok_or("pull request number must be positive")?;
    let version_number = version.ok_or("--expected-version is required; 0 explicitly selects a new merge-receipt stream")?;
    let version = if version_number == 0 {
        ExpectedVersion::NewStream
    } else {
        let version = AggregateVersion::try_new(version_number).ok_or("invalid aggregate version")?;
        version.next().map_err(|_| "aggregate version is exhausted")?;
        ExpectedVersion::Exactly(version)
    };
    let merge = NativeMerge {
        source_ref: source_ref.ok_or("--source-ref is required")?,
        source_tip: source_tip.ok_or("--expected-source is required")?,
        base_tip: base_tip.ok_or("--merge-base is required")?,
        target_ref,
        target_tip_before: target_tip.ok_or("--expected-target is required")?,
        merge_commit: candidate.ok_or("--expected-commit is required and must name the reviewed commit")?,
    };
    merge.validate().map_err(|error| format!("invalid reviewed merge coordinates: {error:?}"))?;
    if !merge.source_ref.as_bytes().starts_with(b"refs/heads/")
        || !merge.target_ref.as_bytes().starts_with(b"refs/heads/")
        || merge.source_ref == merge.target_ref
        || merge.source_tip == merge.target_tip_before
        || merge.merge_commit == merge.source_tip
        || merge.merge_commit == merge.target_tip_before
    {
        return Err("merge apply requires distinct branch refs, distinct parent tips and a new two-parent candidate".to_owned());
    }
    Ok(Options {
        storage: arguments[1].clone().into(), tenant, repository,
        bundle: arguments[5].clone().into(), principal: principal.ok_or("--principal is required")?,
        key: key.ok_or("--idempotency-key is required")?, pull_request, version,
        version_number, pull_request_number: number, merge,
    })
}

fn decimal(value: &str, field: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!("{field} must be a canonical nonnegative decimal integer"));
    }
    value.parse().map_err(|_| format!("{field} exceeds the integer limit"))
}

fn render_receipt(options: &Options, tx_id: TxId, terminal: &TerminalOutcome, cleanup: Option<&str>) -> String {
    let (status, published, rcr, code, refusal) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } =>
            ("committed", true, quote(&repository_commit_id.to_string()), "null".to_owned(), "null".to_owned()),
        DecisionOutcome::Refused { code, refusal_record_id } =>
            ("refused", false, "null".to_owned(), quote(&format!("{code:?}")), quote(&refusal_record_id.to_string())),
    };
    let hex = |name: &RefName| name.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let fields = [
        "\"type\":\"merge_publication\"".to_owned(),
        format!("\"outcome\":\"{status}\""),
        format!("\"published_to_repository\":{published}"),
        format!("\"tx_id\":{}", quote(&tx_id.to_string())),
        format!("\"decision_sequence\":{}", terminal.decision_sequence.get()),
        format!("\"repository_commit_id\":{rcr}"),
        format!("\"refusal_code\":{code}"),
        format!("\"refusal_record_id\":{refusal}"),
        format!("\"repository_id\":{}", quote(&options.repository.to_string())),
        format!("\"pull_request\":{}", options.pull_request_number),
        format!("\"expected_version\":{}", options.version_number),
        format!("\"source_reference_hex\":\"{}\"", hex(&options.merge.source_ref)),
        format!("\"target_reference_hex\":\"{}\"", hex(&options.merge.target_ref)),
        format!("\"expected_source\":\"{}\"", options.merge.source_tip),
        format!("\"expected_target\":\"{}\"", options.merge.target_tip_before),
        format!("\"merge_base\":\"{}\"", options.merge.base_tip),
        format!("\"candidate_commit\":\"{}\"", options.merge.merge_commit),
        // Publication does not observe a destination acknowledgement. A retry
        // may return a historical decision whose delivery has since advanced.
        "\"delivery_acknowledged\":null".to_owned(),
        format!("\"node_closed\":{}", cleanup.is_none()),
        format!("\"cleanup_error\":{}", cleanup.map_or_else(|| "null".to_owned(), quote)),
    ];
    format!("{{{}}}", fields.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(width: usize) -> Vec<String> {
        vec!["apply".into(), "node".into(), "11".repeat(16), "22".repeat(16),
            "refs/heads/main".into(), "reviewed.bundle".into(), "--trusted-local".into(),
            "--principal".into(), "33".repeat(16), "--idempotency-key".into(), "private-retry-key".into(),
            "--source-ref".into(), "refs/heads/topic".into(), "--expected-source".into(), "a".repeat(width),
            "--expected-target".into(), "b".repeat(width), "--merge-base".into(), "c".repeat(width),
            "--expected-commit".into(), "d".repeat(width), "--pull-request".into(), "17".into(),
            "--expected-version".into(), "0".into()]
    }
    fn replace(arguments: &mut [String], flag: &str, value: String) {
        let at = arguments.iter().position(|arg| arg == flag).unwrap();
        arguments[at + 1] = value;
    }

    #[test]
    fn all_review_coordinates_are_required_in_both_hash_domains() {
        for width in [40, 64] {
            let options = parse(&args(width)).unwrap();
            assert_eq!(options.merge.source_tip.to_string(), "a".repeat(width));
            assert_eq!(options.merge.target_tip_before.to_string(), "b".repeat(width));
            assert_eq!(options.merge.merge_commit.to_string(), "d".repeat(width));
            assert_eq!(options.version, ExpectedVersion::NewStream);
            for flag in ["--principal", "--idempotency-key", "--source-ref", "--expected-source",
                "--expected-target", "--merge-base", "--expected-commit", "--pull-request", "--expected-version"]
            {
                let mut missing = args(width);
                let at = missing.iter().position(|arg| arg == flag).unwrap();
                missing.drain(at..at + 2);
                assert!(parse(&missing).is_err(), "missing {flag}");
            }
        }
    }

    #[test]
    fn trust_unknown_options_and_every_duplicate_are_rejected_before_io() {
        let mut missing = args(40);
        missing.retain(|arg| arg != "--trusted-local");
        assert!(parse(&missing).is_err());
        for flag in ["--principal", "--idempotency-key", "--source-ref", "--expected-source",
            "--expected-target", "--merge-base", "--expected-commit", "--pull-request", "--expected-version"]
        {
            let mut duplicate = args(40);
            let at = duplicate.iter().position(|arg| arg == flag).unwrap();
            duplicate.extend([flag.to_owned(), duplicate[at + 1].clone()]);
            assert!(parse(&duplicate).is_err(), "duplicate {flag}");
        }
        for extra in [vec!["--trusted-local"], vec!["--force", "true"], vec!["--approve", "yes"]] {
            let mut invalid = args(40);
            invalid.extend(extra.into_iter().map(str::to_owned));
            assert!(parse(&invalid).is_err());
        }
    }

    #[test]
    fn versions_parent_domains_and_aliases_are_not_guessed() {
        for value in ["-1", "+1", "01", "18446744073709551616", "18446744073709551615"] {
            let mut invalid = args(40);
            replace(&mut invalid, "--expected-version", value.to_owned());
            assert!(parse(&invalid).is_err());
        }
        let mut existing = args(40);
        replace(&mut existing, "--expected-version", "4".to_owned());
        assert_eq!(parse(&existing).unwrap().version,
            ExpectedVersion::Exactly(AggregateVersion::try_new(4).unwrap()));
        for (flag, value) in [
            ("--pull-request", "0".to_owned()), ("--expected-source", "0".repeat(40)),
            ("--expected-source", "a".repeat(64)), ("--expected-source", "b".repeat(40)),
            ("--expected-commit", "b".repeat(40)), ("--source-ref", "refs/heads/main".to_owned()),
            ("--source-ref", "refs/tags/topic".to_owned()),
        ] {
            let mut invalid = args(40);
            replace(&mut invalid, flag, value);
            assert!(parse(&invalid).is_err(), "invalid {flag}");
        }
        assert!(parse(&args(40)).is_ok());
    }

    #[test]
    fn receipt_binds_the_review_without_exposing_the_key_or_claiming_delivery() {
        use fgit_types::{CANONICAL_CODEC_VERSION, DecisionSequence, RepositoryCommitId};
        use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
        let algorithm = DigestAlgorithmId::try_new(2).unwrap();
        let digest = DigestBytes::try_new(&[0x42; 32]).unwrap();
        let tx = TxId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest);
        let terminal = TerminalOutcome {
            decision_sequence: DecisionSequence::try_new(2).unwrap(),
            outcome: DecisionOutcome::Committed {
                repository_commit_id: RepositoryCommitId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest),
            },
        };
        let options = parse(&args(40)).unwrap();
        let receipt = render_receipt(&options, tx, &terminal, Some("close\nfailed"));
        assert!(receipt.contains("\"type\":\"merge_publication\""));
        assert!(receipt.contains("\"pull_request\":17"));
        assert!(receipt.contains("\"delivery_acknowledged\":null"));
        assert!(receipt.contains("\"published_to_repository\":true"));
        assert!(receipt.contains("\"node_closed\":false"));
        assert!(receipt.contains("close\\u000afailed"));
        assert!(!receipt.contains("private-retry-key"));
        assert!(receipt.contains(&format!("\"candidate_commit\":\"{}\"", "d".repeat(40))));
    }
}
