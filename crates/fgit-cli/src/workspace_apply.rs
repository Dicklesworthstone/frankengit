//! Explicit publication of a previously reviewed workspace bundle.
//!
//! Parsing and artifact intake precede node opening. Terminal repository
//! decisions survive shutdown/output failures: a failed cleanup is not an
//! excuse to tell an operator that an acknowledged commit did not happen.

use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitOid, HeadGeneration, PrincipalId,
    RefName, RepositoryId, TenantId, TxId};
use std::path::PathBuf;
#[cfg(test)]
use std::{fs, io::Write};

use super::publication_support::{describe, parse_oid, quote, read_bundle, set_once, write_terminal_receipt};

const MAX_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
const USAGE: &str = "usage: fg workspace apply <storage-root> <tenant-id> <repository-id> <ref> <bundle-path> --trusted-local --principal <principal-id> --idempotency-key <key> --expected-base <native-oid> --expected-commit <reviewed-native-oid>";

struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    reference: RefName,
    bundle: PathBuf,
    principal: PrincipalId,
    key: Vec<u8>,
    base: GitOid,
    candidate: GitOid,
}

pub(super) fn run(arguments: &[String]) -> Result<(), String> {
    let options = parse(arguments)?;
    let input = read_bundle(&options.bundle, MAX_BUNDLE_BYTES)?;
    let mut node = OneNode::open_existing(NodeConfig::new(
        options.storage.clone(), options.tenant, options.repository,
    )).map_err(|error| error.to_string())?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        let result = node.runtime().block_on(node.apply_workspace_bundle_durable_in(
            &request, options.principal, &options.key, &options.reference,
            options.base, options.candidate, &input,
        )).map_err(|error| error.to_string())?;
        match result.commands.as_slice() {
            [command] => Ok((command.tx_id, command.terminal)),
            _ => Err("publication returned an unexpected outcome mapping; do not infer non-commit".to_owned()),
        }
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let (tx_id, terminal) = match operation {
        Ok(decision) => decision,
        Err(error) => {
            let cleanup = cleanup.as_ref().map_or_else(String::new,
                |error| format!("; node shutdown also failed: {error}"));
            return Err(format!("no terminal outcome returned: {error}{cleanup}; this is not evidence of non-commit. Reconcile by retrying the identical bundle, expectations, principal and idempotency key; do not rerun the tool or change the key to recover this attempt"));
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
    let tenant = TenantId::from_hex(&arguments[2]).map_err(|error| error.to_string())?;
    let repository = RepositoryId::from_hex(&arguments[3]).map_err(|error| error.to_string())?;
    let reference = RefName::try_new(arguments[4].as_bytes()).map_err(|error| error.to_string())?;
    if !reference.as_bytes().starts_with(b"refs/heads/") {
        return Err("workspace apply requires a fully qualified branch ref".to_owned());
    }
    let (mut principal, mut key, mut base, mut candidate) = (None, None, None, None);
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
            "--expected-base" => set_once(&mut base, parse_oid(value)?, flag)?,
            "--expected-commit" => set_once(&mut candidate, parse_oid(value)?, flag)?,
            _ => return Err(format!("unknown workspace apply option {flag}; no force option is supported")),
        }
    }
    if !trusted {
        return Err("--trusted-local is required: the local operator authorizes this principal and repository mutation".to_owned());
    }
    let base = base.ok_or("--expected-base is required")?;
    let candidate = candidate.ok_or("--expected-commit is required and must name the reviewed commit")?;
    if base.algorithm() != candidate.algorithm() || base == candidate {
        return Err("expected base and reviewed commit must be distinct nonzero IDs in the same native hash domain".to_owned());
    }
    Ok(Options {
        storage: arguments[1].clone().into(), tenant, repository, reference,
        bundle: arguments[5].clone().into(),
        principal: principal.ok_or("--principal is required")?,
        key: key.ok_or("--idempotency-key is required")?, base, candidate,
    })
}

fn render_receipt(options: &Options, tx_id: TxId, terminal: &TerminalOutcome, cleanup: Option<&str>) -> String {
    let (status, published, rcr, code, refusal) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } =>
            ("committed", true, quote(&repository_commit_id.to_string()), "null".to_owned(), "null".to_owned()),
        DecisionOutcome::Refused { code, refusal_record_id } =>
            ("refused", false, "null".to_owned(), quote(&format!("{code:?}")), quote(&refusal_record_id.to_string())),
    };
    let reference: String = options.reference.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
    let cleanup_text = cleanup.map_or_else(|| "null".to_owned(), quote);
    format!("{{\"type\":\"workspace_publication\",\"outcome\":\"{status}\",\"published_to_repository\":{published},\"tx_id\":{},\"decision_sequence\":{},\"repository_commit_id\":{rcr},\"refusal_code\":{code},\"refusal_record_id\":{refusal},\"expected_base\":\"{}\",\"candidate_commit\":\"{}\",\"reference_hex\":\"{reference}\",\"node_closed\":{},\"cleanup_error\":{cleanup_text}}}",
        quote(&tx_id.to_string()), terminal.decision_sequence.get(), options.base, options.candidate, cleanup.is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(width: usize) -> Vec<String> {
        vec!["apply".into(), "node".into(), "11".repeat(16), "22".repeat(16),
            "refs/heads/main".into(), "reviewed.bundle".into(), "--trusted-local".into(),
            "--principal".into(), "33".repeat(16), "--idempotency-key".into(), "review-1".into(),
            "--expected-base".into(), "a".repeat(width), "--expected-commit".into(), "b".repeat(width)]
    }

    #[test]
    fn both_native_formats_require_complete_independent_review_expectations() {
        for width in [40, 64] {
            let options = parse(&args(width)).unwrap();
            assert_eq!(options.base.to_string(), "a".repeat(width));
            assert_eq!(options.candidate.to_string(), "b".repeat(width));
            assert_eq!(options.key, b"review-1");
            for flag in ["--principal", "--idempotency-key", "--expected-base", "--expected-commit"] {
                let mut missing = args(width);
                let at = missing.iter().position(|arg| arg == flag).unwrap();
                missing.drain(at..at + 2);
                assert!(parse(&missing).is_err());
            }
        }
    }

    #[test]
    fn trust_duplicates_force_zero_and_mixed_domains_refuse_before_io() {
        let mut untrusted = args(40);
        untrusted.retain(|arg| arg != "--trusted-local");
        assert!(parse(&untrusted).is_err());
        for pair in [["--force", "true"], ["--principal", "33333333333333333333333333333333"]] {
            let mut duplicate = args(40);
            duplicate.extend(pair.into_iter().map(str::to_owned));
            assert!(parse(&duplicate).is_err());
        }
        for bad in ["0".repeat(40), "b".repeat(64), "a".repeat(40), "z".repeat(40)] {
            let mut values = args(40);
            *values.last_mut().unwrap() = bad;
            assert!(parse(&values).is_err());
        }
        assert!(parse(&args(40)).is_ok());
    }

    #[test]
    fn bundle_input_rejects_empty_oversized_and_non_regular_artifacts() {
        let path = std::env::temp_dir().join(format!("fg-apply-input-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        assert!(read_bundle(&path, 4).is_err());
        let file = path.join("candidate");
        fs::write(&file, b"").unwrap();
        assert!(read_bundle(&file, 4).is_err());
        fs::write(&file, b"12345").unwrap();
        assert!(read_bundle(&file, 4).is_err());
        fs::write(&file, b"1234").unwrap();
        assert_eq!(read_bundle(&file, 4).unwrap(), b"1234");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn known_decisions_survive_cleanup_and_receipt_output_failures() {
        use fgit_types::{CANONICAL_CODEC_VERSION, DecisionSequence, RefusalCode,
            RefusalRecordId, RepositoryCommitId};
        use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
        let algorithm = DigestAlgorithmId::try_new(2).unwrap();
        let digest = DigestBytes::try_new(&[0x42; 32]).unwrap();
        let tx = TxId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest);
        let rcr = RepositoryCommitId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest);
        let committed = TerminalOutcome {
            decision_sequence: DecisionSequence::try_new(2).unwrap(),
            outcome: DecisionOutcome::Committed { repository_commit_id: rcr },
        };
        let receipt = render_receipt(&parse(&args(40)).unwrap(), tx, &committed, Some("close failed"));
        assert!(receipt.contains("\"published_to_repository\":true"));
        assert!(receipt.contains("\"node_closed\":false"));
        assert!(receipt.contains(&quote(&rcr.to_string())));
        struct BrokenOutput;
        impl Write for BrokenOutput {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let error = write_terminal_receipt(&mut BrokenOutput, &receipt, tx, &committed).unwrap_err();
        assert!(error.contains("is committed as"));
        assert!(error.contains(&rcr.to_string()));
        struct BrokenFlush;
        impl Write for BrokenFlush {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> { Ok(bytes.len()) }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }
        let error = write_terminal_receipt(&mut BrokenFlush, &receipt, tx, &committed).unwrap_err();
        assert!(error.contains("is committed as"));
        let refused = TerminalOutcome {
            decision_sequence: DecisionSequence::try_new(3).unwrap(),
            outcome: DecisionOutcome::Refused {
                code: RefusalCode::ExpectedOldRefMismatch,
                refusal_record_id: RefusalRecordId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest),
            },
        };
        let receipt = render_receipt(&parse(&args(40)).unwrap(), tx, &refused, None);
        assert!(receipt.contains("\"outcome\":\"refused\""));
        assert!(receipt.contains("\"published_to_repository\":false"));
        assert!(receipt.contains("ExpectedOldRefMismatch"));
        let mut output = Vec::new();
        write_terminal_receipt(&mut output, &receipt, tx, &refused).unwrap();
        assert_eq!(output, format!("{receipt}\n").as_bytes());
    }
}
