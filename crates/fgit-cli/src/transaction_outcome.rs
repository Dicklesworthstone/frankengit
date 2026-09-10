//! Read-only lost-response recovery. It never rebuilds or resubmits a mutation.
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::PathBuf;
use fgit_authority::{IdempotencyKey, MAX_IDEMPOTENCY_KEY_BYTES, OutcomeLookup};
use fgit_authority::key_recovery::RequestRecovery;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, Digest, GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use super::publication_support::{describe, quote, write_terminal_receipt};

const USAGE: &str = "usage: fg outcome <storage-root> <tenant-id> <repository-id> --trusted-local\n  --principal <original-principal-id>\n  (--idempotency-key <exact-text> | --idempotency-key-hex <hex> | --key-stdin)\n  [--object-format sha1|sha256]\n\nNo bundle, workspace, command body or transaction ID is needed. The exact key\nis interpreted in the original tenant/repository/principal scope, not as a\ncredential. Stdin is bounded and byte-exact: no newline is removed.\nExit 0: committed; 3: canonical refusal; 4: nonterminal observation; 2: error.\nAn absent key, unobserved seal, or undecided request is NOT proof of rollback.\nNon-atomic receive requires its per-command key; repository creation is a\nseparate protocol. This command does not retry or cancel a mutation.";

struct Options {
    storage: PathBuf, tenant: TenantId, repository: RepositoryId,
    principal: PrincipalId, format: GitHashAlgorithm, key: KeyInput,
}
enum KeyInput { Bytes(Vec<u8>), Stdin }

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        emit(&mut std::io::stdout().lock(), USAGE)?;
        return Ok(0);
    }
    let options = parse(args)?;
    let bytes = match &options.key {
        KeyInput::Bytes(bytes) => bytes.clone(),
        KeyInput::Stdin => read_key(&mut std::io::stdin().lock())?,
    };
    let key = IdempotencyKey::new(bytes).map_err(|_| "invalid bounded idempotency key")?;
    let key_digest = key.digest();
    let session = LoopbackReceiveSession::authenticated(options.principal, key);
    let node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant,
        options.repository).with_object_format(options.format)).map_err(|e| e.to_string())?;
    // Recovery intentionally does not bring a cell into serving state. It can
    // report historical outcomes even when new mutation admission is disabled.
    let request = node.request_context();
    let operation = node.runtime().block_on(node.recover_transaction_in(&request, &session));
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    let report = match operation {
        Ok(report) => report,
        Err(error) => return Err(match cleanup {
            None => error.to_string(), Some(cleanup) => format!("{error}; node shutdown also failed: {cleanup}"),
        }),
    };
    let (receipt, status) = render(&options, key_digest, &report, cleanup.as_deref());
    let known = match &report {
        RequestRecovery::Recovered(request) => report.terminal().map(|outcome| (request.tx_id(), outcome)),
        _ => None,
    };
    let written = match known {
        Some((tx, terminal)) => write_terminal_receipt(&mut std::io::stdout().lock(), &receipt, tx, &terminal),
        None => emit(&mut std::io::stdout().lock(), &receipt),
    };
    if let Err(error) = written {
        return Err(match cleanup {
            Some(cleanup) => format!("{error}; node shutdown also failed: {cleanup}"), None => error,
        });
    }
    if let Some(error) = cleanup {
        let knowledge = known.map_or_else(|| "no terminal outcome was established".into(), |(tx, terminal)| describe(tx, &terminal));
        return Err(format!("{knowledge}; node shutdown failed: {error}"));
    }
    Ok(status)
}

fn emit(output: &mut impl Write, text: &str) -> Result<(), String> {
    writeln!(output, "{text}").and_then(|()| output.flush())
        .map_err(|error| format!("transaction outcome output incomplete: {error}; absence is not proof of non-commit"))
}
fn read_key(input: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    input.take((MAX_IDEMPOTENCY_KEY_BYTES + 1) as u64).read_to_end(&mut bytes)
        .map_err(|error| format!("could not read original key: {error}"))?;
    if bytes.len() > MAX_IDEMPOTENCY_KEY_BYTES { return Err("original key exceeds 256 bytes".into()); }
    Ok(bytes)
}
fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 3 { return Err(USAGE.into()); }
    if args.len() > 16 || args.iter().any(|value| value.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
    { return Err("outcome arguments exceed the bounded profile".into()); }
    if args[0].is_empty() || args[0].len() > 4096 { return Err("invalid storage path".into()); }
    let tenant = TenantId::from_hex(&args[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|_| "invalid repository ID")?;
    let mut principal = None;
    let mut format = GitHashAlgorithm::Sha1;
    let mut key = None;
    let mut trusted = false;
    let mut seen = BTreeSet::new();
    let mut index = 3;
    while index < args.len() {
        let flag = args[index].as_str(); index += 1;
        if !matches!(flag, "--trusted-local" | "--principal" | "--object-format"
            | "--idempotency-key" | "--idempotency-key-hex" | "--key-stdin")
        { return Err(format!("unknown outcome option {flag:?}")); }
        let group = if matches!(flag, "--idempotency-key" | "--idempotency-key-hex" | "--key-stdin") { "original key" } else { flag };
        if !seen.insert(group) { return Err(format!("duplicate {group}")); }
        if flag == "--trusted-local" { trusted = true; continue; }
        if flag == "--key-stdin" { key = Some(KeyInput::Stdin); continue; }
        let value = args.get(index).ok_or_else(|| format!("missing value for {flag}"))?; index += 1;
        match flag {
            "--principal" => principal = Some(PrincipalId::from_hex(value).map_err(|_| "invalid principal ID")?),
            "--object-format" => format = match value.as_str() {
                "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256,
                _ => return Err("object format must be sha1 or sha256".into()),
            },
            "--idempotency-key" => {
                if value.len() > MAX_IDEMPOTENCY_KEY_BYTES { return Err("original key exceeds 256 bytes".into()); }
                key = Some(KeyInput::Bytes(value.as_bytes().to_vec()));
            }
            "--idempotency-key-hex" => key = Some(KeyInput::Bytes(unhex_key(value)?)),
            _ => return Err("inapplicable outcome option".into()),
        }
    }
    if !trusted { return Err("--trusted-local is required; a key is not a credential".into()); }
    Ok(Options { storage: args[0].clone().into(), tenant, repository, format,
        principal: principal.ok_or("the original --principal is required")?,
        key: key.ok_or("exactly one original key input is required")? })
}
fn unhex_key(text: &str) -> Result<Vec<u8>, String> {
    if text.len() > 2 * MAX_IDEMPOTENCY_KEY_BYTES || text.len() % 2 != 0
        || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    { return Err("original key must be at most 256 bytes of lowercase hex".into()); }
    let digit = |byte| if byte <= b'9' { byte - b'0' } else { byte - b'a' + 10 };
    Ok(text.as_bytes().chunks_exact(2).map(|pair| digit(pair[0]) * 16 + digit(pair[1])).collect())
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn digest(value: Digest) -> String {
    format!("{{\"algorithm\":{},\"hex\":{}}}", value.algorithm().code_point(), quote(&hex(value.bytes().as_bytes())))
}
fn render(options: &Options, key_digest: Digest, report: &RequestRecovery, cleanup: Option<&str>) -> (String, u8) {
    let (state, exit, request, outcome) = match report {
        RequestRecovery::KeyNotObserved => ("key_not_observed", 4, None, None),
        RequestRecovery::SealNotObserved => ("seal_not_observed", 4, None, None),
        RequestRecovery::Recovered(request) => match request.outcome() {
            OutcomeLookup::Undecided => ("undecided", 4, Some(request.as_ref()), None),
            OutcomeLookup::Decided(terminal) => match terminal.outcome {
                DecisionOutcome::Committed { .. } => ("committed", 0, Some(request.as_ref()), Some(terminal)),
                DecisionOutcome::Refused { .. } => ("refused", 3, Some(request.as_ref()), Some(terminal)),
            },
        },
    };
    let transaction = request.map_or_else(|| "null".into(), |request| {
        let seal = request.seal();
        format!(concat!("{{\"tx_id\":{},\"seal_id\":{},\"canonical_request_digest\":{},\"request_schema\":{}}}"),
            quote(&request.tx_id().to_string()), quote(&request.seal_id().to_string()),
            digest(seal.canonical_request_digest), quote(&seal.request_schema.to_string()))
    });
    let decision = outcome.map_or_else(|| "null".into(), |terminal| match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => format!(
            "{{\"kind\":\"committed\",\"decision_sequence\":{},\"repository_commit_id\":{}}}",
            terminal.decision_sequence.get(), quote(&repository_commit_id.to_string())),
        DecisionOutcome::Refused { code, refusal_record_id } => format!(
            "{{\"kind\":\"refused\",\"decision_sequence\":{},\"code\":{},\"code_point\":{},\"refusal_record_id\":{}}}",
            terminal.decision_sequence.get(), quote(&format!("{code:?}")), code.code_point(), quote(&refusal_record_id.to_string())),
    });
    (format!(concat!("{{\"type\":\"transaction_outcome\",\"schema_version\":1,",
        "\"tenant_id\":{},\"repository_id\":{},\"principal_id\":{},\"object_format\":{},",
        "\"key_digest\":{},\"state\":{},\"terminal\":{},\"transaction\":{},\"decision\":{},",
        "\"read_only\":true,\"request_reexecuted\":false,\"absence_proves_non_commit\":false,",
        "\"node_closed\":{},\"cleanup_error\":{}}}"),
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(&options.principal.to_string()),
        quote(options.format.as_str()), digest(key_digest), quote(state), outcome.is_some(), transaction, decision,
        cleanup.is_none(), cleanup.map_or_else(|| "null".into(), quote)), exit)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> { ["node", &"11".repeat(16), &"22".repeat(16), "--trusted-local",
        "--principal", &"33".repeat(16), "--idempotency-key", "original-key"].iter().map(|s| s.to_string()).collect() }
    #[test]
    fn recovery_inputs_are_explicit_scoped_and_never_accept_mutation_arguments() {
        let valid = args(); let parsed = parse(&valid).unwrap();
        assert!(matches!(parsed.key, KeyInput::Bytes(ref key) if key == b"original-key"));
        for option in ["--bundle", "--force", "--candidate", "--expected-version", "--tx-id"] {
            let mut bad = valid.clone(); bad.extend([option.into(), "irrelevant".into()]); assert!(parse(&bad).is_err());
        }
        let mut bad = valid.clone(); bad.remove(3); assert!(parse(&bad).is_err());
        for extra in [vec!["--key-stdin"], vec!["--idempotency-key", "same"], vec!["--idempotency-key-hex", "00"], vec!["--principal", "bad"]] {
            let mut bad = valid.clone(); bad.extend(extra.into_iter().map(str::to_string)); assert!(parse(&bad).is_err());
        }
        let mut bad = valid; *bad.last_mut().unwrap() = "x".repeat(257); assert!(parse(&bad).is_err());
    }
    #[test]
    fn stdin_and_hex_preserve_exact_bytes_including_empty_keys_and_newlines() {
        for bytes in [Vec::new(), b"key\0\n\xff".to_vec(), vec![b'x'; 256]] {
            assert_eq!(unhex_key(&hex(&bytes)).unwrap(), bytes);
            assert_eq!(read_key(&mut std::io::Cursor::new(bytes.clone())).unwrap(), bytes);
        }
        assert!(read_key(&mut std::io::Cursor::new(vec![0; 257])).is_err());
        for text in ["0", "GG", "FF", "é"] { assert!(unhex_key(text).is_err()); }
        let mut input = args(); input.truncate(6); input.push("--key-stdin".into());
        assert!(matches!(parse(&input).unwrap().key, KeyInput::Stdin));
    }
    #[test]
    fn nonterminal_reports_do_not_expose_raw_keys_or_assert_noncommit() {
        let options = parse(&args()).unwrap(); let key = IdempotencyKey::new(b"original-key".to_vec()).unwrap();
        for report in [RequestRecovery::KeyNotObserved, RequestRecovery::SealNotObserved] {
            let (text, code) = render(&options, key.digest(), &report, None);
            assert_eq!(code, 4); assert!(text.contains("\"terminal\":false"));
            assert!(text.contains("\"absence_proves_non_commit\":false"));
            assert!(text.contains("\"transaction\":null,\"decision\":null"));
            assert!(!text.contains("original-key"));
            let (failed, _) = render(&options, key.digest(), &report, Some("shutdown\nfailed"));
            assert!(failed.contains("\"node_closed\":false")); assert!(!failed.contains('\n'));
        }
    }
    #[test]
    fn output_write_and_flush_failures_remain_errors() {
        struct Broken(bool);
        impl Write for Broken {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0 { Err(std::io::Error::other("write")) } else { Ok(bytes.len()) }
            }
            fn flush(&mut self) -> std::io::Result<()> { Err(std::io::Error::other("flush")) }
        }
        for fail_write in [true, false] {
            let error = emit(&mut Broken(fail_write), "{}").unwrap_err();
            assert!(error.contains("not proof of non-commit"));
        }
    }
}
