//! Bounded offline Git transfer; canonical publication remains in OneNode.
mod fetch;
mod incremental;
use super::merge_apply::preparation::{publish_new_bundle, require_absent};
use super::publication_support::{describe, quote, read_bundle, set_once, write_terminal_receipt};
use fgit_authority::{IdempotencyKey, MAX_IDEMPOTENCY_KEY_BYTES, TerminalOutcome};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId, TxId,
};
use std::io::{Read, Write};
use std::path::PathBuf;

const MAX_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
const USAGE: &str =
    "usage: fg bundle export <storage-root> <tenant-id> <repository-id> <new-bundle-file>
  --trusted-local [--object-format sha1|sha256]
usage: fg bundle import <storage-root> <tenant-id> <repository-id> <bundle-file>
  --trusted-local --principal <id> (--idempotency-key <key> | --key-stdin)
  [--object-format sha1|sha256]

Export contains only the complete Git object closure of current visible refs.
Import atomically creates every direct ref; any existing destination name refuses
all updates. HEAD is only an advertisement: destination configuration is unchanged.
Self-contained v2/SHA-1 and v3/SHA-256 bundles are supported; prerequisites, filters,
external delta bases and implicit force are refused. Input is bounded to 128 MiB,
with additional pack, expanded-object, reference and work limits enforced by the node.
This is Git transfer, not a backup of issues, reviews, policy, credentials or authority.
Existing output files are never replaced. Keys from stdin are byte-exact, including
newlines, and are never printed. Retry identical inputs/key, or use fg outcome.
Exit 0: exported/committed; 3: canonical refusal; 2: input/infrastructure/cleanup error.";

#[derive(Debug)]
enum Key {
    Bytes(Vec<u8>),
    Stdin,
}
#[derive(Debug)]
struct Options {
    import: bool,
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    path: PathBuf,
    format: GitHashAlgorithm,
    principal: Option<PrincipalId>,
    key: Option<Key>,
}
fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 5 || args.len() > 20 || args.iter().any(|arg| arg.len() > 64 * 1024) {
        return Err(USAGE.into());
    }
    let import = match args[0].as_str() {
        "import" => true,
        "export" => false,
        _ => return Err(USAGE.into()),
    };
    if args[1].is_empty() || args[4].is_empty() {
        return Err("storage and bundle paths must be nonempty".into());
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|e| e.to_string())?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|e| e.to_string())?;
    let (mut principal, mut key, mut format, mut trusted) = (None, None, None, false);
    let mut cursor = 5;
    while cursor < args.len() {
        let flag = args[cursor].as_str();
        cursor += 1;
        if flag == "--trusted-local" {
            if trusted {
                return Err("duplicate --trusted-local".into());
            }
            trusted = true;
            continue;
        }
        if flag == "--key-stdin" {
            set_once(&mut key, Key::Stdin, flag)?;
            continue;
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag {
            "--object-format" => set_once(
                &mut format,
                match value.as_str() {
                    "sha1" => GitHashAlgorithm::Sha1,
                    "sha256" => GitHashAlgorithm::Sha256,
                    _ => return Err("object format must be sha1 or sha256".into()),
                },
                flag,
            )?,
            "--principal" => set_once(
                &mut principal,
                PrincipalId::from_hex(value).map_err(|e| e.to_string())?,
                flag,
            )?,
            "--idempotency-key" => {
                let bytes = value.as_bytes();
                if bytes.is_empty() || bytes.len() > MAX_IDEMPOTENCY_KEY_BYTES {
                    return Err("key must contain 1..256 bytes".into());
                }
                set_once(&mut key, Key::Bytes(bytes.to_vec()), flag)?;
            }
            _ => return Err(format!("unknown bundle option {flag}")),
        }
    }
    if !trusted {
        return Err("--trusted-local is required for repository disclosure or mutation".into());
    }
    if import && (principal.is_none() || key.is_none()) {
        return Err("import requires a principal and an exact retry key".into());
    }
    if !import && (principal.is_some() || key.is_some()) {
        return Err("export does not accept mutation credentials".into());
    }
    let path = PathBuf::from(&args[4]);
    if path.file_name().is_none() {
        return Err("bundle path must name a regular file".into());
    }
    Ok(Options {
        import,
        storage: args[1].clone().into(),
        tenant,
        repository,
        path,
        format: format.unwrap_or(GitHashAlgorithm::Sha1),
        principal,
        key,
    })
}
fn key_bytes(key: &Key, input: &mut impl Read) -> Result<Vec<u8>, String> {
    let bytes = match key {
        Key::Bytes(bytes) => bytes.clone(),
        Key::Stdin => {
            let mut bytes = Vec::new();
            input
                .take((MAX_IDEMPOTENCY_KEY_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            bytes
        }
    };
    if bytes.is_empty() || bytes.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err("key must contain 1..256 exact bytes".into());
    }
    Ok(bytes)
}
pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "sync-export" | "sync-import"))
    {
        return incremental::run(args);
    }
    if args.first().is_some_and(|arg| arg == "fetch") {
        return fetch::run(&args[1..]);
    }
    if args == ["--help"]
        || (args.len() == 2
            && args[1] == "--help"
            && matches!(args[0].as_str(), "export" | "import"))
    {
        writeln!(
            std::io::stdout().lock(),
            "{USAGE}\n\n{}\n\n{}",
            fetch::USAGE,
            incremental::USAGE
        )
        .map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let options = parse(args)?;
    let bytes = if options.import {
        Some(read_bundle(&options.path, MAX_BUNDLE_BYTES)?)
    } else {
        require_absent(&options.path)?;
        None
    };
    let session = match (&options.key, options.principal) {
        (Some(key), Some(principal)) => Some(LoopbackReceiveSession::authenticated(
            principal,
            IdempotencyKey::new(key_bytes(key, &mut std::io::stdin().lock())?)
                .map_err(|e| e.to_string())?,
        )),
        _ => None,
    };
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|e| e.to_string())?;
    enum Completed {
        Import(TxId, TerminalOutcome, usize),
        Export(
            fgit_types::RepositoryAuthorityHeadId,
            Vec<u8>,
            u32,
            fgit_types::GitOid,
        ),
    }
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|e| e.to_string())?;
        let request = node.request_context();
        if let (Some(bytes), Some(session)) = (&bytes, &session) {
            let result = node
                .runtime()
                .block_on(node.import_full_git_bundle_durable_in(
                    &request,
                    session,
                    bytes,
                    Default::default(),
                ))
                .map_err(|e| e.to_string())?;
            let first = result
                .commands
                .first()
                .ok_or("bundle admission returned no terminal outcome")?;
            if !result.session.atomic
                || result.session.tx_ids != vec![first.tx_id]
                || result.commands.iter().any(|c| c != first)
            {
                return Err(format!(
                    "inconsistent atomic bundle result; {}",
                    describe(first.tx_id, &first.terminal)
                ));
            }
            Ok(Completed::Import(
                first.tx_id,
                first.terminal,
                result.commands.len(),
            ))
        } else {
            let (head, bundle) = node
                .runtime()
                .block_on(node.export_full_git_bundle_in(&request, &Default::default(), None))
                .map_err(|e| e.to_string())?;
            let receipt = bundle.pack_receipt();
            let count = receipt.object_count;
            let checksum = receipt.checksum;
            Ok(Completed::Export(
                head,
                bundle.into_bytes(),
                count,
                checksum,
            ))
        }
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    match operation {
        Ok(Completed::Import(tx, terminal, count)) => finish_import(
            &mut std::io::stdout().lock(),
            &options,
            tx,
            &terminal,
            count,
            cleanup.as_deref(),
        ),
        Ok(Completed::Export(head, bytes, count, checksum)) => {
            if let Some(error) = cleanup {
                return Err(format!(
                    "node shutdown failed: {error}; no bundle file published"
                ));
            }
            publish_new_bundle(&options.path, &bytes)?;
            let receipt = format!(
                "{{\"type\":\"git_bundle_export\",\"schema_version\":1,\"source_head\":{},\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"object_count\":{count},\"pack_checksum\":{},\"bundle_bytes\":{},\"bundle_created\":true,\"node_closed\":true,\"repository_changed\":false,\"includes_forge_metadata\":false}}",
                quote(&head.to_string()),
                quote(&options.tenant.to_string()),
                quote(&options.repository.to_string()),
                quote(options.format.as_str()),
                quote(&checksum.to_string()),
                bytes.len()
            );
            writeln!(std::io::stdout().lock(), "{receipt}")
                .and_then(|()| std::io::stdout().flush())
                .map_err(|e| {
                    format!("complete bundle file was created, but receipt output failed: {e}")
                })?;
            Ok(0)
        }
        Err(error) => {
            let cleanup =
                cleanup.map_or_else(String::new, |e| format!("; node shutdown also failed: {e}"));
            if options.import {
                Err(format!(
                    "bundle import returned no terminal outcome: {error}{cleanup}; this is not evidence of non-commit. Retry the identical inputs/key or use fg outcome"
                ))
            } else {
                Err(format!(
                    "bundle export failed: {error}{cleanup}; no bundle file published"
                ))
            }
        }
    }
}
fn finish_import(
    output: &mut impl Write,
    options: &Options,
    tx: TxId,
    terminal: &TerminalOutcome,
    count: usize,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    let (state, exit, rcr, code, refusal) = match terminal.outcome {
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
        "{{\"type\":\"git_bundle_import\",\"schema_version\":1,\"outcome\":{},\"command_committed\":{},\"atomic\":true,\"tx_id\":{},\"decision_sequence\":{},\"repository_commit_id\":{rcr},\"refusal_code\":{code},\"refusal_record_id\":{refusal},\"principal_id\":{},\"delivery_acknowledged\":null,\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"reference_count\":{count},\"node_closed\":{},\"cleanup_error\":{},\"includes_forge_metadata\":false}}",
        quote(state),
        exit == 0,
        quote(&tx.to_string()),
        terminal.decision_sequence.get(),
        options
            .principal
            .map_or_else(|| "null".into(), |id| quote(&id.to_string())),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(options.format.as_str()),
        cleanup.is_none(),
        cleanup.map_or_else(|| "null".into(), quote)
    );
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
    Ok(exit)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn args(operation: &str, extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            operation.into(),
            "root".into(),
            "01".repeat(16),
            "02".repeat(16),
            "transfer.bundle".into(),
            "--trusted-local".into(),
        ];
        args.extend(extra.iter().map(|s| (*s).into()));
        args
    }
    #[test]
    fn explicit_credentials_and_one_exact_key_are_required_only_for_import() {
        assert!(parse(&args("export", &[])).is_ok());
        assert!(parse(&args("import", &[])).is_err());
        let p = "03".repeat(16);
        assert!(parse(&args("import", &["--principal", &p, "--key-stdin"])).is_ok());
        assert!(
            parse(&args(
                "import",
                &[
                    "--principal",
                    &p,
                    "--key-stdin",
                    "--idempotency-key",
                    "other"
                ]
            ))
            .is_err()
        );
        assert!(parse(&args("export", &["--key-stdin"])).is_err());
        assert!(
            parse(&args(
                "export",
                &["--object-format", "sha256", "--object-format", "sha1"]
            ))
            .is_err()
        );
        assert!(parse(&args("export", &["--force"])).is_err());
        let mut untrusted = args("export", &[]);
        untrusted.pop();
        assert!(parse(&untrusted).is_err());
    }
    #[test]
    fn retry_key_is_byte_exact_and_bounded() {
        assert_eq!(
            key_bytes(&Key::Stdin, &mut &b"exact\n"[..]).unwrap(),
            b"exact\n"
        );
        assert!(key_bytes(&Key::Stdin, &mut &b""[..]).is_err());
        assert_eq!(
            key_bytes(&Key::Stdin, &mut &vec![1; 256][..])
                .unwrap()
                .len(),
            256
        );
        assert!(key_bytes(&Key::Stdin, &mut &vec![1; 257][..]).is_err());
    }
    #[test]
    fn terminal_receipts_survive_cleanup_and_output_failures_without_disclosing_keys() {
        use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
        use fgit_types::{
            CANONICAL_CODEC_VERSION, DecisionSequence, RefusalCode, RefusalRecordId,
            RepositoryCommitId,
        };
        struct Broken(bool);
        impl Write for Broken {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0 {
                    Err(std::io::Error::other("write failed"))
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("flush failed"))
            }
        }
        let principal = "03".repeat(16);
        let options = parse(&args(
            "import",
            &[
                "--principal",
                &principal,
                "--idempotency-key",
                "private-retry-key",
            ],
        ))
        .unwrap();
        let algorithm = DigestAlgorithmId::try_new(2).unwrap();
        let digest = DigestBytes::try_new(&[0x42; 32]).unwrap();
        let tx = TxId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest);
        for refused in [false, true] {
            let outcome = if refused {
                DecisionOutcome::Refused {
                    code: RefusalCode::ExpectedOldRefMismatch,
                    refusal_record_id: RefusalRecordId::from_digest(
                        algorithm,
                        CANONICAL_CODEC_VERSION,
                        digest,
                    ),
                }
            } else {
                DecisionOutcome::Committed {
                    repository_commit_id: RepositoryCommitId::from_digest(
                        algorithm,
                        CANONICAL_CODEC_VERSION,
                        digest,
                    ),
                }
            };
            let terminal = TerminalOutcome {
                decision_sequence: DecisionSequence::try_new(2).unwrap(),
                outcome,
            };
            let mut bytes = Vec::new();
            assert_eq!(
                finish_import(&mut bytes, &options, tx, &terminal, 2, None).unwrap(),
                if refused { 3 } else { 0 }
            );
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.contains(&format!("\"command_committed\":{}", !refused)));
            assert!(text.contains("\"reference_count\":2"));
            assert!(!text.contains("private-retry-key"));
            let mut bytes = Vec::new();
            let error = finish_import(&mut bytes, &options, tx, &terminal, 2, Some("close failed"))
                .unwrap_err();
            assert!(error.contains(&describe(tx, &terminal)));
            assert!(
                String::from_utf8(bytes)
                    .unwrap()
                    .contains("\"node_closed\":false")
            );
            for write in [false, true] {
                assert!(
                    finish_import(&mut Broken(write), &options, tx, &terminal, 2, None)
                        .unwrap_err()
                        .contains(&describe(tx, &terminal))
                );
            }
        }
    }
}
