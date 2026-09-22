//! Explicit, exact-old offline fetch. No automatic ref selection or force.
use super::{
    Key, MAX_BUNDLE_BYTES, describe, key_bytes, quote, read_bundle, set_once,
    write_terminal_receipt,
};
use fgit_authority::{IdempotencyKey, MAX_IDEMPOTENCY_KEY_BYTES, TerminalOutcome};
use fgit_node::{BundleRefMapping, LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId, TxId,
};
use std::{collections::BTreeSet, io::Write, path::PathBuf};

pub(super) const USAGE: &str =
    "usage: fg bundle fetch <storage-root> <tenant-id> <repository-id> <bundle-file>
  --trusted-local --principal <id> (--key-stdin | --idempotency-key <key>)
  [--object-format sha1|sha256]
  --map <advertised-source-ref> <destination-ref> <absent|exact-old-oid> ...
  --map-hex <source-ref-bytes-hex> <destination-ref-bytes-hex> <absent|exact-old-oid> ...

At least one explicit mapping is required. Destinations must be under refs/heads/,
refs/remotes/, or refs/tags/. All selected updates publish atomically. Existing
branches and remote-tracking refs must fast-forward through verified native commit
parents. Tags may be created or reasserted, never overwritten. No wildcard, force,
prune, implicit current-tip lookup, remote authentication, or HEAD/metadata rewrite.
Input is a bounded self-contained Git bundle, not an incremental prerequisite bundle.
The retry key binds the exact canonical destination/old/new commands; identical
requests recover their terminal outcome. Reordered maps retain that identity.
Stdin keys preserve every byte, including newlines, and keys are never printed.
Exit 0: committed; 3: canonical refusal; 2: input/intake/infrastructure/cleanup error.";

struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    bundle: PathBuf,
    format: GitHashAlgorithm,
    principal: PrincipalId,
    key: Key,
    mappings: Vec<BundleRefMapping>,
}
fn decode_name(text: &str, hex: bool) -> Result<RefName, String> {
    let bytes = if hex {
        if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("reference hex must be complete hexadecimal byte pairs".into());
        }
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |b: u8| match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    _ => b - b'A' + 10,
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect::<Vec<_>>()
    } else {
        text.as_bytes().to_vec()
    };
    RefName::try_new(&bytes).map_err(|_| "invalid full reference name".into())
}
fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4
        || args.len() > 16404
        || args.iter().any(|v| v.len() > 64 * 1024)
        || args
            .iter()
            .try_fold(0usize, |n, v| n.checked_add(v.len()))
            .is_none_or(|n| n > 1024 * 1024)
    {
        return Err(USAGE.into());
    }
    let storage = PathBuf::from(&args[0]);
    let bundle = PathBuf::from(&args[3]);
    if storage.as_os_str().is_empty() || bundle.file_name().is_none() {
        return Err("storage and bundle paths must be nonempty".into());
    }
    let tenant = TenantId::from_hex(&args[1]).map_err(|e| e.to_string())?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|e| e.to_string())?;
    let (mut principal, mut key, mut format, mut trusted) = (None, None, None, false);
    let mut maps = Vec::new();
    let mut cursor = 4;
    while cursor < args.len() {
        let flag = &args[cursor];
        cursor += 1;
        match flag.as_str() {
            "--trusted-local" => {
                if trusted {
                    return Err("duplicate --trusted-local".into());
                }
                trusted = true;
            }
            "--key-stdin" => set_once(&mut key, Key::Stdin, flag)?,
            "--map" | "--map-hex" => {
                if maps.len() == 4096 || args.len() - cursor < 3 {
                    return Err(
                        "fetch requires 1..4096 complete source/destination/old mappings".into(),
                    );
                }
                let hex = flag == "--map-hex";
                maps.push((
                    decode_name(&args[cursor], hex)?,
                    decode_name(&args[cursor + 1], hex)?,
                    args[cursor + 2].clone(),
                ));
                cursor += 3;
            }
            "--principal" | "--idempotency-key" | "--object-format" => {
                let value = args
                    .get(cursor)
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                cursor += 1;
                match flag.as_str() {
                    "--principal" => set_once(
                        &mut principal,
                        PrincipalId::from_hex(value).map_err(|e| e.to_string())?,
                        flag,
                    )?,
                    "--idempotency-key" => {
                        if value.is_empty() || value.len() > MAX_IDEMPOTENCY_KEY_BYTES {
                            return Err("key must contain 1..256 exact bytes".into());
                        }
                        set_once(&mut key, Key::Bytes(value.as_bytes().to_vec()), flag)?;
                    }
                    _ => set_once(
                        &mut format,
                        match value.as_str() {
                            "sha1" => GitHashAlgorithm::Sha1,
                            "sha256" => GitHashAlgorithm::Sha256,
                            _ => return Err("object format must be sha1 or sha256".into()),
                        },
                        flag,
                    )?,
                }
            }
            _ => return Err(format!("unsupported bundle fetch option {flag}")),
        }
    }
    if !trusted || maps.is_empty() {
        return Err("--trusted-local and at least one --map or --map-hex are required".into());
    }
    let format = format.unwrap_or(GitHashAlgorithm::Sha1);
    let mut destinations = BTreeSet::new();
    let mut mappings = Vec::with_capacity(maps.len());
    for (source, destination, old) in maps {
        if ![b"refs/heads/".as_slice(), b"refs/remotes/", b"refs/tags/"]
            .iter()
            .any(|prefix| destination.as_bytes().starts_with(prefix))
        {
            return Err("fetch destination namespace is unsupported".into());
        }
        if !destinations.insert(destination.clone()) {
            return Err("duplicate fetch destination".into());
        }
        let expected_old = if old == "absent" {
            None
        } else {
            let oid = GitOid::from_hex(format, &old)
                .map_err(|_| "old tip must be an exact object-format-native identity")?;
            if oid.is_zero() {
                return Err("use absent, not a zero object identity".into());
            }
            Some(oid)
        };
        mappings.push(BundleRefMapping {
            source,
            destination,
            expected_old,
        });
    }
    mappings.sort_by(|a, b| a.destination.cmp(&b.destination));
    Ok(Options {
        storage,
        tenant,
        repository,
        bundle,
        format,
        principal: principal.ok_or("principal required")?,
        key: key.ok_or("exact retry key required")?,
        mappings,
    })
}
pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let options = parse(args)?;
    let bytes = read_bundle(&options.bundle, MAX_BUNDLE_BYTES)?;
    let session = LoopbackReceiveSession::authenticated(
        options.principal,
        IdempotencyKey::new(key_bytes(&options.key, &mut std::io::stdin().lock())?)
            .map_err(|e| e.to_string())?,
    );
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|e| format!("cannot open fetch node: {e}"))?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|e| e.to_string())?;
        let request = node.request_context();
        let result = node
            .runtime()
            .block_on(node.fetch_full_git_bundle_durable_in(
                &request,
                &session,
                &bytes,
                &options.mappings,
                Default::default(),
            ))
            .map_err(|e| e.to_string())?;
        let first = result
            .commands
            .first()
            .ok_or("no terminal fetch commands returned")?;
        if !result.session.atomic
            || result.session.tx_ids != vec![first.tx_id]
            || result.commands.len() != options.mappings.len()
            || result.commands.iter().any(|c| c != first)
        {
            return Err(format!(
                "inconsistent atomic fetch receipt; {}",
                describe(first.tx_id, &first.terminal)
            ));
        }
        Ok((first.tx_id, first.terminal))
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    match operation {
        Ok((tx, terminal)) => finish(
            &mut std::io::stdout().lock(),
            &options,
            tx,
            &terminal,
            cleanup.as_deref(),
        ),
        Err(error) => Err(format!(
            "bundle fetch returned no terminal outcome: {error}{}; this is not evidence of non-commit. Retry the same canonical updates and key, or use fg outcome",
            cleanup.map_or_else(String::new, |e| format!("; node shutdown also failed: {e}"))
        )),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn finish(
    output: &mut impl Write,
    options: &Options,
    tx: TxId,
    terminal: &TerminalOutcome,
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
    let mappings = options
        .mappings
        .iter()
        .map(|m| {
            format!(
                "{{\"source_hex\":{},\"destination_hex\":{},\"expected_old\":{}}}",
                quote(&hex(m.source.as_bytes())),
                quote(&hex(m.destination.as_bytes())),
                m.expected_old
                    .map_or_else(|| "null".into(), |oid| quote(&oid.to_string()))
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let receipt = format!(
        "{{\"type\":\"git_bundle_fetch\",\"schema_version\":1,\"outcome\":{},\"command_committed\":{},\"atomic\":true,\"tx_id\":{},\"decision_sequence\":{},\"repository_commit_id\":{rcr},\"refusal_code\":{code},\"refusal_record_id\":{refusal},\"principal_id\":{},\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"mappings\":[{mappings}],\"reference_count\":{},\"includes_forge_metadata\":false,\"delivery_acknowledged\":null,\"node_closed\":{},\"cleanup_error\":{}}}",
        quote(state),
        exit == 0,
        quote(&tx.to_string()),
        terminal.decision_sequence.get(),
        quote(&options.principal.to_string()),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(options.format.as_str()),
        options.mappings.len(),
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
