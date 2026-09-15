//! Explicit ref leases and prerequisite-scoped offline synchronization.
use super::*;
use fgit_types::{GitOid, RefName};
use std::collections::BTreeSet;

pub(super) const USAGE: &str =
    "usage: fg bundle sync-export <storage> <tenant> <repository> <new-bundle>
  --trusted-local [--object-format sha1|sha256]
  --ref <refs/name>... --prerequisite <commit-oid>...
usage: fg bundle sync-import <storage> <tenant> <repository> <bundle>
  --trusted-local --principal <id> (--idempotency-key <key>|--key-stdin)
  --allow-ref-updates --expect <refs/name=old-oid|refs/name=absent>...
  [--object-format sha1|sha256]

Every advertised destination ref needs one exact expectation. A matching old tip
permits replacement, including non-fast-forward replacement; no implicit force,
ref deletion, stale-tip refresh or policy bypass is performed. Protection rules
still apply. Prerequisites must be complete currently visible native commit history.
Maximum 64 refs and 64 prerequisites. Output is create-only. This is Git transfer,
not an authority/forge backup. Import receipts use the existing git_bundle_import
schema and retain historical terminal outcomes; input failures do not prove non-commit.";

struct SyncOptions {
    common: Options,
    references: Vec<RefName>,
    prerequisites: Vec<GitOid>,
    expected: Vec<(RefName, Option<GitOid>)>,
}
fn parse_sync(args: &[String]) -> Result<SyncOptions, String> {
    if args.len() < 5 || args.len() > 1024 || args.iter().any(|s| s.len() > 64 * 1024) {
        return Err(USAGE.into());
    }
    let import = match args[0].as_str() {
        "sync-export" => false,
        "sync-import" => true,
        _ => return Err(USAGE.into()),
    };
    let mut common = args[..5].to_vec();
    common[0] = if import { "import" } else { "export" }.into();
    let (mut names, mut prerequisites, mut expectations, mut consent) =
        (Vec::new(), Vec::new(), Vec::new(), false);
    let mut cursor = 5;
    while cursor < args.len() {
        let flag = args[cursor].as_str();
        cursor += 1;
        match flag {
            "--allow-ref-updates" => {
                if consent || !import {
                    return Err("unexpected or duplicate --allow-ref-updates".into());
                }
                consent = true;
            }
            "--ref" | "--prerequisite" | "--expect" => {
                let value = args
                    .get(cursor)
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                cursor += 1;
                let target = match flag {
                    "--ref" if !import => &mut names,
                    "--prerequisite" if !import => &mut prerequisites,
                    "--expect" if import => &mut expectations,
                    _ => return Err(format!("{flag} is not valid for this operation")),
                };
                if target.len() == 64 {
                    return Err(format!("too many {flag} values"));
                }
                target.push(value.clone());
            }
            "--trusted-local" | "--key-stdin" => common.push(flag.into()),
            _ => {
                common.push(flag.into());
                common.push(
                    args.get(cursor)
                        .ok_or_else(|| format!("missing value for {flag}"))?
                        .clone(),
                );
                cursor += 1;
            }
        }
    }
    let common = super::parse(&common)?;
    if import && (!consent || expectations.is_empty()) {
        return Err(
            "sync-import requires --allow-ref-updates and an expectation for every ref".into(),
        );
    }
    if !import && (names.is_empty() || prerequisites.is_empty()) {
        return Err("sync-export requires references and prerequisite commits".into());
    }
    let parse_oid = |text: &str| -> Result<GitOid, String> {
        let id = GitOid::from_hex(common.format, text).map_err(|e| e.to_string())?;
        if id.is_zero() {
            return Err("zero is not an expected tip or prerequisite; use absent".into());
        }
        Ok(id)
    };
    let parse_ref = |name: &str| -> Result<RefName, String> {
        let name = RefName::try_new(name.as_bytes()).map_err(|e| e.to_string())?;
        if !name.as_bytes().starts_with(b"refs/") {
            return Err("a full refs/ name is required".into());
        }
        Ok(name)
    };
    let references = names
        .iter()
        .map(|s| parse_ref(s))
        .collect::<Result<Vec<_>, _>>()?;
    let prerequisites = prerequisites
        .iter()
        .map(|s| parse_oid(s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected = Vec::new();
    let mut used = BTreeSet::new();
    for expectation in expectations {
        let (name, old) = expectation
            .rsplit_once('=')
            .ok_or("expectation must be refs/name=oid or refs/name=absent")?;
        let name = parse_ref(name)?;
        if !used.insert(name.clone()) {
            return Err("duplicate expected reference".into());
        }
        expected.push((
            name,
            if old == "absent" {
                None
            } else {
                Some(parse_oid(old)?)
            },
        ));
    }
    if references.iter().collect::<BTreeSet<_>>().len() != references.len()
        || prerequisites.iter().collect::<BTreeSet<_>>().len() != prerequisites.len()
    {
        return Err("duplicate reference or prerequisite".into());
    }
    Ok(SyncOptions {
        common,
        references,
        prerequisites,
        expected,
    })
}
pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args.len() == 2 && args[1] == "--help" {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let options = parse_sync(args)?;
    let common = &options.common;
    let input = if common.import {
        Some(read_bundle(&common.path, MAX_BUNDLE_BYTES)?)
    } else {
        require_absent(&common.path)?;
        None
    };
    let session = if let (Some(key), Some(principal)) = (&common.key, common.principal) {
        Some(LoopbackReceiveSession::authenticated(
            principal,
            IdempotencyKey::new(key_bytes(key, &mut std::io::stdin().lock())?)
                .map_err(|e| e.to_string())?,
        ))
    } else {
        None
    };
    let mut node = OneNode::open_existing(
        NodeConfig::new(common.storage.clone(), common.tenant, common.repository)
            .with_object_format(common.format),
    )
    .map_err(|e| e.to_string())?;
    enum Completed {
        Import(TxId, TerminalOutcome, usize),
        Export(fgit_types::RepositoryAuthorityHeadId, Vec<u8>, u32, GitOid),
    }
    let operation = (|| -> Result<Completed, String> {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|e| e.to_string())?;
        let request = node.request_context();
        if let (Some(input), Some(session)) = (&input, &session) {
            let result = node
                .runtime()
                .block_on(node.import_incremental_git_bundle_durable_in(
                    &request,
                    session,
                    input,
                    &options.expected,
                    Default::default(),
                ))
                .map_err(|e| e.to_string())?;
            let first = result
                .commands
                .first()
                .ok_or("no atomic terminal outcome")?;
            if !result.session.atomic
                || result.session.tx_ids != vec![first.tx_id]
                || result.commands.iter().any(|item| item != first)
            {
                return Err(format!(
                    "inconsistent atomic result; {}",
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
                .block_on(node.export_incremental_git_bundle_in(
                    &request,
                    &options.references,
                    &options.prerequisites,
                    &Default::default(),
                    None,
                ))
                .map_err(|e| e.to_string())?;
            let receipt = bundle.pack_receipt();
            let (count, checksum) = (receipt.object_count, receipt.checksum);
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
            common,
            tx,
            &terminal,
            count,
            cleanup.as_deref(),
        ),
        Ok(Completed::Export(head, bytes, count, checksum)) => {
            if let Some(error) = cleanup {
                return Err(format!("shutdown failed: {error}; no bundle published"));
            }
            publish_new_bundle(&common.path, &bytes)?;
            let receipt = format!(
                "{{\"type\":\"git_bundle_incremental_export\",\"schema_version\":1,\"source_head\":{},\"object_format\":{},\"object_count\":{count},\"pack_checksum\":{},\"bundle_bytes\":{},\"reference_count\":{},\"prerequisite_count\":{},\"bundle_created\":true,\"node_closed\":true,\"repository_changed\":false}}",
                quote(&head.to_string()),
                quote(common.format.as_str()),
                quote(&checksum.to_string()),
                bytes.len(),
                options.references.len(),
                options.prerequisites.len()
            );
            let mut output = std::io::stdout().lock();
            writeln!(output, "{receipt}")
                .and_then(|()| output.flush())
                .map_err(|e| format!("complete bundle created, but receipt output failed: {e}"))?;
            Ok(0)
        }
        Err(error) => {
            let cleanup =
                cleanup.map_or_else(String::new, |e| format!("; shutdown also failed: {e}"));
            Err(if common.import {
                format!(
                    "incremental import returned no terminal outcome: {error}{cleanup}; this is not evidence of non-commit. Retry identical inputs/key or use fg outcome"
                )
            } else {
                format!("incremental export failed: {error}{cleanup}; no bundle published")
            })
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn args(import: bool) -> Vec<String> {
        let mut a = vec![
            if import { "sync-import" } else { "sync-export" }.into(),
            "node".into(),
            "01".repeat(16),
            "02".repeat(16),
            "transfer.bundle".into(),
            "--trusted-local".into(),
        ];
        if import {
            a.extend([
                "--principal".into(),
                "03".repeat(16),
                "--key-stdin".into(),
                "--allow-ref-updates".into(),
                "--expect".into(),
                format!("refs/heads/main={}", "aa".repeat(20)),
            ]);
        } else {
            a.extend([
                "--ref".into(),
                "refs/heads/main".into(),
                "--prerequisite".into(),
                "aa".repeat(20),
            ]);
        }
        a
    }
    #[test]
    fn named_frontiers_and_explicit_update_consent_are_required() {
        assert!(parse_sync(&args(false)).is_ok());
        assert!(parse_sync(&args(true)).is_ok());
        for missing in ["--trusted-local", "--allow-ref-updates"] {
            let mut a = args(true);
            a.retain(|s| s != missing);
            assert!(parse_sync(&a).is_err());
        }
        for pair in [
            ["--ref", "refs/heads/main"],
            ["--prerequisite", &"aa".repeat(20)],
        ] {
            let mut a = args(false);
            a.extend(pair.map(String::from));
            assert!(parse_sync(&a).is_err());
        }
    }
    #[test]
    fn expectations_never_refresh_or_drop_duplicate_or_foreign_names() {
        let mut a = args(true);
        a.extend(["--expect".into(), "refs/heads/main=absent".into()]);
        assert!(parse_sync(&a).is_err());
        for bad in [
            "main=absent".into(),
            "refs/heads/main".into(),
            format!("refs/heads/main={}", "00".repeat(20)),
            format!("refs/heads/main={}", "aa".repeat(32)),
        ] {
            let mut a = args(true);
            *a.last_mut().unwrap() = bad;
            assert!(parse_sync(&a).is_err());
        }
        let mut a = args(true);
        *a.last_mut().unwrap() = "refs/heads/name=with=equals=absent".into();
        assert!(parse_sync(&a).unwrap().expected[0].1.is_none());
    }
    #[test]
    fn sha256_and_exact_stdin_keys_preserve_their_domains() {
        let mut a = args(true);
        *a.last_mut().unwrap() = format!("refs/heads/main={}", "ab".repeat(32));
        a.extend(["--object-format".into(), "sha256".into()]);
        let options = parse_sync(&a).unwrap();
        assert_eq!(
            options.expected[0].1.unwrap().algorithm(),
            GitHashAlgorithm::Sha256
        );
        assert_eq!(
            key_bytes(
                options.common.key.as_ref().unwrap(),
                &mut b"key\n".as_slice()
            )
            .unwrap(),
            b"key\n"
        );
    }
}
