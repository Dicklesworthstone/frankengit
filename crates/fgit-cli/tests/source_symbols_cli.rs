#![forbid(unsafe_code)]
//! Real fg processes over native imports and persisted symbol generations.
//! The fixture is deliberately not a filesystem checkout or a mock searcher.
#[path = "../../fgit-node/tests/source_http/support.rs"]
mod support;

use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::source_symbols::{MAX_SYMBOL_WORK, SymbolMatchMode, SymbolQuery};
use fgit_node::OneNode;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use support::*;

const RUST: &[u8] = b"pub fn needle() {}\npub fn needle_more() {}\npub struct Shape;\nmacro_rules! needle_macro { () => { fn needle_generated() {} }; }\npub fn r#type() {}\nconst TEXT: &str = \"fn needle_string() {}\";\n";
const RAW_PATH: &[u8] = b"b\xff\x1b.rs";
const OTHER: &[u8] = b"pub fn needle() {}\n";

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}
fn loose(
    root: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    name: &str,
    body: &[u8],
) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521;
        (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string();
    fs::create_dir_all(root.join("objects").join(&text[..2])).unwrap();
    fs::write(
        root.join("objects").join(&text[..2]).join(&text[2..]),
        encoded,
    )
    .unwrap();
    id
}
fn native_fixture(
    root: &Scratch,
    format: GitHashAlgorithm,
    extra: Option<(&[u8], &[u8])>,
) -> (OneNode, GitOid) {
    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    let selected = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(selected.receipt().generation())
        .unwrap();
    let git = root.0.join("git-source");
    fs::create_dir_all(git.join("refs/heads")).unwrap();
    fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(git.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let blob = |bytes: &[u8]| loose(&git, format, GitObjectKind::Blob, "blob", bytes);
    let tree = |bytes: &[u8]| loose(&git, format, GitObjectKind::Tree, "tree", bytes);
    let commit = |tree: GitOid, parent: Option<GitOid>| {
        let mut body = format!("tree {tree}\n");
        if let Some(parent) = parent {
            body.push_str(&format!("parent {parent}\n"));
        }
        body.push_str("author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nsymbol fixture\n");
        loose(
            &git,
            format,
            GitObjectKind::Commit,
            "commit",
            body.as_bytes(),
        )
    };
    let base = commit(tree(&[]), None);
    let mut entries = vec![
        ("100644", b"a.rs".as_slice(), blob(RUST)),
        ("100755", RAW_PATH, blob(OTHER)),
        ("100644", b"docs.txt".as_slice(), blob(b"\xff not Rust")),
        (
            "120000",
            b"link.rs".as_slice(),
            blob(b"../../outside-secret"),
        ),
        ("160000", b"module.rs".as_slice(), base),
    ];
    if let Some((path, bytes)) = extra {
        entries.push(("100644", path, blob(bytes)));
    }
    entries.sort_by(|a, b| a.1.cmp(b.1));
    let mut bytes = Vec::new();
    for (mode, name, id) in entries {
        bytes.extend_from_slice(mode.as_bytes());
        bytes.push(b' ');
        bytes.extend_from_slice(name);
        bytes.push(0);
        bytes.extend_from_slice(id.as_bytes());
    }
    let main = commit(tree(&bytes), Some(base));
    fs::write(git.join("refs/heads/main"), format!("{main}\n")).unwrap();
    fs::write(
        root.0.join("outside-secret"),
        b"pub fn needle_outside() {}\n",
    )
    .unwrap();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &git,
            OWNER,
            b"symbol-cli-fixture",
        ))
        .unwrap();
    assert!(!imported.commands.is_empty());
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    (node, main)
}
fn arguments(root: &Scratch, format: GitHashAlgorithm, indexed: bool) -> Vec<String> {
    let mut args = vec!["search".into(), "--symbols".into()];
    if indexed {
        args.push("--indexed-current".into());
    }
    args.extend([
        root.0.join("node").to_str().unwrap().into(),
        "31".repeat(16),
        "32".repeat(16),
        "refs/heads/main".into(),
        "--trusted-local".into(),
        "--name".into(),
        "needle".into(),
        "--object-format".into(),
        format.as_str().into(),
    ]);
    args
}
fn invoke(args: &[String], code: i32) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_fg"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn body(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).unwrap()
}
fn with_name(args: &[String], name: &str) -> Vec<String> {
    let mut copy = args.to_vec();
    let index = copy.iter().position(|value| value == "--name").unwrap();
    copy[index + 1] = name.into();
    copy
}
fn open_issue(root: &Scratch, format: GitHashAlgorithm) {
    let node = reopen(&root.config(format));
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, true, true);
    let bytes = b"expected_version=0&title=symbol+CLI+metadata+write&body=";
    let response = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/issues/1/open",
            'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: symbol-cli-issue\r\n",
                bytes.len()
            ),
            bytes,
        ),
        true,
    );
    status(&response, 200);
    assert_eq!(server.finish().accepted_sessions(), 1);
}

#[test]
fn native_cli_scans_and_index_reads_agree_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, commit) = native_fixture(&root, format, None);
        let (source, activation) = node
            .runtime()
            .block_on(node.build_source_symbol_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                None,
                Default::default(),
            ))
            .unwrap();
        let before = generation(&node);
        node.shutdown().unwrap();
        for indexed in [false, true] {
            let args = arguments(&root, format, indexed);
            let output = invoke(&args, 0);
            let text = body(&output);
            assert!(text.contains("\"match_count\":2"));
            assert!(text.contains(&format!("\"path_hex\":\"{}\"", hex(RAW_PATH))));
            assert!(text.contains(&commit.to_string()));
            assert!(text.contains("\"unsupported_language_files\":1"));
            assert!(text.contains("\"non_regular_entries\":2"));
            assert!(text.contains("\"repository_changed\":false,\"index_changed\":false"));
            assert!(!text.contains('\x1b'));
            let mut prefix = args.clone();
            prefix.extend(["--match", "prefix"].map(str::to_owned));
            assert!(body(&invoke(&prefix, 0)).contains("\"match_count\":4"));
            prefix.extend(["--max-matches", "1"].map(str::to_owned));
            let limited = invoke(&prefix, 3);
            assert!(
                body(&limited).contains("\"complete\":false,\"truncated_reason\":\"match_limit\"")
            );
            let mut scoped = args.clone();
            scoped.extend(["--path-hex".into(), hex(RAW_PATH)]);
            assert!(body(&invoke(&scoped, 0)).contains("\"match_count\":1"));
            let raw = invoke(&with_name(&args, "type"), 0);
            assert!(body(&raw).contains("\"raw_identifier\":true"));
            for absent in [
                "needle_generated",
                "needle_string",
                "needle_outside",
                "NEEDLE",
            ] {
                assert!(body(&invoke(&with_name(&args, absent), 0)).contains("\"match_count\":0"));
            }
            let mut typed = with_name(&args, "needle_macro");
            typed.extend(["--kind", "macro"].map(str::to_owned));
            assert!(body(&invoke(&typed, 0)).contains("\"match_count\":1"));
        }
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before);
        let query =
            SymbolQuery::new(b"needle", SymbolMatchMode::Exact, &[], &[], MAX_SYMBOL_WORK).unwrap();
        let (_, checked) = node
            .runtime()
            .block_on(node.search_source_symbols_index_revalidated_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                Some(&activation),
                &query,
                Default::default(),
                32 * 1024 * 1024,
            ))
            .unwrap();
        assert_eq!(checked.source, source);
        assert_eq!(
            checked.generation,
            activation.generation_id.as_internal_object_id().clone()
        );
        assert_eq!(
            checked.generation_number,
            activation.authority_generation.get()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn metadata_advance_preserves_index_origin_and_old_snapshot_pin_refuses() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, _) = native_fixture(&root, format, None);
        let (source, activation) = node
            .runtime()
            .block_on(node.build_source_symbol_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                None,
                Default::default(),
            ))
            .unwrap();
        node.shutdown().unwrap();
        open_issue(&root, format);
        let args = arguments(&root, format, true);
        let output = invoke(&args, 0);
        let text = body(&output);
        let split = text.find("\"indexed_source\":{").unwrap();
        assert!(text.contains("\"distinct_index_provenance\":true"));
        assert!(!text[..split].contains(&head_token(source.head)));
        assert!(text[split..].contains(&head_token(source.head)));
        let mut floor = args.clone();
        let id = activation.generation_id.as_internal_object_id();
        floor.extend([
            "--minimum-generation".into(),
            format!(
                "alg:{}:{}",
                id.algorithm().code_point(),
                hex(id.digest().as_bytes())
            ),
            "--minimum-number".into(),
            activation.authority_generation.get().to_string(),
        ]);
        assert!(body(&invoke(&floor, 0)).contains("\"match_count\":2"));
        *floor.last_mut().unwrap() = u64::MAX.to_string();
        assert!(invoke(&floor, 2).stdout.is_empty());
        for indexed in [false, true] {
            let mut pinned = arguments(&root, format, indexed);
            pinned.extend(["--expected-head".into(), head_token(source.head)]);
            let stale = invoke(&pinned, 2);
            assert!(stale.stdout.is_empty());
            assert!(String::from_utf8_lossy(&stale.stderr).contains("SnapshotMoved"));
            let mut wrong = arguments(&root, format, indexed);
            wrong.extend(["--expected-commit".into(), source.tree.to_string()]);
            let stale = invoke(&wrong, 2);
            assert!(stale.stdout.is_empty());
            assert!(String::from_utf8_lossy(&stale.stderr).contains("CommitMoved"));
        }
    }
}

#[test]
fn missing_index_never_falls_back_and_budget_or_trust_refusals_do_not_publish() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, _) = native_fixture(&root, format, None);
        let before = generation(&node);
        node.shutdown().unwrap();
        let indexed = arguments(&root, format, true);
        for _ in 0..2 {
            let missing = invoke(&indexed, 2);
            assert!(missing.stdout.is_empty());
            assert!(String::from_utf8_lossy(&missing.stderr).contains("Uninitialized"));
        }
        let scan = arguments(&root, format, false);
        assert!(body(&invoke(&scan, 0)).contains("\"match_count\":2"));
        for flag in [
            "--max-work",
            "--max-bytes",
            "--max-file-bytes",
            "--max-files",
        ] {
            let mut small = scan.clone();
            small.extend([flag, "1"].map(str::to_owned));
            assert!(invoke(&small, 2).stdout.is_empty());
        }
        for args in [&scan, &indexed] {
            let mut untrusted = args.clone();
            untrusted.retain(|arg| arg != "--trusted-local");
            assert!(invoke(&untrusted, 2).stdout.is_empty());
            let mut missing_ref = args.clone();
            let index = missing_ref
                .iter()
                .position(|arg| arg == "refs/heads/main")
                .unwrap();
            missing_ref[index] = "refs/heads/missing".into();
            assert!(invoke(&missing_ref, 2).stdout.is_empty());
        }
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before);
        node.runtime()
            .block_on(node.build_source_symbol_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                None,
                Default::default(),
            ))
            .unwrap();
        node.shutdown().unwrap();
        let mut small = indexed;
        small.extend(["--max-index-bytes", "1"].map(str::to_owned));
        assert!(invoke(&small, 2).stdout.is_empty());
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn malformed_source_diagnostic_preserves_raw_path_without_terminal_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, _) = native_fixture(&root, format, Some((b"bad\xff.rs", b"pub fn broken() {")));
        let before = generation(&node);
        node.shutdown().unwrap();
        let output = invoke(&arguments(&root, format, false), 2);
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("path_hex=626164ff2e7273"));
        assert!(error.contains("UnbalancedDelimiter"));
        assert!(!error.contains('\x1b'));
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
