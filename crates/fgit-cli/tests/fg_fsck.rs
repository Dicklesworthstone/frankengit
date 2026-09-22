#![forbid(unsafe_code)]
//! Real CLI/embedded-store regressions. The fixture uses the same tiny stored
//! zlib-member construction as the existing CLI import tests; no external Git.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{GitHashAlgorithm, GitOid};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const ACTOR: &str = "33333333333333333333333333333333";
const HISTORICAL_PAYLOAD: &[u8] = b"fsck historical-only object 8c740f112c6d\n";
static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("frankengit-fsck-{}-{sequence}", std::process::id()));
        // Refuse a stale directory rather than reusing another run's contents.
        fs::create_dir(&root).expect("create isolated scratch directory");
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn text(path: &Path) -> &str { path.to_str().expect("fixture path is UTF-8") }
fn fg(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fg")).args(args).output().expect("run fg binary")
}
fn success(output: Output) -> String {
    assert_eq!(output.status.code(), Some(0), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).expect("CLI output is UTF-8")
}
fn refused(output: Output) -> String {
    assert_eq!(output.status.code(), Some(2), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(output.stdout.is_empty(), "incomplete audit emitted stdout");
    let error = String::from_utf8(output.stderr).expect("CLI error is UTF-8");
    assert!(error.contains("\"type\":\"fsck_error\""), "{error}");
    assert!(error.contains("\"complete\":false"), "{error}");
    error
}
fn audit(root: &Path, format: &str, extra: &[&str]) -> Output {
    let mut args = vec!["fsck", text(root), TENANT, REPOSITORY, "--trusted-local", "--object-format", format];
    args.extend_from_slice(extra);
    fg(&args)
}
fn token(receipt: &str) -> &str {
    receipt.split_once("\"snapshot_token\":\"").expect("snapshot token in receipt")
        .1.split('"').next().expect("snapshot token terminator")
}
fn assert_counts(receipt: &str, refs: usize, objects: usize) {
    assert_eq!(receipt.lines().count(), 1, "one NDJSON receipt");
    assert!(receipt.contains(&format!("\"references_checked\":{refs},")), "{receipt}");
    assert!(receipt.contains(&format!("\"objects_verified\":{objects},")), "{receipt}");
    assert!(receipt.contains("\"complete\":true"));
    assert!(receipt.contains("\"node_closed\":true"));
    assert!(receipt.contains("\"object_graph_verified\":true"));
}

#[test]
fn help_and_invalid_requests_do_not_initialize_storage() {
    let scratch = Scratch::new();
    let absent = scratch.0.join("absent");
    assert!(success(fg(&["fsck", "--help"])).starts_with("usage: fg fsck"));
    refused(fg(&["fsck", text(&absent), TENANT, REPOSITORY]));
    for extra in [vec!["--max-objects", "0"], vec!["--max-bytes", "0"],
        vec!["--max-object-bytes", "0"], vec!["--expected-head", "unqualified"],
        vec!["--timeout-secs", "3601"], vec!["--trusted-local"], vec!["--repair", "yes"]]
    {
        refused(audit(&absent, "sha1", &extra));
        assert!(!absent.exists(), "invalid input created repository state");
    }
}

#[test]
fn both_native_formats_audit_empty_repositories_and_enforce_snapshot_fences() {
    for format in ["sha1", "sha256"] {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        success(fg(&["init", text(&root), TENANT, REPOSITORY, format]));
        let receipt = success(audit(&root, format, &[]));
        assert_counts(&receipt, 0, 0);
        assert!(receipt.contains("\"payload_bytes_verified\":0,"));
        assert!(receipt.contains("\"authority_generation\":1,"));
        assert_eq!(success(audit(&root, format, &["--expected-head", token(&receipt),
            "--expected-generation", "1"])), receipt);

        let mut wrong = token(&receipt).to_owned();
        let last = wrong.pop().expect("nonempty digest");
        wrong.push(if last == '0' { '1' } else { '0' });
        assert!(refused(audit(&root, format, &["--expected-head", &wrong]))
            .contains("authority_head_mismatch"));
        assert!(refused(audit(&root, format, &["--expected-generation", "2"]))
            .contains("authority_generation_mismatch"));
        assert_eq!(success(audit(&root, format, &[])), receipt, "refused audits did not advance authority");
    }
}

struct Fixture { main: GitOid, obsolete: GitOid, obsolete_blob: GitOid, payload_bytes: usize }
fn fixture(source: &Path) -> Fixture {
    let (main, _, main_bytes) = history(source, b"fsck current main object\n");
    let (obsolete, obsolete_blob, old_bytes) = history(source, HISTORICAL_PAYLOAD);
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("refs/heads/main"), format!("{main}\n")).unwrap();
    fs::write(source.join("refs/heads/obsolete"), format!("{obsolete}\n")).unwrap();
    fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    Fixture { main, obsolete, obsolete_blob, payload_bytes: main_bytes + old_bytes }
}
fn history(source: &Path, body: &[u8]) -> (GitOid, GitOid, usize) {
    let blob = loose(source, GitObjectKind::Blob, body);
    let mut tree = b"100644 README\0".to_vec();
    tree.extend_from_slice(blob.require_sha1().unwrap().as_bytes());
    let tree_oid = loose(source, GitObjectKind::Tree, &tree);
    let commit = format!("tree {tree_oid}\nauthor Fsck <fsck@example.invalid> 1 +0000\ncommitter Fsck <fsck@example.invalid> 1 +0000\n\nfsck fixture\n");
    let commit_oid = loose(source, GitObjectKind::Commit, commit.as_bytes());
    (commit_oid, blob, body.len() + tree.len() + commit.len())
}
fn loose(root: &Path, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(GitHashAlgorithm::Sha1, kind, body);
    let oid_text = oid.to_string();
    let path = root.join("objects").join(&oid_text[..2]).join(&oid_text[2..]);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    framed.extend_from_slice(body);
    let length = u16::try_from(framed.len()).expect("small test object");
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend_from_slice(&length.to_le_bytes());
    zlib.extend_from_slice(&(!length).to_le_bytes());
    zlib.extend_from_slice(&framed);
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in framed { a = (a + u32::from(byte)) % 65_521; b = (b + a) % 65_521; }
    zlib.extend_from_slice(&((b << 16) | a).to_be_bytes());
    fs::write(path, zlib).unwrap();
    oid
}

fn imported(scratch: &Scratch) -> (PathBuf, Fixture) {
    let root = scratch.0.join("node");
    let source = scratch.0.join("source.git");
    let fixture = fixture(&source);
    success(fg(&["init", text(&root), TENANT, REPOSITORY]));
    success(fg(&["import", text(&root), TENANT, REPOSITORY, ACTOR, "fsck-fixture", text(&source)]));
    (root, fixture)
}

#[test]
fn full_import_audit_counts_exact_payloads_and_never_truncates_to_a_budget() {
    let scratch = Scratch::new();
    let (root, fixture) = imported(&scratch);
    let receipt = success(audit(&root, "sha1", &[]));
    assert_counts(&receipt, 2, 6);
    assert!(receipt.contains(&format!("\"payload_bytes_verified\":{},", fixture.payload_bytes)));
    assert_eq!(success(audit(&root, "sha1", &["--max-objects", "6", "--max-bytes",
        &fixture.payload_bytes.to_string()])), receipt);
    assert!(refused(audit(&root, "sha1", &["--max-objects", "5"])).contains("max-objects"));
    assert!(refused(audit(&root, "sha1", &["--max-bytes", &(fixture.payload_bytes - 1).to_string()]))
        .contains("max-bytes"));
    refused(audit(&root, "sha1", &["--max-object-bytes", "1"]));
    assert_eq!(success(audit(&root, "sha1", &[])), receipt);
}

/// Fault injection only: inspect this test's loose-object storage, not authority
/// discovery. The production audit never enumerates storage directories.
fn find_payload(root: &Path, payload: &[u8], depth: usize, matches: &mut Vec<(PathBuf, Vec<u8>)>) {
    assert!(depth <= 4, "unexpected fixture object-store layout");
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            find_payload(&entry.path(), payload, depth + 1, matches);
        } else if kind.is_file() {
            let bytes = fs::read(entry.path()).unwrap();
            if bytes.ends_with(payload) { matches.push((entry.path(), bytes)); }
        }
    }
}

#[test]
fn deleted_branch_history_is_still_audited_and_corruption_is_not_repaired() {
    let scratch = Scratch::new();
    let (root, fixture) = imported(&scratch);
    let before = success(audit(&root, "sha1", &[]));
    success(fg(&["branch", "delete", text(&root), TENANT, REPOSITORY,
        "--trusted-local", "--principal", ACTOR, "--idempotency-key", "fsck-delete-old",
        "--ref", "refs/heads/obsolete", "--expected-tip", &fixture.obsolete.to_string()]));
    let after = success(audit(&root, "sha1", &[]));
    assert_counts(&after, 1, 6);
    assert_ne!(token(&before), token(&after));
    assert!(refused(audit(&root, "sha1", &["--expected-head", token(&before)]))
        .contains("authority_head_mismatch"));

    let mut matches = Vec::new();
    find_payload(&root.join("objects"), HISTORICAL_PAYLOAD, 0, &mut matches);
    assert_eq!(matches.len(), 1, "one exact historical object backing file");
    let (path, original) = matches.pop().unwrap();
    let mut corrupt = original.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&path, &corrupt).unwrap();
    // A current-commit doctor sample cannot stand in for the whole-set audit.
    success(fg(&["doctor", text(&root), TENANT, REPOSITORY, &fixture.main.to_string()]));
    let error = refused(audit(&root, "sha1", &[]));
    assert!(error.contains(&fixture.obsolete_blob.to_string()), "{error}");
    assert_eq!(fs::read(&path).unwrap(), corrupt, "fsck must not silently repair bytes");
    fs::write(&path, &original).unwrap();
    assert_eq!(success(audit(&root, "sha1", &[])), after);

    fs::remove_file(&path).unwrap();
    refused(audit(&root, "sha1", &[]));
    assert!(!path.exists(), "fsck must not recreate a missing object");
    fs::write(&path, original).unwrap();
    assert_eq!(success(audit(&root, "sha1", &[])), after);
}

#[path = "fg_fsck/graph_cases.rs"]
mod graph_cases;
