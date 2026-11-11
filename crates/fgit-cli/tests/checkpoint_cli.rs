#![forbid(unsafe_code)]
//! Fresh fg processes exercising persisted outcome checkpoints and admission.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_schema::json::{self, Value};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const PRINCIPAL: &str = "33333333333333333333333333333333";
static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frankengit-checkpoint-cli-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated test directory");
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn text(path: &Path) -> &str {
    path.to_str().expect("UTF-8 fixture path")
}

fn fg(args: &[&str], code: i32) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_fg"))
        .args(args)
        .output()
        .expect("run real fg process");
    assert_eq!(
        output.status.code(),
        Some(code),
        "args={args:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

fn value(output: Output) -> Value {
    let value = json::parse(&output.stdout).expect("complete JSON receipt");
    assert_eq!(field(&value, "node_closed"), &Value::Bool(true));
    value
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    &value.object().expect("JSON object")[key]
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key).text().expect("JSON string")
}

fn count(value: &Value, key: &str) -> u64 {
    field(value, key).unsigned().expect("unsigned JSON number")
}

fn checkpoint(root: &Path, extra: &[&str], code: i32) -> Output {
    let mut args = vec![
        "checkpoint",
        "outcomes",
        text(root),
        TENANT,
        REPOSITORY,
        "--trusted-local",
    ];
    args.extend_from_slice(extra);
    fg(&args, code)
}

fn refused(output: Output) -> String {
    assert!(
        output.stdout.is_empty(),
        "refused checkpoint emitted success"
    );
    let error = json::parse(&output.stderr).expect("structured checkpoint refusal");
    assert_eq!(string(&error, "type"), "outcome_checkpoint_error");
    assert_eq!(field(&error, "complete"), &Value::Bool(false));
    string(&error, "error").to_owned()
}

fn read_issues(root: &Path, format: &str) -> Value {
    value(fg(
        &[
            "issue",
            "list",
            text(root),
            TENANT,
            REPOSITORY,
            "--trusted-local",
            "--object-format",
            format,
        ],
        0,
    ))
}

fn mutation(
    root: &Path,
    format: &str,
    verb: &str,
    key: &str,
    version: &str,
    fields: &[&str],
    code: i32,
) -> Value {
    let mut args = vec![
        "issue",
        verb,
        text(root),
        TENANT,
        REPOSITORY,
        "7",
        "--trusted-local",
        "--object-format",
        format,
        "--principal",
        PRINCIPAL,
        "--idempotency-key",
        key,
        "--expected-version",
        version,
    ];
    args.extend_from_slice(fields);
    value(fg(&args, code))
}

fn same_terminal(left: &Value, right: &Value) {
    for key in [
        "tx_id",
        "decision_sequence",
        "repository_commit_id",
        "refusal_record_id",
        "refusal_code",
        "outcome",
    ] {
        assert_eq!(field(left, key), field(right, key), "{key}");
    }
}

fn assert_checkpoint(receipt: &Value, decisions: u64, published: bool) {
    assert_eq!(string(receipt, "type"), "outcome_checkpoint");
    assert_eq!(field(receipt, "complete"), &Value::Bool(true));
    assert_eq!(field(receipt, "published"), &Value::Bool(published));
    assert_eq!(
        string(receipt, "backup_profile"),
        "decision_history_with_admission_closure_v1"
    );
    assert_eq!(string(receipt, "scope"), "outcome_index_maintenance");
    assert_eq!(count(receipt, "decisions"), decisions);
    assert!(string(receipt, "source_head").starts_with("alg:"));
    assert!(string(receipt, "published_head").starts_with("alg:"));
    assert!(string(receipt, "checkpoint_root").starts_with("alg:"));
}

#[test]
fn help_and_invalid_arguments_do_not_initialize_storage() {
    let scratch = Scratch::new();
    let absent = scratch.0.join("absent");
    for args in [
        vec!["checkpoint", "--help"],
        vec!["checkpoint", "outcomes", "--help"],
    ] {
        let output = fg(&args, 0);
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.starts_with("usage: fg checkpoint outcomes"));
        assert!(help.contains("DecisionHistoryWithAdmissionClosureV1"));
        assert!(help.contains("does not prove non-publication"));
    }
    refused(fg(
        &["checkpoint", "outcomes", text(&absent), TENANT, REPOSITORY],
        2,
    ));
    for extra in [
        vec!["--max-decisions", "0"],
        vec!["--max-decisions", "65537"],
        vec!["--max-bytes", "0"],
        vec!["--max-bytes", "16777217"],
        vec!["--expected-head", "unqualified"],
        vec!["--timeout-secs", "3601"],
        vec!["--trusted-local"],
        vec!["--max-bytes", "1", "--max-bytes", "2"],
        vec!["--prune", "true"],
    ] {
        refused(checkpoint(&absent, &extra, 2));
        assert!(
            !absent.exists(),
            "invalid arguments created repository state"
        );
    }
}

#[test]
fn empty_native_repositories_checkpoint_once_in_both_formats() {
    for format in ["sha1", "sha256"] {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        fg(&["init", text(&root), TENANT, REPOSITORY, format], 0);
        let first = value(checkpoint(&root, &[], 0));
        assert_checkpoint(&first, 0, true);
        assert_ne!(
            field(&first, "source_head"),
            field(&first, "published_head")
        );
        let again = value(checkpoint(
            &root,
            &["--expected-head", string(&first, "published_head")],
            0,
        ));
        assert_checkpoint(&again, 0, false);
        for key in [
            "published_head",
            "authority_generation",
            "checkpoint_root",
            "capsule_id",
        ] {
            assert_eq!(field(&first, key), field(&again, key), "{key}");
        }
        assert_eq!(
            field(&again, "source_head"),
            field(&again, "published_head")
        );
        assert!(
            refused(checkpoint(
                &root,
                &["--expected-head", string(&first, "source_head")],
                2,
            ))
            .contains("HeadMoved")
        );
    }
}

#[test]
fn checkpoint_preserves_terminal_retries_and_later_admission_in_both_formats() {
    for format in ["sha1", "sha256"] {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        fg(&["init", text(&root), TENANT, REPOSITORY, format], 0);
        let open_fields = [
            "--title",
            "Retained decisions",
            "--body",
            "Native checkpoint fixture",
        ];
        let opened = mutation(
            &root,
            format,
            "open",
            "checkpoint-open",
            "0",
            &open_fields,
            0,
        );
        let stale = mutation(&root, format, "close", "checkpoint-refused", "2", &[], 3);
        let before = read_issues(&root, format);
        let source = string(&before, "snapshot_token");

        assert!(refused(checkpoint(&root, &["--max-decisions", "1"], 2)).contains("LimitExceeded"));
        assert!(refused(checkpoint(&root, &["--max-bytes", "1"], 2)).contains("LimitExceeded"));
        let mut unknown = source.to_owned();
        let last = unknown.pop().unwrap();
        unknown.push(if last == '0' { '1' } else { '0' });
        assert!(
            refused(checkpoint(&root, &["--expected-head", &unknown], 2)).contains("HeadMoved")
        );
        refused(fg(
            &[
                "--timeout-secs",
                "0.000000001",
                "checkpoint",
                "outcomes",
                text(&root),
                TENANT,
                REPOSITORY,
                "--trusted-local",
                "--timeout-secs",
                "3600",
            ],
            2,
        ));
        assert_eq!(
            string(&read_issues(&root, format), "snapshot_token"),
            source
        );

        let first = value(checkpoint(&root, &["--expected-head", source], 0));
        assert_checkpoint(&first, 2, true);
        assert_eq!(string(&first, "source_head"), source);
        assert!(count(&first, "leaf_objects") > 0);
        assert!(count(&first, "leaf_bytes") > 0);
        let selected = string(&first, "published_head");
        assert_ne!(selected, source);
        let after = read_issues(&root, format);
        assert_eq!(string(&after, "snapshot_token"), selected);
        assert_eq!(field(&before, "issues"), field(&after, "issues"));

        let again = value(checkpoint(&root, &["--expected-head", selected], 0));
        assert_checkpoint(&again, 2, false);
        for key in [
            "published_head",
            "authority_generation",
            "checkpoint_root",
            "capsule_id",
        ] {
            assert_eq!(field(&first, key), field(&again, key), "{key}");
        }
        same_terminal(
            &opened,
            &mutation(
                &root,
                format,
                "open",
                "checkpoint-open",
                "0",
                &open_fields,
                0,
            ),
        );
        same_terminal(
            &stale,
            &mutation(&root, format, "close", "checkpoint-refused", "2", &[], 3),
        );
        assert_eq!(
            string(&read_issues(&root, format), "snapshot_token"),
            selected
        );

        mutation(
            &root,
            format,
            "comment",
            "checkpoint-after",
            "1",
            &["--body", "Admission after the retained prefix"],
            0,
        );
        let advanced = read_issues(&root, format);
        let advanced_head = string(&advanced, "snapshot_token");
        assert_ne!(advanced_head, selected);
        assert!(
            refused(checkpoint(&root, &["--expected-head", selected], 2)).contains("HeadMoved")
        );
        let second = value(checkpoint(&root, &["--expected-head", advanced_head], 0));
        assert_checkpoint(&second, 3, true);
        assert_eq!(string(&second, "source_head"), advanced_head);
        assert_ne!(
            field(&first, "checkpoint_root"),
            field(&second, "checkpoint_root")
        );
        assert!(count(&second, "authority_generation") > count(&first, "authority_generation"));

        // A selected checkpoint is still subject to explicitly narrowed bounds.
        assert!(refused(checkpoint(&root, &["--max-decisions", "2"], 2)).contains("LimitExceeded"));
        assert_eq!(
            string(&read_issues(&root, format), "snapshot_token"),
            string(&second, "published_head"),
        );
    }
}

fn repository_checkpoint(root: &Path, extra: &[&str], code: i32) -> Output {
    let mut args = vec![
        "checkpoint",
        "repository",
        text(root),
        TENANT,
        REPOSITORY,
        "--trusted-local",
    ];
    args.extend_from_slice(extra);
    fg(&args, code)
}

fn repository_refused(output: Output) -> String {
    assert!(
        output.stdout.is_empty(),
        "refused repository checkpoint emitted success"
    );
    let error = json::parse(&output.stderr).expect("structured repository checkpoint refusal");
    assert_eq!(string(&error, "type"), "repository_checkpoint_error");
    assert_eq!(field(&error, "complete"), &Value::Bool(false));
    string(&error, "error").to_owned()
}

fn assert_repository_checkpoint(receipt: &Value, decisions: u64, objects: u64, published: bool) {
    assert_eq!(string(receipt, "type"), "repository_checkpoint");
    assert_eq!(field(receipt, "complete"), &Value::Bool(true));
    assert_eq!(field(receipt, "published"), &Value::Bool(published));
    assert_eq!(string(receipt, "backup_profile"), "full_closure");
    assert_eq!(string(receipt, "scope"), "repository_full_closure");
    assert_eq!(count(receipt, "decisions"), decisions);
    assert_eq!(count(receipt, "objects"), objects);
    assert!(string(receipt, "source_head").starts_with("alg:"));
    assert!(string(receipt, "published_head").starts_with("alg:"));
    assert!(string(receipt, "checkpoint_root").starts_with("alg:"));
    assert!(string(receipt, "object_closure_root").starts_with("alg:"));
}

#[test]
fn repository_checkpoint_verifies_full_closure_and_refuses_stale_head_and_tampered_capsule_twins() {
    let help = String::from_utf8(fg(&["checkpoint", "repository", "--help"], 0).stdout).unwrap();
    assert!(help.starts_with("usage: fg checkpoint repository"));
    assert!(help.contains("FullClosure"));
    assert!(help.contains("--expected-generation"));

    for format in ["sha1", "sha256"] {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        fg(&["init", text(&root), TENANT, REPOSITORY, format], 0);
        // Commit a real Git tree/blob/commit via native patch prepare-initial + apply-initial + forge issue open.
        let patch_path = scratch.0.join("initial.patch");
        let bundle_path = scratch.0.join("initial.bundle");
        fs::write(
            &patch_path,
            b"diff --git a/README.md b/README.md\nnew file mode 100644\n--- /dev/null\n+++ b/README.md\n@@ -0,0 +1 @@\n+hello full closure\n",
        )
        .unwrap();
        let prepared = value(fg(
            &[
                "patch",
                "prepare-initial",
                text(&root),
                TENANT,
                REPOSITORY,
                "refs/heads/main",
                text(&patch_path),
                text(&bundle_path),
                "--trusted-local",
                "--profile",
                "exact-v1",
                "--object-format",
                format,
                "--author",
                "Test Author <author@example.com>",
                "--timestamp",
                "1700000000",
                "--message",
                "initial commit",
            ],
            0,
        ));
        let candidate_commit = string(&prepared, "candidate_commit");
        fg(
            &[
                "patch",
                "apply-initial",
                text(&root),
                TENANT,
                REPOSITORY,
                "refs/heads/main",
                text(&bundle_path),
                "--trusted-local",
                "--principal",
                PRINCIPAL,
                "--idempotency-key",
                "repo-ckpt-initial",
                "--expected-commit",
                candidate_commit,
            ],
            0,
        );
        mutation(
            &root,
            format,
            "open",
            "repo-ckpt-issue",
            "0",
            &["--title", "Checkpoint issue", "--body", "Body"],
            0,
        );
        let before = read_issues(&root, format);
        let source_head = string(&before, "snapshot_token");

        // Stale generation and tight object-limit refusal twins leave head untouched.
        assert!(
            repository_refused(repository_checkpoint(
                &root,
                &["--expected-generation", "1"],
                2
            ))
            .contains("HeadMoved")
        );
        assert!(
            repository_refused(repository_checkpoint(&root, &["--max-objects", "2"], 2))
                .contains("LimitExceeded")
        );
        assert_eq!(
            string(&read_issues(&root, format), "snapshot_token"),
            source_head
        );

        // Positive full-closure checkpoint activation with exact head + generation fences.
        let first = value(repository_checkpoint(
            &root,
            &["--expected-head", source_head, "--expected-generation", "3"],
            0,
        ));
        assert_repository_checkpoint(&first, 2, 3, true);
        assert_eq!(count(&first, "references"), 1);
        assert_eq!(count(&first, "local_edges"), 2);
        assert!(count(&first, "payload_bytes") > 0);
        let published_head = string(&first, "published_head");
        assert_ne!(published_head, source_head);

        // Stale head fence refuses after activation.
        assert!(
            repository_refused(repository_checkpoint(
                &root,
                &["--expected-head", source_head],
                2
            ))
            .contains("HeadMoved")
        );

        // Idempotent repeat at the published head + generation verifies and emits published=false.
        let again = value(repository_checkpoint(
            &root,
            &[
                "--expected-head",
                published_head,
                "--expected-generation",
                "4",
            ],
            0,
        ));
        assert_repository_checkpoint(&again, 2, 3, false);
        assert_eq!(field(&first, "capsule_id"), field(&again, "capsule_id"));
        assert_eq!(
            field(&first, "object_closure_root"),
            field(&again, "object_closure_root")
        );

        // 1. Corrupt Git object backing file refusal twin + near-identical restored twin.
        fn find_payload_files(
            dir: &Path,
            suffix: &[u8],
            out: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
        ) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if entry.file_type().unwrap().is_dir() {
                    find_payload_files(&path, suffix, out);
                } else if let Ok(bytes) = fs::read(&path)
                    && bytes.ends_with(suffix)
                {
                    out.push((path, bytes));
                }
            }
        }
        let mut blob_files = Vec::new();
        find_payload_files(
            &root.join("objects"),
            b"hello full closure\n",
            &mut blob_files,
        );
        assert_eq!(
            blob_files.len(),
            1,
            "expected one README.md blob backing file"
        );
        let (blob_path, original_blob) = blob_files.pop().unwrap();
        let mut corrupt_blob = original_blob.clone();
        *corrupt_blob.last_mut().unwrap() ^= 0x01;
        fs::write(&blob_path, &corrupt_blob).unwrap();
        let blob_err = repository_refused(repository_checkpoint(&root, &[], 2));
        assert!(
            blob_err.contains("GitBlobStream") && blob_err.contains("PayloadCommitmentMismatch"),
            "unexpected corrupt git object refusal: {blob_err}"
        );
        fs::write(&blob_path, &original_blob).unwrap();
        let after_blob_restore = value(repository_checkpoint(
            &root,
            &["--expected-head", published_head],
            0,
        ));
        assert_repository_checkpoint(&after_blob_restore, 2, 3, false);

        // 2. Persisted capsule tamper twin via FsqliteAuthorityStore (writing valid
        // WAL frames so SQLite does not silently roll back the WAL tail):
        // bind `last_checkpoint_id` to a capsule key holding corrupted frame bytes,
        // verify `fg checkpoint repository` refuses cleanly with a structured capsule/
        // checkpoint error, then restore the pre-tamper SQLite files and verify clean
        // checkpoint verification resumes.
        let saved_sqlite = [
            "authority.fsqlite",
            "authority.fsqlite-wal",
            "authority.fsqlite-shm",
        ]
        .into_iter()
        .map(|name| {
            let path = root.join(name);
            let bytes = fs::read(&path).ok();
            (path, bytes)
        })
        .collect::<Vec<_>>();
        {
            use fgit_authority::{
                AsyncAuthorityStore, CasOutcome, HeadRead, StoreInstanceId, body_key,
                body_key_for_id,
            };
            use fgit_authority_fsqlite::FsqliteAuthorityStore;
            use fgit_codec::{
                CryptoBodyIdentity, DecodeLimits, RepositoryAuthorityHeadBody, body_id,
                decode_body, encode_body,
            };
            use fgit_crypto::IdentityDomain;
            use fgit_node::{NodeConfig, OneNode};
            use fgit_types::{
                CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, RepositoryAuthorityHeadId,
                RepositoryCapsuleId, RepositoryId, TenantId,
            };

            let node = OneNode::open_existing(NodeConfig::new(
                root.clone(),
                TenantId::from_hex(TENANT).unwrap(),
                RepositoryId::from_hex(REPOSITORY).unwrap(),
            ))
            .unwrap();
            let cx = <FsqliteAuthorityStore as AsyncAuthorityStore>::Context::new();
            cx.set_native_cx(node.runtime().request_cx_with_budget(Default::default()));
            let mut authority = node
                .runtime()
                .block_on(FsqliteAuthorityStore::open(
                    &cx,
                    root.join("authority.fsqlite").to_str().unwrap(),
                    StoreInstanceId::from_raw(0x8371),
                    Default::default(),
                ))
                .unwrap();
            let head_key = node.authority_head_key().clone();
            let HeadRead::Present(receipt) = node
                .runtime()
                .block_on(AsyncAuthorityStore::read_head(&authority, &cx, &head_key))
                .unwrap()
            else {
                panic!("expected published head in authority store");
            };
            let current_head: RepositoryAuthorityHeadBody =
                decode_body(receipt.body(), DecodeLimits::default()).unwrap();
            let current_head_id = RepositoryAuthorityHeadId::from_internal_object_id(
                body_id(&CryptoBodyIdentity, &current_head).unwrap(),
            )
            .unwrap();
            let fake_capsule_id = RepositoryCapsuleId::from_digest(
                DigestAlgorithmId::try_new(2).unwrap(),
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[0xee; 32]).unwrap(),
            );
            node.runtime()
                .block_on(AsyncAuthorityStore::put_if_absent(
                    &authority,
                    &cx,
                    &body_key_for_id(fake_capsule_id.as_internal_object_id()).unwrap(),
                    b"corrupt-repository-capsule-frame",
                ))
                .unwrap();
            let mut tampered_head = current_head;
            tampered_head.predecessor_head_id = Some(current_head_id);
            tampered_head.generation = tampered_head.generation.next().unwrap();
            tampered_head.last_checkpoint_id = Some(fake_capsule_id);
            let tampered_head_bytes = encode_body(&tampered_head).unwrap();
            node.runtime()
                .block_on(AsyncAuthorityStore::put_if_absent(
                    &authority,
                    &cx,
                    &body_key(IdentityDomain::RepositoryAuthorityHead, &tampered_head).unwrap(),
                    &tampered_head_bytes,
                ))
                .unwrap();
            let CasOutcome::Committed(_) = node
                .runtime()
                .block_on(AsyncAuthorityStore::compare_exchange_head(
                    &authority,
                    &cx,
                    &head_key,
                    receipt.token(),
                    tampered_head.generation,
                    &tampered_head_bytes,
                ))
                .unwrap()
            else {
                panic!("expected CAS to install tampered capsule head fixture");
            };
            node.runtime().block_on(authority.close(&cx)).unwrap();
            node.shutdown().unwrap();
        }
        let tamper_err = repository_refused(repository_checkpoint(&root, &[], 2));
        assert!(
            tamper_err.contains("Capsule")
                || tamper_err.contains("Checkpoint")
                || tamper_err.contains("Codec"),
            "unexpected tamper refusal: {tamper_err}"
        );
        // Restoring the exact untampered SQLite files restores clean verification.
        for (path, maybe_bytes) in saved_sqlite {
            match maybe_bytes {
                Some(bytes) => fs::write(&path, bytes).unwrap(),
                None => {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        let restored = value(repository_checkpoint(
            &root,
            &["--expected-head", published_head],
            0,
        ));
        assert_repository_checkpoint(&restored, 2, 3, false);
    }
}
