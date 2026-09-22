#![forbid(unsafe_code)]
//! Actual command retries after completion and cross-process restore exclusion.
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use fgit_authority::HeadReadReceipt;
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{RepositoryId, TenantId};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("fg-resume-command-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap(); Self(root)
    }
}
impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn text(path: &Path) -> &str { path.to_str().unwrap() }
fn config(root: &Path) -> NodeConfig {
    NodeConfig::new(root.to_path_buf(), TenantId::from_hex(TENANT).unwrap(), RepositoryId::from_hex(REPOSITORY).unwrap())
}
fn command(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fg-repository-backup")).args(args).output().unwrap()
}
fn success(output: Output) -> String {
    assert_eq!(output.status.code(), Some(0), "stdout={} stderr={}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}
fn refused(output: Output) -> String {
    assert_eq!(output.status.code(), Some(2), "stdout={} stderr={}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(output.stdout.is_empty()); String::from_utf8(output.stderr).unwrap()
}
fn fixture(scratch: &Scratch) -> (PathBuf, String) {
    let root = scratch.0.join("source"); let (node, _) = OneNode::init(config(&root)).unwrap(); node.shutdown().unwrap();
    let backup = scratch.0.join("backup.fg");
    success(command(&["export", text(&root), text(&backup), TENANT, REPOSITORY, "--trusted-local"]));
    let mut hash = Sha256Hasher::new(); hash.update(&fs::read(&backup).unwrap());
    let pin = hash.finish().iter().map(|b| format!("{b:02x}")).collect();
    fs::remove_dir_all(root).unwrap(); (backup, pin)
}
fn restore(input: &Path, root: &Path, pin: &str, instance: &str, resume: bool) -> Output {
    let mut args = vec!["restore", text(input), text(root), "--trusted-local", "--expected-sha256", pin, "--destination-instance", instance];
    if resume { args.push("--resume"); } command(&args)
}
fn head(root: &Path) -> HeadReadReceipt {
    let node = OneNode::open_existing(config(root)).unwrap();
    let receipt = node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().clone();
    node.shutdown().unwrap(); receipt
}

#[test]
fn command_resume_recovers_a_lost_success_response_without_republishing_the_head() {
    let scratch = Scratch::new(); let (input, pin) = fixture(&scratch); let root = scratch.0.join("target");
    let absent = scratch.0.join("absent");
    refused(restore(&input, &absent, &pin, "991", true)); assert!(!absent.exists());
    success(restore(&input, &root, &pin, "991", false)); let original = head(&root);
    refused(restore(&input, &root, &pin, "991", false));
    let retry = success(restore(&input, &root, &pin, "991", true));
    assert!(retry.contains("\"resume_requested\":true")); assert!(retry.contains("\"already_published\":true"));
    assert_eq!(head(&root), original); assert!(!root.join(".restore-quarantine").exists());
    assert!(refused(restore(&input, &root, &pin, "992", true)).contains("intent does not match"));
    assert_eq!(head(&root), original);
    let legacy = scratch.0.join("legacy"); let (node, _) = OneNode::init(config(&legacy)).unwrap(); node.shutdown().unwrap();
    let before = head(&legacy);
    assert!(refused(restore(&input, &legacy, &pin, "991", true)).contains("missing restore intent"));
    assert_eq!(head(&legacy), before);
}

#[test]
fn a_live_restore_lock_excludes_the_command_but_does_not_leave_a_stale_lock() {
    let scratch = Scratch::new(); let (input, pin) = fixture(&scratch); let root = scratch.0.join("target");
    success(restore(&input, &root, &pin, "991", false)); let original = head(&root);
    let lock = OpenOptions::new().read(true).write(true).open(root.join(".restore-lock")).unwrap();
    lock.try_lock().unwrap();
    assert!(refused(restore(&input, &root, &pin, "991", true)).contains("lock unavailable"));
    assert_eq!(head(&root), original); drop(lock);
    success(restore(&input, &root, &pin, "991", true)); assert_eq!(head(&root), original);
}
