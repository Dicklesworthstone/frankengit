#![forbid(unsafe_code)]
//! FG-035 runner acceptance: durable release-attempt journal, real staged-file
//! inventory, verified resume, and root-last local manifest withholding.
//!
//! The execution step in these tests is intentionally a deterministic fixture.
//! It proves the journal/inventory state machine, not operating-system process
//! isolation. Production execution defaults to a typed unavailable refusal
//! until an `fgit-runner` obligation is registered.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_release::{
    Asset, AttemptInputs, AttemptJournal, AttemptRunnerRefusal, EntryState,
    FilesystemAssetInventory, HostFingerprint, MatrixOutcome, ResumeDecision, SourceEntry,
    TargetMatrix, TargetRecord, TargetSpec, TargetStep, TargetStepResult, ToolchainIdentity,
    TreeSnapshot, attempt_identity,
};

static NEXT_TEMP_ROOT: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fgit-release-attempt-runner-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test-owned temporary root must be creatable");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    fgit_crypto::sha256_digest(bytes)
}

fn attempt(seed: u8) -> fgit_release::AttemptIdentity {
    let tree = TreeSnapshot::new().with(SourceEntry::new(
        "src/lib.rs",
        [seed; 32],
        EntryState::Clean,
    ));
    attempt_identity(&AttemptInputs {
        tree,
        toolchain: ToolchainIdentity {
            rustc: "nightly-test".to_owned(),
            cargo: "nightly-test".to_owned(),
            pinned_channel: "nightly-2026-08-20".to_owned(),
        },
        host: HostFingerprint {
            target: "x86_64-unknown-linux-gnu".to_owned(),
            os: "linux".to_owned(),
            arch: "x86_64".to_owned(),
        },
        command: vec!["cargo".to_owned(), "build".to_owned()],
        env: BTreeMap::new(),
    })
    .expect("clean declared test input must mint an attempt")
}

fn target(name: &str, stage: &Path, assets: &[(&str, &[u8])]) -> TargetSpec {
    TargetSpec::new(
        name,
        stage,
        assets
            .iter()
            .map(|(path, bytes)| Asset::new(*path, digest(bytes)))
            .collect(),
    )
    .expect("bounded target fixture must be valid")
}

fn write_asset(stage: &Path, relative: &str, bytes: &[u8]) {
    let path = stage.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("test asset parent must be creatable");
    }
    fs::write(path, bytes).expect("test asset must be writable");
}

struct ScriptedStep {
    results: Vec<TargetStepResult>,
}

impl TargetStep for ScriptedStep {
    fn execute(&mut self, _target: &TargetSpec) -> TargetStepResult {
        self.results.remove(0)
    }
}

#[test]
fn append_only_journal_recovers_the_completed_prefix_after_a_crash_tail() {
    let root = TempRoot::new("crash-tail");
    let stage = root.path().join("stage");
    fs::create_dir(&stage).expect("stage directory");
    write_asset(&stage, "fg", b"release binary");
    let matrix = TargetMatrix::new(
        attempt(1),
        vec![target("linux", &stage, &[("fg", b"release binary")])],
    )
    .expect("matrix");
    let mut journal = AttemptJournal::create(root.path(), matrix.clone()).expect("create journal");
    let outcome = journal
        .run_matrix(&mut ScriptedStep {
            results: vec![TargetStepResult::Failed {
                detail: "compiler failed".to_owned(),
            }],
        })
        .expect("failure is a journalled target outcome");
    assert!(matches!(outcome, MatrixOutcome::Failed { ref target } if target == "linux"));
    let complete_length = fs::metadata(journal.journal_path())
        .expect("journal metadata")
        .len();
    OpenOptions::new()
        .append(true)
        .open(journal.journal_path())
        .expect("append a synthetic crash tail")
        .write_all(&[0, 0, 0])
        .expect("partial frame write");
    drop(journal);

    let reopened =
        AttemptJournal::open(root.path(), matrix).expect("completed prefix survives tail");
    assert!(matches!(
        reopened.target_record("linux"),
        Some(TargetRecord::Failed { detail }) if detail == "compiler failed"
    ));
    assert_eq!(
        fs::metadata(reopened.journal_path())
            .expect("recovered journal metadata")
            .len(),
        complete_length,
        "reopen may trim only a non-record crash tail, never a durable prefix"
    );
}

#[test]
fn journal_hash_chain_refuses_a_complete_tampered_record() {
    let root = TempRoot::new("journal-tamper");
    let stage = root.path().join("stage");
    fs::create_dir(&stage).expect("stage directory");
    write_asset(&stage, "fg", b"release binary");
    let matrix = TargetMatrix::new(
        attempt(11),
        vec![target("linux", &stage, &[("fg", b"release binary")])],
    )
    .expect("matrix");
    let journal = AttemptJournal::create(root.path(), matrix.clone()).expect("create journal");
    let path = journal.journal_path().to_path_buf();
    drop(journal);
    let mut bytes = fs::read(&path).expect("journal bytes");
    let last = bytes.last_mut().expect("declared matrix journal event");
    *last ^= 0x01;
    fs::write(&path, bytes).expect("test tamper write");

    assert!(matches!(
        AttemptJournal::open(root.path(), matrix),
        Err(AttemptRunnerRefusal::JournalCorrupt {
            reason: "journal entry content digest mismatches"
        })
    ));
}

#[test]
fn inventory_refusals_each_have_a_permitted_twin() {
    let root = TempRoot::new("inventory");
    let stage = root.path().join("stage");
    fs::create_dir(&stage).expect("stage directory");

    let traversal = target("traversal", &stage, &[("../escape", b"x")]);
    assert!(matches!(
        FilesystemAssetInventory::collect(&traversal),
        Err(AttemptRunnerRefusal::AssetTraversal { .. })
    ));

    let permitted = target("permitted", &stage, &[("allowed", b"x")]);
    write_asset(&stage, "allowed", b"x");
    FilesystemAssetInventory::collect(&permitted).expect("regular listed asset is permitted");

    fs::remove_file(stage.join("allowed")).expect("replace permitted twin");
    fs::create_dir(stage.join("allowed")).expect("non-regular test directory");
    assert!(matches!(
        FilesystemAssetInventory::collect(&permitted),
        Err(AttemptRunnerRefusal::AssetNonRegular { ref path }) if path == "allowed"
    ));
    fs::remove_dir(stage.join("allowed")).expect("restore permitted twin");
    write_asset(&stage, "allowed", b"x");
    FilesystemAssetInventory::collect(&permitted).expect("regular twin is permitted again");

    write_asset(&stage, "unlisted", b"stale");
    assert!(matches!(
        FilesystemAssetInventory::collect(&permitted),
        Err(AttemptRunnerRefusal::AssetUnlisted { ref path }) if path == "unlisted"
    ));
    fs::remove_file(stage.join("unlisted")).expect("remove unlisted test file");
    FilesystemAssetInventory::collect(&permitted).expect("exact listed set is permitted");
}

#[cfg(unix)]
#[test]
fn symlinked_asset_is_refused_and_regular_twin_is_permitted() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("symlink");
    let stage = root.path().join("stage");
    fs::create_dir(&stage).expect("stage directory");
    fs::write(root.path().join("backing"), b"release binary").expect("backing file");
    let spec = target("linux", &stage, &[("fg", b"release binary")]);
    symlink(root.path().join("backing"), stage.join("fg")).expect("test symlink");
    assert!(matches!(
        FilesystemAssetInventory::collect(&spec),
        Err(AttemptRunnerRefusal::AssetSymlink { ref path }) if path == "fg"
    ));
    fs::remove_file(stage.join("fg")).expect("replace symlink with permitted twin");
    write_asset(&stage, "fg", b"release binary");
    FilesystemAssetInventory::collect(&spec).expect("regular twin is permitted");
}

#[test]
fn resume_reuses_only_a_byte_verified_inventory_identity() {
    let root = TempRoot::new("resume");
    let stage = root.path().join("stage");
    fs::create_dir(&stage).expect("stage directory");
    write_asset(&stage, "fg", b"expected bytes");
    let matrix = TargetMatrix::new(
        attempt(2),
        vec![target("linux", &stage, &[("fg", b"expected bytes")])],
    )
    .expect("matrix");
    let mut journal = AttemptJournal::create(root.path(), matrix).expect("journal");
    let outcome = journal
        .run_matrix(&mut ScriptedStep {
            results: vec![TargetStepResult::Passed],
        })
        .expect("verified target pass");
    assert!(matches!(outcome, MatrixOutcome::Completed { .. }));
    assert!(
        journal.manifest_path().is_file(),
        "the complete verified matrix must emit its local root-last manifest"
    );
    assert!(matches!(
        journal.resume_target("linux"),
        Ok(ResumeDecision::Reuse { .. })
    ));

    write_asset(&stage, "fg", b"substituted bytes");
    assert!(
        matches!(
            journal.resume_target("linux"),
            Ok(ResumeDecision::Rerun { .. })
        ),
        "changed staged bytes must never be called reusable"
    );
}

#[test]
fn cancellation_leaves_resumable_evidence_and_no_manifest_root() {
    let root = TempRoot::new("cancel");
    let first_stage = root.path().join("first");
    let second_stage = root.path().join("second");
    fs::create_dir(&first_stage).expect("first stage");
    fs::create_dir(&second_stage).expect("second stage");
    write_asset(&first_stage, "fg-linux", b"first");
    write_asset(&second_stage, "fg-macos", b"second");
    let matrix = TargetMatrix::new(
        attempt(3),
        vec![
            target("linux", &first_stage, &[("fg-linux", b"first")]),
            target("macos", &second_stage, &[("fg-macos", b"second")]),
        ],
    )
    .expect("matrix");
    let mut journal = AttemptJournal::create(root.path(), matrix.clone()).expect("journal");
    let outcome = journal
        .run_matrix(&mut ScriptedStep {
            results: vec![TargetStepResult::Passed, TargetStepResult::Cancelled],
        })
        .expect("cancellation is retained as a journal outcome");
    assert!(matches!(outcome, MatrixOutcome::Cancelled { ref target } if target == "macos"));
    assert!(
        !journal.manifest_path().exists(),
        "cancellation must withhold the root"
    );
    drop(journal);

    let reopened =
        AttemptJournal::open(root.path(), matrix).expect("cancelled journal is resumable");
    assert!(reopened.is_resumable());
    assert!(matches!(
        reopened.resume_target("linux"),
        Ok(ResumeDecision::Reuse { .. })
    ));
    assert!(!reopened.manifest_path().exists());
}

#[test]
fn failed_target_provably_withholds_the_manifest_root() {
    let root = TempRoot::new("failed");
    let stage = root.path().join("stage");
    fs::create_dir(&stage).expect("stage directory");
    write_asset(&stage, "fg", b"bytes");
    let matrix = TargetMatrix::new(
        attempt(4),
        vec![target("linux", &stage, &[("fg", b"bytes")])],
    )
    .expect("matrix");
    let mut journal = AttemptJournal::create(root.path(), matrix).expect("journal");
    let outcome = journal
        .run_matrix(&mut ScriptedStep {
            results: vec![TargetStepResult::Failed {
                detail: "test lane failed".to_owned(),
            }],
        })
        .expect("target failure should be retained, not erased");
    assert!(matches!(outcome, MatrixOutcome::Failed { ref target } if target == "linux"));
    assert!(matches!(
        journal.emit_manifest(),
        Err(AttemptRunnerRefusal::ManifestWithheld { ref target, state: "failed" }) if target == "linux"
    ));
    assert!(
        !journal.manifest_path().exists(),
        "a failed target must never leave a local release manifest root"
    );
}

#[test]
fn unavailable_executor_is_a_typed_refusal_not_a_success_placeholder() {
    let root = TempRoot::new("unavailable");
    let stage = root.path().join("stage");
    fs::create_dir(&stage).expect("stage directory");
    write_asset(&stage, "fg", b"bytes");
    let matrix = TargetMatrix::new(
        attempt(5),
        vec![target("linux", &stage, &[("fg", b"bytes")])],
    )
    .expect("matrix");
    let mut journal = AttemptJournal::create(root.path(), matrix).expect("journal");
    let refusal = journal.run_matrix(&mut fgit_release::UnavailableTargetStep);
    assert!(matches!(
        refusal,
        Err(AttemptRunnerRefusal::TargetRunnerUnavailable { ref target, .. }) if target == "linux"
    ));
    assert!(!journal.manifest_path().exists());
}
