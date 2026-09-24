#![forbid(unsafe_code)]
//! Actual command processes and embedded authority, not a command mock.
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fgit_authority::{AuthorityLimits, CasOutcome, HeadKey, HeadRead, StoreInstanceId};
use fgit_authority_fsqlite::{
    ExportedBody, ExportedHead, ExportedIssuance, FsqliteAuthorityStore, IssuanceSequence,
    MultiHeadSnapshot, SCHEMA_VERSION, encode_multi_head_snapshot, mint_token,
};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_runtime::{BudgetClass, NodeRuntime, RuntimeProfile};
use fsqlite_types::cx::Cx;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-authority-resume-command-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn archive(&self) -> (PathBuf, String) {
        let mut issuance = Vec::new();
        for (index, key) in [b"a", b"b", b"a", b"b"].into_iter().enumerate() {
            let sequence = index as u64 + 1;
            issuance.push(ExportedIssuance {
                token: mint_token(
                    StoreInstanceId::from_raw(41),
                    IssuanceSequence::new(sequence).unwrap(),
                )
                .to_opaque_bytes()
                .to_vec(),
                sequence,
                head_key: key.to_vec(),
                generation: sequence,
                body: vec![index as u8],
            });
        }
        let heads = issuance[2..]
            .iter()
            .map(|row| ExportedHead {
                key: row.head_key.clone(),
                token: row.token.clone(),
                generation: row.generation,
                body: row.body.clone(),
            })
            .collect();
        let snapshot = MultiHeadSnapshot {
            schema_version: SCHEMA_VERSION,
            instance: 41,
            bodies: vec![ExportedBody {
                key: b"original".to_vec(),
                body: b"value\0\xff".to_vec(),
            }],
            heads,
            issuance,
        };
        let bytes =
            encode_multi_head_snapshot(&snapshot, Default::default(), Default::default()).unwrap();
        let path = self.0.join("archive");
        fs::write(&path, &bytes).unwrap();
        let mut hash = Sha256Hasher::new();
        hash.update(&bytes);
        (
            path,
            hash.finish().iter().map(|b| format!("{b:02x}")).collect(),
        )
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn command(archive: &Path, root: &Path, pin: &str, resume: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fg-authority-backup"));
    command.arg("restore").arg(archive).arg(root).args([
        "--trusted-local",
        "--all-heads",
        "--expected-sha256",
        pin,
        "--destination-instance",
        "42",
    ]);
    if resume {
        command.arg("--resume");
    }
    command.output().unwrap()
}
fn success(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout).unwrap()
}
fn refused(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("\"complete\":false"));
    error
}
fn store<T>(root: &Path, action: impl FnOnce(&NodeRuntime, &FsqliteAuthorityStore, &Cx) -> T) -> T {
    let runtime = RuntimeProfile::production(2).build().unwrap();
    let cx = Cx::new();
    cx.set_native_cx(runtime.request_cx(BudgetClass::Database));
    let mut store = runtime
        .block_on(FsqliteAuthorityStore::open_portable_source(
            &cx,
            root.join("authority.fsqlite").to_str().unwrap(),
            AuthorityLimits::default(),
        ))
        .unwrap();
    let value = action(&runtime, &store, &cx);
    runtime.block_on(store.close(&cx)).unwrap();
    drop(store);
    drop(cx);
    assert!(runtime.join_root(Duration::from_secs(5)));
    value
}
fn snapshot(root: &Path) -> MultiHeadSnapshot {
    store(root, |runtime, store, cx| {
        runtime
            .block_on(store.export_multi_head_portable(cx, Default::default()))
            .unwrap()
    })
}

#[test]
fn completed_restore_retries_across_processes_and_moved_input_without_new_tokens() {
    let scratch = Scratch::new();
    let (archive, pin) = scratch.archive();
    let root = scratch.0.join("target");
    let receipt = success(command(&archive, &root, &pin, false));
    assert!(receipt.contains("\"authority_installed_last\":true"));
    let first = snapshot(&root);
    assert_eq!(first.heads.len(), 2);
    assert_eq!(first.issuance.len(), 4);
    assert_eq!(first.instance, 42);
    let moved = scratch.0.join("renamed-archive");
    fs::rename(archive, &moved).unwrap();
    for _ in 0..2 {
        let receipt = success(command(&moved, &root, &pin, true));
        assert!(receipt.contains("\"already_published\":true"));
        assert_eq!(snapshot(&root), first);
    }
    refused(command(&moved, &root, &pin, false));
    assert_eq!(snapshot(&root), first);
    assert!(!root.join(".authority-restore-quarantine").exists());
}

#[test]
fn live_restore_lock_excludes_another_command_and_handle_close_releases_it() {
    let scratch = Scratch::new();
    let (archive, pin) = scratch.archive();
    let root = scratch.0.join("target");
    success(command(&archive, &root, &pin, false));
    let before = snapshot(&root);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join(".restore-lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let error = refused(command(&archive, &root, &pin, true));
    assert!(error.contains("lock unavailable"), "{error}");
    drop(lock);
    success(command(&archive, &root, &pin, true));
    assert_eq!(snapshot(&root), before);
}

#[test]
fn later_secondary_head_is_not_rewound_and_lost_completed_database_is_not_recreated() {
    let scratch = Scratch::new();
    let (archive, pin) = scratch.archive();
    let root = scratch.0.join("target");
    success(command(&archive, &root, &pin, false));
    store(&root, |runtime, store, cx| {
        let key = HeadKey::new(b"b".to_vec()).unwrap();
        let HeadRead::Present(head) = runtime.block_on(store.read_head(cx, &key)).unwrap() else {
            panic!("secondary head exists")
        };
        assert!(matches!(
            runtime
                .block_on(store.compare_exchange_head(
                    cx,
                    &key,
                    head.token(),
                    head.generation().next().unwrap(),
                    b"later accepted state"
                ))
                .unwrap(),
            CasOutcome::Committed(_)
        ));
    });
    let advanced = snapshot(&root);
    let error = refused(command(&archive, &root, &pin, true));
    assert!(error.contains("whole-image"));
    assert_eq!(snapshot(&root), advanced);
    fs::remove_file(root.join("authority.fsqlite")).unwrap();
    refused(command(&archive, &root, &pin, true));
    assert!(
        !root.join("authority.fsqlite").exists(),
        "old intent cannot restore over lost newer state"
    );
}
