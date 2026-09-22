#![forbid(unsafe_code)]
//! Actual process/disk recovery from the portable authority file alone.
//! Does not claim Git object-fabric or capsule/routing recovery.
use fgit_authority::{
    AuthorityLimits, CasOutcome, HeadGeneration, HeadInit, HeadKey, HeadRead, ImmutableKey,
    ImmutableRead, StoreInstanceId,
};
use fgit_authority_fsqlite::{FsqliteAuthorityStore, IssuanceSequence, mint_token};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fg-portable-disk-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn make_context(runtime: &NodeRuntime) -> Cx {
    let cx = Cx::new();
    cx.set_native_cx(runtime.request_cx(BudgetClass::Database));
    cx
}
fn command(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fg-authority-backup"))
        .args(args)
        .output()
        .unwrap()
}
fn success(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn refusal(output: Output) -> String {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    String::from_utf8(output.stderr).unwrap()
}

#[test]
fn exported_authority_recovers_after_source_removal_and_reopens_with_new_tokens() {
    let scratch = Scratch::new();
    let source_path = scratch.0.join("source.fsqlite");
    let backup_path = scratch.0.join("backup.fg");
    let destination = scratch.0.join("restored");
    let runtime = RuntimeProfile::production(2).build().unwrap();
    let cx = make_context(&runtime);
    let key = HeadKey::new(b"repository/head".to_vec()).unwrap();
    let body_key = ImmutableKey::new(b"canonical/body".to_vec()).unwrap();
    let mut source = runtime
        .block_on(FsqliteAuthorityStore::open(
            &cx,
            text(&source_path),
            StoreInstanceId::from_raw(51),
            AuthorityLimits::default(),
        ))
        .unwrap();
    let original = runtime.block_on(async {
        source
            .put_if_absent(&cx, &body_key, b"persisted canonical payload\0\xff")
            .await
            .unwrap();
        let HeadInit::Created(first) = source
            .initialize_head(&cx, &key, HeadGeneration::FIRST, b"first")
            .await
            .unwrap()
        else {
            panic!("fresh store")
        };
        let CasOutcome::Committed(current) = source
            .compare_exchange_head(
                &cx,
                &key,
                first.token(),
                HeadGeneration::try_new(2).unwrap(),
                b"second",
            )
            .await
            .unwrap()
        else {
            panic!("source CAS")
        };
        current
    });
    runtime.block_on(source.close(&cx)).unwrap();
    drop(source);
    drop(cx);
    assert!(runtime.join_root(Duration::from_secs(5)));

    let receipt = success(command(&[
        "export",
        text(&source_path),
        text(&backup_path),
        "--trusted-local",
    ]));
    assert!(receipt.contains("\"git_objects_included\":false"));
    assert!(receipt.contains("\"head_generation\":2"));
    let hash = receipt
        .split_once("\"sha256\":\"")
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap();
    // Only test-owned temporary source state is removed. The restore must not
    // open it, consult a running source, or require its original tokens.
    fs::remove_file(&source_path).unwrap();
    let restored = success(command(&[
        "restore",
        text(&backup_path),
        text(&destination),
        "--trusted-local",
        "--expected-sha256",
        hash,
        "--destination-instance",
        "52",
    ]));
    assert!(restored.contains("\"source_tokens_preserved\":false"));
    assert!(restored.contains("\"routing_published\":false"));
    assert!(!source_path.exists());
    assert!(
        refusal(command(&[
            "restore",
            text(&backup_path),
            text(&destination),
            "--trusted-local",
            "--expected-sha256",
            hash,
            "--destination-instance",
            "52"
        ]))
        .contains("new restore directory")
    );

    let runtime = RuntimeProfile::production(2).build().unwrap();
    let context = make_context(&runtime);
    let mut target = runtime
        .block_on(FsqliteAuthorityStore::open_portable_source(
            &context,
            text(&destination.join("authority.fsqlite")),
            AuthorityLimits::default(),
        ))
        .unwrap();
    runtime.block_on(async {
        assert_eq!(target.instance_id(), StoreInstanceId::from_raw(52));
        let HeadRead::Present(restored) = target.read_head(&context, &key).await.unwrap() else {
            panic!("restored head")
        };
        assert_eq!(restored.generation(), original.generation());
        assert_eq!(restored.body(), original.body());
        assert_ne!(restored.token(), original.token());
        assert!(
            target
                .authenticate_head_receipt(&context, &original)
                .await
                .is_err()
        );
        target
            .authenticate_head_receipt(&context, &restored)
            .await
            .unwrap();
        assert_eq!(
            target.read_immutable(&context, &body_key).await.unwrap(),
            ImmutableRead::Present(b"persisted canonical payload\0\xff".to_vec())
        );
        let CasOutcome::Committed(next) = target
            .compare_exchange_head(
                &context,
                &key,
                restored.token(),
                HeadGeneration::try_new(3).unwrap(),
                b"after recovery",
            )
            .await
            .unwrap()
        else {
            panic!("restored CAS")
        };
        assert_eq!(
            next.token(),
            mint_token(
                StoreInstanceId::from_raw(52),
                IssuanceSequence::new(3).unwrap()
            )
        );
    });
    runtime.block_on(target.close(&context)).unwrap();
    drop(target);
    drop(context);
    assert!(runtime.join_root(Duration::from_secs(5)));

    let mut bad = fs::read(&backup_path).unwrap();
    let end = bad.len() - 1;
    bad[end] ^= 1;
    fs::write(&backup_path, bad).unwrap();
    let rejected = scratch.0.join("checksum-rejected");
    assert!(
        refusal(command(&[
            "restore",
            text(&backup_path),
            text(&rejected),
            "--trusted-local",
            "--expected-sha256",
            hash,
            "--destination-instance",
            "53"
        ]))
        .contains("checksum mismatch")
    );
    assert!(!rejected.exists());
}
