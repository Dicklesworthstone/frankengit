#![forbid(unsafe_code)]
//! Actual command + disk authority recovery. Slot names are opaque store keys;
//! this test does not claim that a specific node index/forge adapter is wired.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_authority::{
    AuthorityLimits, AuthorityVersionToken, CasOutcome, HeadGeneration, HeadInit,
    HeadKey, HeadReadReceipt, ImmutableKey, StoreInstanceId,
};
use fgit_authority_fsqlite::{
    FsqliteAuthorityStore, MultiHeadSnapshot, decode_multi_head_snapshot,
};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx;

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("fg-multi-head-recovery-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap(); Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn text(path: &Path) -> &str { path.to_str().unwrap() }
fn context(runtime: &NodeRuntime) -> Cx {
    let cx = Cx::new(); cx.set_native_cx(runtime.request_cx(BudgetClass::Database)); cx
}
fn store<T>(path: &Path, instance: u64,
    action: impl FnOnce(&NodeRuntime, &FsqliteAuthorityStore, &Cx) -> T,
) -> T {
    let runtime = RuntimeProfile::deterministic().build().unwrap(); let cx = context(&runtime);
    let mut store = runtime.block_on(FsqliteAuthorityStore::open(&cx, text(path),
        StoreInstanceId::from_raw(instance), AuthorityLimits::default())).unwrap();
    let result = action(&runtime, &store, &cx);
    runtime.block_on(store.close(&cx)).unwrap(); drop(store); drop(cx);
    assert!(runtime.join_root(std::time::Duration::from_secs(5)));
    result
}
fn generation(raw: u64) -> HeadGeneration { HeadGeneration::try_new(raw).unwrap() }
fn command(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fg-authority-backup")).args(args).output().unwrap()
}
fn success(output: Output) -> String {
    assert_eq!(output.status.code(), Some(0), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}
fn refused(output: Output) -> String {
    assert_eq!(output.status.code(), Some(2), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap(); assert!(error.contains("\"complete\":false")); error
}
fn checksum(bytes: &[u8]) -> String {
    let mut hash = Sha256Hasher::new(); hash.update(bytes);
    hash.finish().iter().map(|byte| format!("{byte:02x}")).collect()
}
fn export(database: &Path, archive: &Path) -> Output {
    command(&["export", text(database), text(archive), "--trusted-local", "--all-heads"])
}
fn restore(archive: &Path, target: &Path, pin: &str) -> Output {
    command(&["restore", text(archive), text(target), "--trusted-local", "--all-heads",
        "--expected-sha256", pin, "--destination-instance", "99"])
}
fn fixture(scratch: &Scratch) -> (PathBuf, MultiHeadSnapshot) {
    let root = scratch.0.join("source"); fs::create_dir(&root).unwrap();
    let database = root.join("authority.fsqlite");
    let snapshot = store(&database, 41, |runtime, source, cx| runtime.block_on(async {
        source.put_if_absent(cx, &ImmutableKey::new(b"shared\0\xff".to_vec()).unwrap(), b"exact immutable bytes\0\xff").await.unwrap();
        let repo = HeadKey::new(b"repository/head".to_vec()).unwrap();
        let index = HeadKey::new(b"index/head".to_vec()).unwrap();
        let HeadInit::Created(repo_first) = source.initialize_head(cx, &repo, generation(5), b"repo-old").await.unwrap()
            else { panic!("new repo head"); };
        let HeadInit::Created(index_first) = source.initialize_head(cx, &index, generation(1), b"index-old").await.unwrap()
            else { panic!("new index head"); };
        assert!(matches!(source.compare_exchange_head(cx, &repo, repo_first.token(), generation(9), b"repo-new").await.unwrap(), CasOutcome::Committed(_)));
        assert!(matches!(source.compare_exchange_head(cx, &index, index_first.token(), generation(2), b"index-new").await.unwrap(), CasOutcome::Committed(_)));
        source.export_multi_head_portable(cx, Default::default()).await.unwrap()
    }));
    (database, snapshot)
}

#[test]
fn all_heads_backup_restores_without_source_and_preserves_future_updates() {
    let scratch = Scratch::new(); let (database, original) = fixture(&scratch);
    let v1 = scratch.0.join("v1.backup");
    refused(command(&["export", text(&database), text(&v1), "--trusted-local"]));
    assert!(!v1.exists(), "the old format must not silently choose a head");
    let archive = scratch.0.join("all.backup");
    let receipt = success(export(&database, &archive)); assert!(receipt.contains("\"heads\":2,"));
    let bytes = fs::read(&archive).unwrap(); let pin = checksum(&bytes); assert!(receipt.contains(&pin));
    assert_eq!(decode_multi_head_snapshot(&bytes, Default::default(), Default::default()).unwrap(), original);
    refused(export(&database, &archive)); assert_eq!(fs::read(&archive).unwrap(), bytes);

    // The only remaining recovery input is the exported archive, not the source.
    fs::remove_dir_all(database.parent().unwrap()).unwrap();
    let target = scratch.0.join("restored");
    let receipt = success(restore(&archive, &target, &pin));
    assert!(receipt.contains("\"all_heads_verified\":true"));
    assert!(receipt.contains("\"reopened_and_verified\":true"));
    let restored_db = target.join("authority.fsqlite");
    let advanced = store(&restored_db, 99, |runtime, restored, cx| runtime.block_on(async {
        assert_eq!(restored.instance_id().raw(), 99);
        let receipts = restored.verify_multi_head_import(cx, &original, Default::default()).await.unwrap();
        assert_eq!(receipts.len(), 2);
        for receipt in &receipts { restored.authenticate_head_receipt(cx, receipt).await.unwrap(); }
        for row in &original.issuance {
            let source = HeadReadReceipt::new(HeadKey::new(row.head_key.clone()).unwrap(),
                AuthorityVersionToken::from_opaque_bytes(row.token.as_slice().try_into().unwrap()),
                generation(row.generation), row.body.clone());
            assert!(restored.authenticate_head_receipt(cx, &source).await.is_err());
        }
        for receipt in receipts {
            assert!(matches!(restored.compare_exchange_head(cx, receipt.key(), receipt.token(),
                receipt.generation().next().unwrap(), b"new work after restore").await.unwrap(), CasOutcome::Committed(_)));
        }
        let result = restored.export_multi_head_portable(cx, Default::default()).await.unwrap();
        assert_eq!(result.issuance.len(), 6); assert_eq!(result.heads.len(), 2);
        assert_eq!(result.bodies, original.bodies); result
    }));
    refused(restore(&archive, &target, &pin));
    store(&restored_db, 99, |runtime, restored, cx| {
        assert_eq!(runtime.block_on(restored.export_multi_head_portable(cx, Default::default())).unwrap(), advanced);
    });
}

#[test]
fn corrupt_lineage_valid_checksums_and_wrong_format_cannot_create_destinations() {
    let scratch = Scratch::new(); let (database, original) = fixture(&scratch);
    let archive = scratch.0.join("good.backup"); success(export(&database, &archive));
    let bytes = fs::read(&archive).unwrap(); let pin = checksum(&bytes);
    let wrong_format = scratch.0.join("wrong-format");
    refused(command(&["restore", text(&archive), text(&wrong_format), "--trusted-local",
        "--expected-sha256", &pin, "--destination-instance", "99"]));
    assert!(!wrong_format.exists());
    let wrong_pin = scratch.0.join("wrong-pin");
    refused(restore(&archive, &wrong_pin, &"00".repeat(32))); assert!(!wrong_pin.exists());
    for change in 0..3 {
        let mut bad = original.clone();
        match change {
            0 => { bad.heads.remove(1); }
            1 => { // A fully self-consistent OLD head is still not the slot's latest state.
                let old = &bad.issuance[0];
                let slot = bad.heads.iter_mut().find(|head| head.key == old.head_key).unwrap();
                slot.token = old.token.clone(); slot.generation = old.generation; slot.body = old.body.clone();
            }
            _ => bad.issuance[0].token[0] ^= 1,
        }
        let malformed = fgit_codec::encode_body(&bad).unwrap();
        let input = scratch.0.join(format!("bad-{change}.backup")); fs::write(&input, &malformed).unwrap();
        let target = scratch.0.join(format!("refused-{change}"));
        let error = refused(restore(&input, &target, &checksum(&malformed)));
        assert!(error.contains("invalid all-heads backup"), "{error}");
        assert!(!target.exists());
    }
    // Positive twin proves the valid image is not refused along with the corpus.
    success(restore(&archive, &scratch.0.join("permitted"), &pin));
}
