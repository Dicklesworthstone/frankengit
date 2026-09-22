use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-source-publication-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn stage(&self) -> (PathBuf, PathBuf) {
        let target = self.0.join("target");
        create_private(&target).unwrap();
        let stage = target.join(".restore-quarantine");
        create_private(&stage).unwrap();
        fs::create_dir(stage.join("objects")).unwrap();
        fs::write(stage.join("objects/body"), b"already-verified-body").unwrap();
        fs::write(stage.join("authority.fsqlite"), b"already-closed-image").unwrap();
        (stage, target)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn args() -> Vec<String> {
    [
        "restore",
        "/unused",
        "/new-root",
        "--trusted-local",
        "--expected-sha256",
        &"ab".repeat(32),
        "--destination-instance",
        "12",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
#[test]
fn restore_requires_exact_trust_pin_and_fresh_positive_instance() {
    assert_eq!(parse(&args()).unwrap().instance.raw(), 12);
    for bad in ["", "0", "01", "+1", "-1", "9223372036854775808"] {
        let mut input = args();
        input[7] = bad.into();
        assert!(parse(&input).is_err(), "{bad}");
    }
    for bad in ["", "a", "AB", &"AB".repeat(32), &"a".repeat(65)] {
        let mut input = args();
        input[5] = bad.into();
        assert!(parse(&input).is_err());
    }
    let mut untrusted = args();
    untrusted[3] = "--untrusted".into();
    assert!(parse(&untrusted).is_err());
    let mut duplicate = args();
    duplicate[6] = "--expected-sha256".into();
    assert!(parse(&duplicate).is_err());
    assert!(parse(&[]).is_err());
}
#[test]
fn interruption_after_data_preparation_leaves_no_public_authority() {
    // Filesystem ordering only; these opaque test files are not database fixtures.
    let scratch = Scratch::new();
    let (stage, target) = scratch.stage();
    fs::write(stage.join("authority.fsqlite-wal"), b"closed-WAL").unwrap();
    fs::write(stage.join("authority.fsqlite-shm"), b"discardable-cache").unwrap();
    let ready = PreparedPublication::prepare(&stage, &target).unwrap();
    assert!(!target.join("authority.fsqlite").exists());
    assert_eq!(
        fs::read(target.join("objects/body")).unwrap(),
        b"already-verified-body"
    );
    assert_eq!(
        fs::read(target.join("authority.fsqlite-wal")).unwrap(),
        b"closed-WAL"
    );
    assert!(!stage.join("authority.fsqlite-wal").exists(), "WAL has exactly one recovery location");
    assert!(!target.join("authority.fsqlite-shm").exists());
    drop(ready);
    assert!(
        !target.join("authority.fsqlite").exists(),
        "abandonment is not publication"
    );
    assert!(
        stage.join("authority.fsqlite").exists(),
        "retain interruption evidence"
    );
}
#[test]
fn publication_is_no_replace_and_preserves_both_images_on_collision() {
    let scratch = Scratch::new();
    let (stage, target) = scratch.stage();
    let ready = PreparedPublication::prepare(&stage, &target).unwrap();
    fs::write(target.join("authority.fsqlite"), b"existing-winner").unwrap();
    assert!(ready.publish().is_err());
    assert_eq!(
        fs::read(target.join("authority.fsqlite")).unwrap(),
        b"existing-winner"
    );
    assert_eq!(
        fs::read(stage.join("authority.fsqlite")).unwrap(),
        b"already-closed-image"
    );
}
#[test]
fn file_publication_keeps_data_and_retains_quarantine_until_final_verification() {
    let scratch = Scratch::new();
    let (stage, target) = scratch.stage();
    fs::write(stage.join("authority.fsqlite-wal"), b"closed-WAL").unwrap();
    PreparedPublication::prepare(&stage, &target)
        .unwrap()
        .publish()
        .unwrap();
    assert!(stage.exists(), "publication alone cannot clean recovery evidence");
    assert_eq!(
        fs::read(target.join("authority.fsqlite")).unwrap(),
        b"already-closed-image"
    );
    assert_eq!(
        fs::read(target.join("authority.fsqlite-wal")).unwrap(),
        b"closed-WAL"
    );
    assert!(target.join("objects/body").exists());
}
#[test]
fn unresolved_rollback_journal_refuses_before_any_data_or_head_is_moved() {
    let scratch = Scratch::new();
    let (stage, target) = scratch.stage();
    fs::write(stage.join("authority.fsqlite-journal"), b"unresolved").unwrap();
    assert!(PreparedPublication::prepare(&stage, &target).is_err());
    assert!(!target.join("authority.fsqlite").exists());
    assert!(!target.join("objects").exists());
    assert!(stage.join("objects/body").exists());
}
#[test]
fn checksum_failure_precedes_destination_creation() {
    let scratch = Scratch::new();
    let input = scratch.0.join("bad.fg");
    fs::write(&input, b"corrupted").unwrap();
    let output = scratch.0.join("must-not-exist");
    let error = execute(&Options {
        input,
        output: output.clone(),
        expected: [1; 32],
        instance: StoreInstanceId::from_raw(99),
        profile: Profile::default(),
        resume: false,
    })
    .unwrap_err();
    assert!(error.contains("checksum mismatch"));
    assert!(!output.exists());
}

#[test]
fn restore_accepts_shared_profile_flags_and_rejects_duplicate_limits() {
    let mut input = args();
    input.extend([
        "--max-archive-bytes".into(),
        "2147483648".into(),
        "--timeout-secs".into(),
        "900".into(),
    ]);
    let options = parse(&input).unwrap();
    assert_eq!(options.profile.transfer.max_archive_bytes, 2 << 30);
    assert_eq!(options.profile.timeout.as_secs(), 900);
    let mut input = args();
    input.extend([
        "--max-archive-bytes".into(),
        "1".into(),
        "--max-archive-bytes".into(),
        "2".into(),
    ]);
    assert!(parse(&input).is_err());
}

#[test]
fn resume_is_explicit_unique_and_compatible_with_all_resource_flags() {
    assert!(!parse(&args()).unwrap().resume);
    let mut input = args(); input.push("--resume".into());
    assert!(parse(&input).unwrap().resume);
    input.extend(["--max-archive-bytes".into(), "2147483648".into(), "--timeout-secs".into(), "900".into()]);
    assert_eq!(input.len(), 13); assert!(parse(&input).unwrap().resume);
    let mut duplicate = args(); duplicate.extend(["--resume".into(), "--resume".into()]);
    assert!(parse(&duplicate).unwrap_err().contains("duplicate --resume"));
}
