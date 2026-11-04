use super::*;
use fgit_authority::{AuthorityVersionToken, HeadKey};
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

fn args(operation: &str) -> Vec<String> {
    let paths = if operation == "inventory" {
        vec![
            operation,
            "/unused",
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "--trusted-local",
        ]
    } else {
        vec![
            operation,
            "/unused",
            "/custody",
            "/archive/data",
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "--trusted-local",
        ]
    };
    paths.into_iter().map(str::to_owned).collect()
}

fn import_args() -> Vec<String> {
    let mut out = args("import");
    out.extend([
        "--expected-incarnation".into(),
        "33333333333333333333333333333333".into(),
        "--expected-head-sha256".into(),
        "44".repeat(32),
        "--expected-sha256".into(),
        "55".repeat(32),
    ]);
    out
}

#[test]
fn command_requires_authorization_exact_import_pins_and_independent_finite_budgets() {
    let base = Options::parse(&args("inventory"), None).unwrap();
    assert_eq!(base.action, Action::Inventory);
    assert_eq!(base.format, GitHashAlgorithm::Sha1);
    assert_eq!(
        Options::parse(&import_args(), None).unwrap().action,
        Action::Import
    );
    for operation in ["inventory", "export", "import"] {
        let mut untrusted = if operation == "import" {
            import_args()
        } else {
            args(operation)
        };
        untrusted.retain(|s| s != "--trusted-local");
        assert!(Options::parse(&untrusted, None).is_err());
    }
    assert!(Options::parse(&args("import"), None).is_err());
    for flag in [
        "--expected-incarnation",
        "--expected-head-sha256",
        "--expected-sha256",
    ] {
        let mut missing = import_args();
        let i = missing.iter().position(|s| s == flag).unwrap();
        missing.drain(i..i + 2);
        assert!(Options::parse(&missing, None).is_err());
    }
    for (flag, value) in [
        ("--max-source-objects", "0"),
        ("--max-source-objects", "1000001"),
        ("--max-objects", "01"),
        ("--max-payload-bytes", "1099511627777"),
        ("--max-archive-bytes", "-1"),
        ("--timeout-secs", "3601"),
        ("--expected-head-sha256", "A"),
        ("--unknown", "1"),
        ("--expected-sha256", &"00".repeat(32)),
    ] {
        let mut invalid = args("inventory");
        invalid.extend([flag.to_owned(), value.to_owned()]);
        assert!(Options::parse(&invalid, None).is_err(), "{flag}");
    }
    let mut duplicate = args("inventory");
    duplicate.push("--trusted-local".into());
    assert!(Options::parse(&duplicate, None).is_err());
    assert!(Options::parse(&args("inventory"), Some(Duration::ZERO)).is_err());
    let capped = Options::parse(&args("inventory"), Some(Duration::from_millis(7))).unwrap();
    assert_eq!(capped.timeout, Duration::from_millis(7));
    assert_eq!(capped.source_bytes, base.source_bytes);
    assert_eq!(capped.limits, base.limits);
}

#[test]
fn all_help_paths_are_read_only_and_do_not_need_a_repository() {
    for operation in [None, Some("inventory"), Some("export"), Some("import")] {
        let mut args: Vec<String> = operation.into_iter().map(str::to_owned).collect();
        args.push("--help".into());
        let mut output = Vec::new();
        run(&args, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fg lfs inventory"));
        assert!(output.contains("--expected-head-sha256"));
        assert!(output.contains("earlier valid puts remain"));
    }
}

#[test]
fn source_revalidation_binds_key_token_generation_and_every_head_byte() {
    let receipt = |key: &[u8], token: u8, generation, body: &[u8]| {
        HeadReadReceipt::new(
            HeadKey::new(key.to_vec()).unwrap(),
            AuthorityVersionToken::from_opaque_bytes([token; 16]),
            HeadGeneration::try_new(generation).unwrap(),
            body.to_vec(),
        )
    };
    let original = receipt(b"key", 1, 1, b"body");
    assert!(same_receipt(&original, &original));
    for other in [
        receipt(b"other", 1, 1, b"body"),
        receipt(b"key", 2, 1, b"body"),
        receipt(b"key", 1, 2, b"body"),
        receipt(b"key", 1, 1, b"body!"),
    ] {
        assert!(!same_receipt(&original, &other));
    }
}

fn object(payload: &[u8]) -> LfsObject {
    LfsObject {
        oid: LfsOid::of_payload(payload),
        size: payload.len() as u64,
    }
}

#[test]
fn native_pointer_inventory_deduplicates_exact_identities_and_refuses_unsupported_or_conflicting_pointers()
 {
    let expected = object(b"native referenced bytes");
    let pointer = expected.pointer();
    let mut found = BTreeMap::new();
    let limits = TransferLimits::default();
    for _ in 0..2 {
        observe_pointer(pointer.as_bytes(), pointer.len() as u64, &mut found, limits).unwrap();
    }
    observe_pointer(b"ordinary source", 15, &mut found, limits).unwrap();
    assert_eq!(found, BTreeMap::from([(expected.oid, expected.size)]));
    let conflicting = LfsObject {
        size: expected.size + 1,
        ..expected
    }
    .pointer();
    assert!(
        observe_pointer(
            conflicting.as_bytes(),
            conflicting.len() as u64,
            &mut found,
            limits
        )
        .is_err()
    );
    for invalid in [
        pointer.replace("/spec/v1", "/spec/v2"),
        pointer.trim_end().to_owned(),
        format!("{pointer}ext-0-crypt x\n"),
        pointer.replace("size ", "size 0"),
    ] {
        assert!(
            observe_pointer(
                invalid.as_bytes(),
                invalid.len() as u64,
                &mut BTreeMap::new(),
                limits
            )
            .is_err()
        );
    }
    assert!(observe_pointer(pointer.as_bytes(), 1025, &mut found, limits).is_err());
    let oversized = LfsObject {
        size: MAX_OBJECT_BYTES + 1,
        ..expected
    }
    .pointer();
    assert!(
        observe_pointer(
            oversized.as_bytes(),
            oversized.len() as u64,
            &mut BTreeMap::new(),
            limits
        )
        .is_err()
    );
    let other = object(b"another").pointer();
    assert!(
        observe_pointer(
            other.as_bytes(),
            other.len() as u64,
            &mut found,
            TransferLimits {
                max_objects: 1,
                ..limits
            }
        )
        .is_err()
    );
}

fn source() -> SourceIdentity {
    SourceIdentity {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        format: GitHashAlgorithm::Sha256,
        head_generation: 1,
        head_token: [4; 16],
        head_sha256: [5; 32],
    }
}

fn archive() -> (Vec<u8>, Seal, Vec<LfsObject>) {
    let mut rows = [
        b"first referenced payload".as_slice(),
        b"second referenced payload",
    ]
    .map(|p| (object(p), p));
    rows.sort_by_key(|row| row.0.oid);
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(
        &mut bytes,
        source(),
        rows.len(),
        rows.iter().map(|r| r.0.size).sum(),
        TransferLimits::default(),
        &mut || true,
    )
    .unwrap();
    for (object, mut payload) in rows {
        encoder.object(object, &mut payload, &mut || true).unwrap();
    }
    let seal = encoder.finish(&mut || true).unwrap();
    (bytes, seal, rows.iter().map(|r| r.0).collect())
}

#[test]
fn import_requires_complete_target_coverage_and_only_selects_referenced_records() {
    let (bytes, seal, objects) = archive();
    let verified = transfer::verify(
        &mut Cursor::new(&bytes),
        seal.digest,
        TransferLimits::default(),
        &mut || true,
    )
    .unwrap();
    assert_eq!(
        target_records(&verified, &objects, &mut || true).unwrap(),
        vec![0, 1]
    );
    assert_eq!(
        target_records(&verified, &objects[1..], &mut || true).unwrap(),
        vec![1]
    );
    assert!(
        target_records(&verified, &[], &mut || true)
            .unwrap()
            .is_empty()
    );
    assert!(target_records(&verified, &[object(b"uncovered")], &mut || true).is_err());
    assert!(
        target_records(
            &verified,
            &[LfsObject {
                size: objects[0].size + 1,
                ..objects[0]
            }],
            &mut || true,
        )
        .is_err()
    );
    // Corruption in an unreferenced extra is still caught in the full pass.
    let mut corrupt = bytes;
    let offset = verified.records()[0].payload_offset() as usize;
    corrupt[offset] ^= 1;
    assert!(
        transfer::verify(
            &mut Cursor::new(&corrupt),
            fgit_crypto::sha256_digest(&corrupt),
            TransferLimits::default(),
            &mut || true
        )
        .is_err()
    );
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "fg-lfs-transfer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn private_operation_spool_freezes_the_verified_input_and_rejects_symlinks_and_expiry() {
    let scratch = Scratch::new();
    let path = scratch.0.join("input");
    let (bytes, seal, _) = archive();
    private(&path, &bytes);
    let deadline = Deadline::new(Duration::from_secs(30));
    let mut owned = files::spool(&path, &scratch.0, 1 << 20, deadline).unwrap();
    private(&path, b"caller rewrote original after copy");
    let verified = transfer::verify(
        &mut owned,
        seal.digest,
        TransferLimits::default(),
        &mut || true,
    )
    .unwrap();
    assert_eq!(verified.seal(), seal);
    assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 1); // spool has no path
    let link = scratch.0.join("link");
    symlink(&path, &link).unwrap();
    assert!(files::spool(&link, &scratch.0, 1 << 20, deadline).is_err());
    assert!(files::output(&link).is_err());
    assert!(files::spool(&path, &scratch.0, 1 << 20, Deadline::new(Duration::ZERO)).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(files::spool(&path, &scratch.0, 1 << 20, deadline).is_err());
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(files::output(&scratch.0.join("new")).is_err());
}

#[test]
fn partial_put_and_uncertain_put_errors_preserve_retained_custody_in_machine_output() {
    let error = LfsTransferFailure {
        message: "head moved after verified put".into(),
        progress: ImportProgress {
            attempted: 2,
            created: 1,
            already_present: 0,
        },
    };
    let json = error_json(&error);
    assert!(json.contains("\"retained_custody_may_exist\":true"));
    assert!(json.contains("\"objects_created\":1"));
    assert!(json.contains("\"put_attempts\":2"));
    assert!(json.contains("\"refs_published\":false"));
}
