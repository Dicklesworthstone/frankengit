//! Storage/codec tests; actual native bundle evidence lives in the CLI campaign.
use super::super::{Fields, Invocation, frame};
use super::*;
use std::fs::{DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-saved-workspace-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn claim(&self, key: &str) -> Invocation {
        Invocation::create(&self.0.join("runs"), key, key.as_bytes()).unwrap()
    }
    fn saved(&self, key: &str) -> (PathBuf, [u8; 32], [u8; 32]) {
        let claim = self.claim(key);
        let dir = claim.directory.clone();
        let id = claim.request_id;
        let terminal = claim
            .complete(b"header\n", b"pack\0\xff", b"{\"candidate\":\"example\"}")
            .unwrap();
        (dir, id, terminal)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn ready_results_round_trip_with_independent_request_and_terminal_pins() {
    let root = Root::new();
    let (dir, request, terminal) = root.saved("one");
    for _ in 0..3 {
        let saved = read_saved(&dir, request, Some(terminal)).unwrap();
        assert_eq!(saved.bundle, b"header\npack\0\xff");
        assert_eq!(saved.receipt, "{\"candidate\":\"example\"}");
        assert_eq!(saved.terminal_id, terminal);
    }
    assert!(
        read_saved(&dir, [9; 32], None)
            .unwrap_err()
            .contains("request identity mismatch")
    );
    assert!(
        read_saved(&dir, request, Some([9; 32]))
            .unwrap_err()
            .contains("terminal identity mismatch")
    );
    assert!(read_saved(&dir, request, None).is_ok());
}

#[test]
fn missing_terminal_never_promotes_uncommitted_body_files_or_releases_identity() {
    let root = Root::new();
    let claim = root.claim("interrupted");
    let dir = claim.directory.clone();
    let request = claim.request_id;
    fs::write(dir.join("candidate.bundle"), b"orphaned body").unwrap();
    drop(claim);
    assert!(
        read_saved(&dir, request, None)
            .unwrap_err()
            .contains("unresolved")
    );
    assert!(matches!(
        root.claim_result("interrupted"),
        Err(Refusal::AlreadyReserved(_))
    ));
    let (dir, request, _) = root.saved("permitted");
    assert!(read_saved(&dir, request, None).is_ok());
}
impl Root {
    fn claim_result(&self, key: &str) -> Result<Invocation, Refusal> {
        Invocation::create(&self.0.join("runs"), key, key.as_bytes())
    }
}

#[test]
fn failed_results_retain_bounded_utf8_diagnostics_without_proving_no_effects() {
    let root = Root::new();
    let claim = root.claim("failed");
    let dir = claim.directory.clone();
    let request = claim.request_id;
    claim
        .fail(&format!("original refusal: {}", "é".repeat(MAX_FAILURE)))
        .unwrap();
    let error = read_saved(&dir, request, None).unwrap_err();
    assert!(
        error.contains("external effects may have occurred") && error.contains("original refusal")
    );
    assert!(error.len() < MAX_FAILURE + 200);
    assert!(!dir.join("candidate.bundle").exists());
    assert!(root.claim_result("failed").is_err());
}

#[test]
fn framed_records_reject_every_truncation_checksum_version_and_overflow() {
    let bytes = frame(TERMINAL_MAGIC, b"payload");
    for length in 0..bytes.len() {
        assert!(
            unframe(&bytes[..length], TERMINAL_MAGIC, 1024).is_err(),
            "{length}"
        );
    }
    for index in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[index] ^= 1;
        assert!(unframe(&bad, TERMINAL_MAGIC, 1024).is_err(), "{index}");
    }
    assert_eq!(unframe(&bytes, TERMINAL_MAGIC, 7).unwrap(), b"payload");
    assert!(unframe(&bytes, TERMINAL_MAGIC, 6).is_err());
    assert!(unframe(&frame(REQUEST_MAGIC, b"payload"), TERMINAL_MAGIC, 1024).is_err());
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(unframe(&extra, TERMINAL_MAGIC, 1024).is_err());
    assert!(Reader(&u64::MAX.to_be_bytes()).next().is_err());
}

#[test]
fn corrupt_request_terminal_bundle_or_receipt_never_yields_a_partial_result() {
    let root = Root::new();
    let (dir, request, _) = root.saved("integrity");
    for name in ["request", "terminal", "candidate.bundle", "receipt.json"] {
        let path = dir.join(name);
        let good = fs::read(&path).unwrap();
        for mode in 0..3 {
            let mut bad = good.clone();
            match mode {
                0 => bad[0] ^= 1,
                1 => {
                    bad.pop();
                }
                _ => bad.push(0),
            }
            fs::write(&path, bad).unwrap();
            assert!(read_saved(&dir, request, None).is_err(), "{name}:{mode}");
        }
        fs::write(&path, good).unwrap();
        assert!(read_saved(&dir, request, None).is_ok());
    }
}

#[test]
fn valid_checksums_do_not_allow_swapped_invocation_bindings_or_oversized_lengths() {
    let root = Root::new();
    let (dir, request, _) = root.saved("one");
    let (other, _, _) = root.saved("two");
    let original = fs::read(dir.join("terminal")).unwrap();
    fs::write(
        dir.join("terminal"),
        fs::read(other.join("terminal")).unwrap(),
    )
    .unwrap();
    assert!(
        read_saved(&dir, request, None)
            .unwrap_err()
            .contains("another workspace invocation")
    );
    let mut fields = Fields::default();
    for bytes in [
        b"ready".as_slice(),
        &request,
        &u64::MAX.to_be_bytes(),
        &[0; 32],
        &0u64.to_be_bytes(),
        &[0; 32],
    ] {
        fields.push(bytes).unwrap();
    }
    fs::write(dir.join("terminal"), frame(TERMINAL_MAGIC, &fields.0)).unwrap();
    assert!(
        read_saved(&dir, request, None)
            .unwrap_err()
            .contains("allowance exceeded")
    );
    let mut fields = Fields::default();
    for bytes in [b"unknown".as_slice(), &request] {
        fields.push(bytes).unwrap();
    }
    fs::write(dir.join("terminal"), frame(TERMINAL_MAGIC, &fields.0)).unwrap();
    assert!(
        read_saved(&dir, request, None)
            .unwrap_err()
            .contains("unknown")
    );
    let payload = unframe(&original, TERMINAL_MAGIC, MAX_REQUEST).unwrap();
    fs::write(
        dir.join("terminal"),
        frame(TERMINAL_MAGIC, &[payload, b"extra"].concat()),
    )
    .unwrap();
    assert!(
        read_saved(&dir, request, None)
            .unwrap_err()
            .contains("trailing")
    );
    fs::write(dir.join("terminal"), original).unwrap();
    assert!(read_saved(&dir, request, None).is_ok());
}

#[test]
fn special_shared_public_and_oversized_files_are_refused_before_body_allocation() {
    let root = Root::new();
    let (dir, request, _) = root.saved("private");
    let path = dir.join("candidate.bundle");
    let good = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_saved(&dir, request, None).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, root.0.join("alias")).unwrap();
    assert!(read_saved(&dir, request, None).is_err());
    fs::remove_file(root.0.join("alias")).unwrap();
    assert!(read_saved(&dir, request, None).is_ok());
    fs::remove_file(&path).unwrap();
    symlink("receipt.json", &path).unwrap();
    assert!(read_saved(&dir, request, None).is_err());
    fs::remove_file(&path).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.set_len((MAX_BUNDLE + 1) as u64).unwrap();
    assert!(
        read_saved(&dir, request, None)
            .unwrap_err()
            .contains("read limit")
    );
    file.set_len(0).unwrap();
    file.write_all(&good).unwrap();
    drop(file);
    assert!(read_saved(&dir, request, None).is_ok());
    symlink(&dir, root.0.join("directory-alias")).unwrap();
    assert!(read_saved(&root.0.join("directory-alias"), request, None).is_err());
}

#[test]
fn result_files_are_creation_only_and_failed_writes_leave_an_unresolved_claim() {
    let root = Root::new();
    let claim = root.claim("blocked");
    let dir = claim.directory.clone();
    let request = claim.request_id;
    fs::write(dir.join("receipt.json"), b"existing").unwrap();
    assert!(claim.complete(b"header", b"body", b"new").is_err());
    assert_eq!(fs::read(dir.join("receipt.json")).unwrap(), b"existing");
    assert!(
        read_saved(&dir, request, None)
            .unwrap_err()
            .contains("unresolved")
    );
    assert!(!dir.join("terminal").exists());
}

#[test]
fn recovery_cli_rejects_missing_trust_ids_unknown_options_and_existing_outputs() {
    let root = Root::new();
    let (dir, request, terminal) = root.saved("cli");
    let args = vec![
        "recover".into(),
        dir.to_str().unwrap().into(),
        "--trusted-local".into(),
        "--request-id".into(),
        super::super::super::hex(&request),
    ];
    let mut no_trust = args.clone();
    no_trust.remove(2);
    assert!(recover(&no_trust).is_err());
    for extra in [
        vec!["--request-id".into(), "00".repeat(32)],
        vec!["--unknown".into(), "x".into()],
        vec!["--output".into()],
    ] {
        assert!(recover(&[args.clone(), extra].concat()).is_err());
    }
    let output = root.0.join("recovered.bundle");
    let export = [
        args.clone(),
        vec![
            "--output".into(),
            output.to_str().unwrap().into(),
            "--terminal-id".into(),
            super::super::super::hex(&terminal),
        ],
    ]
    .concat();
    recover(&export).unwrap();
    let original = fs::read(&output).unwrap();
    assert!(recover(&export).is_err());
    assert_eq!(fs::read(output).unwrap(), original);
    recover(&args).unwrap();
}

#[test]
fn oversized_saved_metadata_refuses_before_creating_any_result_body() {
    let root = Root::new();
    let claim = root.claim("metadata-bound");
    let directory = claim.directory.clone();
    let metadata = vec![b'x'; super::super::saved::MAX_RECEIPT + 1];
    assert!(claim.complete(b"header", b"body", &metadata).is_err());
    assert!(!directory.join("candidate.bundle").exists());
    assert!(!directory.join("receipt.json").exists());
    assert!(!directory.join("terminal").exists());
}
