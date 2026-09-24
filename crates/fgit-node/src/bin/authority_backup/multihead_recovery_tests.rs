use super::*;
use fgit_authority::{CasOutcome, HeadGeneration, ImmutableKey};
use fgit_authority_fsqlite::{
    ExportedBody, ExportedHead, ExportedIssuance, IssuanceSequence, SCHEMA_VERSION,
    encode_multi_head_snapshot, mint_token,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-all-heads-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn archive(&self, source: &MultiHeadSnapshot) -> (PathBuf, [u8; 32]) {
        let path = self.0.join("backup");
        let bytes =
            encode_multi_head_snapshot(source, Default::default(), Default::default()).unwrap();
        fs::write(&path, &bytes).unwrap();
        (path, sha256(&bytes))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn target() -> StoreInstanceId {
    StoreInstanceId::from_raw(42)
}
fn source() -> MultiHeadSnapshot {
    let mut issuance = Vec::new();
    for (index, (key, generation)) in [(b"a", 5), (b"b", 1), (b"a", 9), (b"b", 2)]
        .into_iter()
        .enumerate()
    {
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
            generation,
            body: vec![index as u8, 0, 255],
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
    MultiHeadSnapshot {
        schema_version: SCHEMA_VERSION,
        instance: 41,
        bodies: vec![ExportedBody {
            key: b"original".to_vec(),
            body: b"immutable\0bytes".to_vec(),
        }],
        heads,
        issuance,
    }
}
fn observed(root: &Path) -> MultiHeadSnapshot {
    with_store(
        &root.join("authority.fsqlite"),
        target(),
        true,
        |runtime, store, cx| {
            runtime
                .block_on(store.export_multi_head_portable(cx, Default::default()))
                .map_err(|e| e.to_string())
        },
    )
    .unwrap()
}

#[test]
fn every_restore_phase_resumes_from_archive_alone_without_minting_again() {
    for stopped in [
        Stage::Intent,
        Stage::Imported,
        Stage::Reopened,
        Stage::WalPrepared,
        Stage::Published,
        Stage::FinalVerified,
        Stage::Cleaned,
    ] {
        let scratch = Scratch::new();
        let source = source();
        let (archive, pin) = scratch.archive(&source);
        let root = scratch.0.join("target");
        let error = execute_with(&archive, &root, pin, target(), false, |stage| {
            if stage == stopped {
                Err("deliberate interruption".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(error.contains("deliberate interruption"));
        let was_published = matches!(
            stopped,
            Stage::Published | Stage::FinalVerified | Stage::Cleaned
        );
        assert_eq!(
            root.join("authority.fsqlite").exists(),
            was_published,
            "{stopped:?}"
        );
        let receipt = execute(&archive, &root, pin, target(), true)
            .unwrap_or_else(|error| panic!("resume after {stopped:?}: {error}"));
        assert!(receipt.contains("\"resume_requested\":true"));
        assert!(receipt.contains(&format!("\"already_published\":{was_published},")));
        let first = observed(&root);
        assert_eq!(first.bodies, source.bodies);
        assert_eq!(first.heads.len(), 2);
        assert_eq!(first.issuance.len(), 4);
        assert_eq!(first.instance, 42);
        for (expected, actual) in source.issuance.iter().zip(&first.issuance) {
            assert_eq!(expected.generation, actual.generation);
            assert_eq!(expected.body, actual.body);
            assert_ne!(expected.token, actual.token);
        }
        assert!(execute(&archive, &root, pin, target(), false).is_err());
        let receipt = execute(&archive, &root, pin, target(), true).unwrap();
        assert!(receipt.contains("\"already_published\":true"));
        assert_eq!(
            observed(&root),
            first,
            "retry must not issue tokens: {stopped:?}"
        );
        assert!(!root.join(".authority-restore-quarantine").exists());
    }
}

#[test]
fn advanced_secondary_head_and_extra_body_refuse_without_rewriting_any_state() {
    for change in 0..2 {
        let scratch = Scratch::new();
        let (archive, pin) = scratch.archive(&source());
        let root = scratch.0.join("target");
        execute(&archive, &root, pin, target(), false).unwrap();
        with_store(
            &root.join("authority.fsqlite"),
            target(),
            true,
            |runtime, store, cx| {
                if change == 0 {
                    let snapshot = runtime
                        .block_on(store.export_multi_head_portable(cx, Default::default()))
                        .unwrap();
                    let head = &snapshot.heads[1];
                    let key = fgit_authority::HeadKey::new(head.key.clone()).unwrap();
                    let fgit_authority::HeadRead::Present(receipt) =
                        runtime.block_on(store.read_head(cx, &key)).unwrap()
                    else {
                        panic!("second head exists")
                    };
                    assert!(matches!(
                        runtime
                            .block_on(store.compare_exchange_head(
                                cx,
                                &key,
                                receipt.token(),
                                HeadGeneration::try_new(head.generation + 1).unwrap(),
                                b"new accepted work"
                            ))
                            .unwrap(),
                        CasOutcome::Committed(_)
                    ));
                } else {
                    runtime
                        .block_on(store.put_if_absent(
                            cx,
                            &ImmutableKey::new(b"extra".to_vec()).unwrap(),
                            b"new evidence",
                        ))
                        .unwrap();
                }
                Ok(())
            },
        )
        .unwrap();
        let before = observed(&root);
        assert!(
            execute(&archive, &root, pin, target(), true)
                .unwrap_err()
                .contains("whole-image")
        );
        assert_eq!(observed(&root), before);
    }
}

#[test]
fn partial_occupied_quarantine_is_not_filled_in_as_a_retry() {
    let scratch = Scratch::new();
    let (archive, pin) = scratch.archive(&source());
    let root = scratch.0.join("target");
    let custody = Custody::acquire(&root, pin, target(), false).unwrap();
    let quarantine = custody.quarantine().unwrap();
    with_store(
        &quarantine.join("authority.fsqlite"),
        target(),
        false,
        |runtime, store, cx| {
            runtime
                .block_on(store.put_if_absent(
                    cx,
                    &ImmutableKey::new(b"unexpected".to_vec()).unwrap(),
                    b"retained",
                ))
                .unwrap();
            Ok(())
        },
    )
    .unwrap();
    let before = observed(&quarantine);
    drop(custody);
    assert!(execute(&archive, &root, pin, target(), true).is_err());
    assert!(!root.join("authority.fsqlite").exists());
    assert_eq!(observed(&quarantine), before);
}

#[test]
fn wrong_request_and_lost_completed_database_cannot_recreate_old_authority() {
    let scratch = Scratch::new();
    let (archive, pin) = scratch.archive(&source());
    let root = scratch.0.join("target");
    execute(&archive, &root, pin, target(), false).unwrap();
    let before = observed(&root);
    assert!(execute(&archive, &root, [0; 32], target(), true).is_err());
    assert!(execute(&archive, &root, pin, StoreInstanceId::from_raw(99), true).is_err());
    assert_eq!(observed(&root), before);
    fs::remove_file(root.join("authority.fsqlite")).unwrap();
    assert!(execute(&archive, &root, pin, target(), true).is_err());
    assert!(!root.join("authority.fsqlite").exists());
    assert!(!root.join(".authority-restore-quarantine").exists());
}

#[test]
fn empty_whole_store_uses_the_same_publication_and_retry_path() {
    let scratch = Scratch::new();
    let mut empty = source();
    empty.bodies.clear();
    empty.heads.clear();
    empty.issuance.clear();
    let (archive, pin) = scratch.archive(&empty);
    let root = scratch.0.join("target");
    execute(&archive, &root, pin, target(), false).unwrap();
    let first = observed(&root);
    assert!(first.heads.is_empty());
    execute(&archive, &root, pin, target(), true).unwrap();
    assert_eq!(observed(&root), first);
}

#[test]
fn cli_resume_requires_restore_all_heads_and_the_original_pins() {
    use super::super::super::parse;
    let pin = "ab".repeat(32);
    let base: Vec<String> = [
        "restore",
        "archive",
        "target",
        "--trusted-local",
        "--all-heads",
        "--expected-sha256",
        &pin,
        "--destination-instance",
        "42",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert!(!parse(&base).unwrap().resume);
    let mut resumed = base;
    resumed.insert(3, "--resume".into());
    assert!(parse(&resumed).unwrap().resume);
    let mut duplicate = resumed.clone();
    duplicate.push("--resume".into());
    assert!(parse(&duplicate).is_err());
    let mut wrong = resumed.clone();
    wrong[0] = "export".into();
    assert!(parse(&wrong).is_err());
    let mut old_format = resumed.clone();
    old_format.retain(|arg| arg != "--all-heads");
    assert!(parse(&old_format).is_err());
    let mut missing_pin = resumed.clone();
    let index = missing_pin
        .iter()
        .position(|arg| arg == "--expected-sha256")
        .unwrap();
    missing_pin.drain(index..index + 2);
    assert!(parse(&missing_pin).is_err());
    let mut missing_auth = resumed;
    missing_auth.retain(|arg| arg != "--trusted-local");
    assert!(parse(&missing_auth).is_err());
}

#[test]
fn lost_success_output_can_be_resolved_without_reimporting_or_minting() {
    use super::super::super::run;
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    let scratch = Scratch::new();
    let (archive, pin) = scratch.archive(&source());
    let root = scratch.0.join("target");
    let pin_text = hex(&pin);
    let mut args: Vec<String> = [
        "restore",
        archive.to_str().unwrap(),
        root.to_str().unwrap(),
        "--trusted-local",
        "--all-heads",
        "--expected-sha256",
        &pin_text,
        "--destination-instance",
        "42",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert!(
        run(&args, &mut Broken)
            .unwrap_err()
            .contains("operation completed; receipt failed")
    );
    let committed = observed(&root);
    args.push("--resume".into());
    let mut receipt = Vec::new();
    run(&args, &mut receipt).unwrap();
    assert!(
        String::from_utf8(receipt)
            .unwrap()
            .contains("\"already_published\":true")
    );
    assert_eq!(observed(&root), committed);
}
