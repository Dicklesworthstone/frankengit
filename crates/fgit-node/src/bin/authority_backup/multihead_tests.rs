use super::super::{Mode, parse, run};
use super::*;
use fgit_authority_fsqlite::{
    ExportBundle, ExportedHead, ExportedIssuance, IssuanceSequence, MultiHeadSnapshot,
    SCHEMA_VERSION, export_bundle, mint_token,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-all-heads-command-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}
fn sample() -> MultiHeadSnapshot {
    let issuance = [b"a".as_slice(), b"b".as_slice()]
        .into_iter()
        .enumerate()
        .map(|(index, key)| {
            let sequence = index as u64 + 1;
            ExportedIssuance {
                token: mint_token(
                    StoreInstanceId::from_raw(41),
                    IssuanceSequence::new(sequence).unwrap(),
                )
                .to_opaque_bytes()
                .to_vec(),
                sequence,
                head_key: key.to_vec(),
                generation: 1,
                body: key.to_vec(),
            }
        })
        .collect::<Vec<_>>();
    let heads = issuance
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
        bodies: vec![],
        heads,
        issuance,
    }
}

#[test]
fn all_heads_is_explicit_on_export_and_restore_and_duplicate_flags_refuse() {
    let base = args(&["export", "source", "archive", "--trusted-local"]);
    assert!(!parse(&base).unwrap().all_heads);
    let mut all = base.clone();
    all.push("--all-heads".into());
    let options = parse(&all).unwrap();
    assert!(options.all_heads);
    assert!(matches!(options.mode, Mode::Export));
    all.push("--all-heads".into());
    assert!(parse(&all).is_err());
    let pin = "ab".repeat(32);
    let mut restore = args(&[
        "restore",
        "archive",
        "target",
        "--all-heads",
        "--trusted-local",
        "--expected-sha256",
        &pin,
        "--destination-instance",
        "42",
    ]);
    assert!(parse(&restore).unwrap().all_heads);
    restore.remove(3);
    assert!(!parse(&restore).unwrap().all_heads);
    let missing_auth = args(&["export", "source", "archive", "--all-heads"]);
    assert!(parse(&missing_auth).is_err());
    let mut unknown = base;
    unknown.push("--all-heads=true".into());
    assert!(parse(&unknown).is_err());
}

#[test]
fn checksum_and_v2_lineage_refusals_happen_before_destination_creation() {
    let scratch = Scratch::new();
    let input = scratch.0.join("archive");
    let target = scratch.0.join("target");
    let snapshot = sample();
    let bytes =
        encode_multi_head_snapshot(&snapshot, Default::default(), Default::default()).unwrap();
    fs::write(&input, &bytes).unwrap();
    assert!(
        restore(&input, &target, [0; 32], StoreInstanceId::from_raw(42))
            .unwrap_err()
            .contains("checksum")
    );
    assert!(!target.exists());
    assert!(
        restore(
            &input,
            &target,
            sha256(&bytes),
            StoreInstanceId::from_raw(41)
        )
        .unwrap_err()
        .contains("instance")
    );
    assert!(!target.exists());
    let mut bad = snapshot;
    bad.heads.pop();
    let corrupt = fgit_codec::encode_body(&bad).unwrap();
    fs::write(&input, &corrupt).unwrap();
    assert!(
        restore(
            &input,
            &target,
            sha256(&corrupt),
            StoreInstanceId::from_raw(42)
        )
        .unwrap_err()
        .contains("invalid all-heads")
    );
    assert!(
        !target.exists(),
        "a trusted checksum does not excuse missing head history"
    );
}

#[test]
fn neither_command_mode_silently_reinterprets_the_other_format() {
    let scratch = Scratch::new();
    let input = scratch.0.join("archive");
    let target = scratch.0.join("target");
    let old = ExportBundle {
        schema_version: SCHEMA_VERSION,
        instance: 41,
        bodies: vec![],
        head: None,
        issuance: vec![],
    };
    let bytes = export_bundle(&old).unwrap();
    fs::write(&input, &bytes).unwrap();
    assert!(
        restore(
            &input,
            &target,
            sha256(&bytes),
            StoreInstanceId::from_raw(42)
        )
        .is_err()
    );
    assert!(!target.exists());
    let bytes =
        encode_multi_head_snapshot(&sample(), Default::default(), Default::default()).unwrap();
    fs::write(&input, &bytes).unwrap();
    assert!(
        super::super::restore(
            &input,
            &target,
            sha256(&bytes),
            StoreInstanceId::from_raw(42)
        )
        .is_err()
    );
    assert!(!target.exists());
}

#[test]
fn v2_exports_are_byte_deterministic_and_no_replace_through_the_command() {
    let scratch = Scratch::new();
    let database = scratch.0.join("authority.fsqlite");
    let source = sample();
    with_store(
        &database,
        StoreInstanceId::from_raw(42),
        false,
        |runtime, store, cx| {
            runtime
                .block_on(store.import_multi_head_portable(cx, &source, Default::default()))
                .map_err(|error| error.to_string())?;
            Ok(())
        },
    )
    .unwrap();
    let first = scratch.0.join("first.backup");
    let second = scratch.0.join("second.backup");
    let receipt = export(&database, &first).unwrap();
    assert!(receipt.contains("\"heads\":2,"));
    export(&database, &second).unwrap();
    let bytes = fs::read(&first).unwrap();
    assert_eq!(bytes, fs::read(&second).unwrap());
    assert!(export(&database, &first).is_err());
    assert_eq!(fs::read(&first).unwrap(), bytes);
    assert!(super::super::export(&database, &scratch.0.join("v1")).is_err());
}

#[test]
fn a_lost_output_receipt_does_not_make_a_published_backup_disappear() {
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
    let database = scratch.0.join("authority.fsqlite");
    with_store(
        &database,
        StoreInstanceId::from_raw(42),
        false,
        |runtime, store, cx| {
            runtime
                .block_on(store.import_multi_head_portable(cx, &sample(), Default::default()))
                .map_err(|error| error.to_string())?;
            Ok(())
        },
    )
    .unwrap();
    let output = scratch.0.join("published");
    let error = run(
        &args(&[
            "export",
            database.to_str().unwrap(),
            output.to_str().unwrap(),
            "--trusted-local",
            "--all-heads",
        ]),
        &mut Broken,
    )
    .unwrap_err();
    assert!(error.contains("operation completed; receipt failed"));
    let bytes = fs::read(output).unwrap();
    assert_eq!(
        decode_multi_head_snapshot(&bytes, Default::default(), Default::default())
            .unwrap()
            .heads
            .len(),
        2
    );
}
