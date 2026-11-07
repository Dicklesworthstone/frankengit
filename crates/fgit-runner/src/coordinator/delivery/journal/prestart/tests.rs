use super::*;
use std::cell::Cell;
use std::fs::{DirBuilder, Permissions};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-prestart-intent-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sample(landing: bool) -> WatchPrestartIntent {
    WatchPrestartIntent {
        scope: [1; 32],
        event: [2; 32],
        merge_config: [3; 32],
        execution_config: [4; 32],
        event_sha256: sha256_digest(b"{\"event\":1}"),
        bundle_sha256: sha256_digest(b"candidate"),
        bundle_len: 9,
        landing: landing.then(|| (sha256_digest(b"landing"), 7)),
    }
}

fn stage(path: &Path, intent: &WatchPrestartIntent) {
    write_new(&path.join("event.json"), b"{\"event\":1}").unwrap();
    write_new(&path.join("candidate.bundle"), b"candidate").unwrap();
    if intent.landing.is_some() {
        write_new(&path.join("landing.bundle"), b"landing").unwrap();
    }
}

fn seal(bytes: &mut [u8; FRAME_BYTES]) {
    let checksum = sha256_digest(&bytes[..BODY_BYTES]);
    bytes[BODY_BYTES..].copy_from_slice(&checksum);
}

#[test]
fn exact_frames_reject_every_truncation_bit_flip_and_noncanonical_extension() {
    for landing in [false, true] {
        let intent = sample(landing);
        let encoded = intent.encode();
        assert_eq!(WatchPrestartIntent::decode(&encoded).unwrap(), intent);
        for end in 0..encoded.len() {
            assert!(WatchPrestartIntent::decode(&encoded[..end]).is_err());
        }
        for position in 0..encoded.len() {
            let mut changed = encoded;
            changed[position] ^= 1;
            assert!(WatchPrestartIntent::decode(&changed).is_err());
        }
        let mut extra = encoded.to_vec();
        extra.push(0);
        assert!(WatchPrestartIntent::decode(&extra).is_err());
        for (position, value) in [(208, 2), (0, b'X')] {
            let mut changed = encoded;
            changed[position] = value;
            seal(&mut changed);
            assert!(WatchPrestartIntent::decode(&changed).is_err());
        }
        for invalid_length in [0, MAX_BUNDLE_BYTES + 1, u64::MAX] {
            let mut changed = encoded;
            changed[200..208].copy_from_slice(&invalid_length.to_be_bytes());
            seal(&mut changed);
            assert!(WatchPrestartIntent::decode(&changed).is_err());
        }
        let mut changed = encoded;
        changed[208] = 0;
        changed[209] = 1;
        seal(&mut changed);
        assert!(WatchPrestartIntent::decode(&changed).is_err());
    }
}

#[test]
fn creation_is_last_durable_step_and_exact_identity_is_required_after_reopen() {
    for landing in [false, true] {
        let scratch = Scratch::new();
        let intent = sample(landing);
        assert_eq!(
            WatchPrestartIntent::read(
                &scratch.0,
                &intent.scope,
                &intent.event,
                &intent.merge_config,
                &|| true
            )
            .unwrap(),
            None
        );
        assert!(WatchPrestartIntent::create(&scratch.0, &intent, &|| true).is_err());
        assert!(!scratch.0.join(FILE).exists());
        stage(&scratch.0, &intent);
        WatchPrestartIntent::create(&scratch.0, &intent, &|| true).unwrap();
        let reopened = WatchPrestartIntent::read(
            &scratch.0,
            &intent.scope,
            &intent.event,
            &intent.merge_config,
            &|| true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(reopened, intent);
        reopened.verify_artifacts(&scratch.0, &|| true).unwrap();
        assert_eq!(
            reopened.load_bundle(&scratch.0, &|| true).unwrap(),
            b"candidate"
        );
        assert!(WatchPrestartIntent::create(&scratch.0, &intent, &|| true).is_err());
        assert_eq!(fs::read(scratch.0.join(FILE)).unwrap(), intent.encode());
        assert!(
            WatchPrestartIntent::read(
                &scratch.0,
                &[9; 32],
                &intent.event,
                &intent.merge_config,
                &|| true
            )
            .is_err()
        );
        assert!(
            WatchPrestartIntent::read(
                &scratch.0,
                &intent.scope,
                &[9; 32],
                &intent.merge_config,
                &|| true
            )
            .is_err()
        );
        assert!(
            WatchPrestartIntent::read(&scratch.0, &intent.scope, &intent.event, &[9; 32], &|| true)
                .is_err()
        );
    }
}

#[test]
fn corrupt_partial_foreign_or_nonprivate_artifacts_never_become_resumable() {
    for field in ["event.json", "candidate.bundle", "landing.bundle"] {
        let scratch = Scratch::new();
        let intent = sample(true);
        stage(&scratch.0, &intent);
        WatchPrestartIntent::create(&scratch.0, &intent, &|| true).unwrap();
        let path = scratch.0.join(field);
        let original = fs::read(&path).unwrap();
        let mut corrupt = original.clone();
        corrupt[0] ^= 1;
        fs::write(&path, &corrupt).unwrap();
        assert!(intent.verify_artifacts(&scratch.0, &|| true).is_err());
        fs::write(&path, &original).unwrap();
        intent.verify_artifacts(&scratch.0, &|| true).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        assert!(intent.verify_artifacts(&scratch.0, &|| true).is_err());
        fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        let alias = scratch.0.join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(intent.verify_artifacts(&scratch.0, &|| true).is_err());
        fs::remove_file(&alias).unwrap();
        intent.verify_artifacts(&scratch.0, &|| true).unwrap();
        fs::rename(&path, &alias).unwrap();
        symlink(&alias, &path).unwrap();
        assert!(intent.verify_artifacts(&scratch.0, &|| true).is_err());
    }
    let scratch = Scratch::new();
    let intent = sample(false);
    stage(&scratch.0, &intent);
    write_new(&scratch.0.join(FILE), &intent.encode()[..FRAME_BYTES - 1]).unwrap();
    assert!(
        WatchPrestartIntent::read(
            &scratch.0,
            &intent.scope,
            &intent.event,
            &intent.merge_config,
            &|| true
        )
        .is_err()
    );
    assert_eq!(
        fs::metadata(scratch.0.join(FILE)).unwrap().len(),
        (FRAME_BYTES - 1) as u64
    );
}

#[test]
fn cancellation_during_streaming_retains_preparation_without_admitting_an_intent() {
    let scratch = Scratch::new();
    let mut intent = sample(false);
    let candidate = vec![19; 3 * 16 * 1024 + 1];
    intent.bundle_sha256 = sha256_digest(&candidate);
    intent.bundle_len = candidate.len() as u64;
    write_new(&scratch.0.join("event.json"), b"{\"event\":1}").unwrap();
    write_new(&scratch.0.join("candidate.bundle"), &candidate).unwrap();
    let calls = Cell::new(0);
    let live = || {
        calls.set(calls.get() + 1);
        true
    };
    assert_eq!(intent.load_bundle(&scratch.0, &live).unwrap(), candidate);
    let checkpoints = calls.get();
    assert!(checkpoints >= 6);
    for stop in 0..checkpoints {
        let calls = Cell::new(0);
        assert!(
            intent
                .load_bundle(&scratch.0, &|| {
                    let previous = calls.get();
                    calls.set(previous + 1);
                    previous < stop
                })
                .is_err()
        );
        assert!(!scratch.0.join(FILE).exists());
    }
    assert!(WatchPrestartIntent::create(&scratch.0, &intent, &|| false).is_err());
    assert!(!scratch.0.join(FILE).exists());
    WatchPrestartIntent::create(&scratch.0, &intent, &|| true).unwrap();
    assert_eq!(
        fs::read(scratch.0.join("candidate.bundle")).unwrap(),
        candidate
    );
}

#[test]
fn landing_loader_requires_the_original_bounded_private_target_bundle() {
    let scratch = Scratch::new();
    let mut intent = sample(true);
    let landing = vec![29; 3 * 16 * 1024 + 1];
    intent.landing = Some((sha256_digest(&landing), landing.len() as u64));
    write_new(&scratch.0.join("landing.bundle"), &landing).unwrap();
    // Loading the target-addressed bytes does not load a second CI bundle.
    assert!(!scratch.0.join("candidate.bundle").exists());
    let calls = Cell::new(0);
    assert_eq!(
        intent
            .load_landing_bundle(&scratch.0, &|| {
                calls.set(calls.get() + 1);
                true
            })
            .unwrap(),
        landing
    );
    for stop in 0..calls.get() {
        let observed = Cell::new(0);
        assert!(
            intent
                .load_landing_bundle(&scratch.0, &|| {
                    let previous = observed.get();
                    observed.set(previous + 1);
                    previous < stop
                })
                .is_err()
        );
    }
    assert!(
        sample(false)
            .load_landing_bundle(&scratch.0, &|| true)
            .is_err()
    );
    let path = scratch.0.join("landing.bundle");
    fs::write(&path, &landing[..landing.len() - 1]).unwrap();
    assert!(intent.load_landing_bundle(&scratch.0, &|| true).is_err());
    let mut corrupt = landing.clone();
    corrupt[0] ^= 1;
    fs::write(&path, &corrupt).unwrap();
    assert!(intent.load_landing_bundle(&scratch.0, &|| true).is_err());
    fs::write(&path, &landing).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    assert!(intent.load_landing_bundle(&scratch.0, &|| true).is_err());
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let alias = scratch.0.join("landing-alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(intent.load_landing_bundle(&scratch.0, &|| true).is_err());
    fs::remove_file(&alias).unwrap();
    fs::rename(&path, &alias).unwrap();
    symlink(&alias, &path).unwrap();
    assert!(intent.load_landing_bundle(&scratch.0, &|| true).is_err());
    assert_eq!(fs::read(&alias).unwrap(), landing);
}
