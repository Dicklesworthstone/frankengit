//! Tests of the actual versioned progress state and synchronized file barrier.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
const REF: &[u8] = b"refs/heads/main";
fn state() -> State {
    State::new(
        "0101 0202 0303 sha256".into(),
        &[REF.to_vec(), b"refs/heads/z".to_vec()],
    )
    .unwrap()
}
fn pin(number: u64, byte: u8) -> Pin {
    Pin {
        number,
        digest: [byte; 32],
    }
}
fn floor() -> State {
    let mut s = state();
    s.begin_preparation(REF).unwrap();
    s.completed(REF, pin(4, 2)).unwrap();
    s
}

#[test]
fn guarded_phase_roundtrips_and_can_be_abandoned_without_lowering_a_checkpoint() {
    let mut s = floor();
    let original = s.clone();
    s.begin_preparation(REF).unwrap();
    let bytes = s.encode().unwrap();
    assert!(bytes.starts_with(b"frankengit-index-worker-v2 "));
    let mut resumed = State::decode(&bytes, &state()).unwrap();
    assert!(resumed.rows[REF].preparing);
    assert!(!resumed.rows[REF].running);
    assert!(resumed.begin_preparation(REF).is_err());
    resumed.abandon_preparation(REF).unwrap();
    assert_eq!(resumed, original);
    resumed.begin_preparation(REF).unwrap();
    resumed.refuse(REF).unwrap();
    assert_eq!(resumed, original);
}

#[test]
fn legacy_codec_migrates_without_reclassifying_unknown_running_or_losing_pending() {
    let legacy = format!(
        "frankengit-index-worker-v1 0101 0202 0303 sha256\n{} {} 7 - 1\n{} - 0 {} 0\n",
        hex(REF),
        hex(&[4; 32]),
        hex(b"refs/heads/z"),
        hex(&[6; 32])
    );
    let mut resumed = State::decode(legacy.as_bytes(), &state()).unwrap();
    assert!(resumed.rows[REF].running);
    assert!(!resumed.rows[REF].preparing);
    let before = resumed.clone();
    assert!(resumed.abandon_preparation(REF).is_err());
    assert!(resumed.begin_preparation(REF).is_err());
    assert!(resumed.completed(REF, pin(7, 4)).is_err());
    assert_eq!(resumed, before);
    assert_eq!(
        resumed.rows[b"refs/heads/z".as_slice()].pending,
        Some([6; 32])
    );
    let migrated = resumed.encode().unwrap();
    assert_eq!(State::decode(&migrated, &state()).unwrap(), resumed);
    assert!(State::decode(legacy.replacen("- 1\n", "- p\n", 1).as_bytes(), &state()).is_err());
}

#[test]
fn candidate_must_be_recorded_once_and_direct_success_must_match_it_exactly() {
    let mut s = floor();
    s.begin_preparation(REF).unwrap();
    s.arm(REF, [8; 32]).unwrap();
    let before = s.clone();
    assert!(s.arm(REF, [9; 32]).is_err());
    assert!(s.abandon_preparation(REF).is_err());
    assert!(s.refuse(REF).is_err());
    assert!(s.begin_preparation(REF).is_err());
    assert!(s.completed(REF, pin(5, 9)).is_err());
    assert!(s.acknowledge(REF, pin(5, 8), None).is_err());
    assert_eq!(s, before);
    s.completed(REF, pin(5, 8)).unwrap();
    assert_eq!(s.rows[REF].floor, Some(pin(5, 8)));
    assert_eq!(s.rows[REF].pending, None);
}

#[test]
fn failed_publication_requires_the_exact_armed_candidate_and_preserves_the_floor() {
    let mut s = floor();
    let original = s.clone();
    assert!(s.publication_refused(REF, [8; 32]).is_err());
    s.begin_preparation(REF).unwrap();
    assert!(s.publication_refused(REF, [8; 32]).is_err());
    s.arm(REF, [8; 32]).unwrap();
    let before = s.clone();
    assert!(s.publication_refused(REF, [9; 32]).is_err());
    assert_eq!(s, before);
    s.publication_refused(REF, [8; 32]).unwrap();
    assert_eq!(s, original);
}

#[test]
fn all_prepublication_and_pending_truncations_or_contradictions_are_refused() {
    let mut s = floor();
    s.begin_preparation(REF).unwrap();
    for armed in [false, true] {
        let mut value = s.clone();
        if armed {
            value.arm(REF, [8; 32]).unwrap();
        }
        let bytes = value.encode().unwrap();
        for n in 0..bytes.len() {
            assert!(State::decode(&bytes[..n], &state()).is_err());
        }
        assert_eq!(State::decode(&bytes, &state()).unwrap(), value);
    }
    s.rows.get_mut(REF).unwrap().running = true;
    assert!(s.encode().is_err());
    s.rows.get_mut(REF).unwrap().running = false;
    s.rows.get_mut(REF).unwrap().pending = Some([8; 32]);
    assert!(s.encode().is_err());
    let mut old = floor();
    old.begin(REF).unwrap();
    assert!(old.arm(REF, [8; 32]).is_err()); // Legacy running cannot acquire the guarded meaning.
    s.rows.get_mut(REF).unwrap().preparing = false;
    let text = String::from_utf8(s.encode().unwrap()).unwrap();
    let contradictory = text.replacen(
        &format!("{} 0\n", hex(&[8; 32])),
        &format!("{} p\n", hex(&[8; 32])),
        1,
    );
    assert!(State::decode(contradictory.as_bytes(), &state()).is_err());
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "fg-index-barrier-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[cfg(unix)]
fn durable_arm_precedes_effect_and_survives_lost_acknowledgement() {
    let scratch = Scratch::new();
    let mut file = ProgressFile::open(&scratch.0, true, floor()).unwrap();
    file.state.begin_preparation(REF).unwrap();
    file.save().unwrap();
    file.arm(REF, [8; 32]).unwrap();
    // This is the actual selected durable checkpoint at the first point an
    // effect could be invoked, not a record written after its result.
    let disk = fs::read(scratch.0.join("checkpoint")).unwrap();
    assert_eq!(
        State::decode(&disk, &state()).unwrap().rows[REF].pending,
        Some([8; 32])
    );
    file.release().unwrap();
    let mut file = ProgressFile::open(&scratch.0, false, state()).unwrap();
    assert!(file.state.abandon_preparation(REF).is_err());
    assert!(file.state.begin_preparation(REF).is_err());
    file.state
        .acknowledge(REF, pin(6, 9), Some([8; 32]))
        .unwrap(); // Verified superseded recovery.
    file.save().unwrap();
    file.release().unwrap();
    let file = ProgressFile::open(&scratch.0, false, state()).unwrap();
    assert_eq!(file.state.rows[REF].floor, Some(pin(6, 9)));
    file.release().unwrap();
}

#[test]
#[cfg(unix)]
fn failed_durable_barrier_does_not_permit_effects_or_overwrite_interrupted_replacement() {
    let scratch = Scratch::new();
    let mut file = ProgressFile::open(&scratch.0, true, floor()).unwrap();
    file.state.begin_preparation(REF).unwrap();
    file.save().unwrap();
    let preparing = fs::read(scratch.0.join("checkpoint")).unwrap();
    fs::write(scratch.0.join("checkpoint.next"), b"interrupted").unwrap();
    let mut effects = 0;
    if file.arm(REF, [8; 32]).is_ok() {
        effects += 1;
    }
    assert_eq!(effects, 0);
    assert_eq!(fs::read(scratch.0.join("checkpoint")).unwrap(), preparing);
    assert_eq!(
        fs::read(scratch.0.join("checkpoint.next")).unwrap(),
        b"interrupted"
    );
    drop(file); // Fatal progress failure deliberately retains ownership.
    assert!(scratch.0.join("run.lock").exists());
    assert!(ProgressFile::open(&scratch.0, false, state()).is_err());
}

#[test]
#[cfg(unix)]
fn restartable_preparation_and_other_reference_progress_survive_real_reopen() {
    let scratch = Scratch::new();
    let mut file = ProgressFile::open(&scratch.0, true, floor()).unwrap();
    let other = b"refs/heads/z";
    file.state.begin_preparation(other).unwrap();
    file.state.arm(other, [9; 32]).unwrap();
    file.state.begin_preparation(REF).unwrap();
    file.save().unwrap();
    file.release().unwrap();
    let mut file = ProgressFile::open(&scratch.0, false, state()).unwrap();
    file.state.abandon_preparation(REF).unwrap();
    file.save().unwrap();
    assert_eq!(file.state.rows[REF].floor, Some(pin(4, 2)));
    assert_eq!(file.state.rows[other.as_slice()].pending, Some([9; 32]));
    file.release().unwrap();
}
