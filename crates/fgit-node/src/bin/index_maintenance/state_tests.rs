use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
fn state() -> State {
    State::new(
        "0101 0202 0303 sha256".into(),
        &[b"refs/heads/main".to_vec(), b"refs/heads/z\xff".to_vec()],
    )
    .unwrap()
}
fn pin(number: u64, byte: u8) -> Pin {
    Pin {
        number,
        digest: [byte; 32],
    }
}
const REF: &[u8] = b"refs/heads/main";

#[test]
fn codec_roundtrip_keeps_scope_raw_names_and_exact_checkpoints() {
    let mut s = state();
    s.begin(REF).unwrap();
    s.acknowledge(REF, pin(7, 4), None).unwrap();
    let bytes = s.encode().unwrap();
    assert_eq!(State::decode(&bytes, &state()).unwrap(), s);
    assert_eq!(
        state().encode().unwrap(),
        State::decode(&state().encode().unwrap(), &state())
            .unwrap()
            .encode()
            .unwrap()
    );
}
#[test]
fn changed_namespace_or_reference_set_cannot_reset_progress() {
    let bytes = state().encode().unwrap();
    let other = State::new("0101 0202 0404 sha256".into(), &[REF.to_vec()]).unwrap();
    assert!(State::decode(&bytes, &other).is_err());
    assert!(
        State::decode(
            &bytes,
            &State::new(state().binding, &[REF.to_vec()]).unwrap()
        )
        .is_err()
    );
}
#[test]
fn malformed_noncanonical_truncated_and_oversized_states_refuse() {
    let bytes = state().encode().unwrap();
    for cut in 0..bytes.len() {
        assert!(State::decode(&bytes[..cut], &state()).is_err());
    }
    for suffix in [b"\n".as_slice(), b" ", b"injected"] {
        assert!(State::decode(&[bytes.as_slice(), suffix].concat(), &state()).is_err());
    }
    let text = String::from_utf8(bytes).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert!(
        State::decode(
            format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1]).as_bytes(),
            &state()
        )
        .is_err()
    );
    assert!(State::decode(&vec![b'a'; MAX_STATE_BYTES + 1], &state()).is_err());
    for tail in ["- 1 - 0", "- 00 - 0", "- 0 - 2", "a 1 - 0"] {
        let changed = format!("{}\n{} {tail}\n{}\n", lines[0], hex(REF), lines[2]);
        assert!(State::decode(changed.as_bytes(), &state()).is_err());
    }
}
#[test]
fn checkpoint_never_regresses_or_changes_identity_at_the_same_position() {
    let mut s = state();
    s.begin(REF).unwrap();
    s.acknowledge(REF, pin(7, 4), None).unwrap();
    for wrong in [pin(6, 4), pin(7, 5), pin(0, 4), pin(8, 0)] {
        let mut attempt = s.clone();
        attempt.begin(REF).unwrap();
        let unchanged = attempt.clone();
        assert!(attempt.acknowledge(REF, wrong, None).is_err());
        assert_eq!(attempt, unchanged);
    }
    s.begin(REF).unwrap();
    s.acknowledge(REF, pin(7, 4), None).unwrap();
    s.begin(REF).unwrap();
    s.acknowledge(REF, pin(8, 5), None).unwrap();
    assert_eq!(s.rows[REF].floor, Some(pin(8, 5)));
}
#[test]
fn write_ahead_marker_survives_reload_and_blocks_unknown_retries() {
    let mut s = state();
    s.begin(REF).unwrap();
    let mut loaded = State::decode(&s.encode().unwrap(), &state()).unwrap();
    assert!(loaded.rows[REF].running);
    assert!(loaded.begin(REF).is_err());
    assert!(loaded.acknowledge(REF, pin(1, 1), Some([1; 32])).is_err());
}
#[test]
fn pending_candidate_cannot_be_dropped_or_retargeted_by_normal_work() {
    let mut s = state();
    s.begin(REF).unwrap();
    s.uncertain(REF, [4; 32]).unwrap();
    let before = s.clone();
    assert!(s.begin(REF).is_err());
    assert!(s.refuse(REF).is_err());
    assert!(s.acknowledge(REF, pin(2, 5), None).is_err());
    assert!(s.acknowledge(REF, pin(2, 5), Some([3; 32])).is_err());
    assert_eq!(s, before);
    s.acknowledge(REF, pin(2, 5), Some([4; 32])).unwrap();
    assert!(!s.rows[REF].running);
    assert_eq!(s.rows[REF].pending, None);
}
#[test]
fn failed_attempt_preserves_floor_and_leaves_other_refs_untouched() {
    let mut s = state();
    s.begin(REF).unwrap();
    s.acknowledge(REF, pin(4, 2), None).unwrap();
    let old = s.clone();
    s.begin(REF).unwrap();
    s.refuse(REF).unwrap();
    assert_eq!(s, old);
    assert!(s.refuse(REF).is_err());
    assert!(s.begin(b"refs/heads/unconfigured").is_err());
    assert_eq!(s, old);
}
#[test]
fn scope_and_integer_limits_are_not_silently_narrowed() {
    assert!(State::new("ok".into(), &[]).is_err());
    assert!(State::new("ok".into(), &[REF.to_vec(), REF.to_vec()]).is_err());
    assert!(State::new("ok\nnew".into(), &[REF.to_vec()]).is_err());
    assert!(
        State::new(
            "ok".into(),
            &(0..33)
                .map(|n| n.to_string().into_bytes())
                .collect::<Vec<_>>()
        )
        .is_err()
    );
    for n in ["", "00", "-1", "+1", "18446744073709551616", "1\n"] {
        assert!(decimal(n, u64::MAX).is_err());
    }
    assert_eq!(decimal("18446744073709551615", u64::MAX).unwrap(), u64::MAX);
    for h in ["", "a", "FF", "gg"] {
        assert!(unhex(h, 32).is_err());
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "fg-index-progress-{}-{}",
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
fn private_file_save_resume_and_explicit_release_preserve_exact_bytes() {
    let scratch = Scratch::new();
    let mut file = ProgressFile::open(&scratch.0, true, state()).unwrap();
    file.state.begin(REF).unwrap();
    file.save().unwrap();
    file.state.acknowledge(REF, pin(9, 5), None).unwrap();
    file.save().unwrap();
    let expected = file.state.clone();
    file.release().unwrap();
    let file = ProgressFile::open(&scratch.0, false, state()).unwrap();
    assert_eq!(file.state, expected);
    file.release().unwrap();
    assert!(ProgressFile::open(&scratch.0, true, state()).is_err());
    assert!(!scratch.0.join("run.lock").exists());
}
#[test]
#[cfg(unix)]
fn exclusive_and_abandoned_lock_never_gets_automatically_stolen() {
    let scratch = Scratch::new();
    let file = ProgressFile::open(&scratch.0, true, state()).unwrap();
    assert!(ProgressFile::open(&scratch.0, false, state()).is_err());
    drop(file);
    assert!(ProgressFile::open(&scratch.0, false, state()).is_err());
    assert!(scratch.0.join("run.lock").is_file());
}
#[test]
#[cfg(unix)]
fn unknown_crash_and_pending_candidate_survive_file_reopen_without_reset() {
    let scratch = Scratch::new();
    let mut file = ProgressFile::open(&scratch.0, true, state()).unwrap();
    file.state.begin(REF).unwrap();
    file.save().unwrap();
    file.release().unwrap();
    let mut file = ProgressFile::open(&scratch.0, false, state()).unwrap();
    assert!(file.state.begin(REF).is_err());
    file.state.uncertain(REF, [6; 32]).unwrap();
    file.save().unwrap();
    file.release().unwrap();
    let file = ProgressFile::open(&scratch.0, false, state()).unwrap();
    assert_eq!(file.state.rows[REF].pending, Some([6; 32]));
    file.release().unwrap();
}
#[test]
#[cfg(unix)]
fn missing_resume_symlinks_and_interrupted_replacement_fail_without_overwrite() {
    use std::os::unix::fs::symlink;
    let scratch = Scratch::new();
    assert!(ProgressFile::open(&scratch.0, false, state()).is_err());
    let file = ProgressFile::open(&scratch.0, true, state()).unwrap();
    file.release().unwrap();
    let original = fs::read(scratch.0.join("checkpoint")).unwrap();
    fs::write(scratch.0.join("checkpoint.next"), b"interrupted").unwrap();
    assert!(ProgressFile::open(&scratch.0, false, state()).is_err());
    assert_eq!(fs::read(scratch.0.join("checkpoint")).unwrap(), original);
    fs::remove_file(scratch.0.join("checkpoint.next")).unwrap();
    fs::rename(scratch.0.join("checkpoint"), scratch.0.join("target")).unwrap();
    symlink("target", scratch.0.join("checkpoint")).unwrap();
    assert!(ProgressFile::open(&scratch.0, false, state()).is_err());
    assert_eq!(fs::read(scratch.0.join("target")).unwrap(), original);
}
