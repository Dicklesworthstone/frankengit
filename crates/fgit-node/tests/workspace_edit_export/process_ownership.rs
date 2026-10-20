use super::{Fixture, private_parent, reference};
use std::fs;
use std::process::Command;
use std::time::{Duration, Instant};

fn live(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| s.rsplit_once(") ").map(|(_, tail)| tail.as_bytes()[0]))
        .is_some_and(|state| !matches!(state, b'Z' | b'X'))
}

#[test]
fn orphaned_tool_success_never_exports_or_removes_a_live_workspace() {
    let fixture = Fixture::new();
    let parent = private_parent(&fixture);
    let node = fixture.node();
    let request = node.request_context();
    let pidfile = fixture.root.join("orphan.pid");
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        &format!(
            "printf changed > edit.txt; sleep 30 & echo $! > '{}'",
            pidfile.display()
        ),
    ]);
    let result = node.runtime().block_on(node.run_trusted_workspace_tool_in(
        &request,
        &reference(),
        [0x91; 16],
        &parent,
        &[b"edit.txt".to_vec()],
        &[b"edit.txt".to_vec()],
        &mut command,
        Duration::from_secs(10),
        ("Test <test@example.invalid>", 1, b"orphan must refuse\n"),
    ));
    let pid: u32 = fs::read_to_string(pidfile).unwrap().trim().parse().unwrap();
    let until = Instant::now() + Duration::from_millis(500);
    while live(pid) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    let survived = live(pid);
    if survived {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    assert!(!survived, "orphan still live before fixture cleanup");
    let error =
        result.expect_err("leader exit 0 must not authorize export with unjoined descendants");
    assert!(error.retained_workspace().unwrap().is_dir());
}

#[test]
fn joined_children_are_permitted_and_the_same_owner_closes_the_workspace() {
    let fixture = Fixture::new();
    let parent = private_parent(&fixture);
    let node = fixture.node();
    let request = node.request_context();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf changed > edit.txt; sleep 0.02 & wait"]);
    let result = node
        .runtime()
        .block_on(node.run_trusted_workspace_tool_in(
            &request,
            &reference(),
            [0x92; 16],
            &parent,
            &[b"edit.txt".to_vec()],
            &[b"edit.txt".to_vec()],
            &mut command,
            Duration::from_secs(10),
            ("Test <test@example.invalid>", 1, b"joined child\n"),
        ))
        .unwrap();
    assert_ne!(result.candidate_commit, fixture.commit);
    assert_eq!(fs::read_dir(parent).unwrap().count(), 0);
}

#[test]
fn source_pins_are_checked_before_any_host_effect_and_matching_pins_execute() {
    use fgit_types::{
        CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, RepositoryAuthorityHeadId,
    };
    let fixture = Fixture::new();
    let parent = private_parent(&fixture);
    let node = fixture.node();
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let head = selected.basis().id();
    let wrong_head = RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(2).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0xa7; 32]).unwrap(),
    );
    let marker = fixture.root.join("must-not-execute");
    let script = format!(
        "printf started > '{}'; printf changed > edit.txt",
        marker.display()
    );
    for (expected, reason) in [
        ((Some(wrong_head), Some(fixture.commit)), "SnapshotMoved"),
        ((Some(head), Some(fixture.untouched)), "CommitMoved"),
    ] {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &script]);
        let refused = node
            .runtime()
            .block_on(node.run_trusted_workspace_tool_at_in(
                &request,
                &reference(),
                expected,
                [0x93; 16],
                &parent,
                &[b"edit.txt".to_vec()],
                &[b"edit.txt".to_vec()],
                &mut command,
                Duration::from_secs(10),
                ("Test <test@example.invalid>", 1, b"pinned\n"),
            ))
            .unwrap_err();
        assert!(format!("{refused:?}").contains(reason), "{refused:?}");
        assert!(!marker.exists());
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    }
    let mut command = Command::new("/bin/sh");
    command.args(["-c", &script]);
    let result = node
        .runtime()
        .block_on(node.run_trusted_workspace_tool_at_in(
            &request,
            &reference(),
            (Some(head), Some(fixture.commit)),
            [0x93; 16],
            &parent,
            &[b"edit.txt".to_vec()],
            &[b"edit.txt".to_vec()],
            &mut command,
            Duration::from_secs(10),
            ("Test <test@example.invalid>", 1, b"pinned\n"),
        ))
        .unwrap();
    assert!(marker.exists());
    assert_eq!(result.source_commit, fixture.commit);
    assert_ne!(result.candidate_commit, fixture.commit);
    assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
}
