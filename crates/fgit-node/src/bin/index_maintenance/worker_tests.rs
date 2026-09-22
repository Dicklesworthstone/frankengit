use super::*;
fn args(tail: &[&str]) -> Vec<OsString> {
    let mut out: Vec<_> = [
        "/node",
        "01010101010101010101010101010101",
        "02020202020202020202020202020202",
        "sha1",
        "/private-progress",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    out.extend(tail.iter().map(|value| OsString::from(*value)));
    out
}
#[test]
fn scope_mode_and_work_horizon_are_explicit_and_bounded() {
    let one = parse(&args(&["init", "1", "0", "refs/heads/main"])).unwrap();
    assert!(one.initialize);
    assert_eq!(one.passes, 1);
    let multiple = parse(&args(&[
        "resume",
        "100",
        "10",
        "refs/heads/z",
        "refs/heads/a",
    ]))
    .unwrap();
    assert_eq!(multiple.refs[0].as_bytes(), b"refs/heads/a");
    for tail in [
        &["auto", "1", "0", "refs/heads/main"][..],
        &["resume", "0", "1", "refs/heads/main"],
        &["resume", "2", "0", "refs/heads/main"],
        &["resume", "3601", "1", "refs/heads/main"],
        &["resume", "100", "3600", "refs/heads/main"],
        &["resume", "1", "0", "refs/heads/main", "refs/heads/main"],
        &["resume", "1", "0"],
        &["resume", "1", "0", "HEAD"],
    ] {
        assert!(parse(&args(tail)).is_err());
    }
}
#[test]
fn tokens_keep_generation_identity_and_position_separate() {
    let pin = IndexPin {
        digest: [4; 32],
        number: 17,
    };
    assert_eq!(checkpoint(&activation(&pin).unwrap()).unwrap(), pin);
    assert_eq!(activation(&pin).unwrap().authority_generation.get(), 17);
}
#[test]
fn only_definite_precondition_races_allow_a_later_new_attempt() {
    assert!(definite_race(&IndexError::Generation(
        GenerationAuthorityError::ConcurrentActivation
    )));
    assert!(definite_race(&IndexError::Generation(
        GenerationAuthorityError::HeadAlreadyInitialized
    )));
    assert!(!definite_race(&IndexError::Generation(
        GenerationAuthorityError::InvalidActivationReceipt
    )));
    assert!(!definite_race(&IndexError::Generation(
        GenerationAuthorityError::Authority(fgit_authority::AuthorityFailure::Ambiguous(
            fgit_authority::AmbiguityReason::NoResponse
        ))
    )));
    assert!(!definite_race(&IndexError::Uninitialized));
}
#[test]
fn invalid_identity_format_and_unbounded_arguments_refuse_before_node_open() {
    for index in [1, 2, 3] {
        let mut values = args(&["init", "1", "0", "refs/heads/main"]);
        values[index] = OsString::from("bad");
        assert!(parse(&values).is_err());
    }
    let mut values = args(&["init", "1", "0", "refs/heads/main"]);
    values[0] = OsString::from("x".repeat(4097));
    assert!(parse(&values).is_err());
    let mut values = args(&["init", "1", "0"]);
    values.extend((0..33).map(|n| OsString::from(format!("refs/heads/{n}"))));
    assert!(parse(&values).is_err());
}
