use super::*;
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion};
use fgit_forge::event::pull_request::PullRequestAction;
use fgit_types::GitHashAlgorithm;

fn args(format: GitHashAlgorithm) -> Vec<String> {
    vec![
        "reopen".into(), "unopened-node".into(), "11".repeat(16), "22".repeat(16),
        "7".into(), "--trusted-local".into(), "--principal".into(), "33".repeat(16),
        "--idempotency-key".into(), "reopen-exact-request".into(),
        "--expected-version".into(), "2".into(),
        "--source-ref-hex".into(), "726566732f68656164732f746f706963ff".into(),
        "--target-ref".into(), "refs/heads/main".into(),
        "--expected-source".into(), "a".repeat(format.digest_len() * 2),
        "--expected-target".into(), "b".repeat(format.digest_len() * 2),
        "--title".into(), "Resume review".into(), "--body".into(), "Revised\né".into(),
    ]
}

#[test]
fn reopen_cli_keeps_action_complete_bytes_and_exact_positive_version() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let parsed = options::parse(&args(format)).unwrap();
        assert_eq!(parsed.format, format);
        let Operation::Mutate(mutation) = parsed.operation else {
            panic!("reopen must use canonical mutation admission");
        };
        assert_eq!(mutation.command.action, PullRequestAction::Reopen);
        assert_eq!(output::action_name(mutation.command.action), "reopen");
        assert_eq!(mutation.command.expected_version,
            ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap()));
        assert_eq!(mutation.command.data.source_ref.as_bytes(), b"refs/heads/topic\xff");
        assert_eq!(mutation.command.data.body, "Revised\né");
        assert_eq!(mutation.key.as_slice(), b"reopen-exact-request");
        assert_eq!(mutation.command.proposed_event(mutation.principal, format).unwrap().version.get(), 3);
    }
}

#[test]
fn reopen_cli_cannot_omit_authority_preconditions_or_alias_another_action() {
    let original = args(GitHashAlgorithm::Sha1);
    for flag in ["--principal", "--idempotency-key", "--expected-version", "--body"] {
        let mut missing = original.clone();
        let index = missing.iter().position(|value| value == flag).unwrap();
        missing.drain(index..index + 2);
        assert!(options::parse(&missing).is_err(), "{flag}");
    }
    let mut untrusted = original.clone();
    untrusted.retain(|value| value != "--trusted-local");
    assert!(options::parse(&untrusted).is_err());
    for version in ["0", "02", "18446744073709551615"] {
        let mut invalid = original.clone();
        let index = invalid.iter().position(|value| value == "--expected-version").unwrap();
        invalid[index + 1] = version.into();
        assert!(options::parse(&invalid).is_err(), "{version}");
    }
    let Operation::Mutate(reopen) = options::parse(&original).unwrap().operation else {
        panic!("mutation");
    };
    let mut update = original;
    update[0] = "update".into();
    let Operation::Mutate(update) = options::parse(&update).unwrap().operation else {
        panic!("mutation");
    };
    assert_eq!(reopen.command.data, update.command.data);
    assert_ne!(reopen.command.proposed_event(reopen.principal, GitHashAlgorithm::Sha1).unwrap(),
        update.command.proposed_event(update.principal, GitHashAlgorithm::Sha1).unwrap());
}
