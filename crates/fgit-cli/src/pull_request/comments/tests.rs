use super::*;
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_node::PullRequestCommentView;
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm,
    RepositoryAuthorityHeadId,
};

fn args(append: bool) -> Vec<String> {
    let mut args = vec![
        if append { "comment" } else { "comments" }.into(),
        "node".into(),
        "11".repeat(16),
        "22".repeat(16),
        "7".into(),
        "--trusted-local".into(),
    ];
    if append {
        args.extend([
            "--principal".into(),
            "33".repeat(16),
            "--idempotency-key".into(),
            "private-key".into(),
            "--expected-version".into(),
            "0".into(),
            "--body".into(),
            " é\r\n<script>literal</script> \n".into(),
        ]);
    }
    args
}
fn replace(args: &mut [String], flag: &str, value: &str) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value.into();
}
fn head() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[7; 32]).unwrap(),
    )
}

#[test]
fn comment_inputs_preserve_body_and_discussion_version_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut input = args(true);
        input.extend(["--object-format".into(), format.as_str().into()]);
        let parsed = options::parse(&input).unwrap();
        assert_eq!(parsed.format, format);
        let Operation::Append { command, key, .. } = parsed.operation else {
            panic!("append")
        };
        assert_eq!(command.number.get(), 7);
        assert_eq!(command.body, " é\r\n<script>literal</script> \n");
        assert_eq!(command.expected_version, ExpectedVersion::NewStream);
        assert_eq!(key, b"private-key");
        replace(&mut input, "--expected-version", "9007199254740993");
        let Operation::Append { command, .. } = options::parse(&input).unwrap().operation else {
            panic!("append")
        };
        assert_eq!(
            command.expected_version,
            ExpectedVersion::Exactly(AggregateVersion::try_new(9_007_199_254_740_993).unwrap())
        );
    }
}

#[test]
fn incomplete_ambiguous_or_authority_widening_comment_input_refuses() {
    for flag in [
        "--principal",
        "--idempotency-key",
        "--expected-version",
        "--body",
    ] {
        let mut input = args(true);
        let index = input.iter().position(|arg| arg == flag).unwrap();
        input.drain(index..index + 2);
        assert!(options::parse(&input).is_err(), "missing {flag}");
    }
    for (flag, value) in [
        ("--expected-version", "01"),
        ("--expected-version", "18446744073709551615"),
        ("--body", " \r\n\t"),
        ("--body", "a\0b"),
        ("--principal", "invalid"),
    ] {
        let mut input = args(true);
        replace(&mut input, flag, value);
        assert!(options::parse(&input).is_err(), "{flag}");
    }
    for flag in [
        "--expected-version",
        "--body-file",
        "--force",
        "--expected-source",
        "--after",
    ] {
        let mut input = args(true);
        input.extend([flag.into(), "1".into()]);
        assert!(options::parse(&input).is_err(), "{flag}");
    }
    let mut untrusted = args(true);
    untrusted.retain(|arg| arg != "--trusted-local");
    assert!(options::parse(&untrusted).is_err());
    let mut bounded = args(true);
    replace(&mut bounded, "--body", &"x".repeat(65_536));
    assert!(options::parse(&bounded).is_ok());
    replace(&mut bounded, "--body", &"é".repeat(32_769));
    assert!(options::parse(&bounded).is_err());
}

#[test]
fn reads_require_a_pinned_continuation_and_refuse_write_options() {
    let mut input = args(false);
    input.extend(["--after".into(), "1".into()]);
    assert!(options::parse(&input).is_err());
    input.extend(["--expected-head".into(), head_token(head())]);
    assert!(options::parse(&input).is_ok());
    for (flag, value) in [
        ("--limit", "0"),
        ("--limit", "101"),
        ("--body", "comment"),
        ("--principal", &"33".repeat(16)),
        ("--expected-version", "0"),
    ] {
        let mut invalid = args(false);
        invalid.extend([flag.into(), value.into()]);
        assert!(options::parse(&invalid).is_err(), "{flag}");
    }
}

#[test]
fn read_reports_keep_high_water_separate_from_page_completion_and_reject_bad_windows() {
    let options = options::parse(&args(false)).unwrap();
    let mut page = PullRequestCommentsPage {
        number: PullRequestNumber::try_new(7).unwrap(),
        source_head: head(),
        discussion_version: Some(AggregateVersion::try_new(1).unwrap()),
        comments: vec![PullRequestCommentView {
            version: AggregateVersion::try_new(1).unwrap(),
            actor: PrincipalId::from_bytes([3; 16]),
            body: "\"untrusted\"\n\u{202e}".into(),
        }],
        next_after: None,
    };
    let rendered = read_report(&options, "incarnation", Some(&page)).unwrap();
    assert!(rendered.contains("\"discussion_version\":\"1\""));
    assert!(rendered.contains("\"complete\":true"));
    assert!(rendered.contains("\\u202e"));
    assert!(!rendered.contains('\u{202e}'));
    assert!(!rendered.contains("private-key"));
    page.number = PullRequestNumber::try_new(8).unwrap();
    assert!(read_report(&options, "incarnation", Some(&page)).is_err());
    page.number = options.number;
    page.comments[0].version = AggregateVersion::try_new(2).unwrap();
    assert!(read_report(&options, "incarnation", Some(&page)).is_err());
    let absent = read_report(&options, "incarnation", None).unwrap();
    assert!(absent.contains("\"found\":false"));
    assert!(absent.contains("\"discussion_version\":null"));
}
