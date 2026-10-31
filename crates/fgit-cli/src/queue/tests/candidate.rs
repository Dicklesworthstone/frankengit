//! Candidate commands must retain exact observations and never reinterpret
//! preparation flags as publication authority or a merge-method fallback.

use super::*;
use fgit_forge::preparation::MergeProfile;

fn candidate_args(action: &str) -> Vec<String> {
    let mut args = input("land");
    args[0] = action.into();
    if action == "prepare" {
        remove(&mut args, "--principal");
        remove(&mut args, "--idempotency-key");
        args.extend(
            [
                "--profile",
                "path-v1",
                "--author",
                "Queue Author <queue@example.invalid>",
                "--timestamp",
                "1700000000",
                "--message",
                "Reviewed queue candidate\n",
                "--output-bundle",
                "new-queue-candidate.bundle",
            ]
            .map(str::to_owned),
        );
    } else {
        args.extend([
            "--merge-base".into(),
            "cc".repeat(20),
            "--expected-commit".into(),
            "dd".repeat(20),
            "--bundle".into(),
            "reviewed-queue-candidate.bundle".into(),
        ]);
    }
    args
}

#[test]
fn preparation_keeps_queue_and_review_subject_guards_without_write_authority() {
    let parsed = options::parse(&candidate_args("prepare")).unwrap();
    let Operation::Prepare(preparation) = parsed.operation else {
        panic!()
    };
    assert_eq!(preparation.number.get(), 7);
    assert_eq!(preparation.expected_version.get(), 2);
    assert_eq!(preparation.subject.pull_request.get(), 42);
    assert_eq!(preparation.subject.pull_request_version.get(), 3);
    assert_eq!(preparation.subject.policy_epoch.get(), 1);
    assert_eq!(preparation.subject.source_tip.to_string(), "aa".repeat(20));
    assert_eq!(preparation.subject.target_tip.to_string(), "bb".repeat(20));
    assert_eq!(preparation.profile, MergeProfile::PathMergeV1);
    assert_eq!(preparation.metadata.author, preparation.metadata.committer);
    assert_eq!(preparation.metadata.timestamp, 1_700_000_000);
    assert_eq!(preparation.metadata.message, b"Reviewed queue candidate\n");
    for flag in [
        "--expected-incarnation",
        "--expected-version",
        "--expected-policy-epoch",
        "--pull-request",
        "--expected-pull-version",
        "--source-ref",
        "--target-ref",
        "--expected-source-tip",
        "--expected-target-tip",
        "--profile",
        "--author",
        "--timestamp",
        "--message",
        "--output-bundle",
        "--trusted-local",
    ] {
        let mut args = candidate_args("prepare");
        remove(&mut args, flag);
        assert!(options::parse(&args).is_err(), "missing {flag}");
    }
    for (flag, value) in [
        ("--principal", "33333333333333333333333333333333"),
        ("--idempotency-key", "must-not-seal"),
        ("--method", "squash"),
        ("--force", "true"),
        ("--bundle", "unreviewed.bundle"),
        ("--passed-check", "yes"),
    ] {
        let mut args = candidate_args("prepare");
        args.extend([flag, value].map(str::to_owned));
        assert!(options::parse(&args).is_err(), "prepare accepted {flag}");
    }
}

#[test]
fn candidate_metadata_and_native_hash_formats_are_explicit() {
    for (format, width) in [("sha1", 20), ("sha256", 32)] {
        for action in ["prepare", "land-candidate"] {
            let mut args = candidate_args(action);
            args.extend(["--object-format", format].map(str::to_owned));
            replace(&mut args, "--expected-source-tip", &"aa".repeat(width));
            replace(&mut args, "--expected-target-tip", &"bb".repeat(width));
            if action == "land-candidate" {
                replace(&mut args, "--merge-base", &"cc".repeat(width));
                replace(&mut args, "--expected-commit", &"dd".repeat(width));
            } else {
                replace(&mut args, "--profile", "exact-renames-v1");
                args.extend(
                    ["--committer", "Queue Committer <committer@example.invalid>"]
                        .map(str::to_owned),
                );
            }
            let parsed = options::parse(&args).unwrap();
            match parsed.operation {
                Operation::Prepare(preparation) => {
                    assert_eq!(preparation.subject.source_tip.algorithm(), parsed.format);
                    assert_eq!(preparation.profile, MergeProfile::ExactRenamesV1);
                    assert_ne!(preparation.metadata.author, preparation.metadata.committer);
                }
                Operation::LandCandidate { command, .. } => {
                    assert_eq!(command.merge.merge_commit.to_string(), "dd".repeat(width));
                    assert_eq!(command.merge.base_tip.to_string(), "cc".repeat(width));
                    assert_eq!(command.merge.merge_commit.algorithm(), parsed.format);
                }
                _ => panic!(),
            }
        }
    }
    for (flag, value) in [
        ("--profile", "ort"),
        ("--author", "ambient-user"),
        ("--timestamp", "0"),
        ("--timestamp", "01"),
        ("--timestamp", "18446744073709551615"),
        ("--message", ""),
        ("--output-bundle", ""),
        ("--output-bundle", "/"),
    ] {
        let mut args = candidate_args("prepare");
        replace(&mut args, flag, value);
        assert!(
            options::parse(&args).is_err(),
            "prepare accepted invalid {flag}"
        );
    }
}

#[test]
fn candidate_landing_requires_all_exact_coordinates_and_separate_method() {
    for flag in [
        "--trusted-local",
        "--principal",
        "--expected-incarnation",
        "--idempotency-key",
        "--expected-version",
        "--expected-policy-epoch",
        "--pull-request",
        "--expected-pull-version",
        "--source-ref",
        "--target-ref",
        "--expected-source-tip",
        "--expected-target-tip",
        "--merge-base",
        "--expected-commit",
        "--bundle",
    ] {
        let mut args = candidate_args("land-candidate");
        remove(&mut args, flag);
        assert!(options::parse(&args).is_err(), "missing {flag}");
    }
    for field in [
        "--expected-source-tip",
        "--expected-target-tip",
        "--merge-base",
    ] {
        let mut args = candidate_args("land-candidate");
        let index = args.iter().position(|arg| arg == field).unwrap();
        let alias = args[index + 1].clone();
        replace(&mut args, "--expected-commit", &alias);
        assert!(options::parse(&args).is_err(), "candidate aliased {field}");
    }
    for action in ["prepare", "land-candidate"] {
        for (flag, value) in [
            ("--expected-version", "0"),
            ("--expected-version", "18446744073709551614"),
            ("--expected-pull-version", "18446744073709551615"),
            ("--expected-policy-epoch", "0"),
            ("--source-ref", "refs/heads/main"),
            (
                "--expected-source-tip",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ] {
            let mut args = candidate_args(action);
            replace(&mut args, flag, value);
            assert!(options::parse(&args).is_err(), "{action} accepted {flag}");
        }
    }
    for action in ["land", "land-candidate"] {
        for (flag, value) in [
            ("--method", "squash"),
            ("--force", "true"),
            ("--profile", "path-v1"),
            ("--priority", "9"),
            ("--entry", "42"),
            ("--passed-check", "yes"),
        ] {
            let mut args = if action == "land" {
                input(action)
            } else {
                candidate_args(action)
            };
            args.extend([flag, value].map(str::to_owned));
            assert!(options::parse(&args).is_err(), "{action} accepted {flag}");
        }
    }
    let mut old = candidate_args("land-candidate");
    old[0] = "land".into();
    assert!(
        options::parse(&old).is_err(),
        "candidate fields changed old fast-forward grammar"
    );
}

#[test]
fn candidate_receipt_names_the_reviewed_commit_and_preserves_known_outcomes() {
    let options = options::parse(&candidate_args("land-candidate")).unwrap();
    for committed in [false, true] {
        let (tx, terminal) = terminal(committed);
        let report = output::publication(&options, incarnation(), tx, &terminal, None).unwrap();
        assert!(report.contains("\"name\":\"land-candidate\""));
        assert!(report.contains("\"method\":\"merge-commit\""));
        assert!(report.contains(&format!("\"candidate_commit\":\"{}\"", "dd".repeat(20))));
        assert!(report.contains(&format!("\"merge_base\":\"{}\"", "cc".repeat(20))));
        assert!(report.contains(&format!("\"refs_changed\":{committed}")));
        assert!(!report.contains("private-stable-queue-key"));
        assert!(!report.contains("reviewed-queue-candidate.bundle"));
        let mut failing = BrokenOutput;
        let error = finish(&mut failing, &options, incarnation(), tx, &terminal, None).unwrap_err();
        assert!(error.contains(if committed {
            "is committed"
        } else {
            "canonical refusal"
        }));
    }
}

struct BrokenOutput;
impl std::io::Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}
