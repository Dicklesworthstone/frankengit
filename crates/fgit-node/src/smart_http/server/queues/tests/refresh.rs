use super::*;
use fgit_forge::event::pull_request::{MAX_BODY_BYTES, MAX_TITLE_BYTES, PullRequestAction};

fn refresh_form(format: GitHashAlgorithm) -> String {
    format!(
        "{}&expected_policy_epoch=2&expected_recorded_target_tip={}&title=Exact+PR+title&body=Original%0Abody",
        form(format).replace("expected_version=0", "expected_version=4"),
        "cc".repeat(format.digest_len()),
    )
}

fn refresh_command(
    body: &str,
    format: GitHashAlgorithm,
) -> Result<fgit_admission::merge::native::queue::QueueHeadRefreshCommand, ApiError> {
    super::super::refresh::parse(QueueNumber::FIRST, body.as_bytes(), format, incarnation())
}

#[test]
fn target_refresh_has_a_closed_complete_original_command_in_both_object_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let body = refresh_form(format);
        let command = refresh_command(&body, format).unwrap();
        assert_eq!(command.expected_queue_version.get(), 4);
        assert_eq!(command.expected_policy_epoch.get(), 2);
        assert_eq!(
            command.pull_request.expected_version,
            ExpectedVersion::Exactly(fgit_forge::AggregateVersion::try_new(3).unwrap())
        );
        assert_eq!(command.pull_request.action, PullRequestAction::Update);
        assert_eq!(command.pull_request.data.title, "Exact PR title");
        assert_eq!(command.pull_request.data.body, "Original\nbody");
        assert_eq!(
            command.expected_recorded_target_tip.to_string(),
            "cc".repeat(format.digest_len())
        );
        assert_eq!(
            command.pull_request.data.target_tip.to_string(),
            "bb".repeat(format.digest_len())
        );
        command
            .proposed_event(PrincipalId::from_bytes([9; 16]), format)
            .unwrap();

        for required in [
            "expected_incarnation",
            "object_format",
            "expected_version",
            "expected_policy_epoch",
            "pull_request",
            "expected_pull_request_version",
            "source_ref",
            "target_ref",
            "expected_source_tip",
            "expected_recorded_target_tip",
            "expected_target_tip",
            "title",
            "body",
        ] {
            let missing = body
                .split('&')
                .filter(|field| !field.starts_with(&format!("{required}=")))
                .collect::<Vec<_>>()
                .join("&");
            assert!(
                refresh_command(&missing, format).is_err(),
                "missing {required}"
            );
        }
        for extra in [
            "principal=attacker",
            "force=true",
            "trusted_local=true",
            "idempotency_key=body-key",
            "expected_version=4",
            "body=changed",
            "priority=1",
            "entry=7",
            "checks_passed=true",
        ] {
            assert!(
                refresh_command(&format!("{body}&{extra}"), format).is_err(),
                "{extra}"
            );
        }
        for (before, after) in [
            ("expected_version=4", "expected_version=0"),
            ("expected_version=4", "expected_version=04"),
            ("expected_policy_epoch=2", "expected_policy_epoch=0"),
            (
                "expected_pull_request_version=3",
                "expected_pull_request_version=0",
            ),
            (
                "expected_pull_request_version=3",
                "expected_pull_request_version=18446744073709551615",
            ),
            ("pull_request=7", "pull_request=0"),
            ("refs%2Fheads%2Ftopic", "refs%2Fheads%2Fmain"),
            ("refs%2Fheads%2Ftopic", "refs%2Ftags%2Ftopic"),
        ] {
            assert!(
                refresh_command(&body.replace(before, after), format).is_err(),
                "{after}"
            );
        }
        let unchanged = body.replace(
            &"cc".repeat(format.digest_len()),
            &"bb".repeat(format.digest_len()),
        );
        assert_eq!(
            refresh_command(&unchanged, format).unwrap_err().code,
            "queue_refresh_requires_target_movement"
        );
        let zero = body.replace(
            &"cc".repeat(format.digest_len()),
            &"00".repeat(format.digest_len()),
        );
        assert!(refresh_command(&zero, format).is_err());
        assert_eq!(
            super::super::refresh::parse(
                QueueNumber::FIRST,
                body.as_bytes(),
                format,
                RepositoryIncarnationId::from_bytes([8; 16]),
            )
            .unwrap_err()
            .code,
            "repository_incarnation_mismatch"
        );
        let other = if format == GitHashAlgorithm::Sha1 {
            GitHashAlgorithm::Sha256
        } else {
            GitHashAlgorithm::Sha1
        };
        assert_eq!(
            refresh_command(&body, other).unwrap_err().code,
            "object_format_mismatch"
        );
    }
}

#[test]
fn refresh_preserves_raw_refs_and_the_full_bounded_original_body() {
    let body = refresh_form(GitHashAlgorithm::Sha256).replace(
        "source_ref=refs%2Fheads%2Ftopic",
        "source_ref_hex=726566732f68656164732fff",
    );
    assert_eq!(
        refresh_command(&body, GitHashAlgorithm::Sha256)
            .unwrap()
            .pull_request
            .data
            .source_ref
            .as_bytes(),
        b"refs/heads/\xff"
    );
    for malformed in ["726566732F68656164732fff", "726", "zz"] {
        assert!(
            refresh_command(
                &body.replace("726566732f68656164732fff", malformed),
                GitHashAlgorithm::Sha256,
            )
            .is_err()
        );
    }
    assert!(
        refresh_command(
            &format!("{body}&source_ref=refs%2Fheads%2Ftopic"),
            GitHashAlgorithm::Sha256
        )
        .is_err()
    );
    let full = body.replace(
        "body=Original%0Abody",
        &format!("body={}", "%0A".repeat(MAX_BODY_BYTES)),
    );
    assert!(full.len() > MAX_COMMAND_BYTES);
    assert_eq!(
        refresh_command(&full, GitHashAlgorithm::Sha256)
            .unwrap()
            .pull_request
            .data
            .body
            .len(),
        MAX_BODY_BYTES
    );
    assert!(refresh_command(&format!("{full}%0A"), GitHashAlgorithm::Sha256).is_err());
    let empty = body.replace("body=Original%0Abody", "body=");
    assert_eq!(
        refresh_command(&empty, GitHashAlgorithm::Sha256)
            .unwrap()
            .pull_request
            .data
            .body,
        ""
    );
    assert!(
        refresh_command(
            &body.replace(
                "title=Exact+PR+title",
                &format!("title={}", "x".repeat(MAX_TITLE_BYTES + 1))
            ),
            GitHashAlgorithm::Sha256
        )
        .is_err()
    );
    assert!(
        refresh_command(
            &body.replace("body=Original%0Abody", "body=%00"),
            GitHashAlgorithm::Sha256
        )
        .is_err()
    );
}

#[test]
fn refresh_is_a_bounded_body_mutation_with_a_required_key_not_a_landing_or_preparation() {
    for framing in [
        "Content-Length: 1\r\n".to_owned(),
        format!(
            "Content-Length: {}\r\n",
            super::super::refresh::MAX_COMMAND_BYTES
        ),
        "Transfer-Encoding: chunked\r\nExpect: 100-continue\r\n".to_owned(),
    ] {
        let bytes = format!(
            "POST /repo.git/api/v1/queues/1/refresh HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\n{framing}\r\n"
        );
        let request = parse(&bytes).unwrap();
        assert!(request.is_mutation() && request.accepts_body() && request.is_refresh());
        assert!(!request.is_landing() && !request.is_preparation());
        assert!(
            matches!(request.operation, Operation::Refresh { number } if number == QueueNumber::FIRST)
        );
    }
    for (method, suffix, size) in [
        ("POST", "/0/refresh", 1),
        ("POST", "/01/refresh", 1),
        ("POST", "/1/refresh/extra", 1),
        ("POST", "/1/refresh?expected_version=1", 1),
        ("POST", "/1/refresh", 0),
        (
            "POST",
            "/1/refresh",
            super::super::refresh::MAX_COMMAND_BYTES + 1,
        ),
        ("GET", "/1/refresh", 0),
        ("PUT", "/1/refresh", 1),
    ] {
        assert!(
            parse(&wire(method, suffix, size)).is_err(),
            "{method} {suffix}"
        );
    }
    let valid = wire("POST", "/1/refresh", 1);
    assert!(
        parse(&valid.replace("application/x-www-form-urlencoded", "application/json")).is_err()
    );
    assert!(
        parse(&valid.replace("Host: local", "Host: local\r\nGit-Protocol: version=2")).is_err()
    );
}
