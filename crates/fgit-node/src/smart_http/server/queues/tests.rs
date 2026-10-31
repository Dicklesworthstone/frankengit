use super::*;
mod candidate;
use fgit_forge::merge_queue::QueueCommandAction;
use fgit_forge::{ExpectedVersion, QueueNumber};
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryIncarnationId};
use fgit_wire::smart_http::head;

fn incarnation() -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([4; 16])
}
fn form(format: GitHashAlgorithm) -> String {
    format!(
        "expected_incarnation={}&object_format={}&expected_version=0&target_ref=refs%2Fheads%2Fmain&pull_request=7&expected_pull_request_version=3&source_ref=refs%2Fheads%2Ftopic&expected_source_tip={}&expected_target_tip={}",
        incarnation(),
        format.as_str(),
        "aa".repeat(format.digest_len()),
        "bb".repeat(format.digest_len())
    )
}
fn wire(method: &str, suffix: &str, bytes: usize) -> String {
    let headers = if method == "POST" {
        format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {bytes}\r\n")
    } else {
        String::new()
    };
    format!("{method} /repo.git/api/v1/queues{suffix} HTTP/1.1\r\nHost: local\r\n{headers}\r\n")
}
fn parse(bytes: &str) -> Result<Request<'_>, ApiError> {
    Request::parse(
        &head::parse(bytes.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap(),
    )
}

#[test]
fn enqueue_requires_every_immutable_guard_and_preserves_both_native_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let body = form(format);
        let bytes = wire("POST", "/1/enqueue", body.len());
        let request = parse(&bytes).unwrap();
        let command = request
            .command(body.as_bytes(), format, incarnation())
            .unwrap();
        assert_eq!(command.number, QueueNumber::FIRST);
        assert_eq!(command.expected_version, ExpectedVersion::NewStream);
        let QueueCommandAction::Enqueue {
            expected_pull_request_version,
            head_tip,
            expected_target_tip,
            priority,
            ..
        } = &command.action
        else {
            panic!()
        };
        assert_eq!(expected_pull_request_version.get(), 3);
        assert_eq!(head_tip.algorithm(), format);
        assert_eq!(expected_target_tip.algorithm(), format);
        assert_eq!(*priority, 0);
        command
            .proposed_event(PrincipalId::from_bytes([9; 16]), format)
            .unwrap();
        for required in [
            "expected_incarnation",
            "object_format",
            "expected_version",
            "target_ref",
            "pull_request",
            "expected_pull_request_version",
            "source_ref",
            "expected_source_tip",
            "expected_target_tip",
        ] {
            let missing = body
                .split('&')
                .filter(|pair| !pair.starts_with(&format!("{required}=")))
                .collect::<Vec<_>>()
                .join("&");
            assert!(
                request
                    .command(missing.as_bytes(), format, incarnation())
                    .is_err(),
                "missing {required}"
            );
        }
        assert_eq!(
            request
                .command(
                    body.as_bytes(),
                    format,
                    RepositoryIncarnationId::from_bytes([8; 16])
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
            request
                .command(body.as_bytes(), other, incarnation())
                .unwrap_err()
                .code,
            "object_format_mismatch"
        );
    }
}

#[test]
fn identity_overrides_unknown_duplicate_and_malformed_guards_are_not_commands() {
    let body = form(GitHashAlgorithm::Sha1);
    let bytes = wire("POST", "/1/enqueue", body.len());
    let request = parse(&bytes).unwrap();
    for suffix in [
        "principal=attacker",
        "trusted_local=true",
        "idempotency_key=body-key",
        "force=true",
        "expected_version=1",
        "entry=1",
        "priority=4294967296",
        "target_ref_hex=72656673",
    ] {
        assert!(
            request
                .command(
                    format!("{body}&{suffix}").as_bytes(),
                    GitHashAlgorithm::Sha1,
                    incarnation()
                )
                .is_err(),
            "{suffix}"
        );
    }
    for (before, after) in [
        (
            "expected_version=0",
            "expected_version=18446744073709551615",
        ),
        ("expected_version=0", "expected_version=01"),
        (
            "expected_pull_request_version=3",
            "expected_pull_request_version=0",
        ),
        ("pull_request=7", "pull_request=0"),
        ("refs%2Fheads%2Ftopic", "refs%2Ftags%2Ftopic"),
    ] {
        assert!(
            request
                .command(
                    body.replace(before, after).as_bytes(),
                    GitHashAlgorithm::Sha1,
                    incarnation()
                )
                .is_err()
        );
    }
    let zero = body.replace(&"aa".repeat(20), &"00".repeat(20));
    assert!(
        request
            .command(zero.as_bytes(), GitHashAlgorithm::Sha1, incarnation())
            .is_err()
    );
    let oversized = vec![b'a'; MAX_COMMAND_BYTES + 1];
    assert!(
        request
            .command(&oversized, GitHashAlgorithm::Sha1, incarnation())
            .is_err()
    );
}

#[test]
fn exact_reorder_is_nonempty_unique_bounded_and_keeps_the_supplied_order() {
    let prefix = format!(
        "expected_incarnation={}&object_format=sha1&expected_version=2&target_ref=refs%2Fheads%2Fmain",
        incarnation()
    );
    let bytes = wire("POST", "/1/reorder", 1);
    let request = parse(&bytes).unwrap();
    assert!(
        request
            .command(prefix.as_bytes(), GitHashAlgorithm::Sha1, incarnation())
            .is_err()
    );
    let valid = format!("{prefix}&entry=8&entry=7");
    let command = request
        .command(valid.as_bytes(), GitHashAlgorithm::Sha1, incarnation())
        .unwrap();
    let QueueCommandAction::Reorder { order } = command.action else {
        panic!()
    };
    assert_eq!(order.iter().map(|n| n.get()).collect::<Vec<_>>(), [8, 7]);
    assert!(
        request
            .command(
                format!("{valid}&entry=8").as_bytes(),
                GitHashAlgorithm::Sha1,
                incarnation()
            )
            .is_err()
    );
    assert!(
        request
            .command(
                valid
                    .replace("expected_version=2", "expected_version=0")
                    .as_bytes(),
                GitHashAlgorithm::Sha1,
                incarnation()
            )
            .is_err()
    );
    let mut full = prefix;
    for number in 1..=1024 {
        full.push_str(&format!("&entry={number}"));
    }
    assert!(
        request
            .command(full.as_bytes(), GitHashAlgorithm::Sha1, incarnation())
            .is_ok()
    );
    full.push_str("&entry=1025");
    assert!(
        request
            .command(full.as_bytes(), GitHashAlgorithm::Sha1, incarnation())
            .is_err()
    );
}

#[test]
fn raw_branch_bytes_have_one_lossless_encoding_and_do_not_normalize() {
    let body = form(GitHashAlgorithm::Sha1).replace(
        "source_ref=refs%2Fheads%2Ftopic",
        "source_ref_hex=726566732f68656164732fff",
    );
    let bytes = wire("POST", "/1/enqueue", body.len());
    let request = parse(&bytes).unwrap();
    let command = request
        .command(body.as_bytes(), GitHashAlgorithm::Sha1, incarnation())
        .unwrap();
    let QueueCommandAction::Enqueue { source_ref, .. } = command.action else {
        panic!()
    };
    assert_eq!(source_ref.as_bytes(), b"refs/heads/\xff");
    for bad in ["726566732F68656164732fff", "726", "zz"] {
        assert!(
            request
                .command(
                    body.replace("726566732f68656164732fff", bad).as_bytes(),
                    GitHashAlgorithm::Sha1,
                    incarnation()
                )
                .is_err()
        );
    }
}

#[test]
fn request_routes_pages_and_body_envelopes_are_closed() {
    assert!(parse(&wire("GET", "", 0)).is_ok());
    assert!(parse(&wire("GET", "/1", 0)).is_ok());
    for suffix in [
        "?after=1",
        "?limit=0",
        "?limit=101",
        "?render=html_safe",
        "/0",
        "/01",
        "/1?principal=someone",
        "foo",
    ] {
        assert!(parse(&wire("GET", suffix, 0)).is_err(), "{suffix}");
    }
    assert!(parse(&wire("POST", "/1/land", 1)).unwrap().is_landing());
    for suffix in [
        "/1/batch",
        "/1/land/extra",
        "/1/land?expected_version=1",
        "/1/enqueue?expected_version=0",
        "",
    ] {
        assert!(parse(&wire("POST", suffix, 1)).is_err(), "{suffix}");
    }
    assert!(parse(&wire("POST", "/1/enqueue", 0)).is_err());
    assert!(parse(&wire("POST", "/1/enqueue", MAX_COMMAND_BYTES + 1)).is_err());
    assert!(parse(&wire("DELETE", "/1", 0)).is_err());
    assert!(
        parse(&wire("GET", "/1", 0).replace("Host: local", "Host: local\r\nContent-Length: 1"))
            .is_err()
    );
    assert!(
        parse(&wire("GET", "/1", 0).replace("Host: local", "Host: local\r\nExpect: 100-continue"))
            .is_err()
    );
}

#[test]
fn landing_keeps_exact_guards_in_both_hash_domains_and_accepts_only_native_fast_forward_intent() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let body = format!(
            "{}&expected_policy_epoch=2",
            form(format).replace("expected_version=0", "expected_version=4")
        );
        let bytes = wire("POST", "/1/land", body.len());
        let request = parse(&bytes).unwrap();
        assert!(request.is_mutation() && request.is_landing());
        assert!(
            request
                .command(body.as_bytes(), format, incarnation())
                .is_err()
        );
        let command = request
            .landing_command(body.as_bytes(), format, incarnation())
            .unwrap();
        assert_eq!(command.number, QueueNumber::FIRST);
        assert_eq!(command.expected_version.get(), 4);
        assert_eq!(command.expected_pull_request_version.get(), 3);
        assert_eq!(command.expected_policy_epoch.get(), 2);
        assert_eq!(command.pull_request.get(), 7);
        assert_eq!(command.head_tip.algorithm(), format);
        assert_eq!(command.expected_target_tip.algorithm(), format);
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
            "expected_target_tip",
        ] {
            let missing = body
                .split('&')
                .filter(|field| !field.starts_with(&format!("{required}=")))
                .collect::<Vec<_>>()
                .join("&");
            assert!(
                request
                    .landing_command(missing.as_bytes(), format, incarnation())
                    .is_err(),
                "missing {required}"
            );
        }
        for (before, after) in [
            ("expected_version=4", "expected_version=0"),
            ("expected_version=4", "expected_version=04"),
            (
                "expected_version=4",
                "expected_version=18446744073709551614",
            ),
            (
                "expected_version=4",
                "expected_version=18446744073709551615",
            ),
            (
                "expected_pull_request_version=3",
                "expected_pull_request_version=0",
            ),
            (
                "expected_pull_request_version=3",
                "expected_pull_request_version=18446744073709551615",
            ),
            ("expected_policy_epoch=2", "expected_policy_epoch=0"),
            ("pull_request=7", "pull_request=0"),
            ("refs%2Fheads%2Ftopic", "refs%2Fheads%2Fmain"),
            ("refs%2Fheads%2Ftopic", "refs%2Ftags%2Ftopic"),
        ] {
            assert!(
                request
                    .landing_command(
                        body.replace(before, after).as_bytes(),
                        format,
                        incarnation()
                    )
                    .is_err(),
                "accepted {after}"
            );
        }
        for suffix in [
            "priority=0",
            "entry=7",
            "reason=admin-override",
            "method=merge-commit",
            "force=true",
            "principal=attacker",
            "trusted_local=true",
            "expected_policy_epoch=2",
            "source_ref_hex=726566732f68656164732f746f706963",
            "checks_passed=true",
        ] {
            assert!(
                request
                    .landing_command(format!("{body}&{suffix}").as_bytes(), format, incarnation())
                    .is_err(),
                "accepted {suffix}"
            );
        }
        let equal = body.replace(
            &"aa".repeat(format.digest_len()),
            &"bb".repeat(format.digest_len()),
        );
        assert_eq!(
            request
                .landing_command(equal.as_bytes(), format, incarnation())
                .unwrap_err()
                .code,
            "invalid_queue_command"
        );
        let malformed = body.replace(
            &"aa".repeat(format.digest_len()),
            &"00".repeat(format.digest_len()),
        );
        assert!(
            request
                .landing_command(malformed.as_bytes(), format, incarnation())
                .is_err()
        );
        assert_eq!(
            request
                .landing_command(
                    body.as_bytes(),
                    format,
                    RepositoryIncarnationId::from_bytes([9; 16])
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
            request
                .landing_command(body.as_bytes(), other, incarnation())
                .unwrap_err()
                .code,
            "object_format_mismatch"
        );
        let raw = body.replace(
            "source_ref=refs%2Fheads%2Ftopic",
            "source_ref_hex=726566732f68656164732fff",
        );
        assert_eq!(
            request
                .landing_command(raw.as_bytes(), format, incarnation())
                .unwrap()
                .source_ref
                .as_bytes(),
            b"refs/heads/\xff"
        );
        assert!(
            request
                .landing_command(&vec![b'a'; MAX_COMMAND_BYTES + 1], format, incarnation())
                .is_err()
        );
    }
}
