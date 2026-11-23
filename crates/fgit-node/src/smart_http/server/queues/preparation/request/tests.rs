use super::*;

fn incarnation() -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([7; 16])
}

fn form(format: GitHashAlgorithm) -> String {
    format!(
        concat!(
            "expected_incarnation={}&object_format={}&expected_version=7",
            "&pull_request=3&expected_pull_request_version=5&expected_policy_epoch=11",
            "&source_ref=refs/heads/topic&target_ref=refs/heads/main",
            "&expected_source_tip={}&expected_target_tip={}",
            "&author=Alice+%3Ca%40example.invalid%3E&committer=Bot+%3Cb%40example.invalid%3E",
            "&timestamp=17&message=Exact+%F0%9F%A6%80%0A%252f"
        ),
        incarnation(),
        format.as_str(),
        "ab".repeat(format.digest_len()),
        "cd".repeat(format.digest_len()),
    )
}

#[test]
fn original_queue_and_pull_guards_and_deterministic_metadata_survive_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let bytes = form(format);
        let command = parse(bytes.as_bytes(), format, incarnation()).unwrap();
        assert_eq!(command.expected_version.get(), 7);
        assert_eq!(command.subject.pull_request.get(), 3);
        assert_eq!(command.subject.pull_request_version.get(), 5);
        assert_eq!(command.subject.policy_epoch.get(), 11);
        assert_eq!(command.subject.source_tip.algorithm(), format);
        assert_eq!(command.metadata.author, "Alice <a@example.invalid>");
        assert_eq!(command.metadata.committer, "Bot <b@example.invalid>");
        assert_eq!(command.metadata.timestamp, 17);
        assert_eq!(command.metadata.message, "Exact 🦀\n%2f".as_bytes());
        assert_eq!(command.profile, MergeProfile::PathMergeV1);
        assert_eq!(
            parse(bytes.as_bytes(), format, incarnation()).unwrap(),
            command
        );
        let selected = parse(
            format!("{bytes}&method=merge-commit&profile=exact-renames-v1").as_bytes(),
            format,
            incarnation(),
        )
        .unwrap();
        assert_eq!(selected.profile, MergeProfile::ExactRenamesV1);
        assert_eq!(selected.subject, command.subject);
        assert_eq!(selected.metadata, command.metadata);
    }
}

#[test]
fn builtin_attributes_selection_keeps_exact_queue_and_pull_coordinates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let bytes = form(format);
        let mut expected = parse(bytes.as_bytes(), format, incarnation()).unwrap();
        expected.profile = MergeProfile::BuiltinAttributesV1;
        let selected = parse(
            format!("{bytes}&profile=builtin-attributes-v1").as_bytes(),
            format,
            incarnation(),
        )
        .unwrap();
        assert_eq!(selected, expected);
        assert!(
            parse(
                format!("{bytes}&profile=builtin-attributes-v1&method=squash").as_bytes(),
                format,
                incarnation(),
            )
            .is_err()
        );
    }
}

#[test]
fn byte_refs_and_non_utf8_messages_are_lossless_and_exclusively_encoded() {
    let valid = form(GitHashAlgorithm::Sha256)
        .replace(
            "source_ref=refs/heads/topic",
            "source_ref_hex=726566732f68656164732fff",
        )
        .replace(
            "message=Exact+%F0%9F%A6%80%0A%252f",
            "message_hex=fffe0a2526",
        );
    let command = parse(valid.as_bytes(), GitHashAlgorithm::Sha256, incarnation()).unwrap();
    assert_eq!(command.subject.source_ref.as_bytes(), b"refs/heads/\xff");
    assert_eq!(command.metadata.message, b"\xff\xfe\n%&");
    for input in [
        format!("{valid}&source_ref=refs/heads/topic"),
        format!("{valid}&message=duplicate"),
        valid.replace("message_hex=fffe0a2526", "message_hex=FF"),
        valid.replace("message_hex=fffe0a2526", "message_hex=f"),
        valid.replace("message_hex=fffe0a2526", "message_hex="),
        valid.replace("message_hex=fffe0a2526", "message_hex=00"),
        valid.replace(
            "source_ref_hex=726566732f68656164732fff",
            "source_ref=topic",
        ),
        valid.replace(
            "source_ref_hex=726566732f68656164732fff",
            "source_ref=refs/tags/v1",
        ),
    ] {
        assert!(parse(input.as_bytes(), GitHashAlgorithm::Sha256, incarnation()).is_err());
    }
}

#[test]
fn missing_guards_overrides_stale_incarnation_and_unsupported_methods_fail_before_native_reads() {
    let valid = form(GitHashAlgorithm::Sha1);
    for field in [
        "expected_incarnation",
        "object_format",
        "expected_version",
        "pull_request",
        "expected_pull_request_version",
        "expected_policy_epoch",
        "source_ref",
        "target_ref",
        "expected_source_tip",
        "expected_target_tip",
        "author",
        "committer",
        "timestamp",
        "message",
    ] {
        let missing = valid
            .split('&')
            .filter(|part| !part.starts_with(&format!("{field}=")))
            .collect::<Vec<_>>()
            .join("&");
        assert!(
            parse(missing.as_bytes(), GitHashAlgorithm::Sha1, incarnation()).is_err(),
            "{field}"
        );
    }
    for suffix in [
        "actor=forged",
        "principal=forged",
        "expected_head=forged",
        "idempotency_key=forged",
        "checks=passed",
        "candidate_commit=forged",
        "merge_base=forged",
        "expected_version=7",
        "method=squash",
        "method=fast-forward",
        "profile=rename-similarity-v1",
    ] {
        assert!(
            parse(
                format!("{valid}&{suffix}").as_bytes(),
                GitHashAlgorithm::Sha1,
                incarnation()
            )
            .is_err(),
            "{suffix}"
        );
    }
    for (before, after) in [
        ("expected_version=7", "expected_version=0"),
        (
            "expected_version=7",
            "expected_version=18446744073709551614",
        ),
        (
            "expected_pull_request_version=5",
            "expected_pull_request_version=0",
        ),
        (
            "expected_pull_request_version=5",
            "expected_pull_request_version=18446744073709551615",
        ),
        ("expected_policy_epoch=11", "expected_policy_epoch=0"),
        ("pull_request=3", "pull_request=03"),
        ("timestamp=17", "timestamp=0"),
        ("timestamp=17", "timestamp=017"),
        ("timestamp=17", "timestamp=9223372036854775808"),
        ("author=Alice", "author=Alice%0Aparent+injected"),
        ("source_ref=refs/heads/topic", "source_ref=refs/heads/main"),
        ("object_format=sha1", "object_format=sha256"),
    ] {
        assert!(
            parse(
                valid.replace(before, after).as_bytes(),
                GitHashAlgorithm::Sha1,
                incarnation()
            )
            .is_err(),
            "{after}"
        );
    }
    assert!(
        parse(
            valid.as_bytes(),
            GitHashAlgorithm::Sha1,
            RepositoryIncarnationId::from_bytes([8; 16])
        )
        .is_err()
    );
    let null_oid = valid.replace(&"ab".repeat(20), &"00".repeat(20));
    assert!(parse(null_oid.as_bytes(), GitHashAlgorithm::Sha1, incarnation()).is_err());
}

#[test]
fn full_native_message_bound_fits_hex_form_and_allocation_bounds_are_closed() {
    let valid = form(GitHashAlgorithm::Sha1);
    let input = valid.replace(
        "message=Exact+%F0%9F%A6%80%0A%252f",
        &format!("message_hex={}", "ff".repeat(MAX_MESSAGE_BYTES)),
    );
    assert!(input.len() < MAX_COMMAND_BYTES);
    let command = parse(input.as_bytes(), GitHashAlgorithm::Sha1, incarnation()).unwrap();
    assert_eq!(command.metadata.message.len(), MAX_MESSAGE_BYTES);
    assert!(command.metadata.message.iter().all(|byte| *byte == 255));
    assert!(
        parse(
            format!("{input}ff").as_bytes(),
            GitHashAlgorithm::Sha1,
            incarnation()
        )
        .is_err()
    );
    assert!(
        parse(
            &vec![b'x'; MAX_COMMAND_BYTES + 1],
            GitHashAlgorithm::Sha1,
            incarnation()
        )
        .is_err()
    );
    let long_author = valid.replace("author=Alice", &format!("author={}", "x".repeat(1025)));
    assert!(
        parse(
            long_author.as_bytes(),
            GitHashAlgorithm::Sha1,
            incarnation()
        )
        .is_err()
    );
    let long_ref = valid.replace(
        "source_ref=refs/heads/topic",
        &format!("source_ref=refs/heads/{}", "x".repeat(1024)),
    );
    assert!(parse(long_ref.as_bytes(), GitHashAlgorithm::Sha1, incarnation()).is_err());
}
