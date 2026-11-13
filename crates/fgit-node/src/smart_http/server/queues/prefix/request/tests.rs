use super::*;

fn incarnation() -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([7; 16])
}
fn form(format: GitHashAlgorithm, count: usize) -> String {
    let mut body = format!(
        concat!(
            "expected_incarnation={}&object_format={}&expected_version=7&expected_policy_epoch=11",
            "&target_ref=refs/heads/main&expected_target_tip={}&entry_count={}",
            "&author=Alice+%3Ca%40example.invalid%3E&committer=Bot+%3Cb%40example.invalid%3E",
            "&timestamp=17&message=Exact+%F0%9F%A6%80%0A%252f"
        ),
        incarnation(),
        format.as_str(),
        "cd".repeat(format.digest_len()),
        count,
    );
    for index in 0..count {
        body.push_str(&format!(
            "&pull_request_{index}={}&expected_pull_request_version_{index}=5&source_ref_{index}=refs/heads/topic-{index}&expected_source_tip_{index}={}",
            index + 1, format!("{:02x}", index + 1).repeat(format.digest_len()),
        ));
    }
    body
}

#[test]
fn ordered_original_subjects_keep_one_common_target_policy_and_explicit_metadata() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let bytes = form(format, 2);
        let command = parse(bytes.as_bytes(), format, incarnation()).unwrap();
        assert_eq!(command.expected_version.get(), 7);
        assert_eq!(command.profile, MergeProfile::PathMergeV1);
        assert_eq!(command.entries.len(), 2);
        for (index, entry) in command.entries.iter().enumerate() {
            assert_eq!(entry.subject.pull_request.get(), index as u64 + 1);
            assert_eq!(entry.subject.pull_request_version.get(), 5);
            assert_eq!(entry.subject.policy_epoch.get(), 11);
            assert_eq!(entry.subject.target_ref.as_bytes(), b"refs/heads/main");
            assert_eq!(
                entry.subject.target_tip.to_string(),
                "cd".repeat(format.digest_len())
            );
            assert_eq!(entry.subject.source_tip.algorithm(), format);
            assert_eq!(entry.metadata.author, "Alice <a@example.invalid>");
            assert_eq!(entry.metadata.message, "Exact 🦀\n%2f".as_bytes());
            assert_eq!(entry.metadata.timestamp, 17);
        }
        let explicit = parse(
            format!("{bytes}&profile=exact-renames-v1&method=merge-commit").as_bytes(),
            format,
            incarnation(),
        )
        .unwrap();
        assert_eq!(explicit.entries, command.entries);
        assert_eq!(explicit.profile, MergeProfile::ExactRenamesV1);
        // This is a read proposal, not the single-head landing template. It
        // does not reserve or require any future aggregate version.
        assert!(
            parse(
                bytes
                    .replace(
                        "expected_version=7",
                        "expected_version=18446744073709551615"
                    )
                    .as_bytes(),
                format,
                incarnation()
            )
            .is_ok()
        );
    }
}

#[test]
fn builtin_attributes_profile_applies_to_the_exact_ordered_prefix() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let bytes = form(format, 2);
        let mut expected = parse(bytes.as_bytes(), format, incarnation()).unwrap();
        expected.profile = MergeProfile::BuiltinAttributesV1;
        let selected = parse(
            format!("{bytes}&profile=builtin-attributes-v1").as_bytes(),
            format,
            incarnation(),
        )
        .unwrap();
        assert_eq!(selected, expected);
    }
}

#[test]
fn exact_consuming_grammar_refuses_missing_extra_aliased_and_duplicate_members() {
    let valid = form(GitHashAlgorithm::Sha1, 2);
    for field in valid.split('&').map(|part| part.split_once('=').unwrap().0) {
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
    for extra in [
        "actor=forged",
        "principal=forged",
        "checks=passed",
        "idempotency_key=forged",
        "expected_head=forged",
        "candidate_commit=forged",
        "projected_target_tip_1=forged",
        "entry_count=2",
        "pull_request_0=1",
        "pull_request_00=1",
        "pull_request_%2B0=1",
        "pull_request_2=3",
        "source_ref_hex_0=726566732f68656164732fff",
        "target_ref_hex=726566732f68656164732fff",
        "message_hex=ff",
        "author_0=someone",
        "method=squash",
        "method=fast-forward",
        "profile=similarity-renames",
    ] {
        assert!(
            parse(
                format!("{valid}&{extra}").as_bytes(),
                GitHashAlgorithm::Sha1,
                incarnation()
            )
            .is_err(),
            "{extra}"
        );
    }
    for (before, after) in [
        ("entry_count=2", "entry_count=0"),
        ("entry_count=2", "entry_count=02"),
        ("entry_count=2", "entry_count=17"),
        ("pull_request_1=2", "pull_request_1=1"),
        ("pull_request_0=1", "pull_request_00=1"),
        ("pull_request_0=1", "pull_request_0=0"),
        ("expected_version=7", "expected_version=0"),
        ("expected_policy_epoch=11", "expected_policy_epoch=0"),
        (
            "expected_pull_request_version_1=5",
            "expected_pull_request_version_1=0",
        ),
        (
            "source_ref_1=refs/heads/topic-1",
            "source_ref_1=refs/heads/main",
        ),
        (
            "source_ref_1=refs/heads/topic-1",
            "source_ref_1=refs/tags/topic-1",
        ),
        ("timestamp=17", "timestamp=0"),
        ("timestamp=17", "timestamp=017"),
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
    assert!(
        parse(
            valid.replace(&"01".repeat(20), &"00".repeat(20)).as_bytes(),
            GitHashAlgorithm::Sha1,
            incarnation()
        )
        .is_err()
    );
}

#[test]
fn raw_reference_and_message_bytes_remain_exact_and_strictly_bounded() {
    let raw = form(GitHashAlgorithm::Sha256, MAX_PREFIX_ENTRIES)
        .replace(
            "source_ref_0=refs/heads/topic-0",
            "source_ref_hex_0=726566732f68656164732fff",
        )
        .replace(
            "message=Exact+%F0%9F%A6%80%0A%252f",
            &format!("message_hex={}", "ff".repeat(common::MAX_MESSAGE_BYTES)),
        );
    let command = parse(raw.as_bytes(), GitHashAlgorithm::Sha256, incarnation()).unwrap();
    assert_eq!(command.entries.len(), MAX_PREFIX_ENTRIES);
    assert_eq!(
        command.entries[0].subject.source_ref.as_bytes(),
        b"refs/heads/\xff"
    );
    assert!(
        command
            .entries
            .iter()
            .all(|entry| entry.metadata.message == vec![255; common::MAX_MESSAGE_BYTES])
    );
    assert!(raw.len() < MAX_COMMAND_BYTES);
    assert!(
        parse(
            raw.replace("message_hex=", "message_hex=ff").as_bytes(),
            GitHashAlgorithm::Sha256,
            incarnation()
        )
        .is_err()
    );
    for invalid in ["FF", "f", "", "00"] {
        let bytes = form(GitHashAlgorithm::Sha256, 1).replace(
            "message=Exact+%F0%9F%A6%80%0A%252f",
            &format!("message_hex={invalid}"),
        );
        assert!(parse(bytes.as_bytes(), GitHashAlgorithm::Sha256, incarnation()).is_err());
    }
    assert!(
        parse(
            &vec![b'x'; MAX_COMMAND_BYTES + 1],
            GitHashAlgorithm::Sha1,
            incarnation()
        )
        .is_err()
    );
}
