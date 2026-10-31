use super::*;
use crate::smart_http::server::pulls;
use std::io::Cursor;

fn candidate_form(format: GitHashAlgorithm) -> String {
    format!(
        "{}&expected_policy_epoch=2&merge_base={}&expected_commit={}",
        form(format).replace("expected_version=0", "expected_version=4"),
        "cc".repeat(format.digest_len()),
        "dd".repeat(format.digest_len()),
    )
}
fn candidate_head(bytes: usize) -> String {
    wire("POST", "/1/land-candidate", bytes).replace(
        "Content-Type: application/x-www-form-urlencoded",
        "Content-Type: multipart/form-data; boundary=queue-candidate",
    )
}
fn part(name: &str, media: &str, bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("--queue-candidate\r\nContent-Disposition: form-data; name=\"{name}\"\r\nContent-Type: {media}\r\n\r\n").into_bytes();
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
    out
}
fn upload(command: &[u8], bundle: Option<&[u8]>, reverse: bool, media: &str) -> Vec<u8> {
    let metadata = part("command", "application/x-www-form-urlencoded", command);
    let bundle = bundle
        .map(|bytes| part("bundle", media, bytes))
        .unwrap_or_default();
    let mut bytes = if reverse {
        [bundle, metadata].concat()
    } else {
        [metadata, bundle].concat()
    };
    bytes.extend_from_slice(b"--queue-candidate--\r\n");
    bytes
}

#[test]
fn candidate_metadata_binds_every_coordinate_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let body = candidate_form(format);
        let head = candidate_head(body.len());
        let request = parse(&head).unwrap();
        assert!(request.is_mutation() && request.is_landing());
        let command = request
            .candidate_landing_command(body.as_bytes(), format, incarnation())
            .unwrap();
        assert_eq!(command.number, QueueNumber::FIRST);
        assert_eq!(command.expected_version.get(), 4);
        assert_eq!(command.expected_pull_request_version.get(), 3);
        assert_eq!(command.expected_policy_epoch.get(), 2);
        assert_eq!(command.pull_request.get(), 7);
        assert_eq!(
            command.merge.base_tip.to_string(),
            "cc".repeat(format.digest_len())
        );
        assert_eq!(
            command.merge.merge_commit.to_string(),
            "dd".repeat(format.digest_len())
        );
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
            "merge_base",
            "expected_commit",
        ] {
            let missing = body
                .split('&')
                .filter(|field| !field.starts_with(&format!("{required}=")))
                .collect::<Vec<_>>()
                .join("&");
            assert!(
                request
                    .candidate_landing_command(missing.as_bytes(), format, incarnation())
                    .is_err(),
                "missing {required}"
            );
        }
        assert!(
            request
                .landing_command(body.as_bytes(), format, incarnation())
                .is_err()
        );
        assert!(
            request
                .command(body.as_bytes(), format, incarnation())
                .is_err()
        );
        assert_eq!(
            request
                .candidate_landing_command(
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
                .candidate_landing_command(body.as_bytes(), other, incarnation())
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
                .candidate_landing_command(raw.as_bytes(), format, incarnation())
                .unwrap()
                .merge
                .source_ref
                .as_bytes(),
            b"refs/heads/\xff"
        );
    }
}

#[test]
fn candidate_profile_rejects_method_identity_fake_evidence_and_invalid_guards() {
    let format = GitHashAlgorithm::Sha1;
    let body = candidate_form(format);
    let head = candidate_head(body.len());
    let request = parse(&head).unwrap();
    for field in [
        "method=merge-commit",
        "method=fast-forward-only",
        "actor=attacker",
        "principal=attacker",
        "trusted_local=true",
        "force=true",
        "checks_passed=true",
        "required_reviewer=attacker",
        "expected_commit=aa",
        "source_ref_hex=726566732f68656164732f746f706963",
        "entry=7",
    ] {
        assert!(
            request
                .candidate_landing_command(
                    format!("{body}&{field}").as_bytes(),
                    format,
                    incarnation()
                )
                .is_err(),
            "{field}"
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
                .candidate_landing_command(
                    body.replace(before, after).as_bytes(),
                    format,
                    incarnation()
                )
                .is_err(),
            "{after}"
        );
    }
    for candidate in ["aa", "bb", "cc", "00", "DD"] {
        let changed = body.replace(&"dd".repeat(20), &candidate.repeat(20));
        assert!(
            request
                .candidate_landing_command(changed.as_bytes(), format, incarnation())
                .is_err(),
            "candidate {candidate}"
        );
    }
    let equal_tips = body.replace(&"aa".repeat(20), &"bb".repeat(20));
    assert_eq!(
        request
            .candidate_landing_command(equal_tips.as_bytes(), format, incarnation())
            .unwrap_err()
            .code,
        "invalid_queue_command"
    );
    assert_eq!(
        request
            .candidate_landing_command(&vec![b'x'; MAX_COMMAND_BYTES + 1], format, incarnation())
            .unwrap_err()
            .code,
        "resource_limit"
    );
}

#[test]
fn candidate_envelope_is_multipart_only_and_retains_shared_upload_limits() {
    assert!(parse(&candidate_head(1)).is_ok());
    assert!(parse(&candidate_head(pulls::CANDIDATE_UPLOAD_BYTES)).is_ok());
    for header in [
        candidate_head(0),
        candidate_head(pulls::CANDIDATE_UPLOAD_BYTES + 1),
        wire("POST", "/1/land-candidate", 1),
        candidate_head(1).replace("/land-candidate", "/land-candidate?expected_version=4"),
        candidate_head(1).replace("/land-candidate", "/land-candidate/extra"),
        candidate_head(1).replace("boundary=queue-candidate", "boundary=bad boundary"),
        candidate_head(1).replace("Host: local", "Host: local\r\nGit-Protocol: version=2"),
    ] {
        assert!(parse(&header).is_err(), "{header}");
    }
    let chunked = candidate_head(1).replace("Content-Length: 1", "Transfer-Encoding: chunked");
    assert!(parse(&chunked).is_ok());
}

#[test]
fn shared_upload_keeps_binary_bytes_part_order_and_optional_bundle_recovery() {
    let command = candidate_form(GitHashAlgorithm::Sha1);
    let binary = b"PACK\0\xff\r\n--queue-candidateX\0";
    for media in ["application/x-git-bundle", "application/octet-stream"] {
        for reverse in [false, true] {
            for bundle in [None, Some(b"".as_slice()), Some(binary.as_slice())] {
                let bytes = upload(command.as_bytes(), bundle, reverse, media);
                let decoded = pulls::read_candidate_upload(
                    &mut Cursor::new(&bytes),
                    BodyFraming::ContentLength(bytes.len() as u64),
                    HttpLimits::default(),
                )
                .unwrap();
                let (metadata, actual) =
                    pulls::candidate_upload(&decoded, "queue-candidate", &mut || true).unwrap();
                assert_eq!(metadata, command.as_bytes());
                assert_eq!(actual, bundle);
            }
        }
    }
    let bytes = upload(
        command.as_bytes(),
        Some(binary),
        false,
        "application/x-git-bundle",
    );
    assert_eq!(
        pulls::candidate_upload(&bytes, "queue-candidate", &mut || false)
            .unwrap_err()
            .status,
        Status::Timeout
    );
    let mut extra = part("actor", "text/plain", b"attacker");
    extra.extend_from_slice(&bytes);
    assert!(pulls::candidate_upload(&extra, "queue-candidate", &mut || true).is_err());
    let mut duplicate = part(
        "command",
        "application/x-www-form-urlencoded",
        command.as_bytes(),
    );
    duplicate.extend_from_slice(&bytes);
    assert!(pulls::candidate_upload(&duplicate, "queue-candidate", &mut || true).is_err());
    let mut suffix = bytes.clone();
    suffix.extend_from_slice(b"unframed suffix");
    assert!(
        pulls::read_candidate_upload(
            &mut Cursor::new(suffix),
            BodyFraming::ContentLength(bytes.len() as u64),
            HttpLimits::default()
        )
        .is_err()
    );
    assert!(
        pulls::read_candidate_upload(
            &mut Cursor::new(&bytes[..bytes.len() - 1]),
            BodyFraming::ContentLength(bytes.len() as u64),
            HttpLimits::default()
        )
        .is_err()
    );
}
