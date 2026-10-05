use super::*;
use fgit_wire::smart_http::head;
use std::io::Cursor;

fn request() -> Request<'static> {
    Request {
        repository_route: "/repo.git",
        number: PullRequestNumber::FIRST,
    }
}

fn fields(format: GitHashAlgorithm) -> String {
    format!(
        "object_format={}&pull_request_version=1&source_ref=refs%2Fheads%2Ftopic&source_tip={}&target_ref=refs%2Fheads%2Fmain&target_tip={}",
        format.as_str(),
        "a".repeat(format.digest_len() * 2),
        "b".repeat(format.digest_len() * 2)
    )
}

#[test]
fn exact_coordinates_are_preserved_in_both_native_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let command = request()
            .command(fields(format).as_bytes(), format)
            .unwrap();
        assert_eq!(command.version, AggregateVersion::FIRST);
        assert_eq!(command.source_ref.as_bytes(), b"refs/heads/topic");
        assert_eq!(command.target_ref.as_bytes(), b"refs/heads/main");
        assert_eq!(
            command.source_tip,
            GitOid::from_hex(format, &"a".repeat(format.digest_len() * 2)).unwrap()
        );
        assert_eq!(
            command.target_tip,
            GitOid::from_hex(format, &"b".repeat(format.digest_len() * 2)).unwrap()
        );
    }
}

#[test]
fn unknown_duplicate_missing_and_inapplicable_fields_never_reach_admission() {
    let base = fields(GitHashAlgorithm::Sha1);
    for replacement in [
        "principal_id=admin",
        "force=true",
        "candidate_commit=abc",
        "required_reviewer=abc",
        "policy_epoch=1",
        "object_format=sha1",
        "",
    ] {
        let body = base.replace("pull_request_version=1", replacement);
        assert!(
            request()
                .command(body.as_bytes(), GitHashAlgorithm::Sha1)
                .is_err()
        );
    }
    assert!(
        request()
            .command(base.as_bytes(), GitHashAlgorithm::Sha1)
            .is_ok()
    );
}

#[test]
fn invalid_versions_refs_and_tips_refuse_without_refresh_or_format_inference() {
    let base = fields(GitHashAlgorithm::Sha1);
    for (old, new) in [
        ("pull_request_version=1", "pull_request_version=0"),
        (
            "pull_request_version=1",
            "pull_request_version=18446744073709551615",
        ),
        ("object_format=sha1", "object_format=sha256"),
        ("refs%2Fheads%2Ftopic", "refs%2Fheads%2Fmain"),
        ("refs%2Fheads%2Ftopic", "refs%2Fheads%2F.."),
    ] {
        assert!(
            request()
                .command(base.replace(old, new).as_bytes(), GitHashAlgorithm::Sha1)
                .is_err()
        );
    }
    for replacement in [
        "0".repeat(40),
        "A".repeat(40),
        "a".repeat(64),
        "b".repeat(40),
    ] {
        let body = base.replace(&"a".repeat(40), &replacement);
        assert!(
            request()
                .command(body.as_bytes(), GitHashAlgorithm::Sha1)
                .is_err()
        );
    }
}

#[test]
fn route_is_a_body_bearing_mutation_and_never_accepts_a_bundle() {
    let form = "application/x-www-form-urlencoded";
    let path = "1/fast-forward";
    for (method, suffix, media, length, error_code) in [
        ("POST", path, form, 1, None),
        ("GET", path, form, 1, Some("method_not_allowed")),
        (
            "POST",
            "1/fast-forward?force=1",
            form,
            1,
            Some("invalid_mutation_envelope"),
        ),
        (
            "POST",
            path,
            "multipart/form-data; boundary=x",
            1,
            Some("unsupported_media_type"),
        ),
        (
            "POST",
            "0/fast-forward",
            form,
            1,
            Some("invalid_pull_request_number"),
        ),
        ("POST", path, form, 0, Some("invalid_mutation_envelope")),
        ("POST", path, form, 8193, Some("resource_limit")),
    ] {
        let bytes = format!(
            "{method} /repo.git/api/v1/pulls/{suffix} HTTP/1.1\r\nHost: local\r\nContent-Type: {media}\r\nContent-Length: {length}\r\n\r\n"
        );
        let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let result = super::super::Request::parse(&envelope);
        if let Some(code) = error_code {
            assert_eq!(result.unwrap_err().code, code);
        } else {
            let routed = result.unwrap().unwrap();
            assert!(matches!(routed, super::super::Request::FastForward(_)));
            assert!(routed.is_mutation());
            assert!(routed.accepts_body());
        }
    }
}

#[test]
fn chunked_intake_obeys_the_same_small_envelope_and_complete_boundary() {
    let body = fields(GitHashAlgorithm::Sha1);
    let framed = format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len());
    let limits = ingress_limits(HttpLimits::default());
    assert_eq!(
        read_form(
            &mut Cursor::new(framed.as_bytes()),
            BodyFraming::Chunked,
            limits
        )
        .unwrap(),
        body.as_bytes()
    );
    for bad in [
        format!("2001\r\n{}\r\n0\r\n\r\n", "a".repeat(8193)),
        format!("{framed}NEXT"),
        format!("{:x}\r\n{body}\r\n0\r\n", body.len()),
    ] {
        assert!(
            read_form(
                &mut Cursor::new(bad.as_bytes()),
                BodyFraming::Chunked,
                ingress_limits(HttpLimits::default())
            )
            .is_err()
        );
    }
    assert_eq!(
        request()
            .command(&vec![b'a'; 8193], GitHashAlgorithm::Sha1)
            .unwrap_err()
            .code,
        "resource_limit"
    );
}
