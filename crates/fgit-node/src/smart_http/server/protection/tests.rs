//! Hostile-input and canonicalization regressions for the HTTP protection
//! adapter. Real TCP authorization, publication, recovery, and restart coverage
//! lives in tests/protection_http.rs.

use super::*;
use fgit_wire::smart_http::head;

fn person(byte: u8) -> String {
    PrincipalId::from_bytes([byte; 16]).to_string()
}

fn form() -> String {
    format!(
        "expected_version=1&expected_epoch=2&administrator={}&required_reviewer={}:{}",
        person(1),
        hex(b"refs/heads/main"),
        person(2)
    )
}

fn request(
    method: &str,
    suffix: &str,
    headers: &str,
) -> Result<(bool, Option<RepositoryAuthorityHeadId>), ApiError> {
    let bytes = format!(
        "{method} /repo.git/api/v1/protection{suffix} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
    );
    let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let request = Request::parse(&envelope)?;
    assert_eq!(request.repository_route, "/repo.git");
    Ok((request.is_mutation(), request.expected_head))
}

#[test]
fn canonical_replacements_sort_principals_and_raw_references_without_changing_coordinates() {
    let main = hex(b"refs/heads/main");
    let topic = hex(b"refs/heads/topic");
    let body = format!(
        concat!(
            "expected_version=7&expected_epoch=19&administrator={}&administrator={}",
            "&required_reviewer={}:{}&required_reviewer={}:{}&required_reviewer={}:{}"
        ),
        person(3),
        person(1),
        topic,
        person(4),
        main,
        person(3),
        main,
        person(2)
    );
    let command = parse_command(body.as_bytes()).unwrap();
    assert_eq!(
        command.expected_version,
        ExpectedVersion::Exactly(AggregateVersion::try_new(7).unwrap())
    );
    assert_eq!(command.expected_epoch.get(), 19);
    assert_eq!(
        command.protection.administrators,
        [
            PrincipalId::from_bytes([1; 16]),
            PrincipalId::from_bytes([3; 16])
        ]
    );
    assert_eq!(command.protection.branches[0].name.as_bytes(), b"refs/heads/main");
    assert_eq!(command.protection.branches[1].name.as_bytes(), b"refs/heads/topic");
    assert_eq!(
        command.protection.branches[0].reviewers,
        [
            PrincipalId::from_bytes([2; 16]),
            PrincipalId::from_bytes([3; 16])
        ]
    );
    command.protection.validate().unwrap();

    let reordered = body.split('&').rev().collect::<Vec<_>>().join("&");
    assert_eq!(parse_command(reordered.as_bytes()).unwrap(), command);
}

#[test]
fn duplicate_ownership_reviewers_and_scalar_fields_cannot_hide_in_a_replacement() {
    let good = form();
    for extra in [
        format!("&administrator={}", person(1)),
        format!("&required_reviewer={}:{}", hex(b"refs/heads/main"), person(2)),
        "&expected_version=1".to_owned(),
        "&expected_epoch=2".to_owned(),
        "&principal_id=admin".to_owned(),
        "&actor=admin".to_owned(),
        "&administrator_override=true".to_owned(),
        "&expected_head=anything".to_owned(),
    ] {
        let body = good.clone() + &extra;
        assert!(parse_command(body.as_bytes()).is_err(), "{extra}");
    }
    let duplicate_clear = format!(
        "expected_version=1&expected_epoch=2&administrator={}&clear=true&clear=true",
        person(1)
    );
    assert_eq!(
        parse_command(duplicate_clear.as_bytes()).unwrap_err().code,
        "duplicate_field"
    );
}

#[test]
fn disabling_is_explicit_and_retains_a_nonempty_canonical_owner_set() {
    let body = format!(
        "expected_version=1&expected_epoch=2&administrator={}&clear=true",
        person(1)
    );
    let command = parse_command(body.as_bytes()).unwrap();
    assert!(command.protection.branches.is_empty());
    assert_eq!(command.protection.administrators, [PrincipalId::from_bytes([1; 16])]);
    for bad in [
        body.replace("&clear=true", ""),
        body.replace("clear=true", "clear=false"),
        body.replace("clear=true", "clear=1"),
        body.replace("clear=true", "clear="),
        body.replace(&format!("&administrator={}", person(1)), ""),
        form() + "&clear=true",
    ] {
        assert!(parse_command(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn version_and_epoch_must_be_explicit_nonzero_canonical_and_have_successors() {
    let good = form();
    let bootstrap = good.replace("expected_version=1", "expected_version=0");
    let error = parse_command(bootstrap.as_bytes()).unwrap_err();
    assert_eq!(error.status, Status::Forbidden);
    assert_eq!(error.code, "local_bootstrap_required");
    for body in [
        good.replace("expected_version=1&", ""),
        good.replace("expected_epoch=2&", ""),
        good.replace("expected_version=1", "expected_version=01"),
        good.replace("expected_version=1", "expected_version=%2B1"),
        good.replace("expected_version=1", "expected_version=-1"),
        good.replace("expected_version=1", "expected_version=1.0"),
        good.replace("expected_version=1", "expected_version=18446744073709551615"),
        good.replace("expected_version=1", "expected_version=18446744073709551616"),
        good.replace("expected_epoch=2", "expected_epoch=0"),
        good.replace("expected_epoch=2", "expected_epoch=02"),
        good.replace("expected_epoch=2", "expected_epoch=18446744073709551615"),
        good.replace("expected_epoch=2", "expected_epoch=18446744073709551616"),
    ] {
        assert!(parse_command(body.as_bytes()).is_err(), "{body}");
    }
    let boundary = good
        .replace("expected_version=1", "expected_version=18446744073709551614")
        .replace("expected_epoch=2", "expected_epoch=18446744073709551614");
    assert!(parse_command(boundary.as_bytes()).is_ok());
}

#[test]
fn principal_and_reference_hex_are_exact_and_non_utf8_branches_remain_lossless() {
    let raw = b"refs/heads/non-utf8-\xff";
    let body = form().replace(&hex(b"refs/heads/main"), &hex(raw));
    let command = parse_command(body.as_bytes()).unwrap();
    assert_eq!(command.protection.branches[0].name.as_bytes(), raw);
    let json = policy_json(&command.protection).unwrap();
    assert!(json.contains(&format!("\"reference_hex\":\"{}\"", hex(raw))));
    assert!(!json.contains("reference\":"));

    for bad in [
        "".to_owned(),
        "abc".to_owned(),
        hex(b"refs/heads/main").to_uppercase(),
        "zz".to_owned(),
        hex(b"HEAD"),
        hex(b"refs/tags/v1"),
        hex(b"refs/heads/a..b"),
        hex(b"refs/heads/a.lock"),
        hex(b"refs/heads/with space"),
        hex(b"refs/heads/\0"),
    ] {
        assert!(reference(&bad).is_err(), "{bad}");
    }
    for bad in [
        "".to_owned(),
        "a".repeat(31),
        "a".repeat(33),
        "A".repeat(32),
        "g".repeat(32),
        format!(" {}", person(1)),
        format!("{}:{}", person(1), person(2)),
    ] {
        assert!(principal(&bad).is_err(), "{bad}");
    }
}

#[test]
fn reference_limit_is_the_native_byte_limit_and_has_an_exact_accepted_boundary() {
    let prefix = b"refs/heads/";
    let mut allowed = prefix.to_vec();
    allowed.extend(std::iter::repeat_n(b'a', MAX_REF_NAME_LEN - prefix.len()));
    assert_eq!(allowed.len(), MAX_REF_NAME_LEN);
    assert_eq!(reference(&hex(&allowed)).unwrap().as_bytes(), allowed.as_slice());
    allowed.push(b'a');
    let error = reference(&hex(&allowed)).unwrap_err();
    assert_eq!(error.code, "invalid_reference_hex");
}

#[test]
fn every_native_collection_limit_is_enforced_without_silently_truncating_sets() {
    let mut administrators = "expected_version=1&expected_epoch=2&clear=true".to_owned();
    for byte in 1..=MAX_POLICY_ADMINISTRATORS {
        administrators.push_str(&format!("&administrator={}", person(byte as u8)));
    }
    let command = parse_command(administrators.as_bytes()).unwrap();
    assert_eq!(command.protection.administrators.len(), MAX_POLICY_ADMINISTRATORS);
    administrators.push_str(&format!("&administrator={}", person(99)));
    assert_eq!(
        parse_command(administrators.as_bytes()).unwrap_err().status,
        Status::TooLarge
    );

    let mut reviewers = format!(
        "expected_version=1&expected_epoch=2&administrator={}",
        person(1)
    );
    for byte in 1..=MAX_BRANCH_REVIEWERS {
        reviewers.push_str(&format!(
            "&required_reviewer={}:{}",
            hex(b"refs/heads/main"),
            person(byte as u8)
        ));
    }
    let command = parse_command(reviewers.as_bytes()).unwrap();
    assert_eq!(command.protection.branches[0].reviewers.len(), MAX_BRANCH_REVIEWERS);
    reviewers.push_str(&format!(
        "&required_reviewer={}:{}",
        hex(b"refs/heads/main"),
        person(99)
    ));
    assert_eq!(
        parse_command(reviewers.as_bytes()).unwrap_err().status,
        Status::TooLarge
    );

    let mut branches = format!(
        "expected_version=1&expected_epoch=2&administrator={}",
        person(1)
    );
    for branch in 0..MAX_PROTECTED_BRANCHES {
        branches.push_str(&format!(
            "&required_reviewer={}:{}",
            hex(format!("refs/heads/branch-{branch:03}").as_bytes()),
            person(2)
        ));
    }
    let command = parse_command(branches.as_bytes()).unwrap();
    assert_eq!(command.protection.branches.len(), MAX_PROTECTED_BRANCHES);
    branches.push_str(&format!(
        "&required_reviewer={}:{}",
        hex(b"refs/heads/one-more"),
        person(2)
    ));
    assert_eq!(
        parse_command(branches.as_bytes()).unwrap_err().status,
        Status::TooLarge
    );
}

#[test]
fn malformed_form_bytes_never_become_policy_identity_or_ignored_fields() {
    for body in [
        form() + "&administrator=%",
        form() + "&administrator=%FF",
        form() + "&administrator=%00",
        form() + "&administrator",
        form() + "&",
        form() + "&Administrator=anything",
        form().replace("required_reviewer=", "required_reviewer=%2536"),
    ] {
        assert!(parse_command(body.as_bytes()).is_err(), "{body}");
    }
    assert_eq!(
        parse_command(&vec![b'x'; MAX_COMMAND_BYTES + 1]).unwrap_err().status,
        Status::TooLarge
    );
}

#[test]
fn get_is_a_bodyless_read_with_only_an_optional_exact_head_token() {
    assert_eq!(request("GET", "", "").unwrap(), (false, None));
    let token = format!("alg:1:{}", "ab".repeat(32));
    let expected = parse_snapshot(&token).unwrap();
    assert_eq!(head_token(expected), token);
    assert_eq!(
        request("GET", &format!("?expected_head={token}"), "").unwrap(),
        (false, Some(expected))
    );
    for suffix in [
        "?limit=1".to_owned(),
        "?expected_head=".to_owned(),
        "?principal_id=admin".to_owned(),
        format!("?expected_head={token}&expected_head={token}"),
    ] {
        assert!(request("GET", &suffix, "").is_err(), "{suffix}");
    }
    for headers in [
        "Content-Length: 1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Expect: 100-continue\r\n",
        "Git-Protocol: version=2\r\n",
    ] {
        assert!(request("GET", "", headers).is_err(), "{headers}");
    }
}

#[test]
fn routes_methods_media_and_declared_body_limits_are_checked_before_publication() {
    let form_head =
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n";
    assert_eq!(request("POST", "", form_head).unwrap(), (true, None));
    assert!(request(
        "POST",
        "",
        "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\nTransfer-Encoding: chunked\r\n"
    ).unwrap().0);
    for (method, suffix, headers) in [
        ("PUT", "", form_head),
        ("POST", "?expected_head=x", form_head),
        ("POST", "", ""),
        ("POST", "", "Content-Type: application/json\r\nContent-Length: 1\r\n"),
        ("POST", "", "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n"),
        ("GET", "/extra", ""),
        ("GET", "extra", ""),
        ("GET", "/", ""),
    ] {
        assert!(request(method, suffix, headers).is_err(), "{method} {suffix}");
    }
    let at_limit = format!(
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {MAX_COMMAND_BYTES}\r\n"
    );
    assert!(request("POST", "", &at_limit).is_ok());
    let above_limit = format!(
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
        MAX_COMMAND_BYTES + 1
    );
    assert_eq!(
        request("POST", "", &above_limit).unwrap_err().status,
        Status::TooLarge
    );
    assert!(is_route("/repo.git/api/v1/protection"));
    assert!(is_route("/repo.git/api/v1/protection?expected_head=x"));
    assert!(is_route("/repo.git/api/v1/protection/extra"));
    assert!(!is_route("/repo.git/api/v1/pulls"));
    assert!(!is_route("/repo.git?path=/api/v1/protection"));
}
