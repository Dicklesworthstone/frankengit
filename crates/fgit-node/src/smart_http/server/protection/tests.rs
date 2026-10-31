//! Hostile-input and canonicalization regressions for the HTTP protection
//! adapter. Real TCP authorization, publication, recovery, and restart coverage
//! lives in tests/protection_http.rs.

use super::*;
use fgit_wire::smart_http::head;
use std::fmt::Write as _;

fn encoded_policy(source: &str) -> String {
    source
        .as_bytes()
        .iter()
        .map(|byte| format!("%{byte:02X}"))
        .collect()
}

#[test]
fn http_reference_policy_source_and_frame_preserve_complete_canonical_replacement() {
    for (source, profile) in [
        (
            "policy retain { rule keep { when ref.name matches \"refs/tags/**\" and ref.update == delete then deny \"retained tag\" } default allow }",
            "reference_facts_v1",
        ),
        (
            "policy release_authors { rule release { when actor.id == \"33333333333333333333333333333333\" then allow } default deny \"release principal required\" }",
            "reference_actor_id_v1",
        ),
    ] {
        let prefix = format!(
            "expected_version=1&expected_epoch=2&administrator={}",
            person(1)
        );
        let body = format!("{prefix}&ref_policy_source={}", encoded_policy(source));
        let command = parse_command(body.as_bytes()).unwrap();
        assert!(command.protection.branches.is_empty());
        let snapshot = command.protection.ref_policy.as_ref().unwrap();
        let frame = hex(&snapshot.encode().unwrap());
        let from_frame = format!("{prefix}&ref_policy_frame_hex={frame}");
        assert_eq!(parse_command(from_frame.as_bytes()).unwrap(), command);
        let shown = policy_json(&command.protection).unwrap();
        assert!(shown.contains(&format!("\"profile\":\"{profile}\"")));
        assert!(shown.contains(&snapshot.id().to_string()));
        assert!(shown.contains(&format!("\"frame_hex\":\"{frame}\"")));
        for invalid in [
            format!("{body}&ref_policy_frame_hex={frame}"),
            format!("{body}&ref_policy_source={}", encoded_policy(source)),
            format!("{body}&clear=true"),
            format!("{prefix}&ref_policy_frame_hex=00"),
        ] {
            assert!(parse_command(invalid.as_bytes()).is_err());
        }
        let cleared = parse_command(format!("{prefix}&clear=true").as_bytes()).unwrap();
        assert!(cleared.protection.ref_policy.is_none());
        assert_eq!(
            cleared.protection.administrators,
            command.protection.administrators
        );
    }
}

#[test]
fn http_large_reference_policy_frame_roundtrips_without_expanding_other_form_limits() {
    let prefix = format!(
        "expected_version=1&expected_epoch=2&administrator={}",
        person(1)
    );
    let literal = "a".repeat(900);
    let mut source = String::from("policy large { ");
    for index in 0..40 {
        write!(
            source,
            "rule r{index:02} {{ when ref.name == \"{literal}\" then deny \"blocked\" }} "
        )
        .expect("writing to a String cannot fail");
    }
    source.push_str("default allow }");
    let source_form = format!("{prefix}&ref_policy_source={}", encoded_policy(&source));
    assert!(source_form.len() < MAX_COMMAND_BYTES);
    let command = parse_command(source_form.as_bytes()).unwrap();
    let snapshot = command.protection.ref_policy.as_ref().unwrap();
    let frame_hex = hex(&snapshot.encode().unwrap());
    let old_field_limit = fgit_forge::event::issue::MAX_BODY_BYTES;
    assert!(frame_hex.len() > old_field_limit);
    assert!(frame_hex.len() <= 2 * MAX_REF_POLICY_FRAME_BYTES);
    let frame_form = format!("{prefix}&ref_policy_frame_hex={frame_hex}");
    assert!(frame_form.len() < MAX_COMMAND_BYTES);
    assert_eq!(parse_command(frame_form.as_bytes()).unwrap(), command);
    assert!(
        policy_json(&command.protection)
            .unwrap()
            .contains(&frame_hex)
    );

    // The shared issue/PR parser still rejects the same oversized field. Only
    // canonical policy-frame hex receives the protection route's larger bound.
    assert_eq!(
        parse_form(frame_form.as_bytes(), MAX_COMMAND_FIELDS)
            .unwrap_err()
            .code,
        "resource_limit"
    );
    for name in ["body", "ref_policy_source", "administrator"] {
        let form = format!("{prefix}&{name}={}", "a".repeat(old_field_limit + 1));
        assert_eq!(
            parse_command(form.as_bytes()).unwrap_err().code,
            "resource_limit"
        );
    }
    let oversized_frame = format!(
        "{prefix}&ref_policy_frame_hex={}",
        "a".repeat(2 * MAX_REF_POLICY_FRAME_BYTES + 1)
    );
    assert!(oversized_frame.len() < MAX_COMMAND_BYTES);
    assert_eq!(
        parse_command(oversized_frame.as_bytes()).unwrap_err().code,
        "resource_limit"
    );
}

#[test]
fn http_reference_policy_refuses_unavailable_authenticated_facts_before_publication() {
    for source in [
        "policy malformed { default maybe }",
        "policy unavailable { rule r { when principal.kind == human then allow } default deny \"no\" }",
        "policy unavailable { rule r { when ref.force_requested then allow } default deny \"no\" }",
        "policy unavailable { rule r { when ref.update == fast_forward then allow } default deny \"no\" }",
    ] {
        let body = format!("{}&ref_policy_source={}", form(), encoded_policy(source));
        assert_eq!(
            parse_command(body.as_bytes()).unwrap_err().code,
            "invalid_ref_policy"
        );
    }
    let permitted = format!(
        "{}&ref_policy_source={}",
        form(),
        encoded_policy("policy valid { default allow }")
    );
    assert!(parse_command(permitted.as_bytes()).is_ok());
}

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
    assert_eq!(
        command.protection.branches[0].name.as_bytes(),
        b"refs/heads/main"
    );
    assert_eq!(
        command.protection.branches[1].name.as_bytes(),
        b"refs/heads/topic"
    );
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
        format!(
            "&required_reviewer={}:{}",
            hex(b"refs/heads/main"),
            person(2)
        ),
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
    assert_eq!(
        command.protection.administrators,
        [PrincipalId::from_bytes([1; 16])]
    );
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
        good.replace(
            "expected_version=1",
            "expected_version=18446744073709551615",
        ),
        good.replace(
            "expected_version=1",
            "expected_version=18446744073709551616",
        ),
        good.replace("expected_epoch=2", "expected_epoch=0"),
        good.replace("expected_epoch=2", "expected_epoch=02"),
        good.replace("expected_epoch=2", "expected_epoch=18446744073709551615"),
        good.replace("expected_epoch=2", "expected_epoch=18446744073709551616"),
    ] {
        assert!(parse_command(body.as_bytes()).is_err(), "{body}");
    }
    let boundary = good
        .replace(
            "expected_version=1",
            "expected_version=18446744073709551614",
        )
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
        String::new(),
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
        String::new(),
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
    assert_eq!(
        reference(&hex(&allowed)).unwrap().as_bytes(),
        allowed.as_slice()
    );
    allowed.push(b'a');
    let error = reference(&hex(&allowed)).unwrap_err();
    assert_eq!(error.code, "invalid_reference_hex");
}

#[test]
fn every_native_collection_limit_is_enforced_without_silently_truncating_sets() {
    let mut administrators = "expected_version=1&expected_epoch=2&clear=true".to_owned();
    for byte in 1..=MAX_POLICY_ADMINISTRATORS {
        write!(administrators, "&administrator={}", person(byte as u8))
            .expect("writing to a String cannot fail");
    }
    let command = parse_command(administrators.as_bytes()).unwrap();
    assert_eq!(
        command.protection.administrators.len(),
        MAX_POLICY_ADMINISTRATORS
    );
    write!(administrators, "&administrator={}", person(99))
        .expect("writing to a String cannot fail");
    assert_eq!(
        parse_command(administrators.as_bytes()).unwrap_err().status,
        Status::TooLarge
    );

    let mut reviewers = format!(
        "expected_version=1&expected_epoch=2&administrator={}",
        person(1)
    );
    for byte in 1..=MAX_BRANCH_REVIEWERS {
        write!(
            reviewers,
            "&required_reviewer={}:{}",
            hex(b"refs/heads/main"),
            person(byte as u8)
        )
        .expect("writing to a String cannot fail");
    }
    let command = parse_command(reviewers.as_bytes()).unwrap();
    assert_eq!(
        command.protection.branches[0].reviewers.len(),
        MAX_BRANCH_REVIEWERS
    );
    write!(
        reviewers,
        "&required_reviewer={}:{}",
        hex(b"refs/heads/main"),
        person(99)
    )
    .expect("writing to a String cannot fail");
    assert_eq!(
        parse_command(reviewers.as_bytes()).unwrap_err().status,
        Status::TooLarge
    );

    let mut branches = format!(
        "expected_version=1&expected_epoch=2&administrator={}",
        person(1)
    );
    for branch in 0..MAX_PROTECTED_BRANCHES {
        write!(
            branches,
            "&required_reviewer={}:{}",
            hex(format!("refs/heads/branch-{branch:03}").as_bytes()),
            person(2)
        )
        .expect("writing to a String cannot fail");
    }
    let command = parse_command(branches.as_bytes()).unwrap();
    assert_eq!(command.protection.branches.len(), MAX_PROTECTED_BRANCHES);
    write!(
        branches,
        "&required_reviewer={}:{}",
        hex(b"refs/heads/one-more"),
        person(2)
    )
    .expect("writing to a String cannot fail");
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
        parse_command(&vec![b'x'; MAX_COMMAND_BYTES + 1])
            .unwrap_err()
            .status,
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
    let form_head = "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n";
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
        (
            "POST",
            "",
            "Content-Type: application/json\r\nContent-Length: 1\r\n",
        ),
        (
            "POST",
            "",
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n",
        ),
        ("GET", "/extra", ""),
        ("GET", "extra", ""),
        ("GET", "/", ""),
    ] {
        assert!(
            request(method, suffix, headers).is_err(),
            "{method} {suffix}"
        );
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

#[test]
fn check_only_http_commands_preserve_exact_selectors_and_read_representation() {
    let source = hex(b"refs/heads/ci-candidate");
    let job = "build:linux λ";
    let base = form()
        .split('&')
        .filter(|part| !part.starts_with("required_reviewer="))
        .collect::<Vec<_>>()
        .join("&");
    let check = format!(
        "required_check={}:{}:{}:{}:{}",
        hex(b"refs/heads/main"),
        source,
        person(7),
        "55".repeat(32),
        hex(job.as_bytes())
    );
    let body = format!("{base}&{check}");
    let command = parse_command(body.as_bytes()).unwrap();
    let rule = &command.protection.branches[0];
    assert!(rule.reviewers.is_empty());
    assert_eq!(
        rule.required_checks[0].source_ref.as_bytes(),
        b"refs/heads/ci-candidate"
    );
    assert_eq!(
        rule.required_checks[0].publisher,
        PrincipalId::from_bytes([7; 16])
    );
    assert_eq!(rule.required_checks[0].graph_root, [0x55; 32]);
    assert_eq!(rule.required_checks[0].job, job);
    let json = policy_json(&command.protection).unwrap();
    assert!(json.contains(&format!("\"source_ref_hex\":\"{source}\"")));
    assert!(json.contains(&format!("\"job\":{}", quote(job))));
    assert!(parse_command(format!("{body}&{check}").as_bytes()).is_err());
    for bad in [String::new(), "00".into(), "ff".into(), "61".repeat(1025)] {
        let malformed = format!(
            "{base}&required_check={}:{}:{}:{}:{bad}",
            hex(b"refs/heads/main"),
            source,
            person(7),
            "55".repeat(32)
        );
        assert!(parse_command(malformed.as_bytes()).is_err());
    }
}

#[test]
fn approval_quorum_http_is_branch_bound_canonical_and_reported_losslessly() {
    let main = hex(b"refs/heads/main");
    let body = format!(
        "{}&required_reviewer={main}:{}&required_reviewer={main}:{}",
        form(),
        person(3),
        person(4)
    );
    let legacy = parse_command(body.as_bytes()).unwrap();
    assert_eq!(legacy.protection.branches[0].required_approvals, 3);
    let explicit_default = format!("{body}&required_approvals={main}:3");
    assert_eq!(parse_command(explicit_default.as_bytes()).unwrap(), legacy);
    let quorum = format!("{body}&required_approvals={main}:2");
    let command = parse_command(quorum.as_bytes()).unwrap();
    assert_eq!(command.protection.branches[0].required_approvals, 2);
    assert_eq!(
        command.protection.branches[0].reviewers,
        legacy.protection.branches[0].reviewers
    );
    assert!(
        policy_json(&command.protection)
            .unwrap()
            .contains("\"required_approvals\":2")
    );
    let reordered = quorum.split('&').rev().collect::<Vec<_>>().join("&");
    assert_eq!(parse_command(reordered.as_bytes()).unwrap(), command);
    assert!(parse_command(format!("{quorum}&required_approvals={main}:2").as_bytes()).is_err());
}

#[test]
fn approval_quorum_http_refuses_noncanonical_ineligible_and_unlisted_requirements() {
    let main = hex(b"refs/heads/main");
    for count in [
        "0", "2", "33", "65536", "01", "-1", "%2b1", "1.0", "1e0", "",
    ] {
        let body = format!("{}&required_approvals={main}:{count}", form());
        assert!(parse_command(body.as_bytes()).is_err(), "{count}");
    }
    let orphan = format!(
        "{}&required_approvals={}:1",
        form(),
        hex(b"refs/heads/unlisted")
    );
    assert!(parse_command(orphan.as_bytes()).is_err());
    let clear = format!(
        "expected_version=1&expected_epoch=2&administrator={}&clear=true&required_approvals={main}:0",
        person(1)
    );
    assert!(parse_command(clear.as_bytes()).is_err());
}

#[test]
fn check_only_http_accepts_zero_approval_default_and_refuses_positive_quorum() {
    let main = hex(b"refs/heads/main");
    let body = format!(
        "expected_version=1&expected_epoch=2&administrator={}&required_check={main}:{}:{}:{}:{}",
        person(1),
        hex(b"refs/heads/ci"),
        person(7),
        "55".repeat(32),
        hex(b"test"),
    );
    let legacy = parse_command(body.as_bytes()).unwrap();
    assert_eq!(legacy.protection.branches[0].required_approvals, 0);
    assert_eq!(
        parse_command(format!("{body}&required_approvals={main}:0").as_bytes()).unwrap(),
        legacy
    );
    assert!(parse_command(format!("{body}&required_approvals={main}:1").as_bytes()).is_err());
}
