use super::*;

fn candidate(job: &[u8]) -> String {
    format!(
        "{}:{}:{}:{}",
        hex(b"refs/heads/main"),
        person(3),
        "44".repeat(32),
        hex(job)
    )
}
fn candidate_only() -> String {
    format!(
        "expected_version=1&expected_epoch=2&administrator={}&required_candidate_check={}",
        person(1),
        candidate(b"test:unit")
    )
}

#[test]
fn candidate_only_form_and_read_json_retain_exact_selector_without_ci_source() {
    let command = parse_command(candidate_only().as_bytes()).unwrap();
    let rule = &command.protection.branches[0];
    assert!(rule.reviewers.is_empty() && rule.required_checks.is_empty());
    assert_eq!(rule.required_approvals, 0);
    assert_eq!(rule.required_candidate_checks[0].job, "test:unit");
    let rendered = policy_json(&command.protection).unwrap();
    assert!(rendered.contains("\"required_candidate_checks\":[{"));
    assert!(rendered.contains("\"job\":\"test:unit\""));
    assert!(!rendered.contains("source_ref_hex"));
    let mixed = parse_command(
        format!(
            "{}&required_candidate_check={}",
            form(),
            candidate("日本語".as_bytes())
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        mixed.protection.branches[0].required_candidate_checks[0].job,
        "日本語"
    );
    assert!(!mixed.protection.branches[0].reviewers.is_empty());
}

#[test]
fn candidate_form_refuses_duplicates_unknown_authority_and_noncanonical_selector_parts() {
    let valid = candidate_only();
    let main = hex(b"refs/heads/main");
    for invalid in [
        format!(
            "{valid}&required_candidate_check={}",
            candidate(b"test:unit")
        ),
        format!("{valid}&actor={}", person(3)),
        format!("{valid}&clear=true"),
        valid.replace(&main, &hex(b"refs/tags/main")),
        valid.replace(&candidate(b"test:unit"), &candidate(b"bad\njob")),
        valid.replace(&candidate(b"test:unit"), &candidate(&[0xff])),
        valid.replace(
            &candidate(b"test:unit"),
            &format!("{}:extra", candidate(b"test:unit")),
        ),
        valid.replace(&"44".repeat(32), &"44".repeat(31)),
    ] {
        assert!(parse_command(invalid.as_bytes()).is_err(), "{invalid}");
    }
}

#[test]
fn ordinary_and_candidate_checks_share_one_bound_in_either_form_order() {
    let mut body = form();
    for index in 0..31 {
        write!(
            body,
            "&required_candidate_check={}",
            candidate(format!("job-{index:02}").as_bytes())
        )
        .unwrap();
    }
    let ordinary = format!(
        "&required_check={}:{}:{}:{}:{}",
        hex(b"refs/heads/main"),
        hex(b"refs/heads/ci"),
        person(3),
        "44".repeat(32),
        hex(b"ordinary")
    );
    body.push_str(&ordinary);
    let command = parse_command(body.as_bytes()).unwrap();
    assert_eq!(
        command.protection.branches[0]
            .required_candidate_checks
            .len(),
        31
    );
    assert_eq!(command.protection.branches[0].required_checks.len(), 1);
    let overflow = format!("&required_candidate_check={}", candidate(b"overflow"));
    assert!(parse_command(format!("{body}{overflow}").as_bytes()).is_err());
    assert!(
        parse_command(
            format!(
                "{}{overflow}&{}",
                &ordinary[1..],
                body.trim_end_matches(&ordinary)
            )
            .as_bytes()
        )
        .is_err()
    );
}
