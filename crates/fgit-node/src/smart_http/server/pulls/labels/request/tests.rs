use super::*;
use fgit_wire::smart_http::{HttpLimits, head};

fn command(body: &str) -> Result<PullRequestLabelsCommand, ApiError> {
    let raw = format!(
        "POST /tenant/repo.git/api/v1/pulls/7/labels HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    Request::parse(&envelope)?.unwrap().command(body.as_bytes())
}

fn addition(body: &str) -> Result<PullRequestLabelsIntent, ApiError> {
    let raw = format!(
        "POST /tenant/repo.git/api/v1/pulls/7/labels/add HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let request = Request::parse(&envelope)?.unwrap();
    assert!(request.is_mutation());
    assert!(request.is_addition());
    assert!(request.command(body.as_bytes()).is_err());
    request.addition(body.as_bytes())
}

#[test]
fn additions_sort_exact_labels_without_accepting_replacement_preconditions() {
    let intent = addition("label=triage&label=bug&label=%20exact%20&label=%C3%A9").unwrap();
    assert_eq!(intent.number.get(), 7);
    assert_eq!(intent.labels, [" exact ", "bug", "triage", "é"]);
    assert!(command("label=triage&label=bug").is_err());
    for invalid in [
        "",
        "label=",
        "label=+",
        "label=bug&label=bug",
        "label=bug&label=%62ug",
        "label=bug&expected_version=0",
        "label=bug&expected_version=1",
        "clear_labels=true",
        "label=bug&clear_labels=true",
        "label=bug&clear_labels=false",
        "label=bug&actor=trusted",
        "label=bug&expected_head=ignored",
        "label=bug&number=99",
        "label=bug&object_format=sha1",
        "labels=bug",
        "label=x%00y",
        "label=x%0Ay",
        "label=x%C2%85y",
        "label=%FF",
        "label=%",
    ] {
        assert!(addition(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn additive_label_count_and_decoded_byte_bounds_keep_valid_maxima() {
    assert!(addition(&format!("label={}", "é".repeat(MAX_LABEL_BYTES / 2))).is_ok());
    assert!(addition(&format!("label={}", "é".repeat(MAX_LABEL_BYTES / 2 + 1))).is_err());
    let labels = (0..MAX_LABELS)
        .map(|index| format!("label=label-{index:02}"))
        .collect::<Vec<_>>()
        .join("&");
    assert_eq!(addition(&labels).unwrap().labels.len(), MAX_LABELS);
    assert!(addition(&format!("{labels}&label=overflow")).is_err());
    assert!(addition(&format!("label={}", "x".repeat(MAX_FORM_BYTES))).is_err());
    let raw = "POST /repo.git/api/v1/pulls/7/labels/add HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n";
    let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let request = Request::parse(&envelope).unwrap().unwrap();
    assert!(request.addition(&vec![b'x'; MAX_FORM_BYTES + 1]).is_err());
}

#[test]
fn additive_route_requires_post_with_no_snapshot_or_read_grammar() {
    for (method, suffix, headers) in [
        ("GET", "1/labels/add", ""),
        ("HEAD", "1/labels/add", ""),
        ("DELETE", "1/labels/add", ""),
        (
            "POST",
            "1/labels/add?expected_head=ignored",
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n",
        ),
        (
            "POST",
            "1/labels/add",
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n",
        ),
        (
            "POST",
            "1/labels/add",
            "Content-Type: application/json\r\nContent-Length: 1\r\n",
        ),
        (
            "POST",
            "1/labels/add",
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 8193\r\n",
        ),
        (
            "POST",
            "1/labels/add",
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\nGit-Protocol: version=2\r\n",
        ),
        (
            "POST",
            "01/labels/add",
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n",
        ),
        (
            "POST",
            "0/labels/add",
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n",
        ),
    ] {
        let raw = format!(
            "{method} /repo.git/api/v1/pulls/{suffix} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
        );
        let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        assert!(Request::parse(&envelope).is_err(), "{raw}");
    }
}

#[test]
fn explicit_replacement_and_clear_bind_the_label_version_and_preserve_spelling() {
    let result = command("expected_version=0&label=triage&label=bug&label=%20exact%20").unwrap();
    assert_eq!(result.number.get(), 7);
    assert_eq!(result.expected_version, ExpectedVersion::NewStream);
    assert_eq!(result.labels, [" exact ", "bug", "triage"]);
    let result = command("expected_version=23&clear_labels=true").unwrap();
    assert_eq!(
        result.expected_version,
        ExpectedVersion::Exactly(AggregateVersion::try_new(23).unwrap())
    );
    assert!(result.labels.is_empty());
    assert!(command("expected_version=0&clear_labels=true").is_ok());
}

#[test]
fn ambiguous_hidden_or_malformed_command_fields_never_reach_admission() {
    for invalid in [
        "expected_version=0",
        "label=bug",
        "expected_version=0&label=",
        "expected_version=0&label=+",
        "expected_version=0&label=bug&label=bug",
        "expected_version=0&label=bug&clear_labels=true",
        "expected_version=0&clear_labels=false",
        "expected_version=0&clear_labels=true&clear_labels=true",
        "expected_version=0&expected_version=1&label=bug",
        "expected_version=01&label=bug",
        "expected_version=-1&label=bug",
        "expected_version=18446744073709551615&label=bug",
        "expected_version=0&label=x%00y",
        "expected_version=0&label=x%0Ay",
        "expected_version=0&label=x%C2%85y",
        "expected_version=0&label=%FF",
        "expected_version=0&label=%",
        "expected_version=0&label=bug&actor=trusted",
        "expected_version=0&label=bug&expected_head=ignored",
        "expected_version=0&label=bug&object_format=sha1",
        "expected_version=0&label=bug&title=ignored",
    ] {
        assert!(command(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn label_byte_and_count_limits_have_successful_boundary_cases() {
    assert!(command(&format!("expected_version=0&label={}", "é".repeat(32))).is_ok());
    assert!(command(&format!("expected_version=0&label={}", "é".repeat(33))).is_err());
    let labels = (0..MAX_LABELS)
        .map(|index| format!("&label=label-{index:02}"))
        .collect::<String>();
    assert!(command(&format!("expected_version=0{labels}")).is_ok());
    assert!(command(&format!("expected_version=0{labels}&label=overflow")).is_err());
    assert!(
        command(&format!(
            "expected_version=0&label={}",
            "x".repeat(MAX_FORM_BYTES)
        ))
        .is_err()
    );
}

#[test]
fn reads_accept_only_optional_snapshot_and_mutations_have_closed_envelopes() {
    let pin = format!("alg:1:{}", "ab".repeat(32));
    for suffix in [String::new(), format!("?expected_head={pin}")] {
        let raw =
            format!("GET /repo.git/api/v1/pulls/1/labels{suffix} HTTP/1.1\r\nHost: local\r\n\r\n");
        let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let request = Request::parse(&envelope).unwrap().unwrap();
        assert!(!request.is_mutation());
        assert_eq!(request.expected_head.is_some(), !suffix.is_empty());
    }
    for (method, path, headers) in [
        ("GET", "/repo.git/api/v1/pulls/0/labels", ""),
        ("GET", "/repo.git/api/v1/pulls/01/labels", ""),
        ("GET", "/repo.git/api/v1/pulls/1/labels?label=bug", ""),
        ("GET", "/repo.git/api/v1/pulls/1/labels?after=0", ""),
        ("GET", "/repo.git/api/v1/pulls/1/labels?expected_head=x", ""),
        (
            "GET",
            "/repo.git/api/v1/pulls/1/labels",
            "Content-Length: 1\r\n",
        ),
        (
            "POST",
            "/repo.git/api/v1/pulls/1/labels",
            "Content-Length: 1\r\n",
        ),
        (
            "POST",
            "/repo.git/api/v1/pulls/1/labels",
            "Content-Type: application/json\r\nContent-Length: 1\r\n",
        ),
        (
            "POST",
            "/repo.git/api/v1/pulls/1/labels?after=0",
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n",
        ),
        (
            "POST",
            "/repo.git/api/v1/pulls/1/labels",
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n",
        ),
        ("DELETE", "/repo.git/api/v1/pulls/1/labels", ""),
        (
            "GET",
            "/repo.git/api/v1/pulls/1/labels",
            "Git-Protocol: version=2\r\n",
        ),
    ] {
        let raw = format!("{method} {path} HTTP/1.1\r\nHost: local\r\n{headers}\r\n");
        let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        assert!(Request::parse(&envelope).is_err(), "{raw}");
    }
}
