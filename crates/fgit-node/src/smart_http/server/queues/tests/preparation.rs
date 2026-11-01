use super::*;

#[test]
fn preparation_is_a_bounded_body_read_and_does_not_reclassify_queue_writes() {
    for framing in [
        "Content-Length: 1\r\n".to_owned(),
        format!(
            "Content-Length: {}\r\n",
            super::super::preparation::MAX_COMMAND_BYTES
        ),
        "Transfer-Encoding: chunked\r\nExpect: 100-continue\r\n".to_owned(),
    ] {
        let bytes = format!(
            "POST /repo.git/api/v1/queues/1/prepare HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\n{framing}\r\n"
        );
        let request = parse(&bytes).unwrap();
        assert!(request.accepts_body() && request.is_preparation());
        assert!(!request.is_mutation() && !request.is_landing());
        assert!(
            matches!(request.operation, Operation::Prepare { number } if number == QueueNumber::FIRST)
        );
    }
    for suffix in ["/1/enqueue", "/1/dequeue", "/1/reorder", "/1/land"] {
        let bytes = wire("POST", suffix, 1);
        let request = parse(&bytes).unwrap();
        assert!(request.is_mutation() && request.accepts_body());
        assert!(!request.is_preparation());
        assert!(parse(&wire("POST", suffix, MAX_COMMAND_BYTES + 1)).is_err());
    }
    for suffix in ["", "/1"] {
        let bytes = wire("GET", suffix, 0);
        let request = parse(&bytes).unwrap();
        assert!(!request.is_mutation() && !request.accepts_body());
    }
}

#[test]
fn preparation_envelopes_reject_oversize_ambiguous_and_inapplicable_routes() {
    for (method, suffix, size) in [
        ("POST", "/0/prepare", 1),
        ("POST", "/01/prepare", 1),
        ("POST", "/1/prepare/extra", 1),
        ("POST", "/1/prepare?expected_version=1", 1),
        ("POST", "/1/prepare", 0),
        (
            "POST",
            "/1/prepare",
            super::super::preparation::MAX_COMMAND_BYTES + 1,
        ),
        ("GET", "/1/prepare", 0),
        ("PUT", "/1/prepare", 1),
    ] {
        assert!(
            parse(&wire(method, suffix, size)).is_err(),
            "{method} {suffix}"
        );
    }
    let valid = wire("POST", "/1/prepare", 1);
    for media in ["application/json", "multipart/form-data; boundary=upload"] {
        assert!(parse(&valid.replace("application/x-www-form-urlencoded", media)).is_err());
    }
    assert!(
        parse(&valid.replace("Host: local", "Host: local\r\nGit-Protocol: version=2")).is_err()
    );
    assert!(
        parse(&valid.replace(
            "application/x-www-form-urlencoded",
            "application/x-www-form-urlencoded; charset=utf-8"
        ))
        .is_ok()
    );
}
