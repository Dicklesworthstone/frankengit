use super::*;

#[test]
fn prefix_preparation_is_a_body_bearing_read_with_the_shared_form_ceiling() {
    for framing in [
        "Content-Length: 1\r\n".to_owned(),
        format!(
            "Content-Length: {}\r\n",
            super::super::preparation::MAX_COMMAND_BYTES
        ),
        "Transfer-Encoding: chunked\r\nExpect: 100-continue\r\n".to_owned(),
    ] {
        let bytes = format!(
            "POST /repo.git/api/v1/queues/1/prepare-prefix HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\n{framing}\r\n"
        );
        let request = parse(&bytes).unwrap();
        assert!(request.accepts_body() && request.is_preparation());
        assert!(!request.is_mutation() && !request.is_landing());
        assert!(
            matches!(request.operation, Operation::PreparePrefix { number } if number == QueueNumber::FIRST)
        );
    }
    for (method, suffix, bytes) in [
        ("GET", "/1/prepare-prefix", 0),
        ("PUT", "/1/prepare-prefix", 1),
        ("POST", "/0/prepare-prefix", 1),
        ("POST", "/01/prepare-prefix", 1),
        ("POST", "/1/prepare-prefix/extra", 1),
        ("POST", "/1/prepare-prefix?entry_count=2", 1),
        ("POST", "/1/prepare-prefix", 0),
        (
            "POST",
            "/1/prepare-prefix",
            super::super::preparation::MAX_COMMAND_BYTES + 1,
        ),
    ] {
        assert!(
            parse(&wire(method, suffix, bytes)).is_err(),
            "{method} {suffix}"
        );
    }
    let valid = wire("POST", "/1/prepare-prefix", 1);
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
