use super::*;

fn get(fixture: &Fixture, object: LfsObject, token: char, extra: &str) -> Reply {
    fixture.request_with(
        "GET",
        &path(object),
        token,
        b"",
        false,
        "localhost:9418",
        extra,
    )
}

fn headers(reply: &Reply) -> &str {
    let length = reply.output.len() - reply.body().len();
    std::str::from_utf8(&reply.output[..length]).unwrap()
}

fn check(reply: &Reply, status: &str, body: &[u8]) {
    let header = headers(reply);
    assert!(
        header.starts_with(&format!("HTTP/1.1 {status}\r\n")),
        "{header}"
    );
    assert!(
        header.contains(&format!("Content-Length: {}\r\n", body.len())),
        "{header}"
    );
    assert_eq!(reply.body(), body);
    assert_eq!(header.matches("Content-Length:").count(), 1);
}

#[test]
fn authenticated_single_ranges_and_resumption_preserve_verified_identity() {
    let mut fixture = Fixture::new();
    let bytes = b"an asset\0with\xffbinary bytes";
    let object = object(bytes);
    assert_eq!(
        fixture.request("PUT", &path(object), 'a', bytes).result,
        Ok(())
    );
    let full = get(&fixture, object, 'b', "");
    check(&full, "200 OK", bytes);
    let tag = super::super::range::etag(object);
    assert!(headers(&full).contains(&format!("ETag: {tag}\r\n")));
    assert!(headers(&full).contains("Accept-Ranges: bytes\r\n"));
    assert!(!headers(&full).contains("Content-Range:"));
    fixture.profile.lfs = Some(Service::open(&fixture.root, TENANT, REPO, INCARNATION).unwrap());
    for (value, start, end) in [
        ("bytes=0-0", 0, 0),
        ("bytes=3-9", 3, 9),
        ("bytes=8-", 8, bytes.len() - 1),
        ("bytes=-5", bytes.len() - 5, bytes.len() - 1),
        ("bytes=-999", 0, bytes.len() - 1),
        ("bytes=1-999999999999999999999999", 1, bytes.len() - 1),
    ] {
        let reply = get(
            &fixture,
            object,
            'b',
            &format!("Range: {value}\r\nIf-Range: {tag}\r\n"),
        );
        assert_eq!(reply.result, Ok(()));
        check(&reply, "206 Partial Content", &bytes[start..=end]);
        assert!(headers(&reply).contains(&format!(
            "Content-Range: bytes {start}-{end}/{}\r\n",
            bytes.len()
        )));
        assert!(headers(&reply).contains(&format!("ETag: {tag}\r\n")));
    }
    let first = get(&fixture, object, 'b', "Range: bytes=0-7\r\n");
    let rest = get(
        &fixture,
        object,
        'b',
        &format!("Range: bytes=8-\r\nIf-Range: {tag}\r\n"),
    );
    let resumed = [first.body(), rest.body()].concat();
    assert_eq!(resumed, bytes);
    assert_eq!(LfsOid::of_payload(&resumed), object.oid);
}

#[test]
fn if_range_requires_a_matching_strong_validator_and_unsupported_sets_use_full_get() {
    let fixture = Fixture::new();
    let bytes = b"selected immutable bytes";
    let object = object(bytes);
    assert_eq!(
        fixture.request("PUT", &path(object), 'a', bytes).result,
        Ok(())
    );
    let tag = super::super::range::etag(object);
    for extra in [
        "Range: bytes=0-1\r\nIf-Range: \"different\"\r\n".to_owned(),
        format!("Range: bytes=0-1\r\nIf-Range: W/{tag}\r\n"),
        "Range: bytes=0-1\r\nIf-Range: Wed, 21 Oct 2015 07:28:00 GMT\r\n".to_owned(),
        // A failed If-Range condition ignores Range, including its syntax.
        "Range: bytes=invalid\r\nIf-Range: \"different\"\r\n".to_owned(),
        "Range: items=0-1\r\n".to_owned(),
        "Range: bytes=0-1,4-5\r\n".to_owned(),
        "Range: bytes=999-1000,2000-3000\r\n".to_owned(),
        "If-Range: ignored\r\nIf-Range: also-ignored\r\n".to_owned(),
    ] {
        let reply = get(&fixture, object, 'b', &extra);
        assert_eq!(reply.result, Ok(()), "{extra}");
        check(&reply, "200 OK", bytes);
        assert!(!headers(&reply).contains("Content-Range:"));
    }
}

#[test]
fn unsatisfiable_ranges_require_existing_verified_custody_and_report_actual_length() {
    let fixture = Fixture::new();
    for bytes in [b"".as_slice(), b"held asset".as_slice()] {
        let object = object(bytes);
        let missing = get(&fixture, object, 'b', "Range: bytes=999-\r\n");
        assert_eq!(missing.result, Err(Status::NotFound));
        assert!(!headers(&missing).contains("Content-Range:"));
        assert!(!headers(&missing).contains("ETag:"));
        assert_eq!(
            fixture.request("PUT", &path(object), 'a', bytes).result,
            Ok(())
        );
        for value in [
            "bytes=999-",
            "bytes=-0",
            "bytes=99999999999999999999999999999999-",
        ] {
            let reply = get(&fixture, object, 'b', &format!("Range: {value}\r\n"));
            assert_eq!(reply.result, Err(Status::RangeNotSatisfiable));
            check(
                &reply,
                "416 Range Not Satisfiable",
                b"{\"message\":\"lfs_range_not_satisfiable\"}",
            );
            assert!(
                headers(&reply).contains(&format!("Content-Range: bytes */{}\r\n", bytes.len()))
            );
        }
        let whole = get(&fixture, object, 'b', "");
        assert_eq!(whole.result, Ok(()));
        check(&whole, "200 OK", bytes);
        if bytes.is_empty() {
            let empty = get(&fixture, object, 'b', "Range: bytes=0-\r\n");
            assert_eq!(empty.result, Err(Status::RangeNotSatisfiable));
        }
    }
}

#[test]
fn malformed_or_duplicate_ranges_refuse_after_authentication_without_reflection() {
    let fixture = Fixture::new();
    let bytes = b"private asset";
    let object = object(bytes);
    assert_eq!(
        fixture.request("PUT", &path(object), 'a', bytes).result,
        Ok(())
    );
    for extra in [
        "Range: bytes=invalid\r\n".to_owned(),
        "Range: bytes=5-4\r\n".to_owned(),
        "Range: bytes=0-1\r\nRange: bytes=2-3\r\n".to_owned(),
        "Range: bytes=0-1\r\nIf-Range: x\r\nIf-Range: y\r\n".to_owned(),
        format!("Range: bytes=0-{}\r\n", "9".repeat(256)),
    ] {
        let reply = get(&fixture, object, 'b', &extra);
        assert_eq!(reply.result, Err(Status::BadRequest), "{extra}");
        assert!(!headers(&reply).contains("Content-Range:"));
        assert!(!headers(&reply).contains("ETag:"));
        for (token, status) in [
            ('c', Status::Forbidden),
            ('d', Status::Forbidden),
            ('e', Status::Unauthorized),
        ] {
            let denied = get(&fixture, object, token, &extra);
            assert_eq!(denied.result, Err(status));
            assert_eq!(denied.output, get(&fixture, object, token, "").output);
        }
    }
    // Range has no semantics on PUT; it never turns this into a partial upload.
    let ignored = fixture.request_with(
        "PUT",
        &path(object),
        'a',
        bytes,
        false,
        "localhost:9418",
        "Range: invalid\r\nRange: ignored\r\n",
    );
    assert_eq!(ignored.result, Ok(()));
    assert_eq!(get(&fixture, object, 'b', "").body(), bytes);
}

#[test]
fn corruption_outside_the_selected_range_prevents_every_payload_and_length_response() {
    let fixture = Fixture::new();
    let bytes = b"intact prefix and a corrupted suffix";
    let object = object(bytes);
    assert_eq!(
        fixture.request("PUT", &path(object), 'a', bytes).result,
        Ok(())
    );
    let directory = fs::read_dir(&fixture.root)
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("scope-"))
        .unwrap()
        .path();
    let file = fs::read_dir(directory)
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.file_name().len() == 64)
        .unwrap()
        .path();
    let mut damaged = fs::read(&file).unwrap();
    *damaged.last_mut().unwrap() ^= 0x80;
    fs::write(file, damaged).unwrap();
    for range in ["bytes=0-5", "bytes=999-"] {
        let reply = get(&fixture, object, 'b', &format!("Range: {range}\r\n"));
        assert_eq!(reply.result, Err(Status::Unavailable));
        assert!(!headers(&reply).contains("Content-Range:"));
        assert!(!headers(&reply).contains("ETag:"));
        assert!(!reply.body().windows(6).any(|part| part == b"intact"));
    }
}

#[test]
fn live_http_gateway_carries_fragmented_range_requests_without_second_responses() {
    use std::net::{Shutdown, TcpListener, TcpStream};

    let fixture = Fixture::new();
    let bytes = b"resume across the live HTTP gateway";
    let object = object(bytes);
    assert_eq!(
        fixture.request("PUT", &path(object), 'a', bytes).result,
        Ok(())
    );
    for (token, range, status, body, success) in [
        (
            'b',
            "bytes=7-12",
            "206 Partial Content",
            &bytes[7..=12],
            true,
        ),
        (
            'b',
            "bytes=999-",
            "416 Range Not Satisfiable",
            b"{\"message\":\"lfs_range_not_satisfiable\"}".as_slice(),
            false,
        ),
        (
            'c',
            "bytes=7-12",
            "403 Forbidden",
            b"{\"message\":\"lfs_scope_not_granted\"}".as_slice(),
            false,
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                let (socket, _) = listener.accept().unwrap();
                let deadline = GitDaemonSessionDeadline::new(
                    GitDaemonSessionTimeout::DEFAULT,
                    GitDaemonSessionWorkScaling::FLAT,
                );
                super::super::super::serve_connection(socket, deadline, &fixture.profile)
            });
            let mut client = TcpStream::connect(address).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {}\r\nRange: {range}\r\n\r\n",
                path(object),
                token.to_string().repeat(64)
            );
            for fragment in request.as_bytes().chunks(13) {
                client.write_all(fragment).unwrap();
            }
            client.shutdown(Shutdown::Write).unwrap();
            let mut output = Vec::new();
            client.read_to_end(&mut output).unwrap();
            assert_eq!(server.join().unwrap(), success);
            let reply = Reply {
                result: Ok(()),
                output,
            };
            check(&reply, status, body);
            assert_eq!(
                String::from_utf8_lossy(&reply.output)
                    .matches("HTTP/1.1")
                    .count(),
                1
            );
        });
    }
}
