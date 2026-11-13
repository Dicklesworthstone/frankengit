use super::*;

const VERSION: &str = "Tus-Resumable: 1.0.0\r\n";
const PATCH_MEDIA: &str = "Content-Type: application/offset+octet-stream\r\n";

fn upload_path(object: LfsObject) -> String {
    format!("{}/tus", path(object))
}

fn request_head(method: &str, target: &str, token: Option<char>, fields: &str) -> String {
    let authorization = token.map_or_else(String::new, |token| {
        format!("Authorization: Bearer {}\r\n", token.to_string().repeat(64))
    });
    format!("{method} {target} HTTP/1.1\r\nHost: localhost:9418\r\n{authorization}{fields}\r\n")
}

fn exchange(fixture: &Fixture, header: &str, prefix: &[u8], reader: &mut impl Read) -> Reply {
    let envelope = head::parse(header.as_bytes(), fixture.profile.http)
        .unwrap()
        .unwrap();
    let deadline = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let mut output = Vec::new();
    let result = serve(
        &fixture.profile,
        &envelope,
        prefix,
        reader,
        &mut output,
        &deadline,
        Some("127.0.0.1:9418".parse().unwrap()),
    );
    Reply { result, output }
}

fn request(
    fixture: &Fixture,
    method: &str,
    target: &str,
    token: Option<char>,
    fields: &str,
    wire: &[u8],
) -> Reply {
    let header = request_head(method, target, token, fields);
    let prefix = wire.len() / 2;
    exchange(
        fixture,
        &header,
        &wire[..prefix],
        &mut Cursor::new(&wire[prefix..]),
    )
}

fn batch(
    fixture: &Fixture,
    operation: &str,
    object: LfsObject,
    token: char,
    offers: &str,
) -> Reply {
    fixture.request(
        "POST",
        "/repo.git/info/lfs/objects/batch",
        token,
        format!(
            "{{\"operation\":\"{operation}\",\"transfers\":{offers},\"objects\":[{{\"oid\":\"{}\",\"size\":{}}}]}}",
            object.oid, object.size
        )
        .as_bytes(),
    )
}

fn resume(fixture: &Fixture, object: LfsObject, token: char) -> Reply {
    request(
        fixture,
        "HEAD",
        &upload_path(object),
        Some(token),
        VERSION,
        b"",
    )
}

fn patch(
    fixture: &Fixture,
    object: LfsObject,
    token: char,
    offset: u64,
    bytes: &[u8],
    chunked: bool,
) -> Reply {
    let (framing, wire) = if chunked {
        let mut wire = if bytes.is_empty() {
            Vec::new()
        } else {
            format!("{:x}\r\n", bytes.len()).into_bytes()
        };
        if !bytes.is_empty() {
            wire.extend_from_slice(bytes);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        ("Transfer-Encoding: chunked\r\n".to_owned(), wire)
    } else {
        (
            format!("Content-Length: {}\r\n", bytes.len()),
            bytes.to_vec(),
        )
    };
    request(
        fixture,
        "PATCH",
        &upload_path(object),
        Some(token),
        &format!("{VERSION}{PATCH_MEDIA}Upload-Offset: {offset}\r\n{framing}"),
        &wire,
    )
}

fn response(reply: &Reply) -> (&str, &[u8]) {
    let mut bytes = reply.output.as_slice();
    while let Some(rest) = bytes.strip_prefix(b"HTTP/1.1 100 Continue\r\n\r\n") {
        bytes = rest;
    }
    let split = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap();
    (
        std::str::from_utf8(&bytes[..split]).unwrap(),
        &bytes[split + 4..],
    )
}

fn field<'a>(reply: &'a Reply, name: &str) -> Option<&'a str> {
    response(reply).0.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn check_status(reply: &Reply, expected: u16) {
    let (header, _) = response(reply);
    assert_eq!(
        header
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap(),
        expected,
        "{header}"
    );
    assert_eq!(
        reply.result.is_ok(),
        (200..300).contains(&expected),
        "{header}"
    );
}

fn check_resume(reply: &Reply, object: LfsObject, offset: u64) {
    check_status(reply, 200);
    assert_eq!(field(reply, "Tus-Resumable"), Some("1.0.0"));
    assert_eq!(
        field(reply, "Upload-Offset"),
        Some(offset.to_string().as_str())
    );
    assert_eq!(
        field(reply, "Upload-Length"),
        Some(object.size.to_string().as_str())
    );
    assert_eq!(field(reply, "Cache-Control"), Some("no-store"));
    assert!(response(reply).1.is_empty());
}

fn check_patch(reply: &Reply, offset: u64) {
    check_status(reply, 204);
    assert_eq!(field(reply, "Tus-Resumable"), Some("1.0.0"));
    assert_eq!(
        field(reply, "Upload-Offset"),
        Some(offset.to_string().as_str())
    );
    assert_eq!(field(reply, "Content-Length"), None);
    assert!(response(reply).1.is_empty());
}

fn action_path(reply: &Reply, name: &str) -> String {
    check_status(reply, 200);
    let value = reply.json();
    let Some(Value::Array(objects)) = value.object().unwrap().get("objects") else {
        panic!("Batch response has no objects")
    };
    let href = objects[0].object().unwrap()["actions"].object().unwrap()[name]
        .object()
        .unwrap()["href"]
        .text()
        .unwrap();
    href.strip_prefix("http://127.0.0.1:9418")
        .unwrap()
        .to_owned()
}

fn verify(fixture: &Fixture, object: LfsObject, token: char) -> Reply {
    fixture.request(
        "POST",
        &format!("{}/verify", path(object)),
        token,
        format!("{{\"oid\":\"{}\",\"size\":{}}}", object.oid, object.size).as_bytes(),
    )
}

#[test]
fn negotiated_partial_upload_survives_reopen_and_publishes_only_verified_completion() {
    for (chunked, offers) in [(false, r#"["basic","tus"]"#), (true, r#"["tus","basic"]"#)] {
        let mut fixture = Fixture::new();
        let bytes = b"an asset\0with\xffbinary bytes";
        let object = object(bytes);
        check_status(&resume(&fixture, object, 'a'), 404);
        // Basic negotiation remains inert with respect to Tus sessions.
        assert_eq!(fixture.batch("upload", 'a', &[object]).result, Ok(()));
        check_status(&resume(&fixture, object, 'a'), 404);

        let negotiated = batch(&fixture, "upload", object, 'a', offers);
        assert_eq!(
            negotiated.json().object().unwrap()["transfer"].text(),
            Some("tus")
        );
        assert_eq!(action_path(&negotiated, "upload"), upload_path(object));
        assert_eq!(
            action_path(&negotiated, "verify"),
            format!("{}/verify", path(object))
        );
        assert!(!String::from_utf8_lossy(negotiated.body()).contains(&"a".repeat(64)));
        check_resume(&resume(&fixture, object, 'a'), object, 0);

        check_patch(&patch(&fixture, object, 'a', 0, &bytes[..7], chunked), 7);
        check_resume(&resume(&fixture, object, 'a'), object, 7);
        assert_eq!(
            fixture.request("GET", &path(object), 'b', b"").result,
            Err(Status::NotFound)
        );
        assert_eq!(verify(&fixture, object, 'a').result, Err(Status::NotFound));
        let repeated = batch(&fixture, "upload", object, 'a', r#"["tus"]"#);
        assert_eq!(action_path(&repeated, "upload"), upload_path(object));
        check_resume(&resume(&fixture, object, 'a'), object, 7);

        fixture.profile.lfs =
            Some(Service::open(&fixture.root, TENANT, REPO, INCARNATION).unwrap());
        check_resume(&resume(&fixture, object, 'a'), object, 7);
        check_patch(
            &patch(&fixture, object, 'a', 7, &bytes[7..], chunked),
            object.size,
        );
        fixture.profile.lfs =
            Some(Service::open(&fixture.root, TENANT, REPO, INCARNATION).unwrap());
        check_resume(&resume(&fixture, object, 'a'), object, object.size);
        assert_eq!(verify(&fixture, object, 'c').result, Ok(()));
        let downloaded = fixture.request("GET", &path(object), 'b', b"");
        assert_eq!(downloaded.result, Ok(()));
        assert_eq!(downloaded.body(), bytes);

        let download = batch(&fixture, "download", object, 'b', r#"["tus","basic"]"#);
        assert_eq!(
            download.json().object().unwrap()["transfer"].text(),
            Some("basic")
        );
        assert_eq!(action_path(&download, "download"), path(object));
        check_status(&batch(&fixture, "download", object, 'b', r#"["tus"]"#), 400);
        let present = batch(&fixture, "upload", object, 'a', r#"["tus"]"#);
        assert!(!String::from_utf8_lossy(present.body()).contains("\"actions\""));
    }
}

#[test]
fn capabilities_and_method_override_interoperate_without_changing_basic_uploads() {
    let fixture = Fixture::new();
    let bytes = b"overridden PATCH";
    let object = object(bytes);
    for (method, fields) in [
        ("OPTIONS", ""),
        ("POST", "X-HTTP-Method-Override: OPTIONS\r\n"),
        ("OPTIONS", "Tus-Resumable: 0.2.2\r\n"),
        (
            "OPTIONS",
            "Tus-Resumable: 0.2.2\r\nTus-Resumable: 1.0.0\r\n",
        ),
    ] {
        let reply = request(
            &fixture,
            method,
            &upload_path(object),
            Some('c'),
            fields,
            b"",
        );
        check_status(&reply, 204);
        assert_eq!(field(&reply, "Tus-Version"), Some("1.0.0"));
        assert_eq!(
            field(&reply, "Tus-Max-Size"),
            Some(MAX_OBJECT_BYTES.to_string().as_str())
        );
        assert_eq!(field(&reply, "Allow"), Some("HEAD, PATCH, OPTIONS"));
        assert_eq!(field(&reply, "Tus-Extension"), None);
        assert_eq!(field(&reply, "Content-Length"), None);
        assert!(response(&reply).1.is_empty());
    }
    check_status(&batch(&fixture, "upload", object, 'a', r#"["tus"]"#), 200);
    let status = request(
        &fixture,
        "POST",
        &upload_path(object),
        Some('a'),
        &format!("{VERSION}X-HTTP-Method-Override: HEAD\r\n"),
        b"",
    );
    check_resume(&status, object, 0);
    let uploaded = request(
        &fixture,
        "POST",
        &upload_path(object),
        Some('a'),
        &format!(
            "{VERSION}{PATCH_MEDIA}X-HTTP-Method-Override: PATCH\r\nUpload-Offset: 0\r\nContent-Length: {}\r\nExpect: 100-continue\r\n",
            bytes.len()
        ),
        bytes,
    );
    check_patch(&uploaded, object.size);
    assert!(
        uploaded
            .output
            .starts_with(b"HTTP/1.1 100 Continue\r\n\r\n")
    );
    assert_eq!(
        fixture.request("GET", &path(object), 'b', b"").body(),
        bytes
    );

    let basic_bytes = b"basic remains a PUT";
    let basic = super::object(basic_bytes);
    let ordinary = request(
        &fixture,
        "PUT",
        &path(basic),
        Some('a'),
        &format!(
            "Content-Type: {BINARY_MEDIA}\r\nContent-Length: {}\r\nTus-Resumable: unknown\r\nTus-Resumable: duplicate\r\nX-HTTP-Method-Override: PATCH\r\nX-HTTP-Method-Override: HEAD\r\n",
            basic_bytes.len()
        ),
        basic_bytes,
    );
    check_status(&ordinary, 200);
    assert_eq!(
        fixture.request("GET", &path(basic), 'b', b"").body(),
        basic_bytes
    );
}

struct NoRead;
impl Read for NoRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("a refused Tus request consumed its upload body")
    }
}

fn refused_without_read(
    fixture: &Fixture,
    target: &str,
    token: Option<char>,
    metadata: &str,
    expected: u16,
) -> Reply {
    let header = request_head(
        "PATCH",
        target,
        token,
        &format!("{metadata}Expect: 100-continue\r\n"),
    );
    let reply = exchange(fixture, &header, b"", &mut NoRead);
    check_status(&reply, expected);
    assert!(!String::from_utf8_lossy(&reply.output).contains("100 Continue"));
    reply
}

#[test]
fn authentication_scope_repository_and_principal_ownership_precede_resume_or_body_read() {
    let fixture = Fixture::new();
    let bytes = b"principal-bound partial upload";
    let object = object(bytes);
    let target = upload_path(object);
    check_status(&batch(&fixture, "upload", object, 'a', r#"["tus"]"#), 200);
    check_patch(&patch(&fixture, object, 'a', 0, &bytes[..5], false), 5);
    let fields = format!("{VERSION}{PATCH_MEDIA}Upload-Offset: 5\r\nContent-Length: 1\r\n");
    for (token, expected) in [
        (None, 401),
        (Some('e'), 401),
        (Some('b'), 403),
        (Some('d'), 403),
        (Some('c'), 404),
    ] {
        refused_without_read(&fixture, &target, token, &fields, expected);
        let status = request(&fixture, "HEAD", &target, token, VERSION, b"");
        check_status(&status, expected);
        assert!(response(&status).1.is_empty());
        assert_eq!(field(&status, "Upload-Offset"), None);
    }
    refused_without_read(
        &fixture,
        &target.replace("/repo.git/", "/other.git/"),
        Some('a'),
        &fields,
        404,
    );
    let missing = super::object(b"other unknown object");
    let missing_fields = format!("{VERSION}{PATCH_MEDIA}Upload-Offset: 0\r\nContent-Length: 1\r\n");
    refused_without_read(
        &fixture,
        &upload_path(missing),
        Some('a'),
        &missing_fields,
        404,
    );
    let other_repository = Fixture::new();
    check_status(&resume(&other_repository, object, 'a'), 404);

    // Invalid endpoint metadata also remains behind authentication and scope.
    let invalid = format!(
        "Tus-Resumable: unsupported\r\nTus-Resumable: duplicate\r\n{PATCH_MEDIA}Upload-Offset: invalid\r\nContent-Length: 1\r\n"
    );
    refused_without_read(&fixture, &target, Some('e'), &invalid, 401);
    refused_without_read(&fixture, &target, Some('b'), &invalid, 403);
    check_resume(&resume(&fixture, object, 'a'), object, 5);

    // A second writer may negotiate the same identity, but receives its own
    // empty session rather than acquiring another principal's checked prefix.
    check_status(&batch(&fixture, "upload", object, 'c', r#"["tus"]"#), 200);
    check_resume(&resume(&fixture, object, 'c'), object, 0);
    check_patch(&patch(&fixture, object, 'c', 0, &bytes[..2], false), 2);
    check_resume(&resume(&fixture, object, 'c'), object, 2);
    check_resume(&resume(&fixture, object, 'a'), object, 5);
}

#[test]
fn versions_offsets_duplicates_extensions_and_lengths_refuse_before_continue() {
    let fixture = Fixture::new();
    let bytes = b"bounded Tus metadata";
    let object = object(bytes);
    let target = upload_path(object);
    check_status(&batch(&fixture, "upload", object, 'a', r#"["tus"]"#), 200);
    check_patch(&patch(&fixture, object, 'a', 0, &bytes[..2], false), 2);
    for version in ["", "Tus-Resumable: 0.2.2\r\n"] {
        let metadata = format!("{version}{PATCH_MEDIA}Upload-Offset: 2\r\nContent-Length: 1\r\n");
        let reply = refused_without_read(&fixture, &target, Some('a'), &metadata, 412);
        assert_eq!(field(&reply, "Tus-Version"), Some("1.0.0"));
        let head = request(&fixture, "HEAD", &target, Some('a'), version, b"");
        check_status(&head, 412);
        assert!(response(&head).1.is_empty());
    }
    for offset in ["", "-1", "2.0", "18446744073709551616"] {
        let metadata =
            format!("{VERSION}{PATCH_MEDIA}Upload-Offset: {offset}\r\nContent-Length: 1\r\n");
        refused_without_read(&fixture, &target, Some('a'), &metadata, 400);
    }
    let unchanged = request(
        &fixture,
        "PATCH",
        &target,
        Some('a'),
        &format!("{VERSION}{PATCH_MEDIA}Upload-Offset: 02\r\nContent-Length: 0\r\n"),
        b"",
    );
    check_patch(&unchanged, 2);
    refused_without_read(
        &fixture,
        &target,
        Some('a'),
        &format!("{VERSION}{PATCH_MEDIA}Content-Length: 1\r\n"),
        400,
    );
    for offset in [0, 1, 3, object.size + 1] {
        let metadata =
            format!("{VERSION}{PATCH_MEDIA}Upload-Offset: {offset}\r\nContent-Length: 0\r\n");
        refused_without_read(&fixture, &target, Some('a'), &metadata, 409);
    }
    for extra in [
        "Tus-Resumable: 1.0.0\r\n",
        "upload-offset: 2\r\n",
        "Upload-Length: 20\r\n",
        "Upload-Checksum: sha256 untrusted-digest\r\n",
        "Upload-Concat: partial\r\n",
        "Upload-Defer-Length: 1\r\n",
        "Upload-Metadata: private-metadata\r\n",
        "X-HTTP-Method-Override: PATCH\r\nx-http-method-override: PATCH\r\n",
    ] {
        let metadata =
            format!("{VERSION}{PATCH_MEDIA}Upload-Offset: 2\r\nContent-Length: 1\r\n{extra}");
        let reply = refused_without_read(&fixture, &target, Some('a'), &metadata, 400);
        let response = String::from_utf8_lossy(&reply.output);
        assert!(!response.contains("untrusted-digest"));
        assert!(!response.contains("private-metadata"));
    }
    refused_without_read(
        &fixture,
        &target,
        Some('a'),
        &format!(
            "{VERSION}Content-Type: application/octet-stream\r\nUpload-Offset: 2\r\nContent-Length: 1\r\n"
        ),
        415,
    );
    refused_without_read(
        &fixture,
        &target,
        Some('a'),
        &format!(
            "{VERSION}{PATCH_MEDIA}Upload-Offset: 2\r\nContent-Length: {}\r\n",
            object.size - 1
        ),
        413,
    );
    refused_without_read(
        &fixture,
        &target,
        Some('a'),
        &format!(
            "{VERSION}{PATCH_MEDIA}Upload-Offset: 2\r\nContent-Length: 1\r\nX-HTTP-Method-Override: DELETE\r\n"
        ),
        405,
    );
    check_resume(&resume(&fixture, object, 'a'), object, 2);
}

#[test]
fn incomplete_or_invalid_framing_never_reports_full_length_and_valid_prefixes_can_resume() {
    for (framing, wire) in [
        ("Content-Length: 3\r\n", b"c".as_slice()),
        ("Content-Length: 3\r\n", b"cdeEXTRA".as_slice()),
        (
            "Transfer-Encoding: chunked\r\n",
            b"3\r\ncde\r\n0\r\n".as_slice(),
        ),
        (
            "Transfer-Encoding: chunked\r\n",
            b"3\r\ncde\r\n0\r\n\r\nEXTRA".as_slice(),
        ),
        (
            "Transfer-Encoding: chunked\r\n",
            b"4\r\ncdeX\r\n0\r\n\r\n".as_slice(),
        ),
        ("Transfer-Encoding: chunked\r\n", b"z\r\n".as_slice()),
    ] {
        let mut fixture = Fixture::new();
        let bytes = b"abcde";
        let object = object(bytes);
        check_status(&batch(&fixture, "upload", object, 'a', r#"["tus"]"#), 200);
        check_patch(&patch(&fixture, object, 'a', 0, &bytes[..2], false), 2);
        let reply = request(
            &fixture,
            "PATCH",
            &upload_path(object),
            Some('a'),
            &format!("{VERSION}{PATCH_MEDIA}Upload-Offset: 2\r\n{framing}"),
            wire,
        );
        check_status(&reply, 400);
        assert_eq!(field(&reply, "Upload-Offset"), None);
        fixture.profile.lfs =
            Some(Service::open(&fixture.root, TENANT, REPO, INCARNATION).unwrap());
        let status = resume(&fixture, object, 'a');
        check_status(&status, 200);
        let offset = field(&status, "Upload-Offset")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!((2..object.size).contains(&offset), "{framing}: {wire:?}");
        assert_eq!(
            fixture.request("GET", &path(object), 'b', b"").result,
            Err(Status::NotFound)
        );
        assert_eq!(verify(&fixture, object, 'a').result, Err(Status::NotFound));
        check_patch(
            &patch(
                &fixture,
                object,
                'a',
                offset,
                &bytes[offset as usize..],
                false,
            ),
            object.size,
        );
        assert_eq!(
            fixture.request("GET", &path(object), 'b', b"").body(),
            bytes
        );
    }
}

#[test]
fn a_complete_wrong_digest_is_never_visible_as_full_length_or_verified_custody() {
    let mut fixture = Fixture::new();
    let object = object(b"correct");
    check_status(&batch(&fixture, "upload", object, 'a', r#"["tus"]"#), 200);
    let reply = patch(&fixture, object, 'a', 0, b"WRONG!!", false);
    check_status(&reply, 400);
    assert!(String::from_utf8_lossy(response(&reply).1).contains("lfs_tus_session_corrupt"));
    for reopen in [false, true] {
        if reopen {
            fixture.profile.lfs =
                Some(Service::open(&fixture.root, TENANT, REPO, INCARNATION).unwrap());
        }
        let status = resume(&fixture, object, 'a');
        check_status(&status, 400);
        assert_eq!(field(&status, "Upload-Offset"), None);
        assert!(response(&status).1.is_empty());
        assert_eq!(verify(&fixture, object, 'a').result, Err(Status::NotFound));
        assert_eq!(
            fixture.request("GET", &path(object), 'b', b"").result,
            Err(Status::NotFound)
        );
    }
}

#[test]
fn zero_length_upload_finishes_through_verified_custody_without_a_patch() {
    let mut fixture = Fixture::new();
    let object = object(b"");
    check_status(&batch(&fixture, "upload", object, 'c', r#"["tus"]"#), 200);
    fixture.profile.lfs = Some(Service::open(&fixture.root, TENANT, REPO, INCARNATION).unwrap());
    check_resume(&resume(&fixture, object, 'c'), object, 0);
    assert_eq!(verify(&fixture, object, 'c').result, Ok(()));
    let downloaded = fixture.request("GET", &path(object), 'b', b"");
    check_status(&downloaded, 200);
    assert!(downloaded.body().is_empty());
    assert_eq!(
        fixture.request("GET", &path(object), 'c', b"").result,
        Err(Status::Forbidden)
    );
}
