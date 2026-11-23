//! Resumable custody survives a real client half-close and a cold native reopen.
use super::*;
use std::net::Shutdown;

fn write_payload(stream: &mut TcpStream, mut size: u64) {
    let chunk = [0xd3; CHUNK];
    while size != 0 {
        let count = size.min(CHUNK as u64) as usize;
        stream.write_all(&chunk[..count]).unwrap();
        size -= count as u64;
    }
}

fn assert_empty_response(stream: &mut TcpStream, status: u16, offset: u64) {
    let response = head(stream, status);
    assert!(response.contains("Tus-Resumable: 1.0.0\r\n"), "{response}");
    assert!(
        response.contains(&format!("Upload-Offset: {offset}\r\n")),
        "{response}"
    );
    assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0, "no response body");
}

#[test]
fn interrupted_tus_upload_reopens_at_durable_prefix_and_finishes_without_authority_change() {
    let scratch = Scratch::new();
    let object = generated_object(2 * 1024 * 1024 + 73);
    // Cross the periodic checkpoint, then interrupt at a nonaligned boundary.
    // Recovery must include the final successful bytes, not just the checkpoint.
    let prefix = 1024 * 1024 + 37;
    let config = scratch.config();
    let (mut node, _) = OneNode::init(config.clone()).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let incarnation = node.repository_incarnation_id();
    let before = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    let grants = scratch.0.join("credentials");
    credentials(&grants, incarnation, true);
    let object_suffix = format!("/info/lfs/objects/{}/{}", object.oid, object.size);
    let upload_suffix = format!("{object_suffix}/tus");
    let server = Server::start(node, grants.clone(), 2);
    let route = server.route.clone();

    let batch = format!(
        "{{\"operation\":\"upload\",\"transfers\":[\"basic\",\"tus\"],\"objects\":[{{\"oid\":\"{}\",\"size\":{}}}]}}",
        object.oid, object.size,
    );
    let mut request = server.request(
        "POST",
        "/info/lfs/objects/batch",
        'a',
        &format!(
            "Content-Type: application/vnd.git-lfs+json\r\nContent-Length: {}\r\n",
            batch.len(),
        ),
    );
    request.write_all(batch.as_bytes()).unwrap();
    let negotiated = small_response(&mut request, 200);
    assert!(negotiated.contains("\"transfer\":\"tus\""), "{negotiated}");
    assert!(!negotiated.contains("\"error\":"), "{negotiated}");
    assert!(
        negotiated.contains(&format!(
            "\"upload\":{{\"href\":\"http://{}{route}{upload_suffix}\"}}",
            server.address,
        )),
        "{negotiated}"
    );

    let mut interrupted = server.request(
        "PATCH",
        &upload_suffix,
        'a',
        &format!(
            "Tus-Resumable: 1.0.0\r\nUpload-Offset: 0\r\nContent-Type: application/offset+octet-stream\r\nContent-Length: {}\r\nExpect: 100-continue\r\n",
            object.size,
        ),
    );
    assert_eq!(head(&mut interrupted, 100), "HTTP/1.1 100 Continue\r\n\r\n");
    write_payload(&mut interrupted, prefix);
    interrupted.shutdown(Shutdown::Write).unwrap();
    let refused = small_response(&mut interrupted, 400);
    assert!(refused.contains("incomplete_lfs_body"), "{refused}");
    let receipt = server.finish();
    assert_eq!(receipt.accepted_sessions(), 2);
    assert_eq!(receipt.completed_sessions(), 1);
    assert_eq!(receipt.refused_sessions(), 1);

    // The first listener has drained and shut the node down. The next instance
    // obtains its offset from durable custody, not a live connection or cache.
    let mut reopened = OneNode::open_existing(config.clone()).unwrap();
    assert_eq!(reopened.repository_incarnation_id(), incarnation);
    let selected = reopened
        .runtime()
        .block_on(reopened.authenticate_authority_head())
        .unwrap();
    assert_eq!(selected.receipt().generation(), before);
    reopened
        .bring_into_service(selected.receipt().generation())
        .unwrap();
    let server = Server::start(reopened, grants, 6);
    assert_eq!(server.route, route);

    let mut status = server.request("HEAD", &upload_suffix, 'a', "Tus-Resumable: 1.0.0\r\n");
    let response = head(&mut status, 200);
    assert!(response.contains("Tus-Resumable: 1.0.0\r\n"), "{response}");
    assert!(
        response.contains("Cache-Control: no-store\r\n"),
        "{response}"
    );
    assert!(
        response.contains(&format!("Upload-Offset: {prefix}\r\n")),
        "{response}"
    );
    assert!(
        response.contains(&format!("Upload-Length: {}\r\n", object.size)),
        "{response}"
    );
    assert_eq!(status.read(&mut [0; 1]).unwrap(), 0, "HEAD has no body");

    // Another authenticated writer has no right to this principal's staging.
    let mut other = server.request("HEAD", &upload_suffix, 'c', "Tus-Resumable: 1.0.0\r\n");
    let response = head(&mut other, 404);
    assert!(!response.contains("Upload-Offset:"), "{response}");
    assert_eq!(
        other.read(&mut [0; 1]).unwrap(),
        0,
        "refused HEAD has no body"
    );

    let remaining = object.size - prefix;
    let mut resumed = server.request(
        "PATCH",
        &upload_suffix,
        'a',
        &format!(
            "Tus-Resumable: 1.0.0\r\nUpload-Offset: {prefix}\r\nContent-Type: application/offset+octet-stream\r\nContent-Length: {remaining}\r\nExpect: 100-continue\r\n",
        ),
    );
    assert_eq!(head(&mut resumed, 100), "HTTP/1.1 100 Continue\r\n\r\n");
    write_payload(&mut resumed, remaining);
    assert_empty_response(&mut resumed, 204, object.size);
    assert_empty_response(
        &mut server.request("HEAD", &upload_suffix, 'a', "Tus-Resumable: 1.0.0\r\n"),
        200,
        object.size,
    );

    let verification = format!("{{\"oid\":\"{}\",\"size\":{}}}", object.oid, object.size);
    let mut verify = server.request(
        "POST",
        &format!("{object_suffix}/verify"),
        'a',
        &format!(
            "Content-Type: application/vnd.git-lfs+json\r\nContent-Length: {}\r\n",
            verification.len(),
        ),
    );
    verify.write_all(verification.as_bytes()).unwrap();
    assert_eq!(small_response(&mut verify, 200), "{}");

    let mut download = server.request("GET", &object_suffix, 'b', "");
    let response = head(&mut download, 200);
    assert_eq!(content_length(&response), object.size);
    assert!(response.contains("Content-Type: application/octet-stream\r\n"));
    let mut buffer = [0; CHUNK];
    let mut hash = Sha256Hasher::new();
    let mut received = 0_u64;
    loop {
        let count = download.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        received += count as u64;
        assert!(received <= object.size);
        assert!(buffer[..count].iter().all(|byte| *byte == 0xd3));
        hash.update(&buffer[..count]);
    }
    assert_eq!(received, object.size);
    assert_eq!(hex(&hash.finish()), object.oid.to_string());
    let receipt = server.finish();
    assert_eq!(receipt.accepted_sessions(), 6);
    assert_eq!(receipt.completed_sessions(), 5);
    assert_eq!(receipt.refused_sessions(), 1);

    let reopened = OneNode::open_existing(config).unwrap();
    assert_eq!(reopened.repository_incarnation_id(), incarnation);
    assert_eq!(
        reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation(),
        before,
        "resuming and completing LFS custody cannot publish Git authority"
    );
    reopened.shutdown().unwrap();
}
