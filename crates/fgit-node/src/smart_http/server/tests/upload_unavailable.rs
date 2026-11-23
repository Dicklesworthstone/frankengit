use super::*;

fn exchange_unavailable(profile: &Profile, request: &[u8]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let (socket, _) = listener.accept().unwrap();
            let deadline = GitDaemonSessionDeadline::new(
                profile.timeout,
                crate::GitDaemonSessionWorkScaling::FLAT,
            );
            serve_connection(socket, deadline, profile)
        });
        let mut peer = TcpStream::connect(address).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        peer.write_all(request).unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        peer.read_to_string(&mut response).unwrap();
        assert!(!worker.join().unwrap());
        response
    })
}

#[test]
fn unavailable_upload_discovery_and_fetch_are_reads_and_receive_keeps_retry_identity() {
    let mut profile = profile();
    // A regular file cannot contain a repository. Node lease always fails after
    // the normal route, credential, media type and push-key checks succeed.
    let path = std::env::current_exe()
        .unwrap()
        .join("unavailable-repository");
    profile.nodes = Arc::new(NodeLanes::new(
        NodeConfig::new(
            path,
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
        ),
        1,
        "Smart HTTP",
    ));
    let auth = format!("Authorization: {BASIC}\r\n");
    let discovery = format!(
        "GET /repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: local\r\n{auth}\r\n"
    );
    let fetch = format!(
        "POST /repo.git/git-upload-pack HTTP/1.1\r\nHost: local\r\n{auth}Content-Type: application/x-git-upload-pack-request\r\nContent-Length: 4\r\n\r\n0000"
    );
    let mut push = head(&format!("{auth}Idempotency-Key: stable-push\r\n"));
    push.extend_from_slice(b"0000");
    for (request, expected) in [
        (
            discovery.as_bytes(),
            "repository read unavailable; retry the fetch\n",
        ),
        (
            fetch.as_bytes(),
            "repository read unavailable; retry the fetch\n",
        ),
        (
            push.as_slice(),
            "repository operation unavailable; a push may already be committed; retry with the same Idempotency-Key\n",
        ),
    ] {
        let response = exchange_unavailable(&profile, request);
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(
            headers.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
            "{response}"
        );
        assert_eq!(body, expected);
        assert!(headers.contains(&format!("Content-Length: {}\r\n", body.len())));
    }
}

#[test]
fn only_the_typed_upload_session_deadline_gives_the_operator_flag() {
    let deadline = crate::NodeGitDaemonServeRefusal::from(
        crate::GitDaemonTransportRefusal::SessionDeadlineExceeded {
            operation: "private operation details",
        },
    );
    let database_deadline = crate::NodeGitDaemonServeRefusal::from(
        crate::NodePackMaterializationRefusal::BudgetClassExhausted {
            class: fgit_runtime::BudgetClass::Database,
            dimension: fgit_runtime::Exhaustion::Deadline,
            operation: "private database operation",
        },
    );
    for (refusal, expected) in [
        (
            NodeSmartHttpRefusal::from(deadline),
            "upload-pack session deadline exceeded; the operator can raise --session-timeout-secs\n",
        ),
        (
            NodeSmartHttpRefusal::from(database_deadline),
            "repository read unavailable; retry the fetch\n",
        ),
    ] {
        let mut response = Vec::new();
        write_error(
            &mut response,
            HttpVersion::Http11,
            Status::Unavailable,
            Some(UploadUnavailable::from_refusal(&refusal)),
        )
        .unwrap();
        let response = std::str::from_utf8(&response).unwrap();
        assert_eq!(response.split_once("\r\n\r\n").unwrap().1, expected);
    }
}
