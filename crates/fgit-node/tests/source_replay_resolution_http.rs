#![forbid(unsafe_code)]
//! Native conflict reproduction and exact resolution through the real listener.
#[path = "source_replay_http/support.rs"]
mod support;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::GitHashAlgorithm;
use support::*;

fn upload(
    endpoint: &Endpoint,
    direction: &str,
    token: char,
    form: &str,
    files: &[(&str, &[u8])],
    chunked: bool,
) -> BinaryReply {
    let boundary = "replay-resolutions";
    let mut parts = Vec::new();
    parts.push(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"command\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{form}\r\n").into_bytes());
    for (name, content) in files {
        let mut part = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"../../not-a-host-path\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
        part.extend_from_slice(content);
        part.extend_from_slice(b"\r\n");
        parts.push(part);
    }
    if chunked {
        parts.reverse();
    }
    let mut body = parts.concat();
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let (body, framing) = if chunked {
        let mut bytes = Vec::new();
        for part in body.chunks(17) {
            bytes.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            bytes.extend_from_slice(part);
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"0\r\n\r\n");
        (bytes, "Transfer-Encoding: chunked\r\n".into())
    } else {
        let length = body.len();
        (body, format!("Content-Length: {length}\r\n"))
    };
    binary_exchange(
        endpoint,
        &request(
            endpoint,
            "POST",
            &format!("/api/v1/source/{direction}/resolve"),
            token,
            &format!("Content-Type: multipart/form-data; boundary={boundary}\r\n{framing}"),
            &body,
        ),
        true,
    )
}
fn candidate_form(
    format: GitHashAlgorithm,
    reference: &[u8],
    target: &str,
    metadata: &str,
) -> String {
    format!(
        "object_format={}&ref={}&expected_commit={target}&candidate_commit={}",
        format.as_str(),
        encode(reference),
        field(metadata, "candidate_commit")
    )
}

#[test]
fn all_side_choices_and_deletion_use_the_exact_replay_triple_without_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = non_clean_fixture(&root, format, true);
        let before = generation(&node);
        let path = root.0.join("credentials");
        configure(&node, &path);
        let server = SourceServer::start(node, &path, 12);
        let command = form(
            &data.target_ref,
            &data.source_ref,
            data.target_tip,
            data.source_tip,
            data.source_tip,
        );
        for direction in ["cherry-pick", "revert"] {
            let first = post_form(
                &server.client,
                &format!("{direction}/prepare"),
                'a',
                &command,
                false,
            ); // 1
            status(&first, 409);
            let pinned = format!(
                "{command}&expected_head={}",
                field(json(&first), "snapshot_token")
            );
            let descriptor = hex(b"file\xff.txt");
            let ours = post_form(
                &server.client,
                &format!("{direction}/resolve"),
                'a',
                &format!("{pinned}&resolution={descriptor}:ours"),
                true,
            ); // 2
            status(&ours, 200);
            assert_eq!(field(json(&ours), "state"), "no_change");
            assert!(json(&ours).contains("\"choice\":\"ours\""));
            assert!(json(&ours).contains("\"bundle\":null"));
            let theirs = post_form(
                &server.client,
                &format!("{direction}/resolve"),
                'a',
                &format!("{pinned}&resolution={descriptor}:theirs"),
                false,
            ); // 3
            let (metadata, bundle) = extract_candidate(&theirs);
            assert_eq!(field(&metadata, "state"), "resolved");
            assert!(metadata.contains("\"choice\":\"theirs\""));
            let inspect = candidate_form(
                format,
                data.target_ref.as_bytes(),
                &data.target_tip.to_string(),
                &metadata,
            );
            let inspected = multipart(&server.client, "inspect", 'a', &inspect, &bundle, None); // 4
            status(&inspected, 200);
            let expected = if direction == "cherry-pick" {
                b"right\n".as_slice()
            } else {
                b"base\n".as_slice()
            };
            assert!(json(&inspected).contains(&format!("\"after_hex\":\"{}\"", hex(expected))));
            for choice in ["base", "delete"] {
                // 5, 6
                let reply = post_form(
                    &server.client,
                    &format!("{direction}/resolve"),
                    'a',
                    &format!("{pinned}&resolution={descriptor}:{choice}"),
                    false,
                );
                let (metadata, _) = extract_candidate(&reply);
                assert!(metadata.contains(&format!("\"choice\":\"{choice}\"")));
                if choice == "delete" {
                    assert!(metadata.contains("\"result\":null"));
                }
            }
        }
        assert_eq!(server.finish().accepted_sessions(), 12);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn empty_and_binary_file_resolutions_survive_inspection_explicit_apply_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = non_clean_fixture(&root, format, true);
        let before = generation(&node);
        let path = root.0.join("credentials");
        configure(&node, &path);
        let server = SourceServer::start(node, &path, 8);
        let command = form(
            &data.target_ref,
            &data.source_ref,
            data.target_tip,
            data.source_tip,
            data.source_tip,
        );
        let conflict = post_form(&server.client, "cherry-pick/prepare", 'a', &command, false); // 1
        status(&conflict, 409);
        let pinned = format!(
            "{command}&expected_head={}&resolution={}:file:100755:file_0",
            field(json(&conflict), "snapshot_token"),
            hex(b"file\xff.txt")
        );
        let (empty_metadata, empty_bundle) = extract_candidate(&upload(
            &server.client,
            "cherry-pick",
            'a',
            &pinned,
            &[("file_0", b"")],
            true,
        )); // 2
        assert!(
            empty_metadata.contains(&git_object_id(format, GitObjectKind::Blob, b"").to_string())
        );
        let empty = candidate_form(
            format,
            data.target_ref.as_bytes(),
            &data.target_tip.to_string(),
            &empty_metadata,
        );
        status(
            &multipart(&server.client, "inspect", 'a', &empty, &empty_bundle, None),
            200,
        ); // 3
        let bytes = b"\0\xff\r\n--replay-resolutionsX\r\n".as_slice();
        let prepared = upload(
            &server.client,
            "cherry-pick",
            'a',
            &pinned,
            &[("file_0", bytes)],
            true,
        ); // 4
        let (metadata, bundle) = extract_candidate(&prepared);
        assert!(metadata.contains(&git_object_id(format, GitObjectKind::Blob, bytes).to_string()));
        assert_eq!(
            upload(
                &server.client,
                "cherry-pick",
                'a',
                &pinned,
                &[("file_0", bytes)],
                false
            ),
            prepared
        ); // 5
        let apply = candidate_form(
            format,
            data.target_ref.as_bytes(),
            &data.target_tip.to_string(),
            &metadata,
        );
        status(
            &multipart(&server.client, "inspect", 'a', &apply, &bundle, None),
            200,
        ); // 6
        status(
            &multipart(
                &server.client,
                "apply",
                'a',
                &apply,
                &bundle,
                Some("resolved-replay"),
            ),
            403,
        ); // 7
        let committed = multipart(
            &server.client,
            "apply",
            'b',
            &apply,
            &bundle,
            Some("resolved-replay"),
        ); // 8
        status(&committed, 200);
        assert!(json(&committed).contains("\"outcome\":\"committed\""));
        assert_eq!(server.finish().accepted_sessions(), 8);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1);
        let server = SourceServer::start(node, &path, 3);
        status(
            &upload(
                &server.client,
                "cherry-pick",
                'a',
                &pinned,
                &[("file_0", bytes)],
                false,
            ),
            409,
        ); // 1
        assert_eq!(
            multipart(
                &server.client,
                "apply",
                'b',
                &apply,
                &bundle,
                Some("resolved-replay")
            ),
            committed
        ); // 2
        let query = format!(
            "object_format={}&ref={}&path_hex={}",
            format.as_str(),
            encode(data.target_ref.as_bytes()),
            hex(b"file\xff.txt")
        );
        let file = post_form(&server.client, "blob", 'a', &query, false); // 3
        status(&file, 200);
        assert_eq!(field(json(&file), "content_hex"), hex(bytes));
        assert_eq!(field(json(&file), "kind"), "executable");
        assert_eq!(server.finish().accepted_sessions(), 3);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1);
        node.shutdown().unwrap();
    }
}

#[test]
fn stale_ambiguous_extra_and_unscoped_resolutions_refuse_without_staging() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = non_clean_fixture(&root, format, true);
        let before = generation(&node);
        let path = root.0.join("credentials");
        configure(&node, &path);
        let server = SourceServer::start(node, &path, 16);
        let command = form(
            &data.target_ref,
            &data.source_ref,
            data.target_tip,
            data.source_tip,
            data.source_tip,
        );
        let conflict = post_form(&server.client, "cherry-pick/prepare", 'a', &command, false); // 1
        status(&conflict, 409);
        let head = field(json(&conflict), "snapshot_token");
        let pinned = format!("{command}&expected_head={head}");
        let file = hex(b"file\xff.txt");
        let valid = format!("{pinned}&resolution={file}:ours");
        for (bad, expected) in [
            // 2..7
            (pinned.clone(), 400),
            (format!("{valid}&resolution={file}:theirs"), 400),
            (format!("{pinned}&resolution=636c65616e:ours"), 409),
            (
                valid.replace(head, &format!("alg:1:{}", "ab".repeat(32))),
                409,
            ),
            (format!("{command}&resolution={file}:ours"), 400),
            (valid.clone() + "&principal=admin", 400),
        ] {
            let refused = post_form(&server.client, "cherry-pick/resolve", 'a', &bad, false);
            status(&refused, expected);
            assert!(!json(&refused).contains("\"state\":\"no_change\""));
        }
        let descriptor = format!("{pinned}&resolution={file}:file:100644:file_0");
        status(
            &upload(&server.client, "cherry-pick", 'a', &descriptor, &[], false),
            400,
        ); // 8 missing file
        status(
            &upload(
                &server.client,
                "cherry-pick",
                'a',
                &valid,
                &[("file_0", b"unused")],
                false,
            ),
            400,
        ); // 9 unused file
        status(
            &upload(
                &server.client,
                "cherry-pick",
                'a',
                &(descriptor.clone() + "&resolution=61:file:100644:file_0"),
                &[("file_0", b"present")],
                false,
            ),
            400,
        ); // 10 true repeated consumption
        status(
            &upload(
                &server.client,
                "cherry-pick",
                'a',
                &(descriptor.clone() + "&max_text_bytes=1"),
                &[("file_0", b"ab")],
                false,
            ),
            413,
        ); // 11 narrowed byte budget
        status(
            &upload(
                &server.client,
                "cherry-pick",
                'a',
                &descriptor.replace(":100644:", ":120000:"),
                &[("file_0", b"a")],
                false,
            ),
            400,
        ); // 12 unsupported mode
        for (token, key, expected) in [
            ('b', "", 403),
            ('a', "Idempotency-Key: no-read-key\r\n", 400),
        ] {
            // 13, 14
            let reply = binary_exchange(
                &server.client,
                &request(
                    &server.client,
                    "POST",
                    "/api/v1/source/cherry-pick/resolve",
                    token,
                    &format!(
                        "Content-Type: multipart/form-data; boundary=replay-resolutions\r\nContent-Length: 200\r\nExpect: 100-continue\r\n{key}"
                    ),
                    &[],
                ),
                false,
            );
            status(&reply, expected);
            assert!(!reply.head.contains("100 Continue"));
        }
        status(
            &post_form(&server.client, "cherry-pick/prepare", 'a', &valid, false),
            400,
        ); // 15 never fallback
        let unseen = binary_exchange(
            &server.client,
            &request(
                &server.client,
                "POST",
                "/api/v1/outcomes",
                'a',
                "Content-Length: 0\r\nIdempotency-Key: read-only-source-query\r\n",
                &[],
            ),
            true,
        ); // 16
        status(&unseen, 200);
        assert!(json(&unseen).contains("key_not_observed"));
        assert_eq!(server.finish().accepted_sessions(), 16);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
