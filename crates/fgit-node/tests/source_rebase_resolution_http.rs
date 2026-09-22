#![forbid(unsafe_code)]
#[path = "source_rebase_http/support.rs"]
mod support;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{GitHashAlgorithm, GitOid};
use support::*;

fn resolved(
    endpoint: &Endpoint,
    command: &str,
    files: &[(&str, &[u8])],
    reverse: bool,
    chunked: bool,
) -> BinaryReply {
    let boundary = "rebase-resolution-fixture";
    let part = |name: &str, media: &str, bytes: &[u8]| {
        let mut out = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"../../never-open\"\r\nContent-Type: {media}\r\n\r\n").into_bytes();
        out.extend_from_slice(bytes);
        out.extend_from_slice(b"\r\n");
        out
    };
    let mut parts = vec![part(
        "command",
        "application/x-www-form-urlencoded",
        command.as_bytes(),
    )];
    for (name, bytes) in files {
        parts.push(part(name, "application/octet-stream", bytes));
    }
    if reverse {
        parts.reverse();
    }
    let mut body = parts.concat();
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let (wire, framing) = if chunked {
        let mut wire = Vec::new();
        for bytes in body.chunks(17) {
            wire.extend_from_slice(format!("{:x}\r\n", bytes.len()).as_bytes());
            wire.extend_from_slice(bytes);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        (wire, "Transfer-Encoding: chunked\r\n".to_owned())
    } else {
        (body.clone(), format!("Content-Length: {}\r\n", body.len()))
    };
    binary_exchange(
        endpoint,
        &request(
            endpoint,
            "POST",
            "/api/v1/source/rebase/resolve",
            'a',
            &format!("Content-Type: multipart/form-data; boundary={boundary}\r\n{framing}"),
            &wire,
        ),
        true,
    )
}

#[test]
fn two_conflicts_reconstruct_after_restart_and_exact_binary_empty_files_publish_only_at_the_end() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, h) = fixture(&root, format, 1);
        let credentials = root.0.join("credentials");
        configure(&node, &credentials);
        let before = generation(&node);
        let form = prepare_form(&h);
        let server = SourceServer::start(node, &credentials, 2);
        let first = post_form(&server.client, "rebase/prepare", 'a', &form, false);
        status(&first, 409);
        let pinned = form.clone()
            + "&expected_head="
            + &encode(field(json(&first), "snapshot_token").as_bytes());
        let partial_form = pinned.clone() + &format!("&resolution={}:61ff:theirs", h.first);
        let partial = post_form(&server.client, "rebase/resolve", 'a', &partial_form, true);
        status(&partial, 409);
        assert_eq!(
            field(json(&partial), "stopped_commit"),
            h.source.to_string()
        );
        assert_eq!(numeric(json(&partial), "step_count"), 1);
        assert_eq!(numeric(json(&partial), "resolution_consumed_commits"), 1);
        assert!(
            json(&partial).contains("\"candidate_commit\":null")
                && json(&partial).contains("\"bundle\":null")
        );
        let provisional = GitOid::from_hex(format, field(json(&partial), "rewritten")).unwrap();
        server.finish();
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before);
        assert_eq!(tip(&node, b"refs/heads/topic"), h.source);
        assert!(
            node.read_git_object(provisional).is_err(),
            "a resolved prefix must not be staged"
        );
        let server = SourceServer::start(node, &credentials, 5);
        assert_eq!(
            partial,
            post_form(&server.client, "rebase/resolve", 'a', &partial_form, false)
        );
        let full = pinned.clone()
            + &format!(
                "&resolution={}:61ff:file:100755:file_0&resolution={}:62:file:100644:file_1",
                h.first, h.source
            );
        let data = b"\0\xff\r\nexact binary";
        let files = [("file_0", data.as_slice()), ("file_1", b"".as_slice())];
        let prepared = resolved(&server.client, &full, &files, false, false);
        let (metadata, bundle) = extract_candidate(&prepared);
        assert_eq!(numeric(&metadata, "resolution_consumed_commits"), 2);
        assert_eq!(numeric(&metadata, "step_count"), 2);
        assert!(
            metadata.contains("original-commit-path-v1")
                && metadata.contains("\"series_complete\":true")
        );
        assert_eq!(
            prepared,
            resolved(&server.client, &full, &files, true, true)
        );
        let candidate = GitOid::from_hex(format, field(&metadata, "candidate_commit")).unwrap();
        let tree = GitOid::from_hex(format, field(&metadata, "root_tree")).unwrap();
        let command = apply_form(&h, candidate);
        status(
            &multipart(
                &server.client,
                "rebase/apply",
                'a',
                &command,
                &bundle,
                Some("resolved-series"),
            ),
            403,
        );
        let applied = multipart(
            &server.client,
            "rebase/apply",
            'b',
            &command,
            &bundle,
            Some("resolved-series"),
        );
        status(&applied, 200);
        assert!(json(&applied).contains("\"outcome\":\"committed\""));
        server.finish();
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before + 1);
        assert_eq!(tip(&node, b"refs/heads/topic"), candidate);
        assert_eq!(tip(&node, b"refs/heads/main"), h.onto);
        let binary = git_object_id(format, GitObjectKind::Blob, data);
        let empty = git_object_id(format, GitObjectKind::Blob, b"");
        assert_eq!(node.read_git_object(binary).unwrap().payload(), data);
        assert!(node.read_git_object(empty).unwrap().payload().is_empty());
        let object = node.read_git_object(tree).unwrap();
        let a = [b"100755 a\xff\0".as_slice(), binary.as_bytes()].concat();
        let b = [b"100644 b\0".as_slice(), empty.as_bytes()].concat();
        assert!(object.payload().windows(a.len()).any(|w| w == a));
        assert!(object.payload().windows(b.len()).any(|w| w == b));
        drop(object);
        let server = SourceServer::start(node, &credentials, 2);
        assert_eq!(
            applied,
            multipart(
                &server.client,
                "rebase/apply",
                'b',
                &command,
                &bundle,
                Some("resolved-series")
            )
        );
        let stale = post_form(&server.client, "rebase/resolve", 'a', &partial_form, false);
        status(&stale, 409);
        assert!(json(&stale).contains("source_snapshot_moved"));
        server.finish();
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before + 1);
        node.shutdown().unwrap();
    }
}

#[test]
fn resolution_refuses_bad_subjects_parts_and_grants_and_preserves_explicit_side_and_empty_choices()
{
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, h) = fixture(&root, format, 1);
        let credentials = root.0.join("credentials");
        configure(&node, &credentials);
        let before = generation(&node);
        let form = prepare_form(&h);
        let server = SourceServer::start(node, &credentials, 15);
        let first = post_form(&server.client, "rebase/prepare", 'a', &form, false);
        status(&first, 409);
        let pinned = form.clone()
            + "&expected_head="
            + &encode(field(json(&first), "snapshot_token").as_bytes());
        let one = format!("&resolution={}:61ff:theirs", h.first);
        status(
            &post_form(
                &server.client,
                "rebase/resolve",
                'a',
                &(form.clone() + &one),
                false,
            ),
            400,
        );
        status(
            &post_form(
                &server.client,
                "rebase/resolve",
                'a',
                &(pinned.clone() + &one + "&force=true"),
                false,
            ),
            400,
        );
        status(
            &post_form(
                &server.client,
                "rebase/resolve",
                'a',
                &(pinned.clone() + &format!("&resolution={}:61ff:theirs", h.onto)),
                false,
            ),
            400,
        );
        status(
            &post_form(
                &server.client,
                "rebase/resolve",
                'a',
                &(pinned.clone() + &one + &one),
                false,
            ),
            400,
        );
        status(
            &post_form(
                &server.client,
                "rebase/resolve",
                'a',
                &(pinned.clone() + &format!("&resolution={}:6f6e746f:theirs", h.first)),
                false,
            ),
            409,
        );
        status(
            &post_form(
                &server.client,
                "rebase/resolve",
                'a',
                &(pinned.clone() + &format!("&resolution={}:61ff:file:100644:file_0", h.first)),
                false,
            ),
            400,
        );
        status(
            &resolved(
                &server.client,
                &(pinned.clone() + &one),
                &[("file_0", b"unused")],
                false,
                false,
            ),
            400,
        );
        let both = one.clone() + &format!("&resolution={}:62:theirs", h.source);
        status(
            &post_form(
                &server.client,
                "rebase/resolve",
                'a',
                &(pinned.clone() + &both + "&max_conflicts=1"),
                false,
            ),
            413,
        );
        for (token, key, expected) in [
            ('b', "", 403),
            ('a', "Idempotency-Key: no-resolution-transaction\r\n", 400),
        ] {
            let refused = binary_exchange(
                &server.client,
                &request(
                    &server.client,
                    "POST",
                    "/api/v1/source/rebase/resolve",
                    token,
                    &format!(
                        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\nExpect: 100-continue\r\n{key}"
                    ),
                    &[],
                ),
                true,
            );
            status(&refused, expected);
            assert!(!refused.head.contains("100 Continue"));
        }
        let ours = pinned.clone() + &format!("&resolution={}:61ff:ours", h.first);
        let empty_stop = post_form(&server.client, "rebase/resolve", 'a', &ours, false);
        status(&empty_stop, 409);
        assert_eq!(field(json(&empty_stop), "state"), "became_empty");
        assert_eq!(numeric(json(&empty_stop), "resolution_consumed_commits"), 1);
        assert_eq!(numeric(json(&empty_stop), "step_count"), 0);
        let all_ours =
            ours.replace("empty=stop", "empty=drop") + &format!("&resolution={}:62:ours", h.source);
        let dropped = post_form(&server.client, "rebase/resolve", 'a', &all_ours, false);
        let (metadata, _) = extract_candidate(&dropped);
        assert_eq!(field(&metadata, "candidate_commit"), h.onto.to_string());
        assert_eq!(numeric(&metadata, "pack_objects"), 0);
        for choice in ["base", "delete"] {
            let command = pinned.clone()
                + &format!(
                    "&resolution={}:61ff:{choice}&resolution={}:62:theirs",
                    h.first, h.source
                );
            let reply = post_form(&server.client, "rebase/resolve", 'a', &command, false);
            let (metadata, _) = extract_candidate(&reply);
            assert!(metadata.contains(&format!("\"choice\":\"{choice}\"")));
            assert_eq!(numeric(&metadata, "resolution_consumed_commits"), 2);
        }
        server.finish();
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before);
        assert_eq!(tip(&node, b"refs/heads/topic"), h.source);
        node.shutdown().unwrap();
    }
}
