#![forbid(unsafe_code)]
//! Real TCP preparation -> downloaded bundle -> independent review -> merge.
//! The client never invokes the local preparation API or supplies a canned pack.
#[path = "candidate_preparation_http/support.rs"]
mod support;
use support::*;

use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::pull_request::PullRequestData;
use fgit_git_object::{AcceptanceProfile, ParseLimits, ParsedObject, parse_object_body};
use fgit_node::{LoopbackReceiveSession, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PolicyEpoch, RefName};
use std::fs;
use std::path::Path;

const ORIGINAL: &[u8] = b"one\ntwo\nthree\n";
const EDITED: &[u8] = b"one\nEDITED\nthree\n";
const DESTINATION: &[u8] = b"moved\xff.txt";

// Small test-only loose-object encoder. Production still imports and verifies
// each object through its normal native object/closure/admission boundary.
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let name = match kind {
        GitObjectKind::Blob => "blob",
        GitObjectKind::Tree => "tree",
        GitObjectKind::Commit => "commit",
        GitObjectKind::Tag => "tag",
    };
    let id = git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend(length.to_le_bytes());
    bytes.extend((!length).to_le_bytes());
    bytes.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    bytes.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    let directory = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&hex[2..]), bytes).unwrap();
    id
}
fn tree(root: &Path, format: GitHashAlgorithm, entries: &[(&str, &[u8], GitOid)]) -> GitOid {
    let mut body = Vec::new();
    for (mode, name, oid) in entries {
        body.extend_from_slice(mode.as_bytes());
        body.push(b' ');
        body.extend_from_slice(name);
        body.push(0);
        body.extend_from_slice(oid.as_bytes());
    }
    loose(root, format, GitObjectKind::Tree, &body)
}
fn commit(
    root: &Path,
    format: GitHashAlgorithm,
    tree: GitOid,
    parent: Option<GitOid>,
    label: &str,
) -> GitOid {
    let mut body = format!("tree {tree}\n");
    if let Some(parent) = parent {
        body.push_str(&format!("parent {parent}\n"));
    }
    body.push_str("author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n");
    body.push_str(label);
    body.push('\n');
    loose(root, format, GitObjectKind::Commit, body.as_bytes())
}
fn rename_fixture(
    root: &Scratch,
    format: GitHashAlgorithm,
    divergent: bool,
) -> (OneNode, PullRequestData) {
    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(head.receipt().generation())
        .unwrap();
    let source = root.0.join("rename-source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(source.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let original = loose(&source, format, GitObjectKind::Blob, ORIGINAL);
    let edited = loose(&source, format, GitObjectKind::Blob, EDITED);
    let keep = loose(&source, format, GitObjectKind::Blob, b"preserved\n");
    let base_tree = tree(
        &source,
        format,
        &[("100644", b"keep", keep), ("100644", b"text", original)],
    );
    let base = commit(&source, format, base_tree, None, "base");
    let target_tree = if divergent {
        tree(
            &source,
            format,
            &[
                ("100644", b"different", original),
                ("100644", b"keep", keep),
            ],
        )
    } else {
        tree(
            &source,
            format,
            &[("100644", b"keep", keep), ("100755", b"text", edited)],
        )
    };
    let nested = tree(&source, format, &[("100644", DESTINATION, original)]);
    let source_tree = tree(
        &source,
        format,
        &[("100644", b"keep", keep), ("40000", b"nested", nested)],
    );
    let target_tip = commit(&source, format, target_tree, Some(base), "target");
    let source_tip = commit(&source, format, source_tree, Some(base), "source");
    fs::write(source.join("refs/heads/main"), format!("{target_tip}\n")).unwrap();
    fs::write(source.join("refs/heads/topic"), format!("{source_tip}\n")).unwrap();
    let result = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &source,
            OWNER,
            b"rename-http-fixture",
        ))
        .unwrap();
    assert!(!result.commands.is_empty());
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    (
        node,
        PullRequestData {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip,
            target_tip,
            title: "Move and independent edit".into(),
            body: String::new(),
        },
    )
}
fn open_and_command(server: &Server, data: &PullRequestData) -> String {
    committed(&post(
        &server.client,
        1,
        "open",
        'a',
        "rename-pr-open",
        &form(data, 0),
        false,
    ));
    let reviews = get(&server.client, "/api/v1/pulls/1/reviews", 'b');
    status(&reviews, 200);
    preparation_form(
        data,
        PolicyEpoch::try_new(numeric(&reviews.body, "policy_epoch")).unwrap(),
    )
}
fn error(reply: &BinaryReply, expected: u16, code: &str) {
    assert_eq!(
        reply.status,
        expected,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let body = std::str::from_utf8(&reply.body).unwrap();
    assert!(body.contains(&format!("\"code\":\"{code}\"")), "{body}");
    assert!(body.contains("\"outcome_unknown\":false"));
    assert!(!body.contains("\"outcome\":\"refused\""));
    assert!(!body.contains("\"candidate\":{"));
}
fn assert_published_tree(node: &OneNode, candidate: &Candidate) {
    let format = candidate.data.source_tip.algorithm();
    let limits = ParseLimits {
        tree_reference_bytes: format.digest_len(),
        ..ParseLimits::default()
    };
    let commit = node.read_git_object(candidate.binding.commit).unwrap();
    let ParsedObject::Commit(parsed) = parse_object_body(
        GitObjectKind::Commit,
        commit.payload(),
        AcceptanceProfile::StrictCreate,
        &limits,
    )
    .unwrap() else {
        panic!("commit required");
    };
    let oid = |bytes: &[u8]| GitOid::from_hex(format, std::str::from_utf8(bytes).unwrap()).unwrap();
    let parents: Vec<_> = parsed.parent_references().map(oid).collect();
    assert_eq!(
        parents,
        [candidate.data.target_tip, candidate.data.source_tip]
    );
    let tree = node
        .read_git_object(oid(parsed.tree_reference().unwrap()))
        .unwrap();
    let ParsedObject::Tree(entries) = parse_object_body(
        GitObjectKind::Tree,
        tree.payload(),
        AcceptanceProfile::StrictCreate,
        &limits,
    )
    .unwrap() else {
        panic!("tree required");
    };
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.name.as_slice())
            .collect::<Vec<_>>(),
        [b"keep".as_slice(), b"nested".as_slice()]
    );
    let hex: String = entries[1]
        .object_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let nested = node
        .read_git_object(GitOid::from_hex(format, &hex).unwrap())
        .unwrap();
    let ParsedObject::Tree(entries) = parse_object_body(
        GitObjectKind::Tree,
        nested.payload(),
        AcceptanceProfile::StrictCreate,
        &limits,
    )
    .unwrap() else {
        panic!("nested tree required");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, DESTINATION);
    assert_eq!(entries[0].mode, b"100755");
    let edited = git_object_id(format, GitObjectKind::Blob, EDITED);
    assert_eq!(entries[0].object_id, edited.as_bytes());
    assert_eq!(node.read_git_object(edited).unwrap().payload(), EDITED);
}

#[test]
fn http_exact_rename_preserves_cross_directory_edits_modes_review_and_retry_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = rename_fixture(&root, format, false);
        let before = generation(&node);
        let path = root.0.join("credentials");
        configure(&node, &path);
        let server = Server::start(node, &path, 6, true, true);
        let command = open_and_command(&server, &data); // 1, 2
        let legacy = prepare(&server.client, 1, 'd', &command, false); // 3
        assert_eq!(legacy.status, 409);
        let legacy_json = std::str::from_utf8(&legacy.body).unwrap();
        assert!(legacy_json.contains("\"profile\":\"path-merge-v1\""));
        assert!(legacy_json.contains("\"candidate\":null,\"bundle\":null"));
        assert_eq!(
            prepare(
                &server.client,
                1,
                'd',
                &(command.clone() + "&profile=path-merge-v1"),
                true
            ),
            legacy
        ); // 4
        let exact_command = command + "&profile=exact-renames-v1";
        let original = prepare(&server.client, 1, 'd', &exact_command, false); // 5
        let (candidate, metadata) = extract(&original, data.clone());
        assert!(metadata.contains("\"profile\":\"exact-renames-v1\""));
        assert!(!metadata.contains("\"profile\":\"path-merge-v1\""));
        assert_eq!(
            prepare(&server.client, 1, 'd', &exact_command, true),
            original
        ); // 6
        assert_eq!(server.finish().accepted_sessions(), 6);
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before + 1,
            "only PR creation may publish"
        );
        assert!(node.read_git_object(candidate.binding.commit).is_err());
        let sentinel = LoopbackReceiveSession::authenticated(
            FOREIGN,
            IdempotencyKey::new(b"read-only-candidate-preparation".to_vec()).unwrap(),
        );
        assert!(matches!(
            node.runtime()
                .block_on(node.recover_transaction_in(&node.request_context(), &sentinel,))
                .unwrap(),
            RequestRecovery::KeyNotObserved
        ));
        let server = Server::start(node, &path, 6, true, true);
        assert_eq!(
            prepare(&server.client, 1, 'd', &exact_command, true),
            original
        ); // 1
        accepted(&send(
            &server.client,
            "reviews/approve",
            'b',
            "approve-rename",
            &review_form(&candidate, 0),
            Some(&candidate.bundle),
            true,
        )); // 2
        let command = merge_form(&candidate, &[REVIEWER]);
        let published = send(
            &server.client,
            "merge",
            'c',
            "merge-rename",
            &command,
            Some(&candidate.bundle),
            false,
        ); // 3
        accepted(&published);
        assert_eq!(
            send(
                &server.client,
                "merge",
                'c',
                "merge-rename",
                &command,
                None,
                true
            ),
            published
        ); // 4
        let current = get(&server.client, "/api/v1/pulls/1", 'a'); // 5
        status(&current, 200);
        assert!(current.body.contains("\"state\":\"merged\""));
        error(
            &prepare(&server.client, 1, 'd', &exact_command, false),
            409,
            "preparation_subject_moved",
        ); // 6
        assert_eq!(server.finish().accepted_sessions(), 6);
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before + 3,
            "PR, independent approval, coupled merge only"
        );
        let view = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            view.snapshot().refs[&data.target_ref],
            candidate.binding.commit
        );
        assert_eq!(view.snapshot().refs[&data.source_ref], data.source_tip);
        assert_published_tree(&node, &candidate);
        node.shutdown().unwrap();
    }
}

#[test]
fn http_divergent_renames_return_typed_conflict_without_fallback_or_path_disclosure() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = rename_fixture(&root, format, true);
        let before = generation(&node);
        let path = root.0.join("credentials");
        configure(&node, &path);
        let server = Server::start(node, &path, 5, true, false);
        let command = open_and_command(&server, &data); // 1, 2
        // A permitted PathMergeV1 twin proves an implementation could return
        // something, but doing so for an exact-rename refusal would be wrong.
        let (candidate, _) = extract(
            &prepare(&server.client, 1, 'd', &command, false),
            data.clone(),
        ); // 3
        let command = command + "&profile=exact-renames-v1";
        let refused = prepare(&server.client, 1, 'd', &command, false); // 4
        error(&refused, 409, "rename_destinations_diverge");
        let body = std::str::from_utf8(&refused.body).unwrap();
        for private in ["different", "nested", "text", &data.source_tip.to_string()] {
            assert!(!body.contains(private));
        }
        assert_eq!(prepare(&server.client, 1, 'd', &command, true), refused); // 5
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1);
        assert!(node.read_git_object(candidate.binding.commit).is_err());
        let view = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(view.snapshot().refs[&data.target_ref], data.target_tip);
        node.shutdown().unwrap();
    }
}

#[test]
fn http_profile_selection_cannot_bypass_credentials_subject_or_exact_body_rules() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (node, data) = rename_fixture(&root, GitHashAlgorithm::Sha1, false);
    let before = generation(&node);
    let path = root.0.join("credentials");
    configure(&node, &path);
    let server = Server::start(node, &path, 13, true, false);
    let command = open_and_command(&server, &data); // 1, 2
    for value in ["", "ort", "exact-renames-v2", "EXACT-RENAMES-V1"] {
        // 3..6
        error(
            &prepare(
                &server.client,
                1,
                'd',
                &(command.clone() + "&profile=" + value),
                false,
            ),
            400,
            "unsupported_merge_profile",
        );
    }
    // Short duplicate envelope isolates uniqueness from the field-count limit.
    error(
        &prepare(
            &server.client,
            1,
            'd',
            "profile=path-merge-v1&pr%6ffile=exact-renames-v1",
            true,
        ),
        400,
        "duplicate_field",
    ); // 7
    for (token, code, expected) in [('a', "forbidden", 403), ('z', "unauthorized", 401)] {
        // 8, 9
        let headers = "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1024\r\nExpect: 100-continue\r\n";
        let denied = binary_exchange(
            &server.client,
            &request(
                &server.client,
                "POST",
                "/api/v1/pulls/1/prepare",
                token,
                headers,
                &[],
            ),
            false,
        );
        error(&denied, expected, code);
        assert!(!denied.head.contains("100 Continue"));
    }
    let exact = command.clone() + "&profile=exact-renames-v1";
    let stale = exact.replace("pull_request_version=1", "pull_request_version=2");
    error(
        &prepare(&server.client, 1, 'd', &stale, true),
        409,
        "preparation_subject_moved",
    ); // 10
    let truncated = request(
        &server.client,
        "POST",
        "/api/v1/pulls/1/prepare",
        'd',
        &format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            exact.len() + 1
        ),
        exact.as_bytes(),
    );
    let incomplete = binary_exchange(&server.client, &truncated, true); // 11
    assert_eq!(incomplete.status, 400);
    assert!(
        std::str::from_utf8(&incomplete.body)
            .unwrap()
            .contains("\"outcome_unknown\":false")
    );
    let resolved = command
        + &format!(
            "&merge_base={}&resolution=74657874:ours&profile=exact-renames-v1",
            "c".repeat(40)
        );
    error(
        &binary_exchange(
            &server.client,
            &request(
                &server.client,
                "POST",
                "/api/v1/pulls/1/resolve",
                'd',
                &format!(
                    "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
                    resolved.len()
                ),
                resolved.as_bytes(),
            ),
            true,
        ),
        400,
        "unknown_preparation_field",
    ); // 12
    let (candidate, _) = extract(&prepare(&server.client, 1, 'd', &exact, true), data); // 13 permitted twin
    assert_eq!(server.finish().accepted_sessions(), 13);
    let node = reopen(&config);
    assert_eq!(generation(&node), before + 1);
    assert!(node.read_git_object(candidate.binding.commit).is_err());
    node.shutdown().unwrap();
}
