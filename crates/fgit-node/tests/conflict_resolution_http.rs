#![forbid(unsafe_code)]
//! Real TCP conflict discovery -> resolution -> downloaded bundle -> independent
//! review -> coupled merge. No replacement planner, repository or authority.
#[path = "candidate_preparation_http/support.rs"]
mod support;
use support::*;

use std::collections::BTreeSet;
use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand};
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::{MergeMetadata, MergePreparation, PreparationLimits};
use fgit_forge::preparation::resolution::{ConflictResolution, ResolutionChoice};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PolicyEpoch};
use fgit_wire::visibility::RefVisibility;

const PATH_HEX: &str = "66696c65ff2e747874";
const CONTENT: &[u8] = b"\0\xffresolved\r\n--resolve-httpX\n";
fn text<'a>(json: &'a str, field: &str) -> &'a str {
    json.split_once(&format!("\"{field}\":\"")).unwrap().1.split('"').next().unwrap()
}
fn error(reply: &BinaryReply, status: u16, code: &str) {
    assert_eq!(reply.status, status, "{}", String::from_utf8_lossy(&reply.body));
    let body = std::str::from_utf8(&reply.body).unwrap();
    assert!(body.contains(&format!("\"code\":\"{code}\"")), "{body}");
    assert!(!body.contains("\"outcome_unknown\":true"));
    assert!(!body.contains("\"outcome\":\"refused\""));
}
fn resolve_bytes(endpoint: &Endpoint, token: char, command: &str, files: &[(&str, &[u8])], chunked: bool) -> Vec<u8> {
    let (body, media) = if files.is_empty() {
        (command.as_bytes().to_vec(), "application/x-www-form-urlencoded")
    } else {
        let part = |name: &str, media: &str, content: &[u8]| {
            let mut bytes = format!("--resolve-http\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"ignored\"\r\nContent-Type: {media}\r\n\r\n").into_bytes();
            bytes.extend_from_slice(content); bytes.extend_from_slice(b"\r\n"); bytes
        };
        let mut parts = vec![part("command", "application/x-www-form-urlencoded", command.as_bytes())];
        for (name, bytes) in files { parts.push(part(name, "application/octet-stream", bytes)); }
        if chunked { parts.reverse(); }
        let mut body = parts.concat(); body.extend_from_slice(b"--resolve-http--\r\n");
        (body, "multipart/form-data; boundary=resolve-http")
    };
    let (body, framing) = if chunked {
        let mut wire = Vec::new();
        for chunk in body.chunks(37) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk); wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n"); (wire, "Transfer-Encoding: chunked\r\n".to_owned())
    } else { let size = body.len(); (body, format!("Content-Length: {size}\r\n")) };
    request(endpoint, "POST", "/api/v1/pulls/1/resolve", token, &format!("Content-Type: {media}\r\n{framing}"), &body)
}
fn resolve(endpoint: &Endpoint, command: &str, files: &[(&str, &[u8])], chunked: bool) -> BinaryReply {
    binary_exchange(endpoint, &resolve_bytes(endpoint, 'd', command, files, chunked), true)
}
fn discovery(endpoint: &Endpoint, data: &fgit_forge::event::pull_request::PullRequestData) -> (String, String) {
    committed(&post(endpoint, 1, "open", 'a', "open-conflicted-pr", &form(data, 0), false));
    let reviews = get(endpoint, "/api/v1/pulls/1/reviews", 'b'); status(&reviews, 200);
    let epoch = PolicyEpoch::try_new(numeric(&reviews.body, "policy_epoch")).unwrap();
    let command = preparation_form(data, epoch);
    let conflicts = prepare(endpoint, 1, 'd', &command, false);
    assert_eq!(conflicts.status, 409);
    let body = std::str::from_utf8(&conflicts.body).unwrap();
    assert!(body.contains(&format!("\"path_hex\":\"{PATH_HEX}\"")));
    assert!(body.contains("\"candidate\":null"));
    let base = text(body, "merge_base").to_owned();
    (command + &format!("&merge_base={base}"), base)
}

#[test]
fn binary_resolution_survives_restart_and_only_the_reviewed_candidate_can_publish() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, data) = non_clean_fixture(&root, format, true);
        let before = generation(&node);
        let outbox = node.runtime().block_on(node.materialize_admission()).unwrap().snapshot().outbox.len();
        let path = root.0.join("credentials"); configure(&node, &path);
        let server = Server::start(node, &path, 8, true, true);
        let (base_command, base) = discovery(&server.client, &data);
        let command = base_command.clone() + &format!("&resolution={PATH_HEX}:file:100755:file_0");
        let original = resolve(&server.client, &command, &[("file_0", CONTENT)], false);
        let (candidate, metadata) = extract(&original, data.clone());
        assert_eq!(candidate.binding.merge_base, GitOid::from_hex(format, &base).unwrap());
        assert!(metadata.contains("\"state\":\"resolved\""));
        assert!(metadata.contains("\"choice\":\"file\""));
        assert!(metadata.contains(&format!("\"result\":{{\"mode\":{},", 0o100755)));
        assert_eq!(resolve(&server.client, &command, &[("file_0", CONTENT)], true), original);
        error(&resolve(&server.client, &base_command, &[], false), 409, "unresolved_conflicts");
        let extra = base_command + &format!("&resolution={PATH_HEX}:ours&resolution=636c65616e:delete");
        error(&resolve(&server.client, &extra, &[], false), 409, "resolution_names_clean_path");
        let wrong_base = command.replace(&format!("merge_base={base}"), &format!("merge_base={}", data.target_tip));
        error(&resolve(&server.client, &wrong_base, &[("file_0", CONTENT)], false), 409, "resolution_base_mismatch");
        assert_eq!(server.finish().accepted_sessions(), 8);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1, "only PR opening published");
        let blob = git_object_id(format, GitObjectKind::Blob, CONTENT);
        assert!(node.read_git_object(blob).is_err());
        assert!(node.read_git_object(candidate.binding.commit).is_err());
        let no_attempt = LoopbackReceiveSession::authenticated(FOREIGN,
            IdempotencyKey::new(b"read-only-candidate-preparation".to_vec()).unwrap());
        assert!(matches!(node.runtime().block_on(node.recover_transaction_in(&node.request_context(), &no_attempt)).unwrap(), RequestRecovery::KeyNotObserved));
        let server = Server::start(node, &path, 8, true, true);
        assert_eq!(resolve(&server.client, &command, &[("file_0", CONTENT)], false), original);
        accepted(&send(&server.client, "reviews/approve", 'b', "approve-resolution", &review_form(&candidate, 0), Some(&candidate.bundle), true));
        let altered = resolve(&server.client, &command, &[("file_0", b"unreviewed bytes\n")], true);
        let (other, _) = extract(&altered, data.clone());
        assert_ne!(other.binding.commit, candidate.binding.commit);
        refused(&send(&server.client, "merge", 'c', "different-resolution", &merge_form(&other, &[REVIEWER]), Some(&other.bundle), false));
        let merge = merge_form(&candidate, &[REVIEWER]);
        let published = send(&server.client, "merge", 'c', "merge-resolution", &merge, Some(&candidate.bundle), true);
        accepted(&published);
        assert_eq!(send(&server.client, "merge", 'c', "merge-resolution", &merge, None, false), published);
        let pr = get(&server.client, "/api/v1/pulls/1", 'a'); status(&pr, 200);
        assert!(pr.body.contains("\"state\":\"merged\""));
        error(&resolve(&server.client, &command, &[("file_0", CONTENT)], false), 409, "preparation_subject_moved");
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 4, "PR, vote, refused alternative, coupled merge; resolution reads never publish");
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(selected.snapshot().refs[&data.target_ref], candidate.binding.commit);
        assert_eq!(selected.snapshot().refs[&data.source_ref], data.source_tip);
        assert_eq!(selected.snapshot().outbox.len(), outbox + 3);
        assert!(node.read_git_object(blob).is_ok());
        assert!(node.read_git_object(candidate.binding.commit).is_ok());
        node.shutdown().unwrap();
    }
}

#[test]
fn all_side_choices_and_explicit_delete_are_read_only_native_candidates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, data) = non_clean_fixture(&root, format, true); let before = generation(&node);
        let path = root.0.join("credentials"); configure(&node, &path);
        let server = Server::start(node, &path, 7, true, false);
        let (base, _) = discovery(&server.client, &data);
        let mut candidates = BTreeSet::new();
        for choice in ["base", "ours", "theirs", "delete"] {
            let reply = resolve(&server.client, &(base.clone() + &format!("&resolution={PATH_HEX}:{choice}")), &[], true);
            let (candidate, metadata) = extract(&reply, data.clone());
            assert!(metadata.contains(&format!("\"choice\":\"{choice}\"")));
            assert_eq!(metadata.contains("\"result\":null"), choice == "delete");
            candidates.insert(candidate.binding.commit);
        }
        assert_eq!(candidates.len(), 4, "different final trees must not alias");
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before + 1);
        for commit in candidates { assert!(node.read_git_object(commit).is_err()); }
        node.shutdown().unwrap();
    }
}

#[test]
fn grants_keys_framing_and_unused_binary_data_refuse_before_construction() {
    let root = Scratch::new(); let config = root.config(GitHashAlgorithm::Sha1);
    let (node, data) = non_clean_fixture(&root, GitHashAlgorithm::Sha1, true);
    let before = generation(&node); let path = root.0.join("credentials");
    let header = configure(&node, &path);
    let command = preparation_form(&data, PolicyEpoch::FIRST)
        + &format!("&merge_base={}&resolution={PATH_HEX}:ours", data.target_tip);
    let server = Server::start(node, &path, 8, true, false);
    let withheld = |token, extra: &str, length| binary_exchange(&server.client,
        &request(&server.client, "POST", "/api/v1/pulls/1/resolve", token,
            &format!("Content-Type: multipart/form-data; boundary=resolve-http\r\nContent-Length: {length}\r\nExpect: 100-continue\r\n{extra}"), &[]), false);
    for token in ['a', 'b', 'c'] {
        let reply = withheld(token, "", 100);
        assert_eq!(reply.status, 403); assert!(!reply.head.contains("100 Continue"));
    }
    let reply = withheld('d', "Idempotency-Key: not-a-mutation\r\n", 100);
    error(&reply, 400, "preparation_has_no_transaction_key"); assert!(!reply.head.contains("100 Continue"));
    let reply = withheld('d', "", 80 * 1024 * 1024);
    assert_eq!(reply.status, 413); assert!(!reply.head.contains("100 Continue"));
    error(&resolve(&server.client, &command, &[("file_0", b"unused")], false), 400, "unreferenced_resolution_file");
    let mut truncated = resolve_bytes(&server.client, 'd', &command, &[("file_0", CONTENT)], true);
    truncated.truncate(truncated.len() - 3);
    assert_eq!(binary_exchange(&server.client, &truncated, true).status, 400);
    let invalid = command.replace(&format!("{PATH_HEX}:ours"), "2e2e2f78:delete");
    error(&resolve(&server.client, &invalid, &[], false), 400, "invalid_resolution_set");
    server.finish();
    let node = reopen(&config); assert_eq!(generation(&node), before);
    replace(&path, &(header + &row('d', FOREIGN, "read") + &row('f', FOREIGN, "pulls-read")));
    let server = Server::start(node, &path, 2, true, false);
    for token in ['d', 'f'] {
        let reply = binary_exchange(&server.client, &resolve_bytes(&server.client, token, &command, &[], false), true);
        assert_eq!(reply.status, 403);
    }
    server.finish();
    let node = reopen(&config); assert_eq!(generation(&node), before); node.shutdown().unwrap();
}

#[test]
fn exact_pr_resolution_rechecks_version_policy_visibility_cancellation_and_work_bounds() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, data) = non_clean_fixture(&root, format, true);
        let session = LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(b"native-resolution-pr".to_vec()).unwrap());
        let request = node.request_context();
        let command = PullRequestCommand { number: PullRequestNumber::FIRST, expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open, data: data.clone() };
        let (_, result) = node.runtime().block_on(node.admit_pull_request_durable_in(&request, &session, &command, Default::default())).unwrap();
        assert!(matches!(result.outcome, DecisionOutcome::Committed { .. }));
        let current = node.runtime().block_on(node.materialize_admission()).unwrap();
        let metadata = MergeMetadata { author: "Fixture <fixture@example.invalid>".into(), committer: "Fixture <fixture@example.invalid>".into(),
            timestamp: 1, message: b"native resolved candidate\n".to_vec() };
        let automatic = node.runtime().block_on(node.prepare_merge_bundle_in(&request, &data.target_ref, &data.source_ref,
            &RefVisibility::new(), &metadata, PreparationLimits::default())).unwrap();
        let MergePreparation::Conflicted { base, .. } = automatic.outcome else { panic!("conflicting fixture"); };
        let subject = ReviewSubject { pull_request: PullRequestNumber::FIRST, pull_request_version: AggregateVersion::FIRST,
            source_ref: data.source_ref.clone(), target_ref: data.target_ref.clone(), source_tip: data.source_tip, target_tip: data.target_tip,
            policy_epoch: current.basis().body().policy_epoch };
        let choices = [ConflictResolution { path: b"file\xff.txt".to_vec(), choice: ResolutionChoice::Theirs }];
        let mut wrong_version = subject.clone(); wrong_version.pull_request_version = AggregateVersion::FIRST.next().unwrap();
        let mut wrong_epoch = subject.clone(); wrong_epoch.policy_epoch = subject.policy_epoch.next().unwrap();
        for wrong in [&wrong_version, &wrong_epoch] {
            assert!(node.runtime().block_on(node.prepare_resolved_pull_request_bundle_in(&request, wrong, base,
                &RefVisibility::new(), &choices, &metadata, PreparationLimits::default())).is_err());
        }
        let mut hidden = RefVisibility::new(); hidden.push_rule(data.source_ref.as_bytes(), &Default::default()).unwrap();
        assert!(node.runtime().block_on(node.prepare_resolved_pull_request_bundle_in(&request, &subject, base,
            &hidden, &choices, &metadata, PreparationLimits::default())).is_err());
        let cancelled = node.request_context(); cancelled.cancel();
        assert!(node.runtime().block_on(node.prepare_resolved_pull_request_bundle_in(&cancelled, &subject, base,
            &RefVisibility::new(), &choices, &metadata, PreparationLimits::default())).is_err());
        let narrow = PreparationLimits { max_content_merges: 1, ..PreparationLimits::default() };
        assert!(node.runtime().block_on(node.prepare_resolved_pull_request_bundle_in(&request, &subject, base,
            &RefVisibility::new(), &choices, &metadata, narrow)).is_err());
        let result = node.runtime().block_on(node.prepare_resolved_pull_request_bundle_in(&request, &subject, base,
            &RefVisibility::new(), &choices, &metadata, PreparationLimits::default())).unwrap();
        assert_eq!(result.source_head, current.basis().id());
        assert!(node.read_git_object(result.resolved.plan.commit).is_err());
        assert_eq!(generation(&node), current.basis().generation().get());
        node.shutdown().unwrap();
    }
}

#[test]
fn edited_and_closed_prs_cannot_silently_refresh_an_old_resolution_subject() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, mut data) = non_clean_fixture(&root, format, true); let before = generation(&node);
        let path = root.0.join("credentials"); configure(&node, &path);
        let server = Server::start(node, &path, 8, true, false);
        let (base, _) = discovery(&server.client, &data);
        let original = base + &format!("&resolution={PATH_HEX}:ours");
        data.title = "Explicitly edited PR".into();
        committed(&post(&server.client, 1, "update", 'a', "edit-before-resolution", &form(&data, 1), false));
        error(&resolve(&server.client, &original, &[], false), 409, "preparation_subject_moved");
        let refreshed = original.replace("pull_request_version=1", "pull_request_version=2");
        let reply = resolve(&server.client, &refreshed, &[], false);
        let (candidate, metadata) = extract(&reply, data.clone());
        assert!(metadata.contains("\"pull_request_version\":2"));
        committed(&post(&server.client, 1, "close", 'a', "close-before-resolution", &form(&data, 2), false));
        error(&resolve(&server.client, &refreshed, &[], true), 409, "preparation_subject_moved");
        assert_eq!(server.finish().accepted_sessions(), 8);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 3, "opening, edit and close only; stale reads do not publish decisions");
        assert!(node.read_git_object(candidate.binding.commit).is_err());
        node.shutdown().unwrap();
    }
}
