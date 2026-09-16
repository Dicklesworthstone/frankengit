//! Shared real-node/TCP fixture; candidate construction remains the production
//! read-only planner, not a canned pack, fake approval, or alternative engine.
#[path = "../pull_request_http/support.rs"]
mod base;
pub use base::*;

use std::path::Path;
use fgit_forge::event::pull_request::PullRequestData;
use fgit_forge::event::review::CandidateBinding;
use fgit_forge::preparation::{MergeMetadata, MergePreparation, PreparationLimits};
use fgit_node::OneNode;
use fgit_types::{GitHashAlgorithm, PolicyEpoch, PrincipalId};
use fgit_wire::visibility::RefVisibility;

pub const REVIEWER: PrincipalId = PrincipalId::from_bytes([0x44; 16]);
pub const MERGER: PrincipalId = PrincipalId::from_bytes([0x45; 16]);
pub const SECOND: PrincipalId = PrincipalId::from_bytes([0x46; 16]);
pub struct Candidate {
    pub data: PullRequestData,
    pub binding: CandidateBinding,
    pub epoch: PolicyEpoch,
    pub bundle: Vec<u8>,
}
pub fn prepared(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, Candidate) {
    let (node, data) = fixture(root, format);
    let metadata = MergeMetadata { author: "Fixture <fixture@example.invalid>".into(),
        committer: "Fixture <fixture@example.invalid>".into(), timestamp: 1, message: b"reviewed HTTP candidate\n".to_vec() };
    let request = node.request_context();
    let built = node.runtime().block_on(node.prepare_merge_bundle_in(&request, &data.target_ref, &data.source_ref,
        &RefVisibility::new(), &metadata, PreparationLimits::default())).unwrap();
    let MergePreparation::Clean(plan) = built.outcome else { panic!("clean native fixture"); };
    let epoch = node.runtime().block_on(node.materialize_admission()).unwrap().basis().body().policy_epoch;
    let candidate = Candidate { data, binding: CandidateBinding { merge_base: plan.base, commit: plan.commit },
        epoch, bundle: built.bundle.unwrap() };
    assert!(node.read_git_object(candidate.binding.commit).is_err(), "preparation must not import the candidate");
    (node, candidate)
}
pub fn configure(node: &OneNode, path: &Path) -> String {
    let head = grants(node, path);
    replace(path, &(head.clone()
        + &row('a', OWNER, "outcomes-read,pulls-read,pulls-write")
        + &row('b', REVIEWER, "outcomes-read,reviews-read,reviews-write")
        + &row('c', MERGER, "outcomes-read,merges-write")
        + &row('d', FOREIGN, "read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write")
        + &row('e', SECOND, "reviews-write") + &row('f', FOREIGN, "reviews-read")));
    head
}
pub fn open(endpoint: &Endpoint, candidate: &Candidate) {
    committed(&post(endpoint, 1, "open", 'a', "open-review-pr", &form(&candidate.data, 0), false));
}
pub fn common(candidate: &Candidate) -> String {
    format!("object_format={}&pull_request_version=1&policy_epoch={}&source_ref={}&target_ref={}&source_tip={}&target_tip={}&merge_base={}&candidate_commit={}",
        candidate.data.source_tip.algorithm().as_str(), candidate.epoch.get(),
        candidate.data.source_ref.as_str(), candidate.data.target_ref.as_str(), candidate.data.source_tip,
        candidate.data.target_tip, candidate.binding.merge_base, candidate.binding.commit)
}
pub fn review_form(candidate: &Candidate, version: u64) -> String {
    common(candidate) + &format!("&expected_version={version}&reason=Reviewed+exact+candidate")
}
pub fn merge_form(candidate: &Candidate, reviewers: &[PrincipalId]) -> String {
    let mut body = common(candidate);
    for reviewer in reviewers { body.push_str(&format!("&required_reviewer={reviewer}")); }
    body
}
pub fn mutation_bytes(endpoint: &Endpoint, action: &str, token: char, key: &str,
    command: &str, bundle: Option<&[u8]>, chunked: bool,
) -> Vec<u8> {
    let (body, content_type) = if let Some(bundle) = bundle {
        let mut command_part = b"--review-boundary\r\nContent-Disposition: form-data; name=\"command\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n".to_vec();
        command_part.extend_from_slice(command.as_bytes()); command_part.extend_from_slice(b"\r\n");
        let mut bundle_part = b"--review-boundary\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"candidate.bundle\"\r\nContent-Type: application/x-git-bundle\r\n\r\n".to_vec();
        bundle_part.extend_from_slice(bundle); bundle_part.extend_from_slice(b"\r\n");
        let mut body = if chunked { [bundle_part, command_part].concat() } else { [command_part, bundle_part].concat() };
        body.extend_from_slice(b"--review-boundary--\r\n");
        (body, "multipart/form-data; boundary=review-boundary")
    } else { (command.as_bytes().to_vec(), "application/x-www-form-urlencoded") };
    let (wire, framing) = if chunked {
        let mut wire = Vec::new();
        for chunk in body.chunks(97) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk); wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        (wire, "Transfer-Encoding: chunked\r\n".to_owned())
    } else { (body.clone(), format!("Content-Length: {}\r\n", body.len())) };
    request(endpoint, "POST", &format!("/api/v1/pulls/1/{action}"), token,
        &format!("Content-Type: {content_type}\r\n{framing}Idempotency-Key: {key}\r\n"), &wire)
}
pub fn send(endpoint: &Endpoint, action: &str, token: char, key: &str,
    command: &str, bundle: Option<&[u8]>, chunked: bool,
) -> Reply {
    exchange(endpoint, &mutation_bytes(endpoint, action, token, key, command, bundle, chunked), true)
}
pub fn accepted(reply: &Reply) {
    status(reply, 200);
    assert!(reply.body.contains("\"outcome\":\"committed\""));
    assert!(reply.body.contains("\"delivery_acknowledged\":null"));
}
pub fn refused(reply: &Reply) {
    status(reply, 409);
    assert!(reply.body.contains("\"outcome\":\"refused\""));
}
pub fn lookup(endpoint: &Endpoint, token: char, key: &str) -> Reply {
    exchange(endpoint, &request(endpoint, "POST", "/api/v1/outcomes", token,
        &format!("Content-Length: 0\r\nIdempotency-Key: {key}\r\n"), &[]), true)
}
