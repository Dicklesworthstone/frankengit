//! Real native imports and candidates; the server and inspector are never
//! replaced by test doubles. Binary framing helpers are external test clients.
#[path = "../candidate_preparation_http/support.rs"]
mod base;
pub use base::*;

use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::preparation::resolution::{ConflictResolution, ResolutionChoice, ResolutionInputs};
use fgit_forge::preparation::{MergeMetadata, MergePreparation, PreparationLimits};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_node::OneNode;
use fgit_types::GitHashAlgorithm;
use fgit_wire::visibility::RefVisibility;
use std::path::Path;

pub const PATH: &[u8] = b"file\xff.txt";
pub const TEXT: &[u8] = b"actual\r\n\xffcandidate without final LF";
pub fn resolved(root: &Scratch, format: GitHashAlgorithm, content: &[u8]) -> (OneNode, Candidate) {
    let (node, data) = non_clean_fixture(root, format, true);
    let context = node.request_context();
    let metadata = MergeMetadata {
        author: "Inspector <inspect@example.invalid>".into(),
        committer: "Builder <build@example.invalid>".into(),
        timestamp: 1,
        message: b"Actual inspected candidate\n".to_vec(),
    };
    let automatic = node
        .runtime()
        .block_on(node.prepare_merge_bundle_in(
            &context,
            &data.target_ref,
            &data.source_ref,
            &RefVisibility::new(),
            &metadata,
            PreparationLimits::default(),
        ))
        .unwrap();
    let MergePreparation::Conflicted { base, .. } = automatic.outcome else {
        panic!("native conflict fixture")
    };
    let inputs = ResolutionInputs {
        base,
        target: data.target_tip,
        source: data.source_tip,
    };
    let choices = [ConflictResolution {
        path: PATH.to_vec(),
        choice: ResolutionChoice::File {
            mode: 0o100755,
            bytes: content.to_vec(),
        },
    }];
    let built = node
        .runtime()
        .block_on(node.prepare_resolved_merge_bundle_in(
            &context,
            &data.target_ref,
            &data.source_ref,
            &RefVisibility::new(),
            Some(automatic.source_head),
            inputs,
            &choices,
            &metadata,
            PreparationLimits::default(),
        ))
        .unwrap();
    let epoch = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap()
        .basis()
        .body()
        .policy_epoch;
    let candidate = Candidate {
        data,
        binding: CandidateBinding {
            merge_base: base,
            commit: built.resolved.plan.commit,
        },
        epoch,
        bundle: built.bundle,
    };
    assert!(node.read_git_object(candidate.binding.commit).is_err());
    (node, candidate)
}
pub fn subject(candidate: &Candidate) -> ReviewSubject {
    ReviewSubject {
        pull_request: PullRequestNumber::FIRST,
        pull_request_version: AggregateVersion::FIRST,
        source_ref: candidate.data.source_ref.clone(),
        target_ref: candidate.data.target_ref.clone(),
        source_tip: candidate.data.source_tip,
        target_tip: candidate.data.target_tip,
        policy_epoch: candidate.epoch,
    }
}
pub fn credentials(node: &OneNode, path: &Path) -> String {
    let header = header(node);
    replace(
        path,
        &(header.clone()
            + &row('a', OWNER, "pulls-read,pulls-write")
            + &row('b', REVIEWER, "reviews-read,reviews-write")
            + &row('c', MERGER, "merges-write")
            + &row('d', FOREIGN, "read,pulls-read")
            + &row('e', FOREIGN, "read")
            + &row('f', FOREIGN, "pulls-read")),
    );
    header
}
pub fn multipart(command: &str, bundle: Option<&[u8]>, reverse: bool) -> Vec<u8> {
    let mut text = b"--inspect-boundary\r\nContent-Disposition: form-data; name=\"command\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n".to_vec();
    text.extend_from_slice(command.as_bytes());
    text.extend_from_slice(b"\r\n");
    let mut binary = Vec::new();
    if let Some(bundle) = bundle {
        binary.extend_from_slice(b"--inspect-boundary\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"not-a-storage-path\"\r\nContent-Type: application/x-git-bundle\r\n\r\n");
        binary.extend_from_slice(bundle);
        binary.extend_from_slice(b"\r\n");
    }
    let mut body = if reverse {
        [binary, text].concat()
    } else {
        [text, binary].concat()
    };
    body.extend_from_slice(b"--inspect-boundary--\r\n");
    body
}
pub fn inspect_bytes(
    endpoint: &Endpoint,
    number: u64,
    token: char,
    command: &str,
    bundle: Option<&[u8]>,
    chunked: bool,
) -> Vec<u8> {
    let body = multipart(command, bundle, chunked);
    let (wire, framing) = if chunked {
        let mut wire = Vec::new();
        for chunk in body.chunks(31) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        (wire, "Transfer-Encoding: chunked\r\n".to_owned())
    } else {
        let length = body.len();
        (body, format!("Content-Length: {length}\r\n"))
    };
    request(
        endpoint,
        "POST",
        &format!("/api/v1/pulls/{number}/inspect"),
        token,
        &format!("Content-Type: multipart/form-data; boundary=inspect-boundary\r\n{framing}"),
        &wire,
    )
}
pub fn inspect(endpoint: &Endpoint, candidate: &Candidate, token: char, chunked: bool) -> Reply {
    exchange(
        endpoint,
        &inspect_bytes(
            endpoint,
            1,
            token,
            &common(candidate),
            Some(&candidate.bundle),
            chunked,
        ),
        true,
    )
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn json_text<'a>(json: &'a str, field: &str) -> &'a str {
    json.split_once(&format!("\"{field}\":\""))
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
}
pub fn withheld(endpoint: &Endpoint, token: char, extra: &str, length: usize) -> Reply {
    let wire = request(
        endpoint,
        "POST",
        "/api/v1/pulls/1/inspect",
        token,
        &format!(
            "Content-Type: multipart/form-data; boundary=inspect-boundary\r\nContent-Length: {length}\r\nExpect: 100-continue\r\n{extra}"
        ),
        &[],
    );
    let reply = exchange(endpoint, &wire, false);
    assert!(!reply.raw.contains("100 Continue"));
    reply
}
