//! Native fixture and HTTP client shared with the existing PR/review campaigns.
#[path = "../review_merge_http/support.rs"]
mod base;
pub use base::*;

use fgit_authority::IdempotencyKey;
use fgit_crypto::GitObjectKind;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand};
use fgit_forge::event::review::CandidateBinding;
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PolicyEpoch, RepositoryIncarnationId};
use std::path::Path;

pub fn initialized(
    root: &Scratch,
    format: GitHashAlgorithm,
    management: bool,
    landing: bool,
    review: bool,
) -> (OneNode, Candidate, NodeConfig) {
    let (node, data) = fixture(root, format);
    let request = node.request_context();
    for number in [1, 2] {
        let pull = PullRequestCommand {
            number: PullRequestNumber::try_new(number).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: data.clone(),
        };
        let session = |key: String| {
            LoopbackReceiveSession::authenticated(
                OWNER,
                IdempotencyKey::new(key.into_bytes()).unwrap(),
            )
        };
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &request,
                &session(format!("queue-landing-http-pr-{number}")),
                &pull,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let queue = QueueCommand {
            number: QueueNumber::FIRST,
            target_ref: data.target_ref.clone(),
            expected_version: if number == 1 {
                ExpectedVersion::NewStream
            } else {
                ExpectedVersion::Exactly(AggregateVersion::FIRST)
            },
            action: QueueCommandAction::Enqueue {
                pull_request: pull.number,
                expected_pull_request_version: AggregateVersion::FIRST,
                source_ref: data.source_ref.clone(),
                head_tip: data.source_tip,
                expected_target_tip: data.target_tip,
                priority: 0,
            },
        };
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_queue_durable_in(
                &request,
                &session(format!("queue-landing-http-enqueue-{number}")),
                &queue,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
    }
    let mut candidate = Candidate {
        binding: CandidateBinding {
            merge_base: data.target_tip,
            commit: data.source_tip,
        },
        epoch: PolicyEpoch::FIRST,
        bundle: bundle(&node, data.source_tip, data.target_tip),
        data,
    };
    if review {
        let protection = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: PolicyEpoch::FIRST,
            protection: ReviewProtection {
                ref_policy: None,
                administrators: vec![OWNER],
                branches: vec![ProtectedBranch {
                    name: candidate.data.target_ref.clone(),
                    required_approvals: 1,
                    reviewers: vec![REVIEWER],
                    required_checks: Vec::new(),
                }],
            },
        };
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_review_protection_durable_in(
                &request,
                &LoopbackReceiveSession::authenticated(
                    OWNER,
                    IdempotencyKey::new(b"protect-queue-http".to_vec()).unwrap(),
                ),
                &protection,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        candidate.epoch = PolicyEpoch::FIRST.next().unwrap();
    }
    node.shutdown().unwrap();
    let mut config = root.config(format);
    if management {
        config = config.with_http_queue_management();
    }
    if landing {
        config = config.with_http_queue_landings();
    }
    (reopen(&config), candidate, config)
}

struct SourceCommit(CanonicalPackObject);
impl CanonicalObjectSource for SourceCommit {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        if *id == self.0.id() {
            Ok(self.0.clone())
        } else {
            Err(PackWriteError::MissingCanonicalObject(*id))
        }
    }
}

fn bundle(node: &OneNode, source: GitOid, target: GitOid) -> Vec<u8> {
    let object = SourceCommit(CanonicalPackObject::new(
        source,
        GitObjectKind::Commit,
        node.read_git_object(source).unwrap().payload().to_vec(),
        Vec::new(),
        0,
        0,
    ));
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        source.algorithm(),
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(&object, &[source], &mut || true)
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bytes = format!(
        "# v3 git bundle\n@object-format={}\n-{target} target\n{source} refs/heads/main\n\n",
        source.algorithm().as_str()
    )
    .into_bytes();
    bytes.extend(pack);
    bytes
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn queue_credentials(node: &OneNode, path: &Path, scope: &str) -> String {
    let binding = header(node).replace("credentials-v1", "credentials-v2");
    write_credentials(path, &binding, scope);
    binding
}

pub fn write_credentials(path: &Path, binding: &str, scope: &str) {
    let scoped = |token, principal, services: &str, refs: &str| {
        format!("{} {refs}\n", row(token, principal, services).trim_end())
    };
    replace(
        path,
        &(binding.to_owned()
            + &scoped('a', OWNER, "queues-read", "none")
            + &scoped('b', OWNER, "queues-write", "none")
            + &scoped('c', MERGER, "queues-land", scope)
            + &scoped('d', MERGER, "outcomes-read", "none")
            + &scoped('e', REVIEWER, "reviews-write", "none")
            + &scoped(
                'f',
                OWNER,
                "read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write,protection-read,protection-write,lfs-read,lfs-write,artifact-read,queues-read,queues-write",
                "all",
            )),
    );
}

pub fn landing_form(candidate: &Candidate, incarnation: RepositoryIncarnationId) -> String {
    format!(
        "expected_incarnation={incarnation}&object_format={}&expected_version=2&expected_policy_epoch={}&pull_request=1&expected_pull_request_version=1&source_ref={}&target_ref={}&expected_source_tip={}&expected_target_tip={}",
        candidate.data.source_tip.algorithm().as_str(),
        candidate.epoch.get(),
        encode(candidate.data.source_ref.as_bytes()),
        encode(candidate.data.target_ref.as_bytes()),
        candidate.data.source_tip,
        candidate.data.target_tip,
    )
}

pub fn queue_wire(
    endpoint: &Endpoint,
    action: &str,
    token: char,
    key: &str,
    body: &str,
    chunked: bool,
) -> Vec<u8> {
    let (wire, framing) = if chunked {
        let mut wire = Vec::new();
        for chunk in body.as_bytes().chunks(13) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        (wire, "Transfer-Encoding: chunked\r\n".into())
    } else {
        (
            body.as_bytes().to_vec(),
            format!("Content-Length: {}\r\n", body.len()),
        )
    };
    request(
        endpoint,
        "POST",
        &format!("/api/v1/queues/1/{action}"),
        token,
        &format!(
            "Content-Type: application/x-www-form-urlencoded\r\n{framing}Idempotency-Key: {key}\r\n"
        ),
        &wire,
    )
}

pub fn queue_post(
    endpoint: &Endpoint,
    action: &str,
    token: char,
    key: &str,
    body: &str,
    chunked: bool,
) -> Reply {
    exchange(
        endpoint,
        &queue_wire(endpoint, action, token, key, body, chunked),
        true,
    )
}

pub fn landed(reply: &Reply) {
    accepted(reply);
    assert!(reply.body.contains("\"type\":\"merge_queue_publication\""));
    assert!(
        reply
            .body
            .contains("\"name\":\"land\",\"method\":\"fast-forward-only\"")
    );
    assert!(reply.body.contains("\"refs_changed\":true"));
    assert!(reply.body.contains("\"historical_outcome\":true"));
    assert!(
        reply
            .body
            .contains(&format!("\"principal_id\":\"{MERGER}\""))
    );
}

pub fn refused_landing(reply: &Reply, code: &str) {
    refused(reply);
    assert!(
        reply.body.contains(&format!("\"refusal_code\":\"{code}\"")),
        "{}",
        reply.raw
    );
    assert!(reply.body.contains("\"refs_changed\":false"));
}
