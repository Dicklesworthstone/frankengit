//! Existing native histories and HTTP clients; candidate preparation is always
//! requested from the real server in this campaign.
#[path = "../candidate_preparation_http/support.rs"]
mod http;
pub(super) use http::*;
#[path = "../trusted_merge_workflow/support.rs"]
mod native;

use fgit_authority::IdempotencyKey;
use fgit_crypto::GitObjectKind;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_node::{LoopbackReceiveSession, OneNode};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_schema::json::{self, Value};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PolicyEpoch, PrincipalId, RefName};
use std::path::{Path, PathBuf};

pub(super) const ADMIN: PrincipalId = native::OWNER;
pub(super) const MESSAGE: &[u8] = b"Prepare the exact remote queue head\n";

pub(super) fn session(principal: PrincipalId, key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        principal,
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}

pub(super) fn seed_queue(node: &OneNode, data: &PullRequestData, principal: PrincipalId) {
    for number in [1, 2] {
        let pull = PullRequestCommand {
            number: PullRequestNumber::try_new(number).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: data.clone(),
        };
        let (_, outcome) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &node.request_context(),
                &session(principal, &format!("prepare-http-pr-{number}")),
                &pull,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
        let command = QueueCommand {
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
        let (_, outcome) = node
            .runtime()
            .block_on(node.admit_queue_durable_in(
                &node.request_context(),
                &session(principal, &format!("prepare-http-enqueue-{number}")),
                &command,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
    }
}

pub(super) fn protect(node: &OneNode, data: &PullRequestData, principal: PrincipalId) {
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection: ReviewProtection {
            administrators: vec![principal],
            ref_policy: None,
            branches: vec![ProtectedBranch {
                name: data.target_ref.clone(),
                reviewers: vec![REVIEWER],
                required_approvals: 1,
                required_checks: Vec::new(),
                required_candidate_checks: Vec::new(),
                require_merge_queue: true,
            }],
        },
    };
    let (_, outcome) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &node.request_context(),
            &session(principal, "prepare-http-policy"),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
}

pub(super) struct QueueFixture {
    pub(super) native: native::Fixture,
    pub(super) data: PullRequestData,
    pub(super) epoch: PolicyEpoch,
    pub(super) credentials: PathBuf,
}
impl QueueFixture {
    pub(super) fn new(
        format: GitHashAlgorithm,
        reviewed: bool,
        management: bool,
        landings: bool,
    ) -> Self {
        let mut native = native::Fixture::new(format, native::WORKFLOW);
        let data = PullRequestData {
            source_ref: native::source_ref(),
            target_ref: native::target_ref(),
            source_tip: native.source,
            target_tip: native.target,
            title: "Exact remote queue head".into(),
            body: String::new(),
        };
        seed_queue(native.node(), &data, ADMIN);
        if reviewed {
            protect(native.node(), &data, ADMIN);
        }
        if landings {
            native.config = native.config.clone().with_http_queue_landings();
        }
        if management {
            native.config = native.config.clone().with_http_queue_management();
        }
        native.reopen();
        let credentials = native.root.join("http-credentials");
        let binding = format!(
            "frankengit-http-credentials-v2 {} {} {}\n",
            native::TENANT,
            native::REPOSITORY,
            native.node().repository_incarnation_id(),
        );
        grants(&credentials, &binding, &data.target_ref);
        Self {
            native,
            data,
            epoch: if reviewed {
                PolicyEpoch::FIRST.next().unwrap()
            } else {
                PolicyEpoch::FIRST
            },
            credentials,
        }
    }
    pub(super) fn node(&self) -> &OneNode {
        self.native.node()
    }
    pub(super) fn start(&mut self, requests: usize, pulls: bool) -> Server {
        Server::start(
            self.native.node.take().unwrap(),
            &self.credentials,
            requests,
            pulls,
            true,
        )
    }
    pub(super) fn reopen(&mut self) {
        self.native.reopen();
    }
    pub(super) fn form(&self, message: &[u8]) -> String {
        preparation(self.node(), &self.data, self.epoch, message)
    }
    pub(super) fn expected_tree(&self) -> GitOid {
        let format = self.data.source_tip.algorithm();
        let left = fgit_crypto::git_object_id(format, GitObjectKind::Blob, b"target\n");
        let right = fgit_crypto::git_object_id(format, GitObjectKind::Blob, b"source\n");
        fgit_crypto::git_object_id(
            format,
            GitObjectKind::Tree,
            &native::tree_bytes(left, right, self.native.workflow),
        )
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub(super) fn grants(path: &Path, binding: &str, target: &RefName) {
    let scoped = |token, principal, permissions: &str, refs: &str| {
        format!("{} {refs}\n", row(token, principal, permissions).trim_end())
    };
    replace(
        path,
        &(binding.to_owned()
            + &scoped('a', FOREIGN, "read,pulls-read,queues-read", "none")
            + &scoped('b', REVIEWER, "reviews-write", "none")
            + &scoped(
                'c',
                MERGER,
                "outcomes-read,queues-land",
                &format!("exact:{}", hex(target.as_bytes())),
            )
            + &scoped('d', FOREIGN, "read,pulls-read", "none")
            + &scoped('e', FOREIGN, "read,queues-read", "none")
            + &scoped('f', FOREIGN, "pulls-read,queues-read", "none")
            + &scoped('0', FOREIGN, "queues-read,queues-write,queues-land", "all")),
    );
}
pub(super) fn preparation(
    node: &OneNode,
    data: &PullRequestData,
    epoch: PolicyEpoch,
    message: &[u8],
) -> String {
    format!(
        concat!(
            "expected_incarnation={}&object_format={}&expected_version=2&pull_request=1",
            "&expected_pull_request_version=1&expected_policy_epoch={}&source_ref_hex={}&target_ref_hex={}",
            "&expected_source_tip={}&expected_target_tip={}&author=Remote+queue+%3Cqueue%40example.invalid%3E",
            "&committer=Remote+queue+%3Cqueue%40example.invalid%3E&timestamp=17&message_hex={}"
        ),
        node.repository_incarnation_id(),
        data.source_tip.algorithm().as_str(),
        epoch.get(),
        hex(data.source_ref.as_bytes()),
        hex(data.target_ref.as_bytes()),
        data.source_tip,
        data.target_tip,
        hex(message),
    )
}
pub(super) fn replace_field(body: &str, name: &str, value: &str) -> String {
    let prefix = format!("{name}=");
    let mut found = false;
    let changed = body
        .split('&')
        .map(|part| {
            if part.starts_with(&prefix) {
                assert!(!found);
                found = true;
                format!("{name}={value}")
            } else {
                part.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    assert!(found, "missing fixture field {name}");
    changed
}
pub(super) fn chunked_body(body: &[u8], size: usize) -> Vec<u8> {
    let mut wire = Vec::new();
    for part in body.chunks(size) {
        wire.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        wire.extend_from_slice(part);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    wire
}
pub(super) fn queue_prepare_wire(client: &Endpoint, body: &str, chunked: bool) -> Vec<u8> {
    let (wire, framing) = if chunked {
        (
            chunked_body(body.as_bytes(), 127),
            "Transfer-Encoding: chunked\r\n".to_owned(),
        )
    } else {
        (
            body.as_bytes().to_vec(),
            format!("Content-Length: {}\r\n", body.len()),
        )
    };
    request(
        client,
        "POST",
        "/api/v1/queues/1/prepare",
        'a',
        &format!("Content-Type: application/x-www-form-urlencoded\r\n{framing}"),
        &wire,
    )
}
pub(super) fn queue_prepare(client: &Endpoint, body: &str, chunked: bool) -> BinaryReply {
    binary_exchange(client, &queue_prepare_wire(client, body, chunked), true)
}
pub(super) fn withheld(
    client: &Endpoint,
    token: char,
    headers: &str,
    length: usize,
) -> BinaryReply {
    binary_exchange(
        client,
        &request(
            client,
            "POST",
            "/api/v1/queues/1/prepare",
            token,
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\nExpect: 100-continue\r\n{headers}"
            ),
            &[],
        ),
        false,
    )
}
pub(super) fn document(bytes: &[u8]) -> Value {
    json::parse(bytes).unwrap()
}
pub(super) fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.object().unwrap().get(key).unwrap()
}
pub(super) fn text_field<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key).text().unwrap()
}
pub(super) fn landing(metadata: &str) -> (String, String) {
    let value = document(metadata.as_bytes());
    assert_eq!(text_field(&value, "type"), "queue_merge_preparation");
    let queue = field(&value, "queue");
    assert_eq!(field(queue, "number"), &json::number(1));
    assert_eq!(field(queue, "expected_version"), &json::number(2));
    let landing = field(&value, "landing");
    let path = text_field(landing, "api_path").to_owned();
    let command = text_field(landing, "command_form").to_owned();
    assert_eq!(path, "/api/v1/queues/1/land-candidate");
    assert!(!command.contains("idempotency"));
    assert!(!command.contains("principal"));
    (path, command)
}
pub(super) fn land_wire(
    client: &Endpoint,
    path: &str,
    key: &str,
    command: &str,
    bundle: Option<&[u8]>,
    chunked: bool,
) -> Vec<u8> {
    let mut body = b"--queue-http-preparation\r\nContent-Disposition: form-data; name=\"command\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n".to_vec();
    body.extend_from_slice(command.as_bytes());
    body.extend_from_slice(b"\r\n");
    if let Some(bundle) = bundle {
        body.extend_from_slice(b"--queue-http-preparation\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"candidate.bundle\"\r\nContent-Type: application/x-git-bundle\r\n\r\n");
        body.extend_from_slice(bundle);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--queue-http-preparation--\r\n");
    let (wire, framing) = if chunked {
        (
            chunked_body(&body, 127),
            "Transfer-Encoding: chunked\r\n".to_owned(),
        )
    } else {
        let length = body.len();
        (body, format!("Content-Length: {length}\r\n"))
    };
    request(
        client,
        "POST",
        path,
        'c',
        &format!(
            "Content-Type: multipart/form-data; boundary=queue-http-preparation\r\n{framing}Idempotency-Key: {key}\r\n"
        ),
        &wire,
    )
}
pub(super) fn land(
    client: &Endpoint,
    path: &str,
    key: &str,
    command: &str,
    bundle: Option<&[u8]>,
    chunked: bool,
) -> Reply {
    exchange(
        client,
        &land_wire(client, path, key, command, bundle, chunked),
        true,
    )
}

struct CommitSource(CanonicalPackObject);
impl CanonicalObjectSource for CommitSource {
    fn load(&self, oid: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        if *oid == self.0.id() {
            Ok(self.0.clone())
        } else {
            Err(PackWriteError::MissingCanonicalObject(*oid))
        }
    }
}
/// Real fast-forward movement used after capturing the old preparation request.
pub(super) fn advance(
    node: &OneNode,
    reference: &RefName,
    old: GitOid,
    principal: PrincipalId,
    key: &str,
) {
    let original = node.read_git_object(old).unwrap();
    let text = std::str::from_utf8(original.payload()).unwrap();
    let tree = GitOid::from_hex(
        old.algorithm(),
        text.lines().next().unwrap().strip_prefix("tree ").unwrap(),
    )
    .unwrap();
    let body = native::commit_bytes(tree, &[old], key);
    let oid = fgit_crypto::git_object_id(old.algorithm(), GitObjectKind::Commit, &body);
    let source = CommitSource(CanonicalPackObject::new(
        oid,
        GitObjectKind::Commit,
        body,
        Vec::new(),
        0,
        0,
    ));
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        old.algorithm(),
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(&source, &[oid], &mut || true)
    .unwrap();
    let pack = PackWriter::new(limits)
        .write(&plan, &mut || true)
        .unwrap()
        .0;
    let mut bundle = format!(
        "# v3 git bundle\n@object-format={}\n-{old} original\n{oid} ",
        old.algorithm().as_str()
    )
    .into_bytes();
    bundle.extend_from_slice(reference.as_bytes());
    bundle.extend_from_slice(b"\n\n");
    bundle.extend_from_slice(&pack);
    let result = node
        .runtime()
        .block_on(node.import_incremental_git_bundle_durable_in(
            &node.request_context(),
            &session(principal, key),
            &bundle,
            &[(reference.clone(), Some(old))],
            Default::default(),
        ))
        .unwrap();
    assert_eq!(result.commands.len(), 1);
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

pub(super) fn large_message() -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut state = 0x2b98_06fe_537a_c421_u64;
    (0..48 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            alphabet[(state % alphabet.len() as u64) as usize]
        })
        .collect()
}
