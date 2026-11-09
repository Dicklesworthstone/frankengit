//! Exact stored configuration evidence crosses the native authority, source
//! proof and authenticated HTTP boundaries. The fixtures publish through the
//! real embedded store and keep original native Git objects in the fabric.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fgit_admission::{CanonicalRefState, PermittedObjectClosure};
use fgit_authority::{
    AuthenticatedHead, CapabilityRevocationGenerationBody, IdempotencyKey,
    collect_cumulative_outcomes_async, outcome_index_root,
    read_head_selected_capability_revocation_generation_async,
    stage_capability_revocation_generation_async, stage_hidden_ref_policy_async,
    stage_latest_repository_incarnation_configuration_async,
    stage_repository_incarnation_configuration_async,
    stage_revocation_aware_repository_incarnation_configuration_async,
};
use fgit_chronicle::{
    BackupProfile, PublicationBasis, PublicationPlan, PublicationVerdict, ResultingRoots,
};
use fgit_codec::{
    CryptoBodyIdentity, DecodeLimits, HiddenRefPolicyBody, RepositoryIncarnationConfigurationBody,
    RepositoryIncarnationConfigurationBodyV2_1, RepositoryIncarnationConfigurationBodyV2_2,
};
use fgit_crypto::{GitObjectKind, git_object_id, object_closure_merkle_root, sha256_digest};
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_git_object::ObjectType;
use fgit_identity::agent::{
    AgentCredentialAction, AgentCredentialCommand, AgentCredentialGrant, ISSUES_READ, SOURCE_READ,
    SponsorKind, agent_credential_id,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch, PrincipalId, RefName,
    RepositoryAuthorityHeadId, RepositoryId, RootLayoutVersion, TenantId, cell::ReadLabel,
};
use fgit_verified_read::blob::{
    MAX_VERIFIED_BLOB_FRAME_BYTES, VerifiedBlobEnvelope, decode_verified_blob_envelope,
    encode_verified_blob_envelope, verify_blob_against_head,
};
use fgit_verified_read::{
    PinnedAuthorityHead, ReadResponse, VerifiedMembership, VerifiedReadConfiguration,
    VerifiedReadEnvelope, VerifiedReadRefusal, decode_verified_read_envelope,
    encode_verified_read_envelope, verify_envelope,
};
use fgit_wire::visibility::RefVisibility;

use super::{VerifiedReadCapability, VerifiedReadQuery, VerifiedReadServingRefusal};
use crate::{
    ClosureSelectionSource, GitDaemonServerLimits, LoopbackReceiveSession, NodeConfig, OneNode,
    authority_head_id, genesis_head, initialize_embedded_repository,
};

const CONTENT: &[u8] = b"\0\xfforiginal verified source\r\n";
const OWNER: PrincipalId = PrincipalId::from_bytes([0x41; 16]);
const AGENT: PrincipalId = PrincipalId::from_bytes([0x42; 16]);
const LAYOUT: RootLayoutVersion = RootLayoutVersion::RefStateAndObjectClosureMerkleV2;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-verified-configuration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0x31; 16]),
            RepositoryId::from_bytes([0x32; 16]),
        )
        .with_object_format(format)
        .with_root_layout(LAYOUT)
        .with_worker_threads(2)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}

fn authenticated(node: &OneNode) -> AuthenticatedHead {
    node.runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
}

/// Initialize exact canonical schemas through their real authority writers.
/// Nonempty pointers name actual policy/revocation bodies, not invented roots.
fn configured_node(
    scratch: &Scratch,
    format: GitHashAlgorithm,
    minor: u16,
    nonempty_policy: bool,
) -> (OneNode, VerifiedReadConfiguration) {
    let mut node = OneNode::open_components(scratch.config(format)).unwrap();
    let request = node.request_context();
    let policy_root = nonempty_policy.then(|| {
        node.runtime()
            .block_on(stage_hidden_ref_policy_async(
                &node.authority,
                request.authority(),
                &HiddenRefPolicyBody {
                    rules: vec![b"refs/heads/private".to_vec()],
                },
            ))
            .unwrap()
    });
    let base = RepositoryIncarnationConfigurationBody {
        root_layout: LAYOUT,
        object_format: format,
        repository_incarnation_id: node.repository_incarnation_id(),
    };
    let (configuration_root, exact) = match minor {
        0 => (
            node.runtime()
                .block_on(stage_repository_incarnation_configuration_async(
                    &node.authority,
                    request.authority(),
                    &base,
                ))
                .unwrap(),
            VerifiedReadConfiguration::RepositoryIncarnationV2(base),
        ),
        1 => {
            let body = RepositoryIncarnationConfigurationBodyV2_1 {
                root_layout: base.root_layout,
                object_format: base.object_format,
                repository_incarnation_id: base.repository_incarnation_id,
                policy_root,
            };
            (
                node.runtime()
                    .block_on(stage_latest_repository_incarnation_configuration_async(
                        &node.authority,
                        request.authority(),
                        &body,
                    ))
                    .unwrap(),
                VerifiedReadConfiguration::RepositoryIncarnationV2_1(body),
            )
        }
        2 => {
            let capability_revocation_root = nonempty_policy.then(|| {
                let body = CapabilityRevocationGenerationBody::try_new(
                    node.tenant_id(),
                    node.repository_id(),
                    node.repository_incarnation_id(),
                    PolicyEpoch::FIRST,
                    None,
                    vec![[0x61; 16], [0x62; 16]],
                    outcome_index_root(&[]).unwrap(),
                )
                .unwrap();
                node.runtime()
                    .block_on(stage_capability_revocation_generation_async(
                        &node.authority,
                        request.authority(),
                        &body,
                    ))
                    .unwrap()
                    .generation_root()
            });
            let body = RepositoryIncarnationConfigurationBodyV2_2 {
                root_layout: base.root_layout,
                object_format: base.object_format,
                repository_incarnation_id: base.repository_incarnation_id,
                policy_root,
                capability_revocation_root,
            };
            (
                node.runtime()
                    .block_on(
                        stage_revocation_aware_repository_incarnation_configuration_async(
                            &node.authority,
                            request.authority(),
                            &body,
                        ),
                    )
                    .unwrap(),
                VerifiedReadConfiguration::RepositoryIncarnationV2_2(body),
            )
        }
        _ => panic!("fixture names a published configuration schema"),
    };
    let ref_root = node
        .runtime()
        .block_on(node.admission_materializer.stage_ref_state_for_layout_in(
            &node.authority,
            request.authority(),
            node.repository_id(),
            LAYOUT,
            CanonicalRefState::default(),
        ))
        .unwrap();
    node.runtime()
        .block_on(
            node.admission_materializer
                .stage_permitted_object_closure_in(
                    &node.authority,
                    request.authority(),
                    node.repository_id(),
                    PermittedObjectClosure::default(),
                ),
        )
        .unwrap();
    let genesis = genesis_head(node.repository_id(), ref_root, configuration_root).unwrap();
    initialize_embedded_repository(
        node.runtime(),
        &node.authority,
        request.authority(),
        &node.head_key,
        &genesis,
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    (node, exact)
}

struct Source {
    commit: GitOid,
    blob: GitOid,
    objects: Vec<GitOid>,
    commit_body: Vec<u8>,
    tree_body: Vec<u8>,
}

fn publish_source(node: &OneNode) -> Source {
    let blob = node
        .put_git_object(ObjectType::Blob, CONTENT.to_vec())
        .unwrap()
        .identity();
    let tree_body = [b"100644 app\0".as_slice(), blob.as_bytes()].concat();
    let tree = node
        .put_git_object(ObjectType::Tree, tree_body.clone())
        .unwrap()
        .identity();
    let commit_body = format!(
        "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nexact configuration proof fixture\n"
    ).into_bytes();
    let commit = node
        .put_git_object(ObjectType::Commit, commit_body.clone())
        .unwrap()
        .identity();
    let objects = BTreeSet::from([blob, tree, commit]);
    let request = node.request_context();
    let selected = authenticated(node);
    let body = selected.body().unwrap();
    let basis = PublicationBasis::new(authority_head_id(&body).unwrap(), body);
    let record = crate::tests::stage_fixture_ref_record(
        node,
        &request,
        &basis,
        &CanonicalRefState::new(BTreeMap::from([(reference(), commit)])),
        &PermittedObjectClosure::new(objects.clone()),
    );
    let mut roots = ResultingRoots::carried_forward(&basis);
    roots.ref_root = record.resulting_ref_root;
    let mut plan = PublicationPlan::open(basis).unwrap();
    plan.commit(record);
    let outcomes = node
        .runtime()
        .block_on(collect_cumulative_outcomes_async(
            &node.authority,
            request.authority(),
            &node.head_key,
        ))
        .unwrap();
    let sealed = plan
        .seal(
            &CryptoBodyIdentity,
            roots,
            &outcomes,
            selected.receipt().token(),
        )
        .unwrap();
    assert!(matches!(
        node.runtime()
            .block_on(node.publish_decisions_in(&request, &sealed))
            .unwrap(),
        PublicationVerdict::Published(_)
    ));
    Source {
        commit,
        blob,
        objects: objects.into_iter().collect(),
        commit_body,
        tree_body,
    }
}

fn current_proof(node: &OneNode, query: VerifiedReadQuery) -> VerifiedReadEnvelope {
    let served = node
        .runtime()
        .block_on(node.serve_current_verified_read_in(
            &node.request_context(),
            &RefVisibility::new(),
            ReadLabel::current(),
            VerifiedReadCapability::EnvelopeV1,
            query,
        ))
        .unwrap();
    let ReadResponse::Verified(envelope) = served.response() else {
        panic!("a negotiated proof cannot silently become an unproven answer");
    };
    envelope.as_ref().clone()
}

fn check_source_proofs(
    node: &OneNode,
    source: &Source,
    exact: &VerifiedReadConfiguration,
) -> VerifiedReadEnvelope {
    let head = authenticated(node).body().unwrap();
    let pin = PinnedAuthorityHead::new_with_object_closure(
        head.clone(),
        object_closure_merkle_root(&source.objects).unwrap(),
    );
    let absent = git_object_id(node.object_format, GitObjectKind::Blob, b"not admitted");
    assert!(!source.objects.contains(&absent));
    for (query, membership) in [
        (VerifiedReadQuery::Ref(reference()), VerifiedMembership::Ref),
        (
            VerifiedReadQuery::Ref(RefName::try_new(b"refs/heads/missing").unwrap()),
            VerifiedMembership::RefAbsence,
        ),
        (
            VerifiedReadQuery::Object(source.blob),
            VerifiedMembership::Object,
        ),
        (
            VerifiedReadQuery::Object(absent),
            VerifiedMembership::ObjectAbsence,
        ),
    ] {
        let envelope = current_proof(node, query);
        assert_eq!(envelope.exact_configuration(), Some(exact));
        let bytes = encode_verified_read_envelope(&envelope).unwrap();
        let received = decode_verified_read_envelope(&bytes, DecodeLimits::DEFAULT).unwrap();
        assert_eq!(received, envelope);
        assert_eq!(verify_envelope(&pin, &received), Ok(membership));
    }
    let expected = authority_head_id(&head).unwrap();
    let blob = node
        .runtime()
        .block_on(node.verified_blob_in(
            &node.request_context(),
            &RefVisibility::new(),
            &reference(),
            b"app",
            expected,
        ))
        .unwrap();
    let received =
        decode_verified_blob_envelope(&encode_verified_blob_envelope(&blob).unwrap()).unwrap();
    let verified = verify_blob_against_head(expected, &reference(), b"app", &received).unwrap();
    assert_eq!(verified.bytes, CONTENT);
    assert_eq!(verified.source_commit, source.commit);
    assert_eq!(
        authenticated(node).body().unwrap(),
        head,
        "proofs publish no state"
    );
    current_proof(node, VerifiedReadQuery::Ref(reference()))
}

fn credential(node: &OneNode, token: &str, grant: AgentCredentialGrant, revoke: bool) {
    let command = AgentCredentialCommand {
        id: agent_credential_id(token.as_bytes()).unwrap(),
        expected_version: if revoke {
            ExpectedVersion::Exactly(AggregateVersion::FIRST)
        } else {
            ExpectedVersion::NewStream
        },
        action: if revoke {
            AgentCredentialAction::Revoke(grant)
        } else {
            AgentCredentialAction::Issue(grant)
        },
    };
    let session = LoopbackReceiveSession::authenticated(
        OWNER,
        IdempotencyKey::new(format!("proof-credential-{}-{revoke}", command.id).into_bytes())
            .unwrap(),
    );
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_agent_credential_durable_in(
            &node.request_context(),
            &session,
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "{terminal:?}"
    );
}

fn grant(node: &OneNode, operations: u16) -> AgentCredentialGrant {
    let now = crate::agent_credentials::epoch_seconds().unwrap();
    AgentCredentialGrant {
        agent: AGENT,
        sponsor: OWNER,
        sponsor_kind: SponsorKind::Human,
        tenant: node.tenant_id(),
        repository: node.repository_id(),
        incarnation: node.repository_incarnation_id(),
        issued_at: now - 1,
        expires_at: now + 3600,
        operations,
    }
}

fn reopen(config: NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config).unwrap();
    let generation = authenticated(&node).receipt().generation();
    node.bring_into_service(generation).unwrap();
    node
}

#[test]
fn revocation_aware_native_proofs_survive_checkpoint_tail_and_cold_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, exact) = configured_node(&scratch, format, 2, true);
        let source = publish_source(&node);
        let original = authenticated(&node);
        let original_body = original.body().unwrap();
        let original_proof = check_source_proofs(&node, &source, &exact);
        let checkpoint = node
            .runtime()
            .block_on(node.checkpoint_outcomes_in(&node.request_context(), Default::default()))
            .unwrap();
        assert_eq!(
            checkpoint.backup_profile,
            BackupProfile::DecisionHistoryWithAdmissionClosureV1.as_str()
        );

        // These are real canonical forge publications after the checkpoint.
        // Their empty closures must not erase the admitted source prefix.
        let token = format!("fgagent_{}", "a".repeat(64));
        let issued = grant(&node, SOURCE_READ);
        credential(&node, &token, issued, false);
        credential(&node, &token, issued, true);
        let current = authenticated(&node).body().unwrap();
        assert_ne!(current, original_body);
        node.shutdown().unwrap();
        let node = reopen(scratch.config(format));
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&node.request_context()))
            .unwrap();
        assert!(matches!(
            selected.selected_closure().source(),
            ClosureSelectionSource::CapsuleCheckpoint { .. }
        ));
        assert_eq!(
            selected
                .selected_closure()
                .closure()
                .objects()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            source.objects
        );
        assert_eq!(authenticated(&node).body().unwrap(), current);
        check_source_proofs(&node, &source, &exact);

        let revocations = node
            .runtime()
            .block_on(read_head_selected_capability_revocation_generation_async(
                &node.authority,
                node.request_context().authority(),
                node.tenant_id(),
                &authenticated(&node),
            ))
            .unwrap();
        assert_eq!(
            revocations.body().revoked_capability_ids(),
            &[[0x61; 16], [0x62; 16]]
        );
        assert!(
            node.runtime()
                .block_on(node.authenticate_agent_request_in(
                    &node.request_context(),
                    token.as_bytes(),
                    &IdempotencyKey::new(b"revoked-proof".to_vec()).unwrap(),
                    SOURCE_READ,
                    sha256_digest(b"revoked-proof"),
                    4096,
                    65536,
                ))
                .is_err(),
            "supporting the exact configuration must not revive revoked credentials"
        );

        let snapshot = node
            .runtime()
            .block_on(node.serve_snapshot_verified_read_in(
                &node.request_context(),
                original.receipt(),
                &RefVisibility::new(),
                ReadLabel::snapshot(),
                VerifiedReadCapability::EnvelopeV1,
                VerifiedReadQuery::Ref(reference()),
            ))
            .unwrap();
        let ReadResponse::Verified(envelope) = snapshot.response() else {
            panic!("snapshot proof required")
        };
        assert_eq!(envelope.as_ref(), &original_proof);
        assert_eq!(
            verify_envelope(&PinnedAuthorityHead::new(original_body), envelope),
            Ok(VerifiedMembership::Ref)
        );

        let hidden = node.runtime().block_on(node.serve_current_verified_read_in(
            &node.request_context(),
            &RefVisibility::new(),
            ReadLabel::current(),
            VerifiedReadCapability::EnvelopeV1,
            VerifiedReadQuery::Ref(RefName::try_new(b"refs/heads/private").unwrap()),
        ));
        assert!(
            matches!(hidden, Err(VerifiedReadServingRefusal::VerifiedRead(error)) if *error == VerifiedReadRefusal::RefNotFoundOrUnauthorized)
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn exact_native_legacy_twins_and_empty_revocation_selection_never_alias() {
    for minor in [0, 1, 2] {
        let scratch = Scratch::new();
        let (node, exact) = configured_node(&scratch, GitHashAlgorithm::Sha256, minor, false);
        let source = publish_source(&node);
        let original = check_source_proofs(&node, &source, &exact);
        if let VerifiedReadConfiguration::RepositoryIncarnationV2_2(body) = exact {
            let old = RepositoryIncarnationConfigurationBodyV2_1 {
                root_layout: body.root_layout,
                object_format: body.object_format,
                repository_incarnation_id: body.repository_incarnation_id,
                policy_root: body.policy_root,
            };
            let pin = PinnedAuthorityHead::new(original.head().clone());
            for replaced in [
                VerifiedReadConfiguration::RepositoryIncarnationV2_1(old),
                VerifiedReadConfiguration::RepositoryIncarnationV2_2(
                    RepositoryIncarnationConfigurationBodyV2_2 {
                        capability_revocation_root: Some(original.head().ref_root),
                        ..body
                    },
                ),
                VerifiedReadConfiguration::RepositoryIncarnationV2_2(
                    RepositoryIncarnationConfigurationBodyV2_2 {
                        policy_root: Some(original.head().ref_root),
                        ..body
                    },
                ),
            ] {
                let tampered = VerifiedReadEnvelope::new_with_exact_configuration(
                    original.head().clone(),
                    Some(replaced),
                    original.answer().clone(),
                );
                assert_eq!(
                    verify_envelope(&pin, &tampered),
                    Err(VerifiedReadRefusal::ConfigurationRootMismatch)
                );
                let blob = VerifiedBlobEnvelope::from_parts(
                    tampered,
                    b"app".to_vec(),
                    source.commit_body.clone(),
                    vec![source.tree_body.clone()],
                    CONTENT.to_vec(),
                )
                .unwrap();
                let received =
                    decode_verified_blob_envelope(&encode_verified_blob_envelope(&blob).unwrap())
                        .unwrap();
                assert!(
                    verify_blob_against_head(
                        authority_head_id(original.head()).unwrap(),
                        &reference(),
                        b"app",
                        &received
                    )
                    .is_err()
                );
            }
        }
        node.shutdown().unwrap();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn http_proofs(
    node: OneNode,
    scratch: &Scratch,
    expected: RepositoryAuthorityHeadId,
    tokens: &[String],
) -> Vec<(u16, Vec<u8>)> {
    // A broad static row for the revoked canonical bearer must not rescue it.
    let path = scratch.0.join("credentials");
    fs::write(&path, format!(
        "frankengit-http-credentials-v1 {} {} {}\n{} {OWNER} read\n{} {OWNER} issues-read\n{} {OWNER} read\n",
        node.tenant_id(), node.repository_id(), node.repository_incarnation_id(),
        hex(&sha256_digest(tokens[0].as_bytes())),
        hex(&sha256_digest(tokens[1].as_bytes())),
        hex(&sha256_digest(tokens[2].as_bytes())),
    )).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let route = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
    let count = tokens.len();
    let worker = std::thread::spawn(move || {
        let receipt = node
            .serve_repository_http_with_source_bounded(
                &listener,
                GitDaemonServerLimits::try_new(count, 2).unwrap(),
                &path,
                false,
                false,
                true,
                false,
                Duration::from_secs(5),
            )
            .unwrap();
        node.shutdown().unwrap();
        receipt
    });
    let id = expected.as_internal_object_id();
    let target = format!(
        "{route}/api/v1/source/verified-blob?ref_hex={}&path_hex={}&expected_head=alg:{}:{}",
        hex(reference().as_bytes()),
        hex(b"app"),
        id.algorithm().code_point(),
        hex(id.digest().as_bytes()),
    );
    let responses = tokens.iter().map(|token| {
        let mut socket = TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
        write!(socket, "GET {target} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n").unwrap();
        let mut bytes = Vec::new();
        socket.take(MAX_VERIFIED_BLOB_FRAME_BYTES as u64 + 16384).read_to_end(&mut bytes).unwrap();
        let split = bytes.windows(4).position(|part| part == b"\r\n\r\n").unwrap() + 4;
        let headers = std::str::from_utf8(&bytes[..split]).unwrap();
        let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
        let length: usize = headers.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().parse().unwrap();
        assert_eq!(length, bytes.len() - split);
        (status, bytes[split..].to_vec())
    }).collect();
    worker.join().unwrap();
    responses
}

#[test]
fn scoped_http_proofs_support_exact_2_2_without_broadening_sponsored_routes() {
    let scratch = Scratch::new();
    let (node, _) = configured_node(&scratch, GitHashAlgorithm::Sha256, 2, true);
    let source = publish_source(&node);
    let sponsored =
        ['a', 'b', 'c'].map(|value| format!("fgagent_{}", value.to_string().repeat(64)));
    for (index, token) in sponsored.iter().enumerate() {
        let issued = grant(&node, if index == 1 { ISSUES_READ } else { SOURCE_READ });
        credential(&node, token, issued, false);
        if index == 2 {
            credential(&node, token, issued, true);
        }
    }
    node.runtime()
        .block_on(node.checkpoint_outcomes_in(&node.request_context(), Default::default()))
        .unwrap();
    let expected = authority_head_id(&authenticated(&node).body().unwrap()).unwrap();
    node.shutdown().unwrap();
    // The existing proof endpoint admits a static source-read credential.
    // Canonical sponsored credentials still have a closed endpoint allowlist:
    // neither an active SOURCE_READ grant nor a revoked bearer with a static
    // collision acquires this endpoint through configuration proof support.
    let tokens = [
        "d".repeat(64),
        "e".repeat(64),
        sponsored[2].clone(),
        sponsored[0].clone(),
    ];
    let responses = http_proofs(
        reopen(scratch.config(GitHashAlgorithm::Sha256)),
        &scratch,
        expected,
        &tokens,
    );
    assert_eq!(
        responses
            .iter()
            .map(|(status, _)| *status)
            .collect::<Vec<_>>(),
        [200, 403, 403, 403]
    );
    let envelope = decode_verified_blob_envelope(&responses[0].1).unwrap();
    let verified = verify_blob_against_head(expected, &reference(), b"app", &envelope).unwrap();
    assert_eq!(verified.bytes, CONTENT);
    assert_eq!(verified.source_commit, source.commit);
    for (_, body) in &responses[1..] {
        assert!(decode_verified_blob_envelope(body).is_err());
    }
    let node = reopen(scratch.config(GitHashAlgorithm::Sha256));
    assert_eq!(
        authority_head_id(&authenticated(&node).body().unwrap()).unwrap(),
        expected
    );
    node.shutdown().unwrap();
}
