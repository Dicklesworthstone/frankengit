//! Real persisted node operations through MCP framing, with separate grants,
//! exact metadata, canonical refusals and original-key recovery after restart.
use super::*;
use crate::mcp::{WriteGrants, protocol::Server};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{LoopbackReceiveSession, NodeConfig};
use fgit_pack::{EntryKind, object_type_from_base_entry};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    root: PathBuf,
    options: Options,
    commit: GitOid,
    tree: GitOid,
    blob: GitOid,
    orphan: GitOid,
}
fn actor() -> PrincipalId {
    PrincipalId::from_bytes([0xd3; 16])
}
fn reference(bytes: &[u8]) -> RefName {
    RefName::try_new(bytes).unwrap()
}
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-tags-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let mut options = Options {
            storage: root.join("node"),
            tenant: TenantId::from_bytes([0xd1; 16]),
            repository: RepositoryId::from_bytes([0xd2; 16]),
            format,
            incarnation: None,
            issues: false,
            discussions: false,
            pulls: false,
            source: true,
            writes: WriteGrants {
                source: true,
                ..Default::default()
            },
            outcomes: true,
            principal: Some(actor()),
            queues: Default::default(),
            agent_context: false,
            artifacts: false,
            artifact_root: None,
            agent_token_file: None,
            max_messages: 128,
            index_maintenance: None,
        };
        let (mut node, _) = OneNode::init(
            NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
                .with_object_format(format)
                .with_worker_threads(2),
        )
        .unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let main = reference(b"refs/heads/main");
        let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
            &request, &main,
            b"diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1 @@\n+release source\n",
            &MergeMetadata { author: "A <a@example.invalid>".into(), committer: "C <c@example.invalid>".into(), timestamp: 1, message: b"seed\n".to_vec() },
            Default::default(), None,
        )).unwrap();
        let result = node
            .runtime()
            .block_on(node.apply_initial_patch_bundle_durable_in(
                &request,
                &LoopbackReceiveSession::authenticated(
                    actor(),
                    IdempotencyKey::new(b"seed-tags".to_vec()).unwrap(),
                ),
                &main,
                plan.commit,
                bundle.bytes(),
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let orphan = node
            .put_git_object(
                object_type_from_base_entry(EntryKind::Blob).unwrap(),
                b"not-selected-and-not-visible".to_vec(),
            )
            .unwrap()
            .identity();
        options.incarnation = Some(node.repository_incarnation_id());
        node.shutdown().unwrap();
        Self {
            root,
            options,
            commit: plan.commit,
            tree: plan.tree,
            blob: plan.files[0].blob,
            orphan,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn state(node: &OneNode) -> (RepositoryAuthorityHeadId, BTreeMap<RefName, GitOid>) {
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap();
    (selected.basis().id(), selected.snapshot().refs.clone())
}
fn args(reference: &[u8]) -> Object {
    object([("reference_hex", text(hex(reference)))])
        .object()
        .unwrap()
        .clone()
}
fn write_args(name: &str, reference: &[u8], target: GitOid, key: &str) -> Object {
    let mut args = args(reference);
    args.insert("idempotency_key".into(), text(key));
    args.insert(
        if name == DELETE {
            "expected_object"
        } else {
            "target"
        }
        .into(),
        text(target.to_string()),
    );
    if name == ANNOTATE {
        args.insert("target_kind".into(), text("blob"));
        args.insert(
            "tagger".into(),
            text("Claimed Author <metadata@example.invalid>"),
        );
        args.insert("timestamp".into(), text("0"));
        args.insert(
            "message_hex".into(),
            text(hex(
                b"raw\xff\r\n-----BEGIN PGP SIGNATURE-----\nnot-a-verified-signature",
            )),
        );
    }
    args
}
fn server(backend: &mut NodeTools) -> Server {
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"native-tags","version":"1"}}}"#).unwrap();
    assert!(
        server
            .receive(
                backend,
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .is_none()
    );
    server
}
fn invoke(
    server: &mut Server,
    backend: &mut NodeTools,
    next: &mut u64,
    name: &str,
    args: Object,
) -> Value {
    let message = object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(*next)),
        ("method", text("tools/call")),
        (
            "params",
            object([("name", text(name)), ("arguments", Value::Object(args))]),
        ),
    ])
    .encode(json::MAX_INPUT)
    .unwrap();
    *next += 1;
    server.receive(backend, message.as_bytes()).unwrap()
}
fn result(reply: &Value) -> &Object {
    reply.object().unwrap()["result"].object().unwrap()["structuredContent"]
        .object()
        .unwrap()
}
fn success(reply: &Value) -> &Object {
    assert_eq!(
        reply.object().unwrap()["result"].object().unwrap()["isError"],
        Value::Bool(false),
        "{reply:?}"
    );
    result(reply)
}
fn committed(reply: &Value) -> &Object {
    let result = success(reply);
    assert_eq!(result["outcome"].text(), Some("committed"));
    assert_eq!(result["terminal"], Value::Bool(true));
    assert_eq!(result["historical_outcome"], Value::Bool(true));
    assert_eq!(result["current_refs_asserted"], Value::Bool(false));
    assert_eq!(result["ref_transaction_committed"], Value::Bool(true));
    assert!(!result.contains_key("idempotency_key"));
    result
}
fn tool_failure(reply: &Value, code: &str) {
    assert_eq!(
        reply.object().unwrap()["result"].object().unwrap()["isError"],
        Value::Bool(true),
        "{reply:?}"
    );
    assert_eq!(result(reply)["code"].text(), Some(code));
}

#[test]
fn native_tags_complete_the_mcp_release_lifecycle_and_recover_original_decisions_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let mut protocol = server(&mut backend);
        let mut next = 2;
        // Every native target kind stays explicit and independently verified.
        for (suffix, target, kind) in [
            ("commit", fixture.commit, "commit"),
            ("tree", fixture.tree, "tree"),
            ("blob", fixture.blob, "blob"),
        ] {
            let name = format!("refs/tags/{suffix}");
            let created = invoke(
                &mut protocol,
                &mut backend,
                &mut next,
                CREATE,
                write_args(CREATE, name.as_bytes(), target, suffix),
            );
            assert_eq!(
                committed(&created)["new_object"].text(),
                Some(target.to_string().as_str())
            );
            let before = state(&backend.node);
            let read = invoke(
                &mut protocol,
                &mut backend,
                &mut next,
                INSPECT,
                args(name.as_bytes()),
            );
            let read = success(&read);
            assert_eq!(read["peeled_kind"].text(), Some(kind));
            assert_eq!(read["annotation_count"].text(), Some("0"));
            assert_eq!(read["read_only"], Value::Bool(true));
            assert_eq!(state(&backend.node), before);
        }
        let inner_ref = b"refs/tags/release-\xff";
        let inner_args = write_args(ANNOTATE, inner_ref, fixture.blob, "original-inner");
        let expected_inner = input::mutation(ANNOTATE, &inner_args, format)
            .unwrap()
            .command
            .prepare(format)
            .unwrap()
            .object
            .unwrap();
        let created = invoke(
            &mut protocol,
            &mut backend,
            &mut next,
            ANNOTATE,
            inner_args.clone(),
        );
        let original_tx = committed(&created)["tx_id"].clone();
        assert_eq!(
            committed(&created)["new_object"].text(),
            Some(expected_inner.id.to_string().as_str())
        );
        assert_eq!(
            committed(&created)["principal_id"].text(),
            Some(actor().to_string().as_str())
        );
        let mut outer_args = write_args(
            ANNOTATE,
            b"refs/tags/outer",
            expected_inner.id,
            "original-outer",
        );
        outer_args.insert("target_kind".into(), text("tag"));
        outer_args.insert("message_hex".into(), text(hex(b"outer exact\r\n")));
        let expected_outer = input::mutation(ANNOTATE, &outer_args, format)
            .unwrap()
            .command
            .prepare(format)
            .unwrap()
            .object
            .unwrap();
        committed(&invoke(
            &mut protocol,
            &mut backend,
            &mut next,
            ANNOTATE,
            outer_args,
        ));
        let mut inspect_args = args(b"refs/tags/outer");
        inspect_args.insert(
            "expected_object".into(),
            text(expected_outer.id.to_string()),
        );
        let held = state(&backend.node);
        let inspected = invoke(
            &mut protocol,
            &mut backend,
            &mut next,
            INSPECT,
            inspect_args.clone(),
        );
        let inspected = success(&inspected);
        assert_eq!(inspected["annotation_count"].text(), Some("2"));
        assert_eq!(
            inspected["peeled_object"].text(),
            Some(fixture.blob.to_string().as_str())
        );
        let Value::Array(rows) = &inspected["annotations"] else {
            panic!("annotations")
        };
        for (row, expected) in rows.iter().zip([&expected_outer, &expected_inner]) {
            let row = row.object().unwrap();
            let body = unhex(row["body_hex"].text().unwrap(), MAX_OBJECT_BYTES).unwrap();
            assert_eq!(body, expected.body);
            assert_eq!(
                git_object_id(format, GitObjectKind::Tag, &body),
                expected.id
            );
            assert_eq!(row["signature_verified"], Value::Bool(false));
        }
        assert_eq!(
            rows[1].object().unwrap()["signature"].text(),
            Some("opaque_unverifiable")
        );
        assert_eq!(
            inspected["tagger_is_authenticated_principal"],
            Value::Bool(false)
        );
        assert_eq!(state(&backend.node), held);
        let mut limited = inspect_args.clone();
        limited.insert("max_tags".into(), json::number(1));
        tool_failure(
            &invoke(&mut protocol, &mut backend, &mut next, INSPECT, limited),
            "resource_limit",
        );
        let mut wrong = inspect_args.clone();
        wrong.insert("expected_object".into(), text(fixture.blob.to_string()));
        tool_failure(
            &invoke(&mut protocol, &mut backend, &mut next, INSPECT, wrong),
            "tag_object_moved",
        );
        inspect_args.insert("expected_head".into(), inspected["snapshot_token"].clone());
        committed(&invoke(
            &mut protocol,
            &mut backend,
            &mut next,
            CREATE,
            write_args(CREATE, b"refs/tags/alias", expected_outer.id, "alias"),
        ));
        tool_failure(
            &invoke(
                &mut protocol,
                &mut backend,
                &mut next,
                INSPECT,
                inspect_args,
            ),
            "snapshot_moved",
        );
        let alias = invoke(
            &mut protocol,
            &mut backend,
            &mut next,
            INSPECT,
            args(b"refs/tags/alias"),
        );
        assert_eq!(success(&alias)["annotation_count"].text(), Some("2"));
        // Deletion compares the outer object, never its peeled payload.
        let refs = state(&backend.node).1;
        let wrong_delete = invoke(
            &mut protocol,
            &mut backend,
            &mut next,
            DELETE,
            write_args(DELETE, inner_ref, fixture.blob, "wrong-outer"),
        );
        assert_eq!(result(&wrong_delete)["outcome"].text(), Some("refused"));
        assert_eq!(
            wrong_delete.object().unwrap()["result"].object().unwrap()["isError"],
            Value::Bool(true)
        );
        assert_eq!(state(&backend.node).1, refs);
        let delete_args = write_args(DELETE, inner_ref, expected_inner.id, "delete-inner");
        let deleted = invoke(
            &mut protocol,
            &mut backend,
            &mut next,
            DELETE,
            delete_args.clone(),
        );
        let deletion_tx = committed(&deleted)["tx_id"].clone();
        let after_delete = state(&backend.node);
        backend.close().unwrap();

        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let mut protocol = server(&mut backend);
        let mut next = 2;
        let replay = invoke(
            &mut protocol,
            &mut backend,
            &mut next,
            ANNOTATE,
            inner_args.clone(),
        );
        assert_eq!(committed(&replay)["tx_id"], original_tx);
        let replay = invoke(&mut protocol, &mut backend, &mut next, DELETE, delete_args);
        assert_eq!(committed(&replay)["tx_id"], deletion_tx);
        assert_eq!(
            state(&backend.node),
            after_delete,
            "historical retries cannot recreate the deleted tag"
        );
        tool_failure(
            &invoke(
                &mut protocol,
                &mut backend,
                &mut next,
                INSPECT,
                args(inner_ref),
            ),
            "tag_unavailable",
        );
        let recovered = invoke(
            &mut protocol,
            &mut backend,
            &mut next,
            outcomes::NAME,
            object([("idempotency_key", text("original-inner"))])
                .object()
                .unwrap()
                .clone(),
        );
        assert_eq!(success(&recovered)["tx_id"], original_tx);
        let mut changed = inner_args;
        changed.insert("message_hex".into(), text(hex(b"changed under old key")));
        let changed = invoke(&mut protocol, &mut backend, &mut next, ANNOTATE, changed);
        tool_failure(&changed, "tag_mutation_outcome_unknown");
        assert_eq!(result(&changed)["outcome_unknown"], Value::Bool(true));
        assert_eq!(state(&backend.node), after_delete);
        // The other visible outer tag still authorizes its original chain.
        assert_eq!(
            success(&invoke(
                &mut protocol,
                &mut backend,
                &mut next,
                INSPECT,
                args(b"refs/tags/outer")
            ))["annotation_count"]
                .text(),
            Some("2")
        );
        backend.close().unwrap();
    }
}

#[test]
fn source_grants_visibility_and_native_kind_checks_precede_any_false_success() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut writer_options = fixture.options.clone();
    writer_options.source = false;
    writer_options.outcomes = false;
    let mut writer = NodeTools::open(writer_options).unwrap();
    let before = state(&writer.node);
    assert_eq!(
        writer.call(INSPECT, &Object::new()).unwrap_err().code,
        "tool_not_granted"
    );
    assert_eq!(
        inspect(&writer, &Object::new()).unwrap_err().code,
        "tool_not_granted"
    );
    for name in [CREATE, ANNOTATE, DELETE] {
        assert!(writer.tools().iter().any(|tool| tool.name == name));
        assert!(writer.is_mutation(name));
    }
    let mut wrong_kind = write_args(
        ANNOTATE,
        b"refs/tags/wrong-kind",
        fixture.blob,
        "wrong-kind",
    );
    wrong_kind.insert("target_kind".into(), text("commit"));
    assert_eq!(
        writer.call(ANNOTATE, &wrong_kind).unwrap_err().code,
        "tag_mutation_outcome_unknown"
    );
    for name in [CREATE, ANNOTATE] {
        assert!(
            writer
                .call(
                    name,
                    &write_args(name, b"refs/tags/orphan", fixture.orphan, name)
                )
                .is_err()
        );
    }
    assert_eq!(state(&writer.node), before);
    let allowed = write_args(
        ANNOTATE,
        b"refs/tags/permitted",
        fixture.blob,
        "visible-blob",
    );
    let accepted = writer.call(ANNOTATE, &allowed).unwrap();
    assert_eq!(
        accepted.object().unwrap()["outcome"].text(),
        Some("committed")
    );
    let receipt = accepted.object().unwrap();
    let outer = receipt["new_object"].clone();
    let collision = writer
        .call(ANNOTATE, &{
            let mut duplicate = allowed.clone();
            duplicate.insert("idempotency_key".into(), text("cannot-overwrite"));
            duplicate
        })
        .unwrap();
    assert_eq!(
        collision.object().unwrap()["outcome"].text(),
        Some("refused")
    );
    assert!(writer.result_is_error(ANNOTATE, &collision));
    writer.close().unwrap();

    let mut read_options = fixture.options.clone();
    read_options.writes = Default::default();
    read_options.outcomes = false;
    read_options.principal = None;
    let mut reader = NodeTools::open(read_options).unwrap();
    let before = state(&reader.node);
    for name in [CREATE, ANNOTATE, DELETE] {
        assert!(!reader.tools().iter().any(|tool| tool.name == name));
        assert_eq!(
            reader.call(name, &Object::new()).unwrap_err().code,
            "tool_not_granted"
        );
        assert_eq!(
            write(&reader, name, &Object::new()).unwrap_err().code,
            "tool_not_granted"
        );
    }
    let mut query = args(b"refs/tags/permitted");
    query.insert("expected_object".into(), outer);
    assert!(reader.call(INSPECT, &query).is_ok());
    for field in ["max_object_bytes", "max_total_bytes"] {
        let mut limited = query.clone();
        limited.insert(field.into(), json::number(1));
        assert!(reader.call(INSPECT, &limited).is_err());
    }
    assert_eq!(state(&reader.node), before);
    reader.close().unwrap();
}
