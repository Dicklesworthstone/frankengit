use super::*;
use fgit_admission::{AdmissionResult, CommandOutcome, SessionMapping};
use fgit_authority::{ExpectedOld, ProposedNew, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::tags::{TagAnnotation, TagCommand, TagMetadata, TagRead, TagSignatureState};
use fgit_schema::mcp::ReadMutationClass;
use fgit_types::{
    DecisionOutcome, DecisionSequence, GitHashAlgorithm, GitOid, PrincipalId, RefName, RefusalCode,
    RefusalRecordId, RepositoryCommitId, RepositoryId, RepositoryIncarnationId, TenantId, TxId,
};
use std::collections::BTreeSet;

fn map(value: Value) -> Object {
    value.object().unwrap().clone()
}
fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
    git_object_id(format, GitObjectKind::Blob, &[byte])
}
fn arguments(name: &str, format: GitHashAlgorithm) -> Object {
    let mut args = map(object([("reference", text("refs/tags/release"))]));
    if name == INSPECT {
        return args;
    }
    args.insert("idempotency_key".into(), text("original-release"));
    args.insert(
        if name == DELETE {
            "expected_object"
        } else {
            "target"
        }
        .into(),
        text(oid(format, 7).to_string()),
    );
    if name == ANNOTATE {
        args.insert("target_kind".into(), text("blob"));
        args.insert(
            "tagger".into(),
            text("Release Author <author@example.invalid>"),
        );
        args.insert("timestamp".into(), text("0"));
        args.insert(
            "message_hex".into(),
            text(hex(b"release\xff\r\nwithout-final")),
        );
    }
    args
}

#[test]
fn commands_preserve_raw_names_metadata_and_exact_nonforced_ref_shapes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for name in [CREATE, ANNOTATE, DELETE] {
            let mut args = arguments(name, format);
            args.remove("reference");
            args.insert("reference_hex".into(), text(hex(b"refs/tags/raw/\xff")));
            let parsed = input::mutation(name, &args, format).unwrap();
            assert_eq!(parsed.command.reference().as_bytes(), b"refs/tags/raw/\xff");
            assert!(!parsed.reference_command.force);
            match name {
                CREATE => {
                    assert_eq!(parsed.reference_command.expected_old, ExpectedOld::Absent);
                    assert_eq!(
                        parsed.reference_command.proposed_new,
                        ProposedNew::Update(oid(format, 7))
                    );
                    assert!(parsed.command.prepare(format).unwrap().object.is_none());
                }
                DELETE => {
                    assert_eq!(
                        parsed.reference_command.expected_old,
                        ExpectedOld::Exactly(oid(format, 7))
                    );
                    assert_eq!(parsed.reference_command.proposed_new, ProposedNew::Delete);
                }
                _ => {
                    let TagCommand::Annotated { metadata, .. } = &parsed.command else {
                        panic!("annotation")
                    };
                    assert_eq!(metadata.message, b"release\xff\r\nwithout-final");
                    assert_eq!(metadata.timestamp, 0);
                    let prepared = parsed.command.prepare(format).unwrap();
                    let body = prepared.object.unwrap();
                    assert_eq!(
                        parsed.reference_command.proposed_new,
                        ProposedNew::Update(body.id)
                    );
                    assert_eq!(
                        body.id,
                        git_object_id(format, GitObjectKind::Tag, &body.body)
                    );
                    assert!(body.body.ends_with(b"release\xff\r\nwithout-final"));
                }
            }
        }
        for message in [Vec::new(), vec![0xff; MAX_MESSAGE_BYTES]] {
            let mut args = arguments(ANNOTATE, format);
            args.insert("message_hex".into(), text(hex(&message)));
            let parsed = input::mutation(ANNOTATE, &args, format).unwrap();
            let TagCommand::Annotated { metadata, .. } = parsed.command else {
                panic!("annotation")
            };
            assert_eq!(metadata.message, message);
            // Maximum accepted annotation remains in the ordinary MCP envelope.
            let request = object([
                ("jsonrpc", text("2.0")),
                ("id", json::number(2)),
                ("method", text("tools/call")),
                (
                    "params",
                    object([("name", text(ANNOTATE)), ("arguments", Value::Object(args))]),
                ),
            ]);
            let encoded = request.encode(json::MAX_INPUT).unwrap();
            assert_eq!(json::parse(encoded.as_bytes()).unwrap(), request);
        }
    }
}

#[test]
fn tag_arguments_cannot_smuggle_authority_names_domains_or_implicit_values() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for name in [CREATE, ANNOTATE, DELETE] {
            let args = arguments(name, format);
            for field in [
                "principal",
                "force",
                "storage",
                "message_file",
                "object_format",
                "expected_head",
                "approved",
                "signature_verified",
            ] {
                let mut bad = args.clone();
                bad.insert(field.into(), text("injected"));
                assert_eq!(
                    input::mutation(name, &bad, format).err().unwrap().code,
                    "unknown_argument"
                );
            }
            for reference in [
                "",
                "refs/heads/release",
                "refs/tags/../release",
                "refs/tags/a.lock",
            ] {
                let mut bad = args.clone();
                bad.insert("reference".into(), text(reference));
                assert!(input::mutation(name, &bad, format).is_err());
            }
            let mut bad = args.clone();
            bad.insert("reference_hex".into(), text(hex(b"refs/tags/release")));
            assert_eq!(
                input::mutation(name, &bad, format).err().unwrap().code,
                "exactly_one_reference_required"
            );
            let mut bad = args.clone();
            bad.remove("reference");
            assert!(input::mutation(name, &bad, format).is_err());
            let pin = if name == DELETE {
                "expected_object"
            } else {
                "target"
            };
            for value in [
                text("latest"),
                text("0".repeat(format.digest_len() * 2)),
                text("A".repeat(format.digest_len() * 2)),
                text("12".repeat(if format == GitHashAlgorithm::Sha1 {
                    32
                } else {
                    20
                })),
                Value::Null,
                json::number(1),
            ] {
                let mut bad = args.clone();
                bad.insert(pin.into(), value);
                assert!(input::mutation(name, &bad, format).is_err());
            }
            for key in [
                "".to_owned(),
                "new key".into(),
                "secret\n".into(),
                "é".into(),
                "x".repeat(257),
            ] {
                let mut bad = args.clone();
                bad.insert("idempotency_key".into(), text(key));
                assert_eq!(
                    input::mutation(name, &bad, format).err().unwrap().code,
                    "invalid_idempotency_key"
                );
            }
        }
        let args = arguments(ANNOTATE, format);
        for (field, value) in [
            ("timestamp", text("01")),
            ("timestamp", json::number(1)),
            ("timestamp", text("9223372036854775808")),
            ("timestamp", text("-1")),
            ("tagger", text("Name <>")),
            ("tagger", text("Name <a@b>\ninjected")),
            ("tagger", text("x".repeat(1025))),
            ("target_kind", text("commit\nblob")),
            ("message_hex", text("00")),
            ("message_hex", text("FF")),
            ("message_hex", text("f")),
            ("message_hex", text("ff".repeat(MAX_MESSAGE_BYTES + 1))),
        ] {
            let mut bad = args.clone();
            bad.insert(field.into(), value);
            assert!(input::mutation(ANNOTATE, &bad, format).is_err(), "{field}");
        }
    }
}

#[test]
fn inspection_pins_only_compare_current_tags_and_limits_only_narrow() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut args = arguments(INSPECT, format);
        args.insert(
            "expected_head".into(),
            text(format!("alg:1:{}", "ab".repeat(32))),
        );
        args.insert("expected_object".into(), text(oid(format, 1).to_string()));
        let query = input::inspection(&args, format).unwrap();
        assert_eq!(query.expected_object, Some(oid(format, 1)));
        assert_eq!(query.limits, default_limits());
        for (name, maximum) in [
            ("max_tags", 64),
            ("max_object_bytes", MAX_OBJECT_BYTES),
            ("max_total_bytes", MAX_TOTAL_BYTES),
        ] {
            let mut smaller = args.clone();
            smaller.insert(name.into(), json::number(1));
            assert!(input::inspection(&smaller, format).is_ok());
            for value in [
                json::number(0),
                json::number(maximum as u64 + 1),
                text("1"),
                Value::Null,
            ] {
                let mut bad = args.clone();
                bad.insert(name.into(), value);
                assert_eq!(
                    input::inspection(&bad, format).err().unwrap().code,
                    "invalid_tag_limits"
                );
            }
        }
        for name in ["idempotency_key", "target", "principal", "force"] {
            let mut bad = args.clone();
            bad.insert(name.into(), text("not-a-read-field"));
            assert_eq!(
                input::inspection(&bad, format).err().unwrap().code,
                "unknown_argument"
            );
        }
    }
}

fn sample(format: GitHashAlgorithm) -> (input::Inspection, TagRead) {
    let reference = RefName::try_new(b"refs/tags/outer-\xff").unwrap();
    let make = |name: RefName, target, kind, message: &[u8], signature| {
        let prepared = TagCommand::Annotated {
            name,
            target,
            target_kind: kind,
            metadata: TagMetadata {
                tagger: "A <a@example.invalid>".into(),
                timestamp: 0,
                message: message.to_vec(),
            },
        }
        .prepare(format)
        .unwrap()
        .object
        .unwrap();
        TagAnnotation {
            id: prepared.id,
            target,
            target_kind: kind,
            body: prepared.body,
            signature,
        }
    };
    let peeled = oid(format, 7);
    let inner = make(
        RefName::try_new(b"refs/tags/inner").unwrap(),
        peeled,
        GitObjectKind::Blob,
        b"untrusted\xff\r\n-----BEGIN PGP SIGNATURE-----\nopaque",
        TagSignatureState::OpaqueUnverifiable,
    );
    let outer = make(
        reference.clone(),
        inner.id,
        GitObjectKind::Tag,
        b"<script>content</script>",
        TagSignatureState::Absent,
    );
    let report = TagRead {
        head: parse_head(&format!("alg:1:{}", "ab".repeat(32))).unwrap(),
        reference: reference.clone(),
        tip: outer.id,
        peeled,
        peeled_kind: GitObjectKind::Blob,
        annotations: vec![outer, inner],
    };
    let query = input::Inspection {
        reference,
        expected_head: Some(report.head),
        expected_object: Some(report.tip),
        limits: default_limits(),
    };
    (query, report)
}

#[test]
fn inspection_preserves_native_bytes_and_distinguishes_signature_presence_from_trust() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (query, report) = sample(format);
        let result = output::inspection(format, &query, &report, &mut || true).unwrap();
        assert_eq!(result["annotation_count"].text(), Some("2"));
        assert_eq!(
            result["peeled_object"].text(),
            Some(report.peeled.to_string().as_str())
        );
        for flag in [
            "signature_verified",
            "tagger_is_authenticated_principal",
            "repository_changed",
            "transaction_created",
            "published",
        ] {
            assert_eq!(result[flag], Value::Bool(false));
        }
        let Value::Array(rows) = &result["annotations"] else {
            panic!("annotations")
        };
        for (row, original) in rows.iter().zip(&report.annotations) {
            let row = row.object().unwrap();
            assert_eq!(
                unhex(row["body_hex"].text().unwrap(), MAX_OBJECT_BYTES).unwrap(),
                original.body
            );
            assert_eq!(row["signature_verified"], Value::Bool(false));
        }
        assert_eq!(
            rows[1].object().unwrap()["signature"].text(),
            Some("opaque_unverifiable")
        );
        let wire = Value::Object(result).encode(MAX_RESULT_BYTES).unwrap();
        assert!(!wire.contains("<script>"));
        let mut light = report.clone();
        light.annotations.clear();
        light.tip = light.peeled;
        let mut light_query = query;
        light_query.expected_object = Some(light.tip);
        assert!(output::inspection(format, &light_query, &light, &mut || true).is_ok());
    }
}

#[test]
fn inconsistent_chains_native_hashes_work_bounds_and_cancellation_never_render_success() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut query, report) = sample(format);
        let mut variants = Vec::new();
        let mut bad = report.clone();
        bad.annotations[0].body.push(b'!');
        variants.push(bad);
        let mut bad = report.clone();
        bad.annotations[0].target = report.peeled;
        variants.push(bad);
        let mut bad = report.clone();
        bad.annotations[0].target_kind = GitObjectKind::Blob;
        variants.push(bad);
        let mut bad = report.clone();
        bad.annotations[1].target = report.tip;
        variants.push(bad);
        let mut bad = report.clone();
        bad.peeled_kind = GitObjectKind::Tag;
        variants.push(bad);
        let mut bad = report.clone();
        bad.reference = RefName::try_new(b"refs/tags/other").unwrap();
        variants.push(bad);
        let mut bad = report.clone();
        bad.tip = oid(format, 9);
        variants.push(bad);
        let mut bad = report.clone();
        bad.head = parse_head(&format!("alg:1:{}", "cd".repeat(32))).unwrap();
        variants.push(bad);
        for bad in variants {
            assert_eq!(
                output::inspection(format, &query, &bad, &mut || true)
                    .unwrap_err()
                    .code,
                "invalid_tag_report"
            );
        }
        query.limits.max_tags = 1;
        assert!(output::inspection(format, &query, &report, &mut || true).is_err());
        query.limits = default_limits();
        query.limits.max_object_bytes = report.annotations[0].body.len() - 1;
        assert!(output::inspection(format, &query, &report, &mut || true).is_err());
        query.limits = default_limits();
        query.limits.max_total_bytes = report
            .annotations
            .iter()
            .map(|row| row.body.len())
            .sum::<usize>()
            - 1;
        assert!(output::inspection(format, &query, &report, &mut || true).is_err());
        query.limits = default_limits();
        assert_eq!(
            output::inspection(format, &query, &report, &mut || false)
                .unwrap_err()
                .code,
            "tag_read_cancelled"
        );
        let mut calls = 0;
        assert_eq!(
            output::inspection(format, &query, &report, &mut || {
                calls += 1;
                calls < 3
            })
            .unwrap_err()
            .code,
            "tag_read_cancelled"
        );
    }
}

#[test]
fn native_byte_budget_does_not_override_the_complete_hex_result_limit() {
    let format = GitHashAlgorithm::Sha256;
    let (mut query, mut report) = sample(format);
    // Four valid native annotation bodies plus the one-byte terminal blob fit
    // the original-read budget. Hex plus required metadata may still exceed
    // the independent MCP output cap. The entire result must then refuse.
    let chain = |body_bytes: usize| {
        let mut target = report.peeled;
        let mut kind = GitObjectKind::Blob;
        let mut rows = Vec::new();
        for index in 0..4 {
            let mut body = format!("object {target}\ntype {}\ntag boundary-{index}\ntagger A <a@example.invalid> 0 +0000\n\n", kind.label()).into_bytes();
            body.resize(body_bytes, b'x');
            let id = git_object_id(format, GitObjectKind::Tag, &body);
            rows.push(TagAnnotation {
                id,
                target,
                target_kind: kind,
                body,
                signature: TagSignatureState::Absent,
            });
            target = id;
            kind = GitObjectKind::Tag;
        }
        rows.reverse();
        rows
    };
    let smaller = chain(MAX_TOTAL_BYTES / 4 - 4096);
    let boundary = chain(MAX_TOTAL_BYTES / 4 - 1);
    report.annotations = smaller;
    report.tip = report.annotations[0].id;
    query.expected_object = Some(report.tip);
    let fields = output::inspection(format, &query, &report, &mut || true).unwrap();
    assert!(output::bounded_inspection(fields).is_ok());
    report.annotations = boundary;
    report.tip = report.annotations[0].id;
    query.expected_object = Some(report.tip);
    assert!(
        report
            .annotations
            .iter()
            .map(|row| row.body.len())
            .sum::<usize>()
            + 1
            <= MAX_TOTAL_BYTES
    );
    let fields = output::inspection(format, &query, &report, &mut || true).unwrap();
    assert_eq!(
        output::bounded_inspection(fields).unwrap_err().code,
        "tag_result_limit"
    );
}

fn terminal(committed: bool) -> AdmissionResult {
    let algorithm = DigestAlgorithmId::try_new(1).unwrap();
    let digest = |byte| DigestBytes::try_new(&[byte; 32]).unwrap();
    let tx = TxId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest(1));
    let terminal = TerminalOutcome {
        decision_sequence: DecisionSequence::FIRST,
        outcome: if committed {
            DecisionOutcome::Committed {
                repository_commit_id: RepositoryCommitId::from_digest(
                    algorithm,
                    CANONICAL_CODEC_VERSION,
                    digest(2),
                ),
            }
        } else {
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                refusal_record_id: RefusalRecordId::from_digest(
                    algorithm,
                    CANONICAL_CODEC_VERSION,
                    digest(3),
                ),
            }
        },
    };
    AdmissionResult {
        session: SessionMapping {
            atomic: true,
            tx_ids: vec![tx],
        },
        commands: vec![CommandOutcome {
            tx_id: tx,
            terminal,
        }],
    }
}

#[test]
fn only_one_atomic_terminal_decision_can_be_a_tag_publication_receipt() {
    for committed in [false, true] {
        let result = terminal(committed);
        for name in [CREATE, ANNOTATE, DELETE] {
            let input = input::mutation(
                name,
                &arguments(name, GitHashAlgorithm::Sha1),
                GitHashAlgorithm::Sha1,
            )
            .unwrap();
            let report = output::publication(name, &input.reference_command, &result).unwrap();
            assert_eq!(report["ref_transaction_committed"], Value::Bool(committed));
            assert_eq!(report["current_refs_asserted"], Value::Bool(false));
            assert_eq!(report["historical_outcome"], Value::Bool(true));
            assert_eq!(report["terminal"], Value::Bool(true));
            assert_eq!(report["outcome_unknown"], Value::Bool(false));
            assert!(!report.contains_key("idempotency_key"));
        }
        let mut malformed = terminal(committed);
        malformed.session.atomic = false;
        assert!(!output::terminal(&malformed).unwrap_err().invalid);
        let mut malformed = terminal(committed);
        malformed.session.tx_ids.clear();
        assert!(!output::terminal(&malformed).unwrap_err().invalid);
        let mut malformed = terminal(committed);
        malformed.commands.clear();
        assert!(!output::terminal(&malformed).unwrap_err().invalid);
        let mut malformed = terminal(committed);
        malformed.commands.push(malformed.commands[0]);
        assert!(!output::terminal(&malformed).unwrap_err().invalid);
    }
}

fn options() -> Options {
    Options {
        storage: std::path::PathBuf::new(),
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        format: GitHashAlgorithm::Sha1,
        incarnation: Some(RepositoryIncarnationId::from_bytes([3; 16])),
        issues: true,
        discussions: true,
        pulls: true,
        source: false,
        queues: Default::default(),
        agent_context: false,
        artifacts: false,
        artifact_root: None,
        writes: Default::default(),
        outcomes: true,
        principal: Some(PrincipalId::from_bytes([4; 16])),
        agent_token_file: None,
        max_messages: 10,
        index_maintenance: None,
    }
}

#[test]
fn discovery_uses_only_explicit_source_grants_and_preserves_the_closed_agent_profile() {
    for read in [false, true] {
        for write in [false, true] {
            let mut options = options();
            options.source = read;
            options.writes.source = write;
            let tools = tools_for_options(&options);
            for name in [INSPECT, CREATE, ANNOTATE, DELETE] {
                assert_eq!(
                    tools.iter().any(|tool| tool.name == name),
                    if name == INSPECT { read } else { write }
                );
            }
            options.agent_token_file = Some("unused-private-token".into());
            assert!(
                tools_for_options(&options)
                    .iter()
                    .all(|tool| !matches!(tool.name, INSPECT | CREATE | ANNOTATE | DELETE))
            );
            for name in [INSPECT, CREATE, ANNOTATE, DELETE] {
                assert!(agent::operation(&options, name).is_none());
            }
        }
    }
}

#[test]
fn tag_registry_matches_the_closed_served_schemas_and_mutation_classes() {
    for tool in std::iter::once(read_tool()).chain(write_tools()) {
        let contract = fgit_schema::mcp::find_tool(tool.name).unwrap();
        let declared: BTreeSet<_> = contract
            .input_fields
            .iter()
            .map(|field| field.name)
            .collect();
        let schema = tool.schema.object().unwrap();
        let properties = schema["properties"].object().unwrap();
        let served: BTreeSet<_> = properties.keys().map(String::as_str).collect();
        assert_eq!(declared, served, "{}", tool.name);
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        assert!(schema.contains_key("oneOf"));
        assert_eq!(
            contract.read_mutation == ReadMutationClass::Mutation,
            is_write(tool.name)
        );
        assert_eq!(
            properties.contains_key("idempotency_key"),
            is_write(tool.name)
        );
        assert_eq!(
            properties.contains_key("expected_head"),
            tool.name == INSPECT
        );
        assert!(tool.schema.encode(16 * 1024).is_ok());
    }
}
