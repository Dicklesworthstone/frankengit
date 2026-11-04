use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::{
    PlannedMergeObject, rebase::PreparedRebase, resolution::ResolutionChoice,
};
use std::collections::BTreeSet;

fn fields<const N: usize>(pairs: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(pairs) else {
        unreachable!()
    };
    fields
}
fn id(format: GitHashAlgorithm, byte: u8) -> GitOid {
    GitOid::from_hex(format, &hex(&vec![byte; format.digest_len()])).unwrap()
}
fn args(format: GitHashAlgorithm) -> Object {
    fields([
        ("operation", text(PREPARE)),
        ("profile", text("linear-v1")),
        ("reference", text("refs/heads/topic")),
        ("onto_reference", text("refs/heads/main")),
        ("expected_source", text(raw_oid(id(format, 2)))),
        ("expected_onto", text(raw_oid(id(format, 4)))),
        ("upstream", text(raw_oid(id(format, 3)))),
        ("expected_head", text(format!("alg:1:{}", "ab".repeat(32)))),
        ("empty", text("stop")),
        ("committer", text("Committer <committer@example.invalid>")),
        ("timestamp", text("2")),
    ])
}
fn side(path: &[u8], choice: &str) -> Value {
    object([("path_hex", text(hex(path))), ("choice", text(choice))])
}
fn file(path: &[u8], bytes: &[u8]) -> Value {
    object([
        ("path_hex", text(hex(path))),
        ("choice", text("file")),
        ("mode", text("100755")),
        (
            "bytes_hex_chunks",
            Value::Array(
                bytes
                    .chunks(CHUNK_BYTES)
                    .map(|bytes| text(hex(bytes)))
                    .collect(),
            ),
        ),
    ])
}
fn recipe(original: GitOid, paths: Vec<Value>) -> Value {
    object([
        ("original", text(raw_oid(original))),
        ("paths", Value::Array(paths)),
    ])
}
fn resolve(format: GitHashAlgorithm, recipes: Vec<Value>) -> Object {
    let mut fields = args(format);
    fields.insert("operation".into(), text(RESOLVE));
    fields.insert("resolutions".into(), Value::Array(recipes));
    fields
}

#[test]
fn two_raw_branches_native_ids_and_explicit_empty_policy_are_closed() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut raw = args(format);
        raw.remove("reference");
        raw.remove("onto_reference");
        raw.insert("reference_hex".into(), text(hex(b"refs/heads/\xff")));
        raw.insert("onto_reference_hex".into(), text(hex(b"refs/heads/\xfe")));
        let parsed = input::parse(&raw, format).unwrap();
        assert_eq!(parsed.selection.reference.as_bytes(), b"refs/heads/\xff");
        assert_eq!(
            parsed.selection.onto_reference.as_bytes(),
            b"refs/heads/\xfe"
        );
        assert_eq!(parsed.request.source_tip, id(format, 2));
        assert_eq!(parsed.request.upstream, id(format, 3));
        assert_eq!(parsed.request.onto, id(format, 4));
        assert_eq!(parsed.request.empty, EmptyCommitPolicy::Stop);
        for required in [
            "operation",
            "profile",
            "reference",
            "onto_reference",
            "expected_source",
            "expected_onto",
            "upstream",
            "empty",
            "committer",
            "timestamp",
        ] {
            let mut bad = args(format);
            bad.remove(required);
            assert!(input::parse(&bad, format).is_err(), "{required}");
        }
        for name in [
            "principal",
            "storage",
            "tenant_id",
            "repository_id",
            "force",
            "shell",
            "author",
            "message_hex",
            "expected_base",
            "idempotency_key",
            "resolutions",
        ] {
            let mut bad = args(format);
            bad.insert(name.into(), Value::Null);
            assert_eq!(
                input::parse(&bad, format).unwrap_err().code,
                "unknown_argument",
                "{name}"
            );
        }
        for (name, value) in [
            ("reference_hex", text(hex(b"refs/heads/topic"))),
            ("onto_reference_hex", text(hex(b"refs/heads/main"))),
            ("onto_reference", text("refs/heads/topic")),
            ("reference", text("refs/tags/release")),
            ("onto_reference", text("main")),
            ("profile", text("merge-v1")),
            ("empty", text("automatic")),
            ("expected_source", text("00".repeat(format.digest_len()))),
            ("expected_onto", text("AB".repeat(format.digest_len()))),
            ("upstream", text("abcd")),
            ("committer", text("A <a@example.invalid>\nparent injected")),
            ("committer", text("ambient")),
            ("timestamp", text("0")),
            ("timestamp", text("01")),
            ("timestamp", json::number(2)),
            ("timestamp", text(u64::MAX.to_string())),
        ] {
            let mut bad = args(format);
            bad.insert(name.into(), value);
            assert!(input::parse(&bad, format).is_err(), "{name}");
        }
        for name in [
            "max_commits",
            "max_edges",
            "max_tree_entries",
            "max_preparation_bytes",
        ] {
            for value in [json::number(0), json::number(u64::MAX), text("1")] {
                let mut bad = args(format);
                bad.insert(name.into(), value);
                assert!(input::parse(&bad, format).is_err(), "{name}");
            }
        }
    }
}

#[test]
fn original_commit_resolution_grammar_shares_replay_rules_and_global_envelopes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let choices = vec![side(b"z", "ours"), file(b"a-\xff", b"\0\xff\r\n")];
        let good = resolve(format, vec![recipe(id(format, 2), choices.clone())]);
        let parsed = input::parse(&good, format).unwrap();
        let native = parsed.resolutions.unwrap();
        let shared = fields([("resolutions", Value::Array(choices))]);
        assert_eq!(
            native[0].paths,
            super::super::replay::input::resolutions(&shared).unwrap()
        );
        assert_eq!(
            native[0].paths[0].choice,
            ResolutionChoice::File {
                mode: 0o100755,
                bytes: b"\0\xff\r\n".to_vec()
            }
        );
        let mut missing = good;
        missing.remove("expected_head");
        assert_eq!(
            input::parse(&missing, format).unwrap_err().code,
            "resolution_snapshot_required"
        );
        for rows in [
            vec![],
            vec![recipe(id(format, 1), vec![])],
            vec![
                recipe(id(format, 1), vec![side(b"a", "ours")]),
                recipe(id(format, 1), vec![side(b"b", "theirs")]),
            ],
            vec![recipe(
                id(format, 1),
                vec![side(b"a", "ours"), side(b"a", "theirs")],
            )],
            vec![recipe(
                id(format, 1),
                vec![side(b"a", "ours"), side(b"a/b", "theirs")],
            )],
            vec![recipe(id(format, 1), vec![side(b"../x", "ours")])],
            vec![recipe(id(format, 1), vec![side(b"x/.GiT/config", "ours")])],
            vec![recipe(id(format, 1), vec![side(b"a", "automatic")])],
        ] {
            assert!(input::parse(&resolve(format, rows), format).is_err());
        }
        let mut exact = resolve(
            format,
            vec![
                recipe(
                    id(format, 1),
                    vec![file(b"a", &vec![1; MAX_BUNDLE_BYTES / 2 - 1])],
                ),
                recipe(
                    id(format, 2),
                    vec![file(b"b", &vec![2; MAX_BUNDLE_BYTES / 2 - 1])],
                ),
            ],
        );
        input::parse(&exact, format).unwrap();
        let Value::Array(rows) = exact.get_mut("resolutions").unwrap() else {
            unreachable!()
        };
        rows[1] = recipe(
            id(format, 2),
            vec![file(b"b", &vec![2; MAX_BUNDLE_BYTES / 2])],
        );
        assert_eq!(
            input::parse(&exact, format).unwrap_err().code,
            "resolution_byte_limit"
        );
        let many = resolve(
            format,
            vec![
                recipe(
                    id(format, 1),
                    (0..32)
                        .map(|n| side(format!("a{n:02}").as_bytes(), "ours"))
                        .collect(),
                ),
                recipe(
                    id(format, 2),
                    (0..33)
                        .map(|n| side(format!("b{n:02}").as_bytes(), "ours"))
                        .collect(),
                ),
            ],
        );
        assert_eq!(
            input::parse(&many, format).unwrap_err().code,
            "resolution_count_limit"
        );
    }
}

#[test]
fn published_schema_and_parser_contracts_cover_all_three_operations() {
    let registry = fgit_schema::mcp::REGISTRY
        .iter()
        .find(|entry| entry.name == NAME)
        .unwrap();
    for operation in [PREPARE, RESOLVE, INSPECT] {
        let schema = schema(operation);
        let root = schema.object().unwrap();
        assert_eq!(root["additionalProperties"], Value::Bool(false));
        let properties = root["properties"].object().unwrap();
        let mut names: BTreeSet<_> = input::SELECTION_FIELDS.iter().copied().collect();
        names.extend(if operation == INSPECT {
            vec![
                "expected_candidate",
                "bundle_hex_chunks",
                "expected_bundle_sha256",
                "context_lines",
                "max_changes",
                "max_blob_bytes",
                "max_output_bytes",
                "max_diff_work",
            ]
        } else {
            vec![
                "upstream",
                "empty",
                "committer",
                "timestamp",
                "max_commits",
                "max_edges",
                "max_tree_entries",
                "max_preparation_bytes",
            ]
        });
        if operation == RESOLVE {
            names.insert("resolutions");
        }
        assert_eq!(
            properties
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            names
        );
        for name in names {
            assert!(
                registry.input_fields.iter().any(|field| field.name == name),
                "{name}"
            );
        }
        let Value::Array(required) = &root["required"] else {
            unreachable!()
        };
        assert_eq!(
            required.contains(&text("expected_head")),
            operation == RESOLVE
        );
        assert_eq!(
            required.contains(&text("resolutions")),
            operation == RESOLVE
        );
        let Value::Array(selectors) = &root["allOf"] else {
            unreachable!()
        };
        assert_eq!(selectors.len(), 2);
        assert!(schema.encode(16 * 1024).is_ok());
    }
}

#[test]
fn mapping_must_name_real_single_parent_generated_commits_and_terminal_original() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = input::parse(&args(format), format).unwrap();
        let tree = id(format, 5);
        let body = format!("tree {tree}\nparent {}\nauthor Original <original@example.invalid> 1 +0000\ncommitter Committer <committer@example.invalid> 2 +0000\n\noriginal\n", input.request.onto).into_bytes();
        let commit = git_object_id(format, GitObjectKind::Commit, &body);
        let mut plan = PreparedRebase {
            request: input.request,
            commit,
            tree,
            steps: vec![RebaseStep {
                original: input.request.source_tip,
                rewritten: commit,
                tree,
                kind: RebaseStepKind::Replayed,
            }],
            objects: vec![PlannedMergeObject {
                id: commit,
                kind: GitObjectKind::Commit,
                body: body.clone(),
            }],
        };
        output::validate_clean(&input, &plan, &mut || true).unwrap();
        plan.steps[0].original = input.request.upstream;
        assert!(output::validate_clean(&input, &plan, &mut || true).is_err());
        plan.steps[0].original = input.request.source_tip;
        plan.objects[0].body.push(b'!');
        assert!(output::validate_clean(&input, &plan, &mut || true).is_err());
        plan.objects[0].body = body;
        plan.steps[0].kind = RebaseStepKind::DroppedEmpty;
        assert!(output::validate_clean(&input, &plan, &mut || true).is_err());
        assert_eq!(
            output::validate_clean(&input, &plan, &mut || false)
                .unwrap_err()
                .code,
            "rebase_cancelled"
        );
    }
}

#[test]
fn publication_handoff_preserves_transport_but_never_mints_retry_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = input::parse(&args(format), format).unwrap();
        let bytes = vec![0xff; MAX_BUNDLE_BYTES];
        let mut name = b"refs/heads/".to_vec();
        name.resize(fgit_types::MAX_REF_NAME_LEN, 0xff);
        let reference = RefName::try_new(&name).unwrap();
        let published = publication(
            &reference,
            input.selection.source,
            input.selection.onto,
            id(format, 9),
            &bytes,
        )
        .unwrap();
        let mut fields = published.object().unwrap().clone();
        assert!(!fields.contains_key("idempotency_key"));
        assert!(!fields.contains_key("expected_head"));
        assert_eq!(chunks(&fields, "bundle_hex_chunks").unwrap(), bytes);
        fields.insert("idempotency_key".into(), text("caller-owned-original-key"));
        let wire = object([
            ("jsonrpc", text("2.0")),
            ("id", json::number(1)),
            ("method", text("tools/call")),
            (
                "params",
                object([
                    ("name", text(PUBLICATION_TOOL)),
                    ("arguments", Value::Object(fields)),
                ]),
            ),
        ])
        .encode(json::MAX_INPUT)
        .unwrap();
        assert!(json::parse(wire.as_bytes()).is_ok());
        let mut inspection = published.object().unwrap().clone();
        inspection.remove("onto");
        inspection.insert("operation".into(), text(INSPECT));
        inspection.insert("profile".into(), text("linear-v1"));
        name[fgit_types::MAX_REF_NAME_LEN - 1] = 0xfe;
        inspection.insert("onto_reference_hex".into(), text(hex(&name)));
        inspection.insert("expected_onto".into(), text(raw_oid(input.selection.onto)));
        inspection.insert(
            "expected_head".into(),
            args(format)["expected_head"].clone(),
        );
        inspection.insert(
            "expected_bundle_sha256".into(),
            text(hex(&fgit_crypto::sha256_digest(&bytes))),
        );
        inspection::parse(&inspection, format).unwrap();
        let inspection = handoff(Value::Object(inspection)).unwrap();
        let wire = object([
            ("jsonrpc", text("2.0")),
            ("id", json::number(1)),
            ("method", text("tools/call")),
            (
                "params",
                object([("name", text(NAME)), ("arguments", inspection)]),
            ),
        ])
        .encode(json::MAX_INPUT)
        .unwrap();
        assert!(json::parse(wire.as_bytes()).is_ok());
        assert!(
            publication(
                &input.selection.reference,
                input.selection.source,
                input.selection.onto,
                id(format, 9),
                &vec![0; MAX_BUNDLE_BYTES + 1]
            )
            .is_err()
        );
    }
}

#[test]
fn exact_encoded_result_and_cancellation_budgets_never_return_complete_prefixes() {
    bounded(
        object([("content", text("\\".repeat(MAX_RESULT_BYTES / 2 - 32)))]),
        &mut || true,
    )
    .unwrap();
    assert_eq!(
        bounded(
            object([("content", text("\\".repeat(MAX_RESULT_BYTES / 2)))]),
            &mut || true
        )
        .unwrap_err()
        .code,
        "rebase_result_limit"
    );
    assert_eq!(
        bounded(object([("complete", Value::Bool(true))]), &mut || false)
            .unwrap_err()
            .code,
        "rebase_cancelled"
    );
    assert_eq!(
        rebase_error(&RebaseError::UpstreamOutsideLinearHistory).code,
        "upstream_outside_linear_history"
    );
    assert_eq!(
        rebase_error(&RebaseError::Preparation(PreparationError::Source(
            MergeSourceError::Cancelled
        )))
        .code,
        "rebase_cancelled"
    );
}
