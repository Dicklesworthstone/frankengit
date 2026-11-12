use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::replay::PreparedReplay;
use fgit_forge::preparation::{ConflictKind, MergeConflict, MergeEntry, PlannedMergeObject};
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
        ("profile", text("path-v1")),
        ("direction", text("cherry-pick")),
        ("reference", text("refs/heads/main")),
        ("source_reference", text("refs/heads/topic")),
        ("expected_base", text(raw_oid(id(format, 1)))),
        ("expected_source", text(raw_oid(id(format, 2)))),
        ("selected_commit", text(raw_oid(id(format, 3)))),
        ("expected_head", text(format!("alg:1:{}", "ab".repeat(32)))),
        ("author", text("Author <author@example.invalid>")),
        ("committer", text("Committer <committer@example.invalid>")),
        ("timestamp", text("2")),
        ("message_hex", text(hex(b"selected change\r\n"))),
    ])
}
fn choice(path: &[u8], name: &str) -> Value {
    object([("path_hex", text(hex(path))), ("choice", text(name))])
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
                    .map(|part| text(hex(part)))
                    .collect(),
            ),
        ),
    ])
}
fn resolve(format: GitHashAlgorithm, rows: Vec<Value>) -> Object {
    let mut fields = args(format);
    fields.insert("operation".into(), text(RESOLVE));
    fields.insert("resolutions".into(), Value::Array(rows));
    fields
}

#[test]
fn raw_refs_selected_history_and_commit_metadata_remain_exact_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fields = args(format);
        fields.remove("reference");
        fields.remove("source_reference");
        fields.insert("reference_hex".into(), text(hex(b"refs/heads/\xff")));
        fields.insert("source_reference_hex".into(), text(hex(b"refs/heads/\xfe")));
        fields.insert("message_hex".into(), text("ff0d0a"));
        fields.insert("mainline".into(), json::number(2));
        fields.insert("direction".into(), text("revert"));
        let input = input::parse(&fields, format).unwrap();
        assert_eq!(input.reference.as_bytes(), b"refs/heads/\xff");
        assert_eq!(input.source.as_bytes(), b"refs/heads/\xfe");
        assert_eq!(input.request.direction, ReplayDirection::Revert);
        assert_eq!(input.request.mainline, Some(2));
        assert_eq!(input.request.selected_commit, id(format, 3));
        assert_ne!(input.request.selected_commit, input.request.source_tip);
        assert_eq!(input.metadata.message, b"\xff\r\n");
        fields.remove("mainline");
        fields.insert("source_reference_hex".into(), text(hex(b"refs/heads/\xff")));
        fields.insert("expected_source".into(), fields["expected_base"].clone());
        assert!(
            input::parse(&fields, format).is_ok(),
            "same-ref revert is valid"
        );
    }
}

#[test]
fn selectors_mainlines_authority_overrides_and_commit_header_injection_are_closed() {
    let format = GitHashAlgorithm::Sha256;
    for required in [
        "operation",
        "profile",
        "direction",
        "reference",
        "source_reference",
        "expected_base",
        "expected_source",
        "selected_commit",
        "author",
        "committer",
        "timestamp",
        "message_hex",
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
        "idempotency_key",
        "merge_base",
        "candidate_commit",
        "bundle_hex_chunks",
        "shell",
        "resolutions",
    ] {
        let mut bad = args(format);
        bad.insert(name.into(), Value::Null);
        assert_eq!(
            input::parse(&bad, format).err().unwrap().code,
            "unknown_argument",
            "{name}"
        );
    }
    for (name, value) in [
        ("reference_hex", text(hex(b"refs/heads/main"))),
        ("source_reference_hex", text(hex(b"refs/heads/topic"))),
        ("reference", text("refs/tags/release")),
        ("source_reference", text("main")),
        ("profile", text("exact-renames-v1")),
        ("direction", text("rebase")),
        ("selected_commit", text("00".repeat(32))),
        ("selected_commit", text("ab".repeat(20))),
        ("selected_commit", text("AB".repeat(32))),
        ("mainline", json::number(0)),
        ("mainline", json::number(65536)),
        ("mainline", text("1")),
        ("mainline", Value::Null),
        ("author", text("A <a@example.invalid>\nparent injected")),
        ("committer", text("ambient")),
        ("timestamp", text("0")),
        ("timestamp", text("01")),
        ("timestamp", text(u64::MAX.to_string())),
        ("message_hex", text("00")),
        ("message_hex", text("61".repeat(4097))),
    ] {
        let mut bad = args(format);
        bad.insert(name.into(), value);
        assert!(input::parse(&bad, format).is_err(), "{name}");
    }
}

#[test]
fn resolution_requires_original_snapshot_and_every_choice_is_exact_and_bounded() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let good = resolve(
            format,
            vec![
                file(b"z-\xff", b"\0\xff\r\n"),
                choice(b"b", "delete"),
                file(b"a", b""),
            ],
        );
        let parsed = input::parse(&good, format).unwrap();
        let choices = parsed.resolutions.unwrap();
        assert_eq!(
            choices[0].choice,
            ResolutionChoice::File {
                mode: 0o100755,
                bytes: vec![]
            }
        );
        assert_eq!(choices[1].choice, ResolutionChoice::Delete);
        assert_eq!(choices[2].path, b"z-\xff");
        assert_eq!(
            choices[2].choice,
            ResolutionChoice::File {
                mode: 0o100755,
                bytes: b"\0\xff\r\n".to_vec(),
            }
        );
        let mut missing = good;
        missing.remove("expected_head");
        assert_eq!(
            input::parse(&missing, format).err().unwrap().code,
            "resolution_snapshot_required"
        );
        for rows in [
            vec![],
            vec![choice(b"x", "ours"), choice(b"x", "theirs")],
            vec![
                choice(b"a", "ours"),
                choice(b"a-", "base"),
                choice(b"a/b", "delete"),
            ],
            vec![choice(b"../x", "ours")],
            vec![choice(b"x/.GiT/config", "ours")],
            vec![choice(b"x", "auto")],
            vec![choice(b"x", "ours"); MAX_RESOLUTIONS + 1],
        ] {
            assert!(input::parse(&resolve(format, rows), format).is_err());
        }
        let exact = vec![0x7f; MAX_BUNDLE_BYTES - 1];
        let boundary = resolve(format, vec![file(b"x", &exact)]);
        assert!(input::parse(&boundary, format).is_ok());
        let wire = object([
            ("jsonrpc", text("2.0")),
            ("id", json::number(1)),
            ("method", text("tools/call")),
            (
                "params",
                object([("name", text(NAME)), ("arguments", Value::Object(boundary))]),
            ),
        ])
        .encode(json::MAX_INPUT)
        .unwrap();
        assert!(json::parse(wire.as_bytes()).is_ok());
        assert_eq!(
            input::parse(
                &resolve(
                    format,
                    vec![
                        file(b"a", &vec![1; MAX_BUNDLE_BYTES / 2]),
                        file(b"b", &vec![1; MAX_BUNDLE_BYTES / 2]),
                    ]
                ),
                format
            )
            .err()
            .unwrap()
            .code,
            "resolution_byte_limit"
        );
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
fn discovery_registry_and_parser_field_sets_match_for_both_operations() {
    let entry = fgit_schema::mcp::REGISTRY
        .iter()
        .find(|entry| entry.name == NAME)
        .unwrap();
    for resolving in [false, true] {
        let schema = schema(resolving);
        let root = schema.object().unwrap();
        assert_eq!(root["additionalProperties"], Value::Bool(false));
        let properties = root["properties"].object().unwrap();
        let mut names: BTreeSet<_> = input::COMMON_FIELDS.iter().copied().collect();
        if resolving {
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
                entry.input_fields.iter().any(|field| field.name == name),
                "{name}"
            );
        }
        let Value::Array(required) = &root["required"] else {
            unreachable!()
        };
        assert_eq!(required.contains(&text("expected_head")), resolving);
        assert_eq!(required.contains(&text("resolutions")), resolving);
        let Value::Array(alternatives) = &root["allOf"] else {
            unreachable!()
        };
        assert_eq!(alternatives.len(), 2);
        assert!(schema.encode(16 * 1024).is_ok());
    }
}

#[test]
fn replay_coordinates_and_native_commit_headers_cannot_be_substituted() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = input::parse(&args(format), format).unwrap();
        let point = ReplayCoordinates {
            request: input.request,
            selected_parent: Some(id(format, 4)),
            selected_mainline: Some(1),
        };
        output::coordinates(point, input.request).unwrap();
        let mut wrong = point;
        wrong.request.direction = ReplayDirection::Revert;
        assert!(output::coordinates(wrong, input.request).is_err());
        wrong = point;
        wrong.selected_mainline = Some(2);
        assert!(output::coordinates(wrong, input.request).is_err());
        wrong = point;
        wrong.selected_parent = None;
        assert!(output::coordinates(wrong, input.request).is_err());
        let tree = id(format, 5);
        let body = format!(
            "tree {tree}\nparent {}\nauthor Author <author@example.invalid> 2 +0000\ncommitter Committer <committer@example.invalid> 2 +0000\n\nselected change\r\n",
            input.request.target,
        ).into_bytes();
        let commit = git_object_id(format, GitObjectKind::Commit, &body);
        let mut plan = PreparedReplay {
            coordinates: point,
            tree,
            commit,
            objects: vec![PlannedMergeObject {
                id: commit,
                kind: GitObjectKind::Commit,
                body: body.clone(),
            }],
        };
        assert_eq!(
            output::commit_body(&input, &plan, &mut || true).unwrap(),
            body
        );
        plan.objects[0].body.push(b'!');
        assert!(output::commit_body(&input, &plan, &mut || true).is_err());
        plan.objects[0].body = body;
        assert_eq!(
            output::commit_body(&input, &plan, &mut || false)
                .unwrap_err()
                .code,
            "replay_cancelled"
        );
    }
}

#[test]
fn complete_resolution_receipts_check_original_sides_uploaded_hashes_and_raw_paths() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let side = |bytes: &[u8]| MergeEntry {
            name: b"\xff".to_vec(),
            mode: 0o100755,
            oid: git_object_id(format, GitObjectKind::Blob, bytes),
        };
        let conflict = MergeConflict {
            path: b"dir/\xff".to_vec(),
            kind: ConflictKind::Binary,
            base: Some(side(b"base")),
            ours: Some(side(b"ours")),
            theirs: Some(side(b"parent")),
        };
        let mut request = ConflictResolution {
            path: conflict.path.clone(),
            choice: ResolutionChoice::Theirs,
        };
        let mut row = ResolvedPath {
            conflict: conflict.clone(),
            choice: ResolutionKind::Theirs,
            result: conflict.theirs.clone(),
        };
        let check = |request: &ConflictResolution, row: &ResolvedPath| {
            output::receipts(
                std::slice::from_ref(request),
                std::slice::from_ref(row),
                format,
                Default::default(),
                &mut || true,
            )
        };
        let receipt = check(&request, &row).unwrap();
        assert!(receipt.encode(16 * 1024).unwrap().contains("6469722fff"));
        row.result = conflict.base.clone();
        assert!(
            check(&request, &row).is_err(),
            "revert theirs cannot become selected-commit base"
        );
        request.choice = ResolutionChoice::File {
            mode: 0o100755,
            bytes: b"\0\xff".to_vec(),
        };
        row.choice = ResolutionKind::File;
        row.result = Some(side(b"\0\xff"));
        check(&request, &row).unwrap();
        row.result.as_mut().unwrap().mode = 0o100644;
        assert!(check(&request, &row).is_err());
        row.result = Some(side(b"other"));
        assert!(check(&request, &row).is_err());
        row.result = None;
        row.choice = ResolutionKind::Delete;
        request.choice = ResolutionChoice::Delete;
        check(&request, &row).unwrap();
        row.conflict.path = b"unrequested".to_vec();
        assert!(check(&request, &row).is_err());
    }
}

#[test]
fn handoffs_fit_real_rpc_input_and_never_invent_retry_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = input::parse(&args(format), format).unwrap();
        let bytes = vec![0xff; MAX_BUNDLE_BYTES];
        let (publication, inspection) = output::handoffs(
            &input.reference,
            input.request.target,
            id(format, 7),
            input.expected_head.unwrap(),
            &bytes,
        )
        .unwrap();
        assert!(
            !publication
                .object()
                .unwrap()
                .contains_key("idempotency_key")
        );
        assert_eq!(
            inspection.object().unwrap()["expected_head"],
            args(format)["expected_head"]
        );
        for (tool, value) in [
            ("frankengit_source_publish", publication),
            (NAME, inspection),
        ] {
            let mut value = value.object().unwrap().clone();
            if tool == "frankengit_source_publish" {
                value.insert("idempotency_key".into(), text("caller-owned-original-key"));
            }
            assert_eq!(chunks(&value, "bundle_hex_chunks").unwrap(), bytes);
            let wire = object([
                ("jsonrpc", text("2.0")),
                ("id", json::number(1)),
                ("method", text("tools/call")),
                (
                    "params",
                    object([("name", text(tool)), ("arguments", Value::Object(value))]),
                ),
            ])
            .encode(json::MAX_INPUT)
            .unwrap();
            assert!(json::parse(wire.as_bytes()).is_ok());
        }
        assert!(
            output::handoffs(
                &input.reference,
                input.request.target,
                id(format, 7),
                input.expected_head.unwrap(),
                &vec![0xff; MAX_BUNDLE_BYTES + 1],
            )
            .is_err()
        );
    }
}

#[test]
fn encoded_result_exhaustion_and_cancellation_never_return_a_complete_prefix() {
    // Each backslash expands to two JSON bytes; this crosses the independent
    // result ceiling even though the source string is much smaller than it.
    let within = object([("content", text("\\".repeat(MAX_RESULT_BYTES / 2 - 32)))]);
    output::bounded(within, &mut || true).unwrap();
    let over = object([("content", text("\\".repeat(MAX_RESULT_BYTES / 2)))]);
    assert_eq!(
        output::bounded(over, &mut || true).unwrap_err().code,
        "candidate_response_limit"
    );
    assert_eq!(
        output::bounded(object([("complete", Value::Bool(true))]), &mut || false)
            .unwrap_err()
            .code,
        "replay_cancelled"
    );
}

#[test]
fn typed_replay_refusals_do_not_expose_private_object_or_conflict_details() {
    assert_eq!(
        replay_error(&ReplayError::MainlineRequired { parents: 2 }).code,
        "mainline_required"
    );
    assert_eq!(
        replay_error(&ReplayError::InvalidMainline {
            requested: 3,
            parents: 2
        })
        .code,
        "invalid_mainline"
    );
    assert_eq!(
        replay_error(&ReplayError::CommitOutsideSourceHistory).code,
        "reference_unavailable"
    );
    assert_eq!(
        replay_error(&ReplayError::Resolution(Box::new(
            ResolutionError::NoConflicts
        )))
        .code,
        "no_conflicts_to_resolve"
    );
    assert_eq!(
        replay_error(&ReplayError::Preparation(PreparationError::Source(
            MergeSourceError::Cancelled
        )))
        .code,
        "replay_cancelled"
    );
}
