#![forbid(unsafe_code)]
//! Native file moves and mode edits over real authority-selected workspaces.

#[path = "workspace_metadata_edits/fixture.rs"]
mod fixture;

use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{LoopbackReceiveSession, NodeWorkspaceRefusal};
use fgit_treefs::{
    CapabilityRefusal, ExportLimits, FileMode, IntentLog, SparseRefusal, TreeEditIntent,
};
use fgit_types::GitHashAlgorithm;
use fgit_wire::visibility::RefVisibility;
use fixture::*;

const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];

#[test]
fn cross_directory_rename_and_chmod_reuse_the_verified_blob() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let before = fixture.head();
        let log = intents([
            rename(
                "src/tool.sh",
                "dst/renamed.sh",
                Some(fixture.original_basis()),
            ),
            chmod("dst/renamed.sh", None, FileMode::Executable),
        ]);
        let mut capability = complete_capability();
        let result = export(
            &fixture,
            &fixture.node().request_context(),
            fixture.commit,
            &mut capability,
            &log,
            ExportLimits {
                max_total_bytes: 1024,
                ..ExportLimits::default()
            },
        )
        .unwrap();
        assert_eq!(
            result.tree,
            fixture.expected_tree(
                None,
                &[
                    ("occupied.sh", FileMode::Regular, fixture.occupied),
                    ("renamed.sh", FileMode::Executable, fixture.file),
                ],
            )
        );
        assert_eq!(
            result.paths,
            vec![path("dst/renamed.sh"), path("src/tool.sh")]
        );
        assert_eq!(
            result.objects.len(),
            3,
            "source, destination and root trees"
        );
        assert!(
            result
                .objects
                .values()
                .all(|(kind, _)| *kind == GitObjectKind::Tree)
        );
        assert!(result.reused > 0);
        assert!(
            capability.fetched_bytes() < fixture.file_bytes as u64,
            "metadata edits must not fetch or copy the large source blob"
        );
        assert_eq!(
            result,
            export_default(&fixture, &log).unwrap(),
            "deterministic replay"
        );
        assert!(
            fixture.node().read_git_object(result.tree).is_err(),
            "direct export is a preparation artifact"
        );
        assert_eq!(fixture.head(), before);
    }
}

#[test]
fn chmod_of_base_files_preserves_identity_and_combines_with_later_edits() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let changed = export_default(
            &fixture,
            &intents([chmod(
                "src/tool.sh",
                Some(fixture.original_basis()),
                FileMode::Executable,
            )]),
        )
        .unwrap();
        assert_eq!(
            changed.tree,
            fixture.expected_tree(
                Some((FileMode::Executable, fixture.file)),
                &[("occupied.sh", FileMode::Regular, fixture.occupied)],
            )
        );
        assert_eq!(changed.objects.len(), 2, "only the source and root trees");
        assert!(
            changed
                .objects
                .values()
                .all(|(kind, _)| *kind == GitObjectKind::Tree)
        );
        let restored = export_default(
            &fixture,
            &intents([
                chmod(
                    "src/tool.sh",
                    Some(fixture.original_basis()),
                    FileMode::Executable,
                ),
                chmod("src/tool.sh", None, FileMode::Regular),
            ]),
        )
        .unwrap();
        assert_eq!(restored.tree, fixture.root_tree);
        let identity_then_move = export_default(
            &fixture,
            &intents([
                chmod(
                    "src/tool.sh",
                    Some(fixture.original_basis()),
                    FileMode::Regular,
                ),
                rename(
                    "src/tool.sh",
                    "dst/occupied.sh",
                    Some(fixture.original_basis()),
                ),
            ]),
        )
        .unwrap();
        assert_eq!(
            identity_then_move.tree,
            fixture.expected_tree(None, &[("occupied.sh", FileMode::Regular, fixture.file)])
        );
    }
}

#[test]
fn ordered_writes_moves_overwrites_and_mode_changes_carry_the_current_content() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let body = b"new executable contents\n";
        let changed = git_object_id(format, GitObjectKind::Blob, body);
        let result = export_default(
            &fixture,
            &intents([
                write("src/tool.sh", body, FileMode::Regular),
                // This hint describes the staged body, not the immutable base.
                // The evaluator must carry its own overlay entry either way.
                rename(
                    "src/tool.sh",
                    "dst/occupied.sh",
                    Some(basis(changed, FileMode::Regular)),
                ),
                chmod("dst/occupied.sh", None, FileMode::Executable),
                rename("dst/occupied.sh", "src/tool.sh", None),
            ]),
        )
        .unwrap();
        assert_eq!(
            result.tree,
            fixture.expected_tree(Some((FileMode::Executable, changed)), &[])
        );
        assert_eq!(
            result.paths,
            vec![path("dst/occupied.sh"), path("src/tool.sh")]
        );
        assert_eq!(
            result.objects.get(&changed),
            Some(&(GitObjectKind::Blob, body.to_vec()))
        );
        assert_eq!(
            result
                .objects
                .values()
                .filter(|(kind, _)| *kind == GitObjectKind::Blob)
                .count(),
            1,
            "the replacement body survives once through the rename chain"
        );

        // A missing base source is permitted when a prior write creates it.
        let created = export_default(
            &fixture,
            &intents([
                write("src/new.sh", body, FileMode::Regular),
                rename("src/new.sh", "dst/occupied.sh", None),
                chmod("dst/occupied.sh", None, FileMode::Executable),
            ]),
        )
        .unwrap();
        assert_eq!(
            created.tree,
            fixture.expected_tree(
                Some((FileMode::Regular, fixture.file)),
                &[("occupied.sh", FileMode::Executable, changed)],
            )
        );

        let deleted = export_default(
            &fixture,
            &intents([
                rename(
                    "src/tool.sh",
                    "dst/occupied.sh",
                    Some(fixture.original_basis()),
                ),
                TreeEditIntent::Delete {
                    path: path("dst/occupied.sh"),
                },
            ]),
        )
        .unwrap();
        assert_eq!(deleted.tree, fixture.expected_tree(None, &[]));
    }
}

#[test]
fn base_hints_cannot_substitute_objects_modes_domains_or_absent_sources() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let before = fixture.head();
        let other_format = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        let other_domain = git_object_id(other_format, GitObjectKind::Blob, b"other domain");
        let mut malformed = fixture.original_basis();
        malformed.oid.push(0);
        let invalid = [
            None,
            Some(basis(fixture.untouched, FileMode::Regular)),
            Some(basis(fixture.file, FileMode::Executable)),
            Some(basis(other_domain, FileMode::Regular)),
            Some(malformed),
        ];
        for hint in invalid {
            for operation in [
                rename("src/tool.sh", "dst/occupied.sh", hint.clone()),
                chmod("src/tool.sh", hint, FileMode::Executable),
            ] {
                assert!(matches!(
                    export_default(&fixture, &intents([operation])),
                    Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
                ));
            }
        }

        let forged = Some(basis(fixture.untouched, FileMode::Regular));
        assert!(
            matches!(
                export_default(
                    &fixture,
                    &intents([
                        chmod(
                            "src/tool.sh",
                            Some(fixture.original_basis()),
                            FileMode::Regular
                        ),
                        rename("src/tool.sh", "dst/occupied.sh", forged),
                    ]),
                ),
                Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
            ),
            "a no-op chmod does not authenticate a later arbitrary base hint"
        );

        for log in [
            intents([rename(
                "src/missing.sh",
                "dst/occupied.sh",
                Some(fixture.original_basis()),
            )]),
            intents([
                TreeEditIntent::Delete {
                    path: path("src/tool.sh"),
                },
                rename(
                    "src/tool.sh",
                    "dst/occupied.sh",
                    Some(fixture.original_basis()),
                ),
            ]),
            intents([
                TreeEditIntent::Delete {
                    path: path("src/tool.sh"),
                },
                chmod(
                    "src/tool.sh",
                    Some(fixture.original_basis()),
                    FileMode::Executable,
                ),
            ]),
        ] {
            assert!(matches!(
                export_default(&fixture, &log),
                Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
            ));
        }

        for operation in [
            rename(
                "src/tool.sh",
                "dst/occupied.sh",
                Some(fixture.original_basis()),
            ),
            chmod(
                "src/tool.sh",
                Some(fixture.original_basis()),
                FileMode::Executable,
            ),
        ] {
            assert!(export_default(&fixture, &intents([operation])).is_ok());
        }
        assert_eq!(
            fixture.head(),
            before,
            "refusal and permitted exports publish nothing"
        );
    }
}

#[test]
fn rename_requires_both_path_capabilities_and_complete_rebuilt_directories() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let before = fixture.head();
        let log = intents([rename(
            "src/tool.sh",
            "dst/renamed.sh",
            Some(fixture.original_basis()),
        )]);
        let all_reads = ["dst", "link", "module", "src", "untouched.txt"];
        for (writes, denied) in [(["dst"], "src/tool.sh"), (["src"], "dst/renamed.sh")] {
            let mut cap = capability(&all_reads, &writes);
            assert!(matches!(
                export(
                    &fixture, &fixture.node().request_context(), fixture.commit,
                    &mut cap, &log, ExportLimits::default(),
                ),
                Err(NodeWorkspaceRefusal::Manifest(SparseRefusal::Capability(
                    CapabilityRefusal::WriteOutsideScope { path: refused },
                ))) if refused == path(denied)
            ));
            assert_eq!(
                cap.fetched_bytes(),
                0,
                "reject scope before reading the source"
            );
        }
        for (reads, denied) in [
            (
                vec!["dst", "link", "module", "untouched.txt"],
                "src/tool.sh",
            ),
            (
                vec!["link", "module", "src", "untouched.txt"],
                "dst/renamed.sh",
            ),
        ] {
            let mut cap = capability(&reads, &["src", "dst"]);
            assert!(matches!(
                export(
                    &fixture, &fixture.node().request_context(), fixture.commit,
                    &mut cap, &log, ExportLimits::default(),
                ),
                Err(NodeWorkspaceRefusal::Manifest(SparseRefusal::Capability(
                    CapabilityRefusal::ReadOutsideScope { path: refused },
                ))) if refused == path(denied)
            ));
            assert_eq!(cap.fetched_bytes(), 0);
        }

        let mut hidden_root_sibling =
            capability(&["dst", "link", "module", "src"], &["src", "dst"]);
        assert!(matches!(
            export(
                &fixture,
                &fixture.node().request_context(),
                fixture.commit,
                &mut hidden_root_sibling,
                &log,
                ExportLimits::default(),
            ),
            Err(NodeWorkspaceRefusal::IncompleteWorkspaceExportScope)
        ));

        // Exact leaf grants permit the two edits but cannot reconstruct their
        // parent directories from an incomplete/disclosure-filtered listing.
        for reads in [
            vec!["dst", "link", "module", "src/tool.sh", "untouched.txt"],
            vec!["dst/renamed.sh", "link", "module", "src", "untouched.txt"],
        ] {
            let mut cap = capability(&reads, &["src", "dst"]);
            assert!(
                export(
                    &fixture,
                    &fixture.node().request_context(),
                    fixture.commit,
                    &mut cap,
                    &log,
                    ExportLimits::default(),
                )
                .is_err()
            );
        }
        assert!(export_default(&fixture, &log).is_ok());
        assert_eq!(fixture.head(), before);
    }
}

#[test]
fn unsupported_entry_kinds_and_move_shapes_have_permitted_file_twins() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        for (from, to) in [
            ("src/tool.sh", "src/tool.sh"),
            ("src/tool.sh", "src/tool.sh/child"),
            ("src/tool.sh", "src"),
            ("src/tool.sh", "dst"),
            ("src/tool.sh", "link"),
            ("src", "new"),
            ("link", "dst/renamed.sh"),
            ("module", "dst/renamed.sh"),
        ] {
            assert!(
                matches!(
                    export_default(
                        &fixture,
                        &intents([rename(from, to, Some(fixture.original_basis()))]),
                    ),
                    Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
                ),
                "unsupported rename {from} -> {to}"
            );
        }
        for target in ["src", "link", "module"] {
            assert!(matches!(
                export_default(
                    &fixture,
                    &intents([chmod(
                        target,
                        Some(fixture.original_basis()),
                        FileMode::Executable
                    )]),
                ),
                Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
            ));
        }
        assert!(
            export_default(
                &fixture,
                &intents([rename(
                    "src/tool.sh",
                    "dst/renamed.sh",
                    Some(fixture.original_basis())
                )]),
            )
            .is_ok()
        );
        assert!(
            export_default(
                &fixture,
                &intents([chmod(
                    "src/tool.sh",
                    Some(fixture.original_basis()),
                    FileMode::Executable
                )]),
            )
            .is_ok()
        );
    }
}

#[test]
fn metadata_edits_obey_export_and_fetch_limits_and_stale_source_checks() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let before = fixture.head();
        let log = intents([rename(
            "src/tool.sh",
            "dst/occupied.sh",
            Some(fixture.original_basis()),
        )]);
        let request = fixture.node().request_context();
        assert!(
            matches!(
                export(
                    &fixture,
                    &request,
                    fixture.commit,
                    &mut complete_capability(),
                    &log,
                    ExportLimits {
                        max_objects: 1,
                        ..ExportLimits::default()
                    },
                ),
                Err(NodeWorkspaceRefusal::WorkspaceEditLimit)
            ),
            "both affected paths consume the finite edit envelope"
        );
        assert!(matches!(
            export(
                &fixture,
                &request,
                fixture.commit,
                &mut complete_capability(),
                &log,
                ExportLimits {
                    max_total_bytes: 1,
                    ..ExportLimits::default()
                },
            ),
            Err(NodeWorkspaceRefusal::WorkspaceExport(_))
        ));
        let mut no_fetch = complete_capability().with_file_budget(0);
        assert!(matches!(
            export(
                &fixture,
                &request,
                fixture.commit,
                &mut no_fetch,
                &log,
                ExportLimits::default()
            ),
            Err(NodeWorkspaceRefusal::Manifest(SparseRefusal::Capability(
                CapabilityRefusal::FileBudgetExceeded { .. },
            )))
        ));
        assert!(matches!(
            export(
                &fixture,
                &request,
                fixture.untouched,
                &mut complete_capability(),
                &log,
                ExportLimits::default(),
            ),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        let allowed = export(
            &fixture,
            &request,
            fixture.commit,
            &mut complete_capability(),
            &log,
            ExportLimits {
                max_objects: 3,
                max_total_bytes: 1024,
                max_tree_entries: 8,
            },
        )
        .unwrap();
        assert_eq!(
            allowed.tree,
            fixture.expected_tree(None, &[("occupied.sh", FileMode::Regular, fixture.file)])
        );
        assert_eq!(fixture.head(), before);
    }
}

#[test]
fn retained_sessions_apply_chained_metadata_edits_and_remain_usable_after_refusal() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let node = fixture.node();
        let before = fixture.head();
        let session = LoopbackReceiveSession::authenticated(
            PRINCIPAL,
            IdempotencyKey::new(b"metadata-workspace-session".to_vec()).unwrap(),
        );
        let request = node.request_context();
        let opened = node
            .runtime()
            .block_on(node.open_merge_workspace_in(
                &request,
                &session,
                &reference(),
                &RefVisibility::new(),
                complete_capability(),
                0,
                ExportLimits {
                    max_objects: 32,
                    max_total_bytes: 4096,
                    max_tree_entries: 32,
                },
            ))
            .unwrap();
        assert_eq!(opened.tree(), fixture.root_tree);
        let body = b"session-owned replacement\n";
        let blob = git_object_id(format, GitObjectKind::Blob, body);
        let written = node
            .runtime()
            .block_on(node.edit_merge_workspace_in(
                &request,
                &session,
                &opened,
                &intents([write("src/tool.sh", body, FileMode::Regular)]),
                0,
            ))
            .unwrap();
        let moved = node
            .runtime()
            .block_on(node.edit_merge_workspace_in(
                &request,
                &session,
                &written,
                &intents([
                    rename("src/tool.sh", "dst/occupied.sh", None),
                    chmod("dst/occupied.sh", None, FileMode::Executable),
                ]),
                0,
            ))
            .unwrap();
        assert_ne!(moved.snapshot_digest(), written.snapshot_digest());
        assert_eq!(
            moved.tree(),
            fixture.expected_tree(None, &[("occupied.sh", FileMode::Executable, blob)])
        );
        assert!(
            matches!(
                node.runtime().block_on(node.edit_merge_workspace_in(
                    &request,
                    &session,
                    &moved,
                    &intents([rename(
                        "src/tool.sh",
                        "dst/again.sh",
                        Some(fixture.original_basis())
                    )]),
                    0,
                )),
                Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
            ),
            "the source whiteout survives across append calls"
        );
        assert!(matches!(
            node.runtime().block_on(node.edit_merge_workspace_in(
                &request,
                &session,
                &written,
                &IntentLog::new(),
                0,
            )),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));

        let back = intents([rename("dst/occupied.sh", "src/tool.sh", None)]);
        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(matches!(
            node.runtime()
                .block_on(node.edit_merge_workspace_in(&cancelled, &session, &moved, &back, 0,)),
            Err(NodeWorkspaceRefusal::Cancelled { .. })
        ));
        // The same receipt remains current after both refusal and cancellation.
        let restored = node
            .runtime()
            .block_on(node.edit_merge_workspace_in(&request, &session, &moved, &back, 0))
            .unwrap();
        assert_eq!(
            restored.tree(),
            fixture.expected_tree(Some((FileMode::Executable, blob)), &[])
        );
        assert_eq!(node.read_git_object(blob).unwrap().payload(), body);
        assert!(node.read_git_object(restored.tree()).is_ok());
        assert_eq!(
            fixture.head(),
            before,
            "session editing is not ref publication"
        );
        node.runtime()
            .block_on(node.close_merge_workspace_in(&request, &session, &restored))
            .unwrap();
    }
}
