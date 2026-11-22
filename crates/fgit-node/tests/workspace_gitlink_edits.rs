#![forbid(unsafe_code)]
//! Explicit native gitlink editing keeps foreign commits opaque and authorized.

#[allow(dead_code)]
#[path = "workspace_metadata_edits/fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "workspace_gitlink_edits/support.rs"]
mod support;

use fgit_authority::IdempotencyKey;
use fgit_crypto::GitObjectKind;
use fgit_node::{LoopbackReceiveSession, NodeWorkspaceRefusal};
use fgit_treefs::{CapabilityRefusal, ExportLimits, FileMode, SparseRefusal, TreeEditIntent};
use fgit_wire::visibility::RefVisibility;
use fixture::*;
use support::*;

fn prepare(
    fixture: &Fixture,
    log: &fgit_treefs::IntentLog,
) -> Result<ExportObservation, NodeWorkspaceRefusal> {
    export_gitlinks(
        fixture,
        &fixture.node().request_context(),
        fixture.commit,
        &mut complete_capability(),
        log,
        ExportLimits::default(),
    )
}

#[test]
fn explicit_gitlinks_add_update_and_delete_without_loading_foreign_commits() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let before = fixture.head();
        assert_eq!(expected_tree(&fixture, &[]), fixture.root_tree);
        let first = pointer(format, b"foreign first");
        let second = pointer(format, b"foreign second");
        for (log, edits) in [
            (
                intents([update("module", first)]),
                vec![("module", Some(("160000", first)))],
            ),
            (
                intents([update("new/dependency", first)]),
                vec![("new/dependency", Some(("160000", first)))],
            ),
            (intents([delete("module")]), vec![("module", None)]),
            (
                intents([
                    update("module", first),
                    delete("module"),
                    update("module", second),
                    update("new/dependency", first),
                    delete("new/dependency"),
                ]),
                vec![("module", Some(("160000", second)))],
            ),
        ] {
            let exported = prepare(&fixture, &log).unwrap();
            assert_eq!(exported.tree, expected_tree(&fixture, &edits));
            assert!(
                exported
                    .objects
                    .values()
                    .all(|(kind, _)| *kind == GitObjectKind::Tree)
            );
            assert!(!exported.objects.contains_key(&first));
            assert!(!exported.objects.contains_key(&second));
            assert_eq!(
                prepare(&fixture, &log).unwrap(),
                exported,
                "deterministic exact export"
            );
        }
        for foreign in [original_pointer(&fixture), first, second] {
            assert!(fixture.node().read_git_object(foreign).is_err());
        }
        assert_eq!(
            fixture.head(),
            before,
            "candidate export never publishes refs"
        );
    }
}

#[test]
fn ordinary_profile_keeps_refusing_gitlink_mutations() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let next = pointer(format, b"foreign replacement");
        for log in [
            intents([update("new/dependency", next)]),
            intents([delete("module")]),
        ] {
            assert!(matches!(
                export_default(&fixture, &log),
                Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
            ));
            assert!(prepare(&fixture, &log).is_ok());
        }
    }
}

#[test]
fn gitlink_identity_width_zero_and_retained_bytes_refuse_before_source_reads() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let width = format.digest_len();
        for after_oid in [
            vec![0; width],
            vec![1; width - 1],
            vec![1; if width == 20 { 32 } else { 20 }],
        ] {
            let mut cap = complete_capability();
            let log = intents([TreeEditIntent::UpdateSubmodule {
                path: path("module"),
                after_oid,
            }]);
            assert!(matches!(
                export_gitlinks(
                    &fixture,
                    &fixture.node().request_context(),
                    fixture.commit,
                    &mut cap,
                    &log,
                    ExportLimits::default()
                ),
                Err(NodeWorkspaceRefusal::ObjectFormatMismatch)
            ));
            assert_eq!(cap.fetched_bytes(), 0);
        }
        let mut cap = complete_capability();
        let log = intents([update("module", pointer(format, b"foreign replacement"))]);
        let limits = ExportLimits {
            max_total_bytes: width - 1,
            ..ExportLimits::default()
        };
        assert!(matches!(
            export_gitlinks(
                &fixture,
                &fixture.node().request_context(),
                fixture.commit,
                &mut cap,
                &log,
                limits
            ),
            Err(NodeWorkspaceRefusal::WorkspaceEditLimit)
        ));
        assert_eq!(cap.fetched_bytes(), 0);
        assert!(prepare(&fixture, &log).is_ok());
    }
}

#[test]
fn gitlink_kind_provenance_forbids_rename_chmod_and_implicit_conversion() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let next = pointer(format, b"foreign replacement");
        let cases = [
            intents([update("src/tool.sh", next)]),
            intents([update("link", next)]),
            intents([update("src", next)]),
            intents([delete("src/tool.sh"), update("src/tool.sh", next)]),
            intents([
                delete("module"),
                write("module", b"local", FileMode::Regular),
            ]),
            intents([
                write("new/pointer", b"local", FileMode::Regular),
                delete("new/pointer"),
                update("new/pointer", next),
            ]),
            intents([
                update("new/pointer", next),
                delete("new/pointer"),
                write("new/pointer", b"local", FileMode::Regular),
            ]),
            intents([rename("module", "new/moved", None)]),
            intents([rename(
                "src/tool.sh",
                "module",
                Some(fixture.original_basis()),
            )]),
            intents([chmod("module", None, FileMode::Executable)]),
            intents([
                update("new/pointer", next),
                rename("new/pointer", "new/moved", None),
            ]),
            intents([
                update("new/pointer", next),
                write("new/pointer/child", b"local", FileMode::Regular),
            ]),
            intents([
                write("new/pointer/child", b"local", FileMode::Regular),
                update("new/pointer", next),
            ]),
            intents([
                delete("module"),
                write("module/child", b"local", FileMode::Regular),
            ]),
        ];
        for log in cases {
            assert!(
                prepare(&fixture, &log).is_err(),
                "refused conversion: {:?}",
                log.intents()
            );
        }
        assert!(
            prepare(
                &fixture,
                &intents([
                    update("module", next),
                    write("new/ordinary", b"independent local file", FileMode::Regular),
                ])
            )
            .is_ok()
        );
    }
}

#[test]
fn gitlinks_obey_whole_directory_scope_exact_base_and_cancellation() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let node = fixture.node();
        let log = intents([update("module", pointer(format, b"foreign replacement"))]);
        let request = node.request_context();
        assert!(matches!(
            export_gitlinks(
                &fixture,
                &request,
                fixture.commit,
                &mut capability(&["module"], &[]),
                &log,
                ExportLimits::default()
            ),
            Err(NodeWorkspaceRefusal::Manifest(SparseRefusal::Capability(
                CapabilityRefusal::WriteOutsideScope { .. }
            )))
        ));
        assert!(matches!(
            export_gitlinks(
                &fixture,
                &request,
                fixture.commit,
                &mut capability(&["module"], &["module"]),
                &log,
                ExportLimits::default()
            ),
            Err(NodeWorkspaceRefusal::IncompleteWorkspaceExportScope)
        ));
        assert!(matches!(
            export_gitlinks(
                &fixture,
                &request,
                pointer(format, b"stale base"),
                &mut complete_capability(),
                &log,
                ExportLimits::default()
            ),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(matches!(
            export_gitlinks(
                &fixture,
                &cancelled,
                fixture.commit,
                &mut complete_capability(),
                &log,
                ExportLimits::default()
            ),
            Err(NodeWorkspaceRefusal::Cancelled { .. })
        ));
        assert!(prepare(&fixture, &log).is_ok());
    }
}

#[test]
fn gitlink_sessions_retain_profile_kind_history_and_exact_snapshot_after_refusals() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let node = fixture.node();
        let before = fixture.head();
        let request = node.request_context();
        let principal = LoopbackReceiveSession::authenticated(
            PRINCIPAL,
            IdempotencyKey::new(b"opaque-gitlink-session".to_vec()).unwrap(),
        );
        let next = pointer(format, b"foreign replacement");
        let limits = ExportLimits {
            max_objects: 64,
            max_total_bytes: 8192,
            max_tree_entries: 64,
        };
        let ordinary = node
            .runtime()
            .block_on(node.open_merge_workspace_in(
                &request,
                &principal,
                &reference(),
                &RefVisibility::new(),
                complete_capability(),
                0,
                limits,
            ))
            .unwrap();
        assert!(matches!(
            node.runtime().block_on(node.edit_merge_workspace_in(
                &request,
                &principal,
                &ordinary,
                &intents([update("module", next)]),
                0,
            )),
            Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
        ));
        node.runtime()
            .block_on(node.close_merge_workspace_in(&request, &principal, &ordinary))
            .unwrap();
        let opened = node
            .runtime()
            .block_on(node.open_gitlink_merge_workspace_in(
                &request,
                &principal,
                &reference(),
                &RefVisibility::new(),
                complete_capability(),
                0,
                limits,
            ))
            .unwrap();
        let changed = node
            .runtime()
            .block_on(node.edit_merge_workspace_in(
                &request,
                &principal,
                &opened,
                &intents([update("module", next), update("new/pointer", next)]),
                0,
            ))
            .unwrap();
        assert_eq!(
            changed.tree(),
            expected_tree(
                &fixture,
                &[
                    ("module", Some(("160000", next))),
                    ("new/pointer", Some(("160000", next)))
                ]
            )
        );
        let deleted = node
            .runtime()
            .block_on(node.edit_merge_workspace_in(
                &request,
                &principal,
                &changed,
                &intents([delete("module"), delete("new/pointer")]),
                0,
            ))
            .unwrap();
        for target in ["module", "new/pointer"] {
            assert!(matches!(
                node.runtime().block_on(node.edit_merge_workspace_in(
                    &request,
                    &principal,
                    &deleted,
                    &intents([write(target, b"never a local file", FileMode::Regular)]),
                    0,
                )),
                Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
            ));
        }
        let cancelled = node.request_context();
        cancelled.cancel();
        let restore = intents([update("module", original_pointer(&fixture))]);
        assert!(
            node.runtime()
                .block_on(
                    node.edit_merge_workspace_in(&cancelled, &principal, &deleted, &restore, 0)
                )
                .is_err()
        );
        let restored = node
            .runtime()
            .block_on(node.edit_merge_workspace_in(&request, &principal, &deleted, &restore, 0))
            .unwrap();
        assert_eq!(restored.tree(), fixture.root_tree);
        assert_eq!(fixture.head(), before);
        assert!(node.read_git_object(next).is_err());
        node.runtime()
            .block_on(node.close_merge_workspace_in(&request, &principal, &restored))
            .unwrap();
    }
}

#[test]
fn retained_gitlink_identity_bytes_share_the_session_append_budget() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let node = fixture.node();
        let request = node.request_context();
        let principal = LoopbackReceiveSession::authenticated(
            PRINCIPAL,
            IdempotencyKey::new(b"bounded-gitlink-identities".to_vec()).unwrap(),
        );
        let limits = ExportLimits {
            max_objects: 64,
            max_total_bytes: 512,
            max_tree_entries: 64,
        };
        let opened = node
            .runtime()
            .block_on(node.open_gitlink_merge_workspace_in(
                &request,
                &principal,
                &reference(),
                &RefVisibility::new(),
                complete_capability(),
                0,
                limits,
            ))
            .unwrap();
        let next = pointer(format, b"foreign replacement");
        let count = limits.max_total_bytes / format.digest_len();
        let accepted = intents((0..count).map(|_| update("module", next)));
        let changed = node
            .runtime()
            .block_on(node.edit_merge_workspace_in(&request, &principal, &opened, &accepted, 0))
            .unwrap();
        assert_eq!(
            changed.tree(),
            expected_tree(&fixture, &[("module", Some(("160000", next)))])
        );
        assert!(matches!(
            node.runtime().block_on(node.edit_merge_workspace_in(
                &request,
                &principal,
                &changed,
                &intents([update("module", next)]),
                0,
            )),
            Err(NodeWorkspaceRefusal::WorkspaceEditLimit)
        ));
        node.runtime()
            .block_on(node.close_merge_workspace_in(&request, &principal, &changed))
            .unwrap();
    }
}
