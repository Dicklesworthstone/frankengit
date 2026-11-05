#![forbid(unsafe_code)]
//! Native symlink edits over real SHA-1 and SHA-256 authority-selected bases.

#[allow(dead_code)]
#[path = "workspace_metadata_edits/fixture.rs"]
mod fixture;

use std::collections::BTreeMap;

use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{LoopbackReceiveSession, NodeWorkspaceRefusal};
use fgit_treefs::{
    BaseError, CapabilityRefusal, ExportLimits, FileMode, IntentLog, SparseRefusal, SymlinkPolicy,
    TreeEditIntent,
};
use fgit_types::{GitHashAlgorithm, GitOid};
use fgit_wire::visibility::RefVisibility;
use fixture::*;

const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];
const SCOPES: [&str; 6] = ["dst", "link", "module", "new", "src", "untouched.txt"];

fn symlink(target: &str, bytes: &[u8]) -> TreeEditIntent {
    TreeEditIntent::CreateSymlink {
        path: path(target),
        link_target: bytes.to_vec(),
    }
}

fn delete(target: &str) -> TreeEditIntent {
    TreeEditIntent::Delete { path: path(target) }
}

fn original_link(fixture: &Fixture) -> GitOid {
    git_object_id(fixture.format, GitObjectKind::Blob, b"src/tool.sh")
}

fn tree(format: GitHashAlgorithm, mut entries: Vec<(String, &'static str, GitOid)>) -> GitOid {
    entries.sort_by_key(|(name, mode, _)| {
        let mut key = name.as_bytes().to_vec();
        if *mode == "40000" {
            key.push(b'/');
        }
        key
    });
    let mut body = Vec::new();
    for (name, mode, oid) in entries {
        body.extend(mode.as_bytes());
        body.push(b' ');
        body.extend(name.as_bytes());
        body.push(0);
        body.extend(oid.as_bytes());
    }
    git_object_id(format, GitObjectKind::Tree, &body)
}

/// Independently construct the complete expected fixture tree, including every
/// untouched sibling. No workspace exporter or tree parser computes this oracle.
fn expected_tree(fixture: &Fixture, edits: &[(&str, Option<(&'static str, GitOid)>)]) -> GitOid {
    let keep = git_object_id(fixture.format, GitObjectKind::Blob, b"directory sibling\n");
    let module = git_object_id(
        fixture.format,
        GitObjectKind::Commit,
        b"external repository",
    );
    let mut leaves: BTreeMap<String, (&'static str, GitOid)> = [
        ("dst/keep.txt", ("100644", keep)),
        ("dst/occupied.sh", ("100644", fixture.occupied)),
        ("link", ("120000", original_link(fixture))),
        ("module", ("160000", module)),
        ("src/keep.txt", ("100644", keep)),
        ("src/tool.sh", ("100644", fixture.file)),
        ("untouched.txt", ("100644", fixture.untouched)),
    ]
    .into_iter()
    .map(|(name, entry)| (name.to_owned(), entry))
    .collect();
    for (name, entry) in edits {
        if let Some(entry) = entry {
            leaves.insert((*name).to_owned(), *entry);
        } else {
            leaves.remove(*name);
        }
    }
    let mut root = Vec::new();
    let mut directories: BTreeMap<String, Vec<(String, &'static str, GitOid)>> = BTreeMap::new();
    for (name, (mode, oid)) in leaves {
        if let Some((directory, child)) = name.split_once('/') {
            assert!(
                !child.contains('/'),
                "fixture oracle handles one directory level"
            );
            directories.entry(directory.to_owned()).or_default().push((
                child.to_owned(),
                mode,
                oid,
            ));
        } else {
            root.push((name, mode, oid));
        }
    }
    for (name, children) in directories {
        root.push((name, "40000", tree(fixture.format, children)));
    }
    tree(fixture.format, root)
}

#[test]
fn creates_and_updates_symlinks_as_exact_inert_git_blob_data() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let before = fixture.head();
        assert_eq!(expected_tree(&fixture, &[]), fixture.root_tree);
        let targets: [&[u8]; 3] = [
            b"../../outside/never-follow",
            b"/absolute/target",
            b"raw\0link-text\xff",
        ];
        for target in targets {
            let blob = git_object_id(format, GitObjectKind::Blob, target);
            let result = export_default(
                &fixture,
                &intents([symlink("link", target), symlink("new/created", target)]),
            )
            .unwrap();
            assert_eq!(
                result.tree,
                expected_tree(
                    &fixture,
                    &[
                        ("link", Some(("120000", blob))),
                        ("new/created", Some(("120000", blob))),
                    ]
                )
            );
            assert_eq!(
                result.objects[&blob],
                (GitObjectKind::Blob, target.to_vec())
            );
            assert_eq!(
                result
                    .objects
                    .values()
                    .filter(|(kind, _)| *kind == GitObjectKind::Blob)
                    .count(),
                1
            );
        }
        assert_eq!(
            fixture.head(),
            before,
            "an edit export must not publish a ref"
        );
    }
}

#[test]
fn base_symlink_rename_chains_preserve_mode_and_blob_identity_without_copying() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let before = fixture.head();
        let result = export_default(
            &fixture,
            &intents([
                rename("link", "dst/occupied.sh", None),
                rename("dst/occupied.sh", "new/again", None),
            ]),
        )
        .unwrap();
        assert_eq!(
            result.tree,
            expected_tree(
                &fixture,
                &[
                    ("link", None),
                    ("dst/occupied.sh", None),
                    ("new/again", Some(("120000", original_link(&fixture)))),
                ]
            )
        );
        assert!(result.reused >= 1);
        assert!(
            result
                .objects
                .values()
                .all(|(kind, _)| *kind == GitObjectKind::Tree)
        );
        assert_eq!(
            result.paths,
            vec![path("dst/occupied.sh"), path("link"), path("new/again")]
        );
        assert_eq!(fixture.head(), before);
    }
}

#[test]
fn ordered_replacements_and_moves_preserve_the_current_entry_kind() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let target = b"../new-target";
        let file = b"ordinary replacement\n";
        let link_blob = git_object_id(format, GitObjectKind::Blob, target);
        let file_blob = git_object_id(format, GitObjectKind::Blob, file);
        let result = export_default(
            &fixture,
            &intents([
                symlink("src/tool.sh", target),
                rename("src/tool.sh", "link", None),
                write("src/tool.sh", file, FileMode::Executable),
                rename("link", "dst/occupied.sh", None),
                chmod("src/tool.sh", None, FileMode::Regular),
                symlink("link", b"superseded"),
                delete("link"),
            ]),
        )
        .unwrap();
        assert_eq!(
            result.tree,
            expected_tree(
                &fixture,
                &[
                    ("src/tool.sh", Some(("100644", file_blob))),
                    ("dst/occupied.sh", Some(("120000", link_blob))),
                    ("link", None),
                ]
            )
        );
        assert_eq!(result.objects[&link_blob].1, target);
        assert_eq!(result.objects[&file_blob].1, file);
        assert_eq!(
            result
                .objects
                .values()
                .filter(|(kind, _)| *kind == GitObjectKind::Blob)
                .count(),
            2
        );

        let file_over_link = export_default(
            &fixture,
            &intents([rename(
                "src/tool.sh",
                "link",
                Some(fixture.original_basis()),
            )]),
        )
        .unwrap();
        assert_eq!(
            file_over_link.tree,
            expected_tree(
                &fixture,
                &[
                    ("src/tool.sh", None),
                    ("link", Some(("100644", fixture.file))),
                ]
            )
        );
        assert!(
            file_over_link
                .objects
                .values()
                .all(|(kind, _)| *kind == GitObjectKind::Tree)
        );

        let write_over_link = export_default(
            &fixture,
            &intents([write("link", file, FileMode::Executable)]),
        )
        .unwrap();
        assert_eq!(
            write_over_link.tree,
            expected_tree(&fixture, &[("link", Some(("100755", file_blob)))])
        );
    }
}

#[test]
fn deletions_and_inverse_cancellation_do_not_resurrect_links_or_retain_dead_bodies() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let deleted = export_default(&fixture, &intents([delete("link")])).unwrap();
        assert_eq!(deleted.tree, expected_tree(&fixture, &[("link", None)]));
        let cancelled = export_default(
            &fixture,
            &intents([
                symlink("new/temporary", b"../temporary"),
                delete("new/temporary"),
            ]),
        )
        .unwrap();
        assert_eq!(cancelled.tree, fixture.root_tree);
        assert!(
            cancelled
                .objects
                .values()
                .all(|(kind, _)| *kind == GitObjectKind::Tree)
        );

        let body = b"../recreated";
        let blob = git_object_id(format, GitObjectKind::Blob, body);
        let recreated = export_default(
            &fixture,
            &intents([
                delete("link"),
                symlink("link", body),
                rename("link", "new/recreated", None),
            ]),
        )
        .unwrap();
        assert_eq!(
            recreated.tree,
            expected_tree(
                &fixture,
                &[("link", None), ("new/recreated", Some(("120000", blob))),]
            )
        );
    }
}

#[test]
fn symlink_policy_and_both_rename_scopes_are_enforced_before_fetching() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let edits = intents([rename("link", "new/moved", None)]);
        for (writes, denied) in [(["new"], "link"), (["link"], "new/moved")] {
            let mut cap = capability(&SCOPES, &writes);
            assert!(matches!(export(
                &fixture, &fixture.node().request_context(), fixture.commit, &mut cap,
                &edits, ExportLimits::default(),
            ), Err(NodeWorkspaceRefusal::Manifest(SparseRefusal::Capability(
                CapabilityRefusal::WriteOutsideScope { path: refused },
            ))) if refused == path(denied)));
            assert_eq!(cap.fetched_bytes(), 0);
        }
        let mut cap = complete_capability().with_symlink_policy(SymlinkPolicy::Refuse);
        assert!(matches!(
            export(
                &fixture,
                &fixture.node().request_context(),
                fixture.commit,
                &mut cap,
                &intents([symlink("new/forbidden", b"../target")]),
                ExportLimits::default(),
            ),
            Err(NodeWorkspaceRefusal::Manifest(SparseRefusal::Capability(
                CapabilityRefusal::SymlinkRefused { .. },
            )))
        ));
        assert_eq!(cap.fetched_bytes(), 0);
        assert!(export_default(&fixture, &edits).is_ok());
    }
}

#[test]
fn typed_sources_cannot_be_forged_chmodded_or_traversed_as_directories() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let file_hint = basis(original_link(&fixture), FileMode::Regular);
        for edit in [
            rename("link", "new/moved", Some(file_hint.clone())),
            chmod("link", Some(file_hint), FileMode::Regular),
            symlink("src", b"../replace-directory"),
            symlink("module", b"../replace-gitlink"),
        ] {
            assert!(matches!(
                export_default(&fixture, &intents([edit])),
                Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
            ));
        }
        assert!(matches!(export_default(&fixture, &intents([
            write("link/escaped", b"never followed", FileMode::Regular),
        ])), Err(NodeWorkspaceRefusal::Manifest(SparseRefusal::Base(
            BaseError::SymlinkTraversal { path: refused },
        ))) if refused == path("link")));
        assert!(
            export_default(
                &fixture,
                &intents([
                    symlink("new/link", b"../../outside"),
                    write("new/link/escaped", b"never followed", FileMode::Regular),
                ])
            )
            .is_err()
        );
        assert!(
            export_default(
                &fixture,
                &intents([
                    symlink("new/link", b"../../outside"),
                    rename("new/link", "new/moved", None),
                ])
            )
            .is_ok()
        );
    }
}

#[test]
fn retained_sessions_carry_base_symlinks_across_appends_and_preserve_refused_state() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let node = fixture.node();
        let before = fixture.head();
        let request = node.request_context();
        let session = LoopbackReceiveSession::authenticated(
            PRINCIPAL,
            IdempotencyKey::new(b"base-symlink-workspace-session".to_vec()).unwrap(),
        );
        let opened = node
            .runtime()
            .block_on(node.open_merge_workspace_in(
                &request,
                &session,
                &reference(),
                &RefVisibility::new(),
                complete_capability(),
                0,
                ExportLimits::default(),
            ))
            .unwrap();
        let moved = node
            .runtime()
            .block_on(node.edit_merge_workspace_in(
                &request,
                &session,
                &opened,
                &intents([rename("link", "new/moved", None)]),
                0,
            ))
            .unwrap();
        assert_eq!(
            moved.tree(),
            expected_tree(
                &fixture,
                &[
                    ("link", None),
                    ("new/moved", Some(("120000", original_link(&fixture)))),
                ]
            )
        );
        assert_ne!(moved.snapshot_digest(), opened.snapshot_digest());
        assert!(matches!(
            node.runtime().block_on(node.edit_merge_workspace_in(
                &request,
                &session,
                &moved,
                &intents([chmod("new/moved", None, FileMode::Executable)]),
                0,
            )),
            Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
        ));
        let body = b"../new-target";
        let blob = git_object_id(format, GitObjectKind::Blob, body);
        let edited = node
            .runtime()
            .block_on(node.edit_merge_workspace_in(
                &request,
                &session,
                &moved,
                &intents([
                    symlink("link", body),
                    rename("new/moved", "dst/occupied.sh", None),
                ]),
                0,
            ))
            .unwrap();
        assert_eq!(
            edited.tree(),
            expected_tree(
                &fixture,
                &[
                    ("link", Some(("120000", blob))),
                    ("dst/occupied.sh", Some(("120000", original_link(&fixture)))),
                ]
            )
        );
        assert_eq!(node.read_git_object(blob).unwrap().payload(), body);
        assert_eq!(fixture.head(), before);
        node.runtime()
            .block_on(node.close_merge_workspace_in(&request, &session, &edited))
            .unwrap();
    }
}

#[test]
fn symlink_bodies_obey_direct_limits_and_cumulative_session_limits() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let node = fixture.node();
        let before = fixture.head();
        let request = node.request_context();
        let limits = ExportLimits {
            max_objects: 32,
            max_total_bytes: 1024,
            max_tree_entries: 32,
        };
        let mut cap = complete_capability();
        assert!(matches!(
            export(
                &fixture,
                &request,
                fixture.commit,
                &mut cap,
                &intents([symlink("new/oversized", &vec![b'x'; 1025])]),
                limits,
            ),
            Err(NodeWorkspaceRefusal::WorkspaceEditLimit)
        ));
        assert_eq!(cap.fetched_bytes(), 0);

        let session = LoopbackReceiveSession::authenticated(
            PRINCIPAL,
            IdempotencyKey::new(b"symlink-workspace-session".to_vec()).unwrap(),
        );
        let opened = node
            .runtime()
            .block_on(node.open_merge_workspace_in(
                &request,
                &session,
                &reference(),
                &RefVisibility::new(),
                complete_capability(),
                0,
                limits,
            ))
            .unwrap();
        let target = vec![b't'; 600];
        let blob = git_object_id(format, GitObjectKind::Blob, &target);
        let created = node
            .runtime()
            .block_on(node.edit_merge_workspace_in(
                &request,
                &session,
                &opened,
                &intents([symlink("new/first", &target)]),
                0,
            ))
            .unwrap();
        assert_eq!(
            created.tree(),
            expected_tree(&fixture, &[("new/first", Some(("120000", blob)))])
        );
        assert!(matches!(
            node.runtime().block_on(node.edit_merge_workspace_in(
                &request,
                &session,
                &created,
                &intents([symlink("new/second", &target)]),
                0,
            )),
            Err(NodeWorkspaceRefusal::WorkspaceEditLimit)
        ));

        // Rejection retained the same session observation; its current link
        // content, rather than the immutable base, survives the next append.
        let moved = node
            .runtime()
            .block_on(node.edit_merge_workspace_in(
                &request,
                &session,
                &created,
                &intents([rename("new/first", "link", None)]),
                0,
            ))
            .unwrap();
        assert_eq!(
            moved.tree(),
            expected_tree(&fixture, &[("link", Some(("120000", blob)))])
        );
        assert_ne!(moved.snapshot_digest(), created.snapshot_digest());
        assert!(matches!(
            node.runtime().block_on(node.edit_merge_workspace_in(
                &request,
                &session,
                &created,
                &IntentLog::new(),
                0,
            )),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        assert_eq!(node.read_git_object(blob).unwrap().payload(), target);
        assert!(node.read_git_object(moved.tree()).is_ok());
        assert_eq!(fixture.head(), before);
        node.runtime()
            .block_on(node.close_merge_workspace_in(&request, &session, &moved))
            .unwrap();
    }
}
