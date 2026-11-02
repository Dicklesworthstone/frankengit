#![forbid(unsafe_code)]
//! Native directory import, actual public Git serving, and fresh-config reopen.
//! Stored DEFLATE source entries distinguish original representation reuse from
//! the ordinary deterministic compressed writer; every response is decoded too.

#[path = "import_pack_reuse/support.rs"]
mod support;
use support::*;

use fgit_node::LooseGitImportRefusal;
use fgit_types::{DecisionOutcome, RefusalCode};
use std::cell::Cell;
use std::fs;

#[test]
fn imported_ofs_and_forward_ref_packs_are_reused_after_source_removal_and_cold_open() {
    for format in FORMATS {
        for layout in [Layout::Ofs, Layout::ForwardRef] {
            let scratch = Scratch::new();
            let root = scratch.0.join("node");
            let fixture = fixture(&scratch.0.join("source"), format, layout, false);
            let node = node(&root, format, CACHE_BYTES);
            assert_committed(&import(&node, &fixture.root, b"native-pack-custody"));
            #[cfg(unix)]
            assert_eq!(slots(&root).len(), 1);
            fs::remove_dir_all(&fixture.root).unwrap();
            let (node, warm) = fetch(node, fixture.tip, format);
            assert_eq!(
                warm, fixture.packs[0],
                "a warm fetch retains the source's exact stored entries"
            );
            assert_eq!(decode(&warm, format), fixture.objects);
            node.shutdown().unwrap();
            let node = reopen(&root, format, CACHE_BYTES);
            let (node, cold) = fetch(node, fixture.tip, format);
            #[cfg(unix)]
            assert_eq!(
                cold, fixture.packs[0],
                "a new config must revalidate durable raw custody"
            );
            assert_eq!(decode(&cold, format), fixture.objects);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn one_import_activates_multiple_packs_and_reuses_their_entry_runs_after_reopen() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        let fixture = fixture(&scratch.0.join("source"), format, Layout::Split, false);
        let node = node(&root, format, CACHE_BYTES);
        assert_committed(&import(&node, &fixture.root, b"two-native-source-packs"));
        #[cfg(unix)]
        assert_eq!(
            slots(&root).len(),
            2,
            "staging must retain both pending representations"
        );
        let (node, warm) = fetch(node, fixture.tip, format);
        assert_original_runs(&warm, &fixture, format);
        node.shutdown().unwrap();
        fs::remove_dir_all(&fixture.root).unwrap();
        let (node, cold) = fetch(reopen(&root, format, CACHE_BYTES), fixture.tip, format);
        #[cfg(unix)]
        assert_original_runs(&cold, &fixture, format);
        assert_eq!(decode(&cold, format), fixture.objects);
        node.shutdown().unwrap();
    }
}

fn assert_original_runs(bytes: &[u8], fixture: &Fixture, format: fgit_types::GitHashAlgorithm) {
    let hash_bytes = fixture.tip.as_bytes().len();
    let runs: Vec<_> = fixture
        .packs
        .iter()
        .map(|pack| &pack[12..pack.len() - hash_bytes])
        .collect();
    let body = &bytes[12..bytes.len() - hash_bytes];
    assert!(
        body == [runs[0], runs[1]].concat() || body == [runs[1], runs[0]].concat(),
        "composition copies whole original entry runs without recompression"
    );
    assert_eq!(decode(bytes, format), fixture.objects);
}

#[test]
fn disabled_overbudget_and_unselected_custody_leave_complete_imports_fetchable() {
    for format in FORMATS {
        for (budget, unselected) in [(0, false), (1, false), (CACHE_BYTES, true)] {
            let scratch = Scratch::new();
            let root = scratch.0.join("node");
            let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, unselected);
            let node = node(&root, format, budget);
            assert_committed(&import(&node, &fixture.root, b"optional-import-custody"));
            assert!(slots(&root).is_empty());
            if let Some(id) = fixture.unselected {
                assert!(node.read_git_object(id).is_err());
            }
            let (node, output) = fetch(node, fixture.tip, format);
            assert_ne!(output, fixture.packs[0]);
            assert_eq!(
                decode(&output, format),
                fixture.objects,
                "fallback neither omits selected objects nor adds unreachable support"
            );
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn cache_persistence_io_failure_preserves_the_committed_import_and_cold_writer_fallback() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        let fixture = fixture(&scratch.0.join("source"), format, Layout::ForwardRef, false);
        let node = node(&root, format, CACHE_BYTES);
        fs::write(
            root.join("received-pack-cache"),
            b"cache directory deliberately unavailable",
        )
        .unwrap();
        assert_committed(&import(
            &node,
            &fixture.root,
            b"optional-durable-cache-failure",
        ));
        let (node, warm) = fetch(node, fixture.tip, format);
        assert_eq!(
            warm, fixture.packs[0],
            "failed persistence does not poison verified live custody"
        );
        node.shutdown().unwrap();
        let (node, cold) = fetch(reopen(&root, format, CACHE_BYTES), fixture.tip, format);
        assert_ne!(cold, fixture.packs[0]);
        assert_eq!(decode(&cold, format), fixture.objects);
        node.shutdown().unwrap();
    }
}

#[test]
fn corrupted_sources_and_refused_admission_leave_no_imported_cache_or_native_objects() {
    for format in FORMATS {
        for corrupt in [false, true] {
            let scratch = Scratch::new();
            let root = scratch.0.join("node");
            let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, false);
            let node = node(&root, format, CACHE_BYTES);
            if corrupt {
                let mut raw = fixture.packs[0].clone();
                *raw.last_mut().unwrap() ^= 1;
                fs::write(&fixture.pack_paths[0], raw).unwrap();
                let request = node.request_context();
                let refused = node
                    .runtime()
                    .block_on(node.import_loose_git_directory_durable_in(
                        &request,
                        &fixture.root,
                        fgit_types::PrincipalId::from_bytes([0xc9; 16]),
                        b"corrupt-source-import",
                    ));
                assert!(matches!(
                    refused,
                    Err(fgit_node::NodeSourceImportRefusal::Staging(_))
                ));
            } else {
                fs::write(
                    fixture.root.join("packed-refs"),
                    format!(
                        "# pack-refs with: sorted\n{} refs/heads/a\n{} refs/heads/a/b\n",
                        fixture.tip, fixture.tip
                    ),
                )
                .unwrap();
                let result = import(&node, &fixture.root, b"refused-native-source-import");
                assert_eq!(result.commands.len(), 3);
                assert!(
                    result.commands.iter().all(|command| matches!(
                        command.terminal.outcome,
                        DecisionOutcome::Refused {
                            code: RefusalCode::RefNameConflict,
                            ..
                        }
                    )),
                    "{result:?}"
                );
            }
            assert!(slots(&root).is_empty());
            let request = node.request_context();
            let state = node
                .runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap();
            assert!(state.snapshot().refs.is_empty());
            for id in fixture.objects.keys() {
                assert!(
                    node.read_git_object(*id).is_err(),
                    "refused durable preparation must not place {id}"
                );
            }
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn cancellation_during_standalone_placement_drops_custody_and_an_uncancelled_retry_succeeds() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, false);
        let node = node(&root, format, CACHE_BYTES);
        let original_files = file_count(&root.join("objects"));
        let stopped = Cell::new(false);
        let result = node.stage_loose_git_import_with_deadline(&fixture.root, &mut || {
            if file_count(&root.join("objects")) > original_files {
                stopped.set(true);
            }
            !stopped.get()
        });
        assert!(
            stopped.get(),
            "the fault is injected only once immutable placement begins"
        );
        assert!(matches!(
            result,
            Err(LooseGitImportRefusal::Interrupted {
                code: RefusalCode::CancellationInProgress,
                ..
            })
        ));
        assert!(
            slots(&root).is_empty(),
            "a partial placement cannot activate raw custody"
        );
        assert_committed(&import(
            &node,
            &fixture.root,
            b"retry-after-import-placement-cancellation",
        ));
        let (node, pack) = fetch(node, fixture.tip, format);
        assert_eq!(pack, fixture.packs[0]);
        assert_eq!(decode(&pack, format), fixture.objects);
        node.shutdown().unwrap();
    }
}
