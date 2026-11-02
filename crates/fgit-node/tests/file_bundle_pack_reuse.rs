#![forbid(unsafe_code)]
#![cfg(unix)]
//! Real file-backed full/incremental intake, immutable placement and later native
//! serving. No test manufactures a cache receipt or supplies placement evidence.

#[allow(dead_code)]
#[path = "import_pack_reuse/support.rs"]
mod support;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_authority::IdempotencyKey;
use fgit_git_object::ObjectType;
use fgit_node::{
    LoopbackReceiveSession, OneNode, SelectedStreamBundleExport, StreamBundleExportQuery,
    StreamBundleImportQuery, StreamBundleImportRefusal, StreamBundleReuse,
};
use fgit_pack::full_bundle::fetch::BundleRefMapping;
use fgit_pack::full_bundle::{FullBundleInput, FullBundleLimits};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, RefusalCode};
use fgit_wire::visibility::RefVisibility;
use support::*;

fn reference(name: &str) -> RefName {
    RefName::try_new(name.as_bytes()).unwrap()
}

fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xc9; 16]),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}

fn bundle(
    format: GitHashAlgorithm,
    refs: &[(&str, GitOid)],
    prerequisites: &[GitOid],
    raw: &[u8],
) -> Vec<u8> {
    let mut bytes = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    for id in prerequisites {
        bytes.extend(format!("-{id} prerequisite\n").as_bytes());
    }
    for (name, id) in refs {
        bytes.extend(format!("{id} {name}\n").as_bytes());
    }
    bytes.push(b'\n');
    bytes.extend(raw);
    bytes
}

fn full_raw(bytes: &[u8]) -> &[u8] {
    FullBundleInput::parse(bytes, FullBundleLimits::default(), &mut || true)
        .unwrap()
        .pack_bytes()
}

fn incremental_raw(bytes: &[u8]) -> &[u8] {
    FullBundleInput::parse_incremental(bytes, FullBundleLimits::default(), &mut || true)
        .unwrap()
        .pack_bytes()
}

fn file_import(
    node: &OneNode,
    path: &Path,
    key: &str,
    query: StreamBundleImportQuery,
) -> Result<AdmissionResult, StreamBundleImportRefusal> {
    let request = node.import_request_context(None);
    let mut file = fs::File::open(path).unwrap();
    node.runtime()
        .block_on(node.import_full_git_bundle_reader_durable_in(
            &request,
            &session(key),
            &mut file,
            query,
            AdmissionLimits::default(),
        ))
}

fn export(node: &OneNode) -> (SelectedStreamBundleExport, Vec<u8>) {
    let request = node.request_context();
    let mut bytes = Vec::new();
    let report = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_in(
            &request,
            &RefVisibility::default(),
            StreamBundleExportQuery::default().with_verified_pack_reuse(true),
            &mut bytes,
        ))
        .unwrap();
    (report, bytes)
}

fn incremental_export(
    node: &OneNode,
    name: &str,
    base: GitOid,
) -> (SelectedStreamBundleExport, Vec<u8>) {
    let request = node.request_context();
    let mut bytes = Vec::new();
    let report = node
        .runtime()
        .block_on(node.export_incremental_git_bundle_stream_in(
            &request,
            &[reference(name)],
            &[base],
            &RefVisibility::default(),
            StreamBundleExportQuery::default().with_verified_pack_reuse(true),
            &mut bytes,
        ))
        .unwrap();
    (report, bytes)
}

fn old_history(fixture: &Fixture) -> (GitOid, Objects) {
    let (&commit, (_, body)) = fixture
        .objects
        .iter()
        .find(|(id, (kind, _))| **id != fixture.tip && *kind == ObjectType::Commit)
        .unwrap();
    let first = std::str::from_utf8(body).unwrap().lines().next().unwrap();
    let tree = GitOid::from_hex(commit.algorithm(), first.strip_prefix("tree ").unwrap()).unwrap();
    let tree_body = &fixture.objects[&tree].1;
    let blob = GitOid::from_hex(
        commit.algorithm(),
        &fgit_crypto::lowercase_hex(
            &tree_body[tree_body.len() - commit.algorithm().digest_len()..],
        ),
    )
    .unwrap();
    let objects = [commit, tree, blob]
        .into_iter()
        .map(|id| (id, fixture.objects[&id].clone()))
        .collect();
    (commit, objects)
}

fn refs(node: &OneNode) -> BTreeMap<RefName, GitOid> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap()
        .snapshot()
        .refs
        .clone()
}

fn private_blob_present(root: &Path) -> bool {
    fs::read_dir(root.join("staging")).unwrap().any(|entry| {
        let entry = entry.unwrap();
        entry.path().extension().is_some_and(|ext| ext == "stage")
            && entry.metadata().unwrap().len() > 0
    })
}

#[test]
fn file_import_preserves_ofs_and_forward_ref_for_warm_and_cold_clone_and_export() {
    for format in FORMATS {
        for layout in [Layout::Ofs, Layout::ForwardRef] {
            let scratch = Scratch::new();
            let root = scratch.0.join("node");
            let fixture = fixture(&scratch.0.join("source"), format, layout, false);
            let path = scratch.0.join("input.bundle");
            fs::write(
                &path,
                bundle(
                    format,
                    &[("refs/heads/main", fixture.tip)],
                    &[],
                    &fixture.packs[0],
                ),
            )
            .unwrap();
            let node = node(&root, format, CACHE_BYTES);
            assert_committed(
                &file_import(&node, &path, "file-native-custody", Default::default()).unwrap(),
            );
            assert_eq!(slots(&root).len(), 1);
            let (report, output) = export(&node);
            assert_eq!(report.reuse(), StreamBundleReuse::Reused);
            assert_eq!(full_raw(&output), fixture.packs[0]);
            assert_eq!(decode(full_raw(&output), format), fixture.objects);
            assert_eq!(report.receipt().compression_work(), 0);
            fs::remove_file(&path).unwrap();
            fs::remove_dir_all(&fixture.root).unwrap();
            let (node, warm) = fetch(node, fixture.tip, format);
            assert_eq!(warm, fixture.packs[0]);
            node.shutdown().unwrap();
            let node = reopen(&root, format, CACHE_BYTES);
            let (report, cold) = export(&node);
            assert_eq!(report.reuse(), StreamBundleReuse::Reused);
            assert_eq!(cold, output);
            let (node, cold) = fetch(node, fixture.tip, format);
            assert_eq!(cold, fixture.packs[0]);
            assert_eq!(decode(&cold, format), fixture.objects);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn file_incremental_import_and_fetch_retain_thin_custody_and_compose_with_originals() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, false);
        let seed = support::fixture(&scratch.0.join("seed"), format, Layout::Split, false);
        let (base, held) = old_history(&fixture);
        let source = node(&scratch.0.join("source-node"), format, CACHE_BYTES);
        assert_committed(&import(&source, &fixture.root, b"prepare-thin-source"));
        let (source_report, input) = incremental_export(&source, "refs/heads/main", base);
        assert_eq!(source_report.reuse(), StreamBundleReuse::Reused);
        assert_eq!(
            source_report
                .receipt()
                .received()
                .unwrap()
                .external_base_count(),
            1
        );
        let path = scratch.0.join("incremental.bundle");
        fs::write(&path, &input).unwrap();
        source.shutdown().unwrap();
        for mapped in [false, true] {
            let root = scratch
                .0
                .join(if mapped { "mapped" } else { "synchronized" });
            let node = node(&root, format, CACHE_BYTES);
            let seed_path = scratch.0.join("seed.bundle");
            let name = if mapped {
                "refs/remotes/upstream/main"
            } else {
                "refs/heads/main"
            };
            fs::write(
                &seed_path,
                bundle(format, &[(name, base)], &[], &seed.packs[0]),
            )
            .unwrap();
            assert_committed(
                &file_import(&node, &seed_path, "seed-originals", Default::default()).unwrap(),
            );
            assert_eq!(decode(full_raw(&export(&node).1), format), held);
            let request = node.import_request_context(None);
            let mut file = fs::File::open(&path).unwrap();
            let result = if mapped {
                node.runtime()
                    .block_on(node.fetch_incremental_git_bundle_reader_durable_in(
                        &request,
                        &session("thin-file-fetch"),
                        &mut file,
                        &[BundleRefMapping {
                            source: reference("refs/heads/main"),
                            destination: reference(name),
                            expected_old: Some(base),
                        }],
                        Default::default(),
                        AdmissionLimits::default(),
                    ))
            } else {
                node.runtime()
                    .block_on(node.import_incremental_git_bundle_reader_durable_in(
                        &request,
                        &session("thin-file-synchronize"),
                        &mut file,
                        &[(reference(name), Some(base))],
                        Default::default(),
                        AdmissionLimits::default(),
                    ))
            }
            .unwrap();
            assert_committed(&result);
            assert_eq!(slots(&root).len(), 2);
            assert_eq!(refs(&node)[&reference(name)], fixture.tip);
            let (report, output) = incremental_export(&node, name, base);
            assert_eq!(report.reuse(), StreamBundleReuse::Reused);
            assert_eq!(
                report.receipt().received().unwrap().external_base_count(),
                1
            );
            assert_eq!(incremental_raw(&output), incremental_raw(&input));
            let (report, output) = export(&node);
            assert_eq!(report.reuse(), StreamBundleReuse::Reused);
            assert_eq!(report.receipt().received().unwrap().source_pack_count(), 2);
            assert_eq!(decode(full_raw(&output), format), fixture.objects);
            node.shutdown().unwrap();
            let node = reopen(&root, format, CACHE_BYTES);
            let (report, output) = incremental_export(&node, name, base);
            assert_eq!(report.reuse(), StreamBundleReuse::Reused);
            assert_eq!(incremental_raw(&output), incremental_raw(&input));
            let (report, output) = export(&node);
            assert_eq!(report.reuse(), StreamBundleReuse::Reused);
            assert_eq!(decode(full_raw(&output), format), fixture.objects);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn mapped_full_selection_captures_only_when_every_raw_member_is_an_uploaded_placement() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let fixture = fixture(&scratch.0.join("source"), format, Layout::ForwardRef, false);
        let (base, held) = old_history(&fixture);
        let path = scratch.0.join("mapped.bundle");
        fs::write(
            &path,
            bundle(
                format,
                &[("refs/heads/base", base), ("refs/heads/main", fixture.tip)],
                &[],
                &fixture.packs[0],
            ),
        )
        .unwrap();
        for all in [false, true] {
            let root = scratch.0.join(if all { "all" } else { "subset" });
            let node = node(&root, format, CACHE_BYTES);
            let request = node.import_request_context(None);
            let mut file = fs::File::open(&path).unwrap();
            let source = if all {
                "refs/heads/main"
            } else {
                "refs/heads/base"
            };
            let result = node
                .runtime()
                .block_on(node.fetch_full_git_bundle_reader_durable_in(
                    &request,
                    &session("mapped-full-custody"),
                    &mut file,
                    &[BundleRefMapping {
                        source: reference(source),
                        destination: reference("refs/remotes/upstream/main"),
                        expected_old: None,
                    }],
                    Default::default(),
                    AdmissionLimits::default(),
                ))
                .unwrap();
            assert_committed(&result);
            let (report, output) = export(&node);
            if all {
                assert_eq!(report.reuse(), StreamBundleReuse::Reused);
                assert_eq!(full_raw(&output), fixture.packs[0]);
            } else {
                assert_eq!(report.reuse(), StreamBundleReuse::Miss);
                assert!(slots(&root).is_empty());
                assert_eq!(decode(full_raw(&output), format), held);
                for id in fixture.objects.keys().filter(|id| !held.contains_key(id)) {
                    assert!(node.read_git_object(*id).is_err());
                }
            }
            assert_eq!(refs(&node).len(), 1);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn capacity_streamed_object_bounds_and_unselected_raw_members_only_disable_optional_capture() {
    for format in FORMATS {
        for mode in 0..4 {
            let scratch = Scratch::new();
            let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, mode == 3);
            let root = scratch.0.join("node");
            let node = node(&root, format, if mode < 2 { mode } else { CACHE_BYTES });
            let path = scratch.0.join("input.bundle");
            fs::write(
                &path,
                bundle(
                    format,
                    &[("refs/heads/main", fixture.tip)],
                    &[],
                    &fixture.packs[0],
                ),
            )
            .unwrap();
            let mut query = StreamBundleImportQuery::default();
            if mode == 2 {
                // Blob programs/results still use authenticated file custody;
                // a small resident object bound cannot become a capture refusal.
                query.limits.pack.max_object_bytes = 1024;
                query.limits.graph.max_object_bytes = 1024;
            }
            assert_committed(&file_import(&node, &path, "optional-custody-miss", query).unwrap());
            assert!(slots(&root).is_empty());
            let (report, output) = export(&node);
            assert_eq!(report.reuse(), StreamBundleReuse::Miss);
            assert_eq!(decode(full_raw(&output), format), fixture.objects);
            if let Some(id) = fixture.unselected {
                assert!(node.read_git_object(id).is_err());
            }
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn corrupt_input_and_atomic_refusal_cannot_activate_file_pack_custody() {
    for format in FORMATS {
        for corrupt in [false, true] {
            let scratch = Scratch::new();
            let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, false);
            let root = scratch.0.join("node");
            let node = node(&root, format, CACHE_BYTES);
            let refs = if corrupt {
                vec![("refs/heads/main", fixture.tip)]
            } else {
                vec![
                    ("refs/heads/a", fixture.tip),
                    ("refs/heads/a/b", fixture.tip),
                ]
            };
            let mut bytes = bundle(format, &refs, &[], &fixture.packs[0]);
            if corrupt {
                *bytes.last_mut().unwrap() ^= 1;
            }
            let path = scratch.0.join("input.bundle");
            fs::write(&path, bytes).unwrap();
            let result = file_import(&node, &path, "rejected-file-custody", Default::default());
            if corrupt {
                assert!(result.is_err());
            } else {
                let result = result.unwrap();
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
            assert!(self::refs(&node).is_empty());
            for id in fixture.objects.keys() {
                assert!(node.read_git_object(*id).is_err());
            }
            assert!(!private_blob_present(&root));
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn cancellation_during_actual_blob_staging_releases_raw_reservations_before_retry() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let fixture = fixture(&scratch.0.join("source"), format, Layout::ForwardRef, false);
        let root = scratch.0.join("node");
        let node = node(&root, format, CACHE_BYTES);
        let path = scratch.0.join("input.bundle");
        fs::write(
            &path,
            bundle(
                format,
                &[("refs/heads/main", fixture.tip)],
                &[],
                &fixture.packs[0],
            ),
        )
        .unwrap();
        let stopped = Cell::new(false);
        let request = node.import_request_context(None);
        let mut file = fs::File::open(&path).unwrap();
        let result = node
            .runtime()
            .block_on(node.import_full_git_bundle_reader_controlled_in(
                &request,
                &session("cancel-file-then-retry"),
                &mut file,
                Default::default(),
                AdmissionLimits::default(),
                &mut || {
                    if private_blob_present(&root) {
                        stopped.set(true);
                    }
                    !stopped.get()
                },
            ));
        assert!(
            stopped.get(),
            "the stop must reach the actual private blob write"
        );
        assert!(result.is_err());
        assert!(slots(&root).is_empty());
        assert!(refs(&node).is_empty());
        assert!(!private_blob_present(&root));
        for id in fixture.objects.keys() {
            assert!(node.read_git_object(*id).is_err());
        }
        assert_committed(
            &file_import(&node, &path, "cancel-file-then-retry", Default::default()).unwrap(),
        );
        let (report, output) = export(&node);
        assert_eq!(report.reuse(), StreamBundleReuse::Reused);
        assert_eq!(full_raw(&output), fixture.packs[0]);
        node.shutdown().unwrap();
    }
}

#[test]
fn source_replacement_after_verification_cannot_replace_captured_pack_bytes() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, false);
        let root = scratch.0.join("node");
        let node = node(&root, format, CACHE_BYTES);
        let path = scratch.0.join("input.bundle");
        fs::write(
            &path,
            bundle(
                format,
                &[("refs/heads/main", fixture.tip)],
                &[],
                &fixture.packs[0],
            ),
        )
        .unwrap();
        let replaced = Cell::new(false);
        let request = node.import_request_context(None);
        let mut file = fs::File::open(&path).unwrap();
        let result = node
            .runtime()
            .block_on(node.import_full_git_bundle_reader_controlled_in(
                &request,
                &session("replace-after-native-read"),
                &mut file,
                Default::default(),
                AdmissionLimits::default(),
                &mut || {
                    if !replaced.get() && private_blob_present(&root) {
                        fs::write(&path, b"different bytes after original native verification")
                            .unwrap();
                        replaced.set(true);
                    }
                    true
                },
            ))
            .unwrap();
        assert!(replaced.get());
        assert_committed(&result);
        let (report, output) = export(&node);
        assert_eq!(report.reuse(), StreamBundleReuse::Reused);
        assert_eq!(full_raw(&output), fixture.packs[0]);
        assert_eq!(decode(full_raw(&output), format), fixture.objects);
        node.shutdown().unwrap();
    }
}

#[test]
fn changed_private_blob_cannot_activate_original_file_pack_custody() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, false);
        let root = scratch.0.join("node");
        let node = node(&root, format, CACHE_BYTES);
        let path = scratch.0.join("input.bundle");
        fs::write(
            &path,
            bundle(
                format,
                &[("refs/heads/main", fixture.tip)],
                &[],
                &fixture.packs[0],
            ),
        )
        .unwrap();
        let body_bytes = fixture
            .objects
            .values()
            .filter(|(kind, _)| *kind == ObjectType::Blob)
            .map(|(_, body)| body.len())
            .min()
            .unwrap();
        let corrupted = Cell::new(false);
        let request = node.import_request_context(None);
        let mut file = fs::File::open(&path).unwrap();
        let result = node
            .runtime()
            .block_on(node.import_full_git_bundle_reader_controlled_in(
                &request,
                &session("changed-private-file-candidate"),
                &mut file,
                Default::default(),
                AdmissionLimits::default(),
                &mut || {
                    if !corrupted.get() {
                        for entry in fs::read_dir(root.join("staging")).unwrap() {
                            let entry = entry.unwrap();
                            if entry.path().extension().is_some_and(|ext| ext == "stage")
                                && entry.metadata().unwrap().len() > body_bytes as u64
                            {
                                // Change the actual owned file after its payload
                                // write, retaining the same native source and ID.
                                // No callback manufactures a replacement receipt.
                                let mut bytes = fs::read(entry.path()).unwrap();
                                *bytes.last_mut().unwrap() ^= 1;
                                fs::write(entry.path(), bytes).unwrap();
                                corrupted.set(true);
                                break;
                            }
                        }
                    }
                    true
                },
            ));
        assert!(corrupted.get(), "fault must reach a real private payload");
        if let Ok(result) = result {
            assert!(!result.commands.is_empty());
            assert!(
                result.commands.iter().all(|command| matches!(
                    command.terminal.outcome,
                    DecisionOutcome::Refused { .. }
                )),
                "{result:?}"
            );
        }
        assert!(refs(&node).is_empty());
        assert!(
            slots(&root).is_empty(),
            "changed custody cannot activate its raw representation"
        );
        // Publication failure may leave ordinary unreferenced immutable
        // objects. Their existence is not a ref or cache-activation receipt.
        node.shutdown().unwrap();
    }
}
