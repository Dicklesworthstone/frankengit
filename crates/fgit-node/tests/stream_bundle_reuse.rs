#![forbid(unsafe_code)]
//! Public import -> authenticated bundle selection -> verified representation
//! reuse, including a new process-equivalent configuration after shutdown.

#[path = "import_pack_reuse/support.rs"]
mod support;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};

use fgit_crypto::{git_object_id, sha256_digest};
use fgit_git_object::ObjectType;
use fgit_node::{
    OneNode, SelectedStreamBundleExport, StreamBundleExportQuery, StreamBundleExportRefusal,
    StreamBundleReuse,
};
use fgit_pack::full_bundle::{FullBundleInput, FullBundleLimits};
use fgit_pack::{
    ExternalBaseLookup, NativeChecksumVerifier, PackError, PackLimits, PackObject, ScalarResolver,
    read_verified_pack,
};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use fgit_wire::WireLimits;
use fgit_wire::visibility::RefVisibility;
use support::*;

fn export(
    node: &OneNode,
    query: StreamBundleExportQuery,
    visibility: &RefVisibility,
) -> (SelectedStreamBundleExport, Vec<u8>) {
    let request = node.request_context();
    let mut bytes = Vec::new();
    let report = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_in(&request, visibility, query, &mut bytes))
        .unwrap();
    (report, bytes)
}

fn query() -> StreamBundleExportQuery {
    StreamBundleExportQuery::default().with_verified_pack_reuse(true)
}

fn pack(bytes: &[u8]) -> &[u8] {
    FullBundleInput::parse(bytes, FullBundleLimits::default(), &mut || true)
        .unwrap()
        .pack_bytes()
}

fn old_history(fixture: &Fixture, format: GitHashAlgorithm) -> (GitOid, Objects) {
    let (&commit, (_, body)) = fixture
        .objects
        .iter()
        .find(|(id, (kind, _))| **id != fixture.tip && *kind == ObjectType::Commit)
        .unwrap();
    let first = std::str::from_utf8(body).unwrap().lines().next().unwrap();
    let tree = GitOid::from_hex(format, first.strip_prefix("tree ").unwrap()).unwrap();
    let tree_body = &fixture.objects[&tree].1;
    let blob = GitOid::from_hex(
        format,
        &fgit_crypto::lowercase_hex(&tree_body[tree_body.len() - format.digest_len()..]),
    )
    .unwrap();
    let objects = [commit, tree, blob]
        .into_iter()
        .map(|id| (id, fixture.objects[&id].clone()))
        .collect();
    (commit, objects)
}

#[test]
fn explicit_full_reuse_preserves_imported_ofs_and_forward_ref_bytes_warm_and_cold() {
    for format in FORMATS {
        for layout in [Layout::Ofs, Layout::ForwardRef] {
            let scratch = Scratch::new();
            let root = scratch.0.join("node");
            let fixture = fixture(&scratch.0.join("source"), format, layout, false);
            let node = node(&root, format, CACHE_BYTES);
            assert_committed(&import(&node, &fixture.root, b"stream-bundle-custody"));
            let (default, baseline) = export(
                &node,
                StreamBundleExportQuery::default(),
                &RefVisibility::default(),
            );
            assert_eq!(default.reuse(), StreamBundleReuse::NotRequested);
            assert!(default.receipt().encoded().is_some());
            assert!(default.receipt().received().is_none());
            assert_ne!(pack(&baseline), fixture.packs[0]);
            let (warm, bytes) = export(&node, query(), &RefVisibility::default());
            assert_eq!(warm.reuse(), StreamBundleReuse::Reused);
            assert_eq!(warm.head(), default.head());
            assert_eq!(warm.generation(), default.generation());
            assert_eq!(warm.receipt().profile_id(), "git-bundle-received-pack-v1");
            assert!(warm.receipt().encoded().is_none());
            assert!(warm.receipt().framing().is_some());
            assert_eq!(warm.receipt().received().unwrap().source_pack_count(), 1);
            assert_eq!(warm.receipt().received().unwrap().external_base_count(), 0);
            assert_eq!(warm.receipt().compression_work(), 0);
            assert_eq!(warm.receipt().bundle_sha256(), sha256_digest(&bytes));
            assert_eq!(pack(&bytes), fixture.packs[0]);
            assert_eq!(decode(pack(&bytes), format), fixture.objects);
            let (_, after) = export(
                &node,
                StreamBundleExportQuery::default(),
                &RefVisibility::default(),
            );
            assert_eq!(
                after, baseline,
                "opting in cannot alter future default output"
            );
            node.shutdown().unwrap();
            fs::remove_dir_all(&fixture.root).unwrap();
            let node = reopen(&root, format, CACHE_BYTES);
            let (cold, restored) = export(&node, query(), &RefVisibility::default());
            #[cfg(unix)]
            {
                assert_eq!(cold.reuse(), StreamBundleReuse::Reused);
                assert_eq!(restored, bytes);
            }
            assert_eq!(cold.head(), warm.head());
            assert_eq!(decode(pack(&restored), format), fixture.objects);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn disjoint_imported_packs_compose_into_one_exact_full_bundle() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let fixture = fixture(&scratch.0.join("source"), format, Layout::Split, false);
        let node = node(&scratch.0.join("node"), format, CACHE_BYTES);
        assert_committed(&import(&node, &fixture.root, b"stream-bundle-compose"));
        let (report, bytes) = export(&node, query(), &RefVisibility::default());
        assert_eq!(report.reuse(), StreamBundleReuse::Reused);
        let received = report.receipt().received().unwrap();
        assert_eq!(received.profile(), "received-pack-concat-v1");
        assert_eq!(received.source_pack_count(), 2);
        let raw = pack(&bytes);
        let runs: Vec<_> = fixture
            .packs
            .iter()
            .map(|raw| &raw[12..raw.len() - format.digest_len()])
            .collect();
        let body = &raw[12..raw.len() - format.digest_len()];
        assert!(body == [runs[0], runs[1]].concat() || body == [runs[1], runs[0]].concat());
        assert_eq!(decode(raw, format), fixture.objects);
        node.shutdown().unwrap();
    }
}

#[test]
fn incremental_reuse_borrows_only_declared_verified_prerequisite_history_after_restart() {
    for format in FORMATS {
        for layout in [Layout::Ofs, Layout::ForwardRef] {
            let scratch = Scratch::new();
            let root = scratch.0.join("node");
            let fixture = fixture(&scratch.0.join("source"), format, layout, false);
            let (base, held) = old_history(&fixture, format);
            let expected: Objects = fixture
                .objects
                .iter()
                .filter(|(id, _)| !held.contains_key(*id))
                .map(|(id, object)| (*id, object.clone()))
                .collect();
            let node = node(&root, format, CACHE_BYTES);
            assert_committed(&import(&node, &fixture.root, b"stream-incremental-custody"));
            {
                let request = node.request_context();
                let mut bytes = Vec::new();
                let report = node
                    .runtime()
                    .block_on(node.export_incremental_git_bundle_stream_in(
                        &request,
                        &[RefName::try_new(b"refs/heads/main").unwrap()],
                        &[base],
                        &RefVisibility::default(),
                        query(),
                        &mut bytes,
                    ))
                    .unwrap();
                assert_eq!(report.reuse(), StreamBundleReuse::Reused);
                assert_eq!(
                    report.receipt().profile_id(),
                    "git-bundle-incremental-received-pack-v1"
                );
                assert_eq!(report.receipt().object_count(), 3);
                assert_eq!(report.receipt().prerequisite_count(), 1);
                assert_eq!(report.receipt().external_object_count(), held.len());
                let received = report.receipt().received().unwrap();
                assert_eq!(received.profile(), "received-pack-select-thin-v1");
                assert_eq!(received.external_base_count(), 1);
                let input = FullBundleInput::parse_incremental(
                    &bytes,
                    FullBundleLimits::default(),
                    &mut || true,
                )
                .unwrap();
                assert_eq!(input.prerequisites(), &[base]);
                assert_eq!(
                    decode_with_held(input.pack_bytes(), format, &held),
                    expected
                );
            }
            node.shutdown().unwrap();
            #[cfg(unix)]
            {
                let node = reopen(&root, format, CACHE_BYTES);
                let request = node.request_context();
                let mut bytes = Vec::new();
                let report = node
                    .runtime()
                    .block_on(node.export_incremental_git_bundle_stream_in(
                        &request,
                        &[RefName::try_new(b"refs/heads/main").unwrap()],
                        &[base],
                        &RefVisibility::default(),
                        query(),
                        &mut bytes,
                    ))
                    .unwrap();
                assert_eq!(report.reuse(), StreamBundleReuse::Reused);
                assert_eq!(
                    report.receipt().received().unwrap().external_base_count(),
                    1
                );
                let input = FullBundleInput::parse_incremental(
                    &bytes,
                    FullBundleLimits::default(),
                    &mut || true,
                )
                .unwrap();
                assert_eq!(
                    decode_with_held(input.pack_bytes(), format, &held),
                    expected
                );
                node.shutdown().unwrap();
            }
        }
    }
}

#[test]
fn hidden_pack_members_are_removed_and_cannot_authorize_a_prerequisite() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, false);
        let (base, visible) = old_history(&fixture, format);
        fs::create_dir_all(fixture.root.join("refs/private")).unwrap();
        fs::write(
            fixture.root.join("refs/private/next"),
            format!("{}\n", fixture.tip),
        )
        .unwrap();
        fs::write(fixture.root.join("refs/heads/main"), format!("{base}\n")).unwrap();
        let node = node(&scratch.0.join("node"), format, CACHE_BYTES);
        assert_committed(&import(&node, &fixture.root, b"stream-hidden-selection"));
        let mut visibility = RefVisibility::default();
        visibility
            .push_rule(b"refs/private", &WireLimits::default())
            .unwrap();
        let (report, bytes) = export(&node, query(), &visibility);
        assert_eq!(report.reuse(), StreamBundleReuse::Reused);
        assert_eq!(decode(pack(&bytes), format), visible);
        let parsed =
            FullBundleInput::parse(&bytes, FullBundleLimits::default(), &mut || true).unwrap();
        assert_eq!(parsed.references().len(), 1);
        assert_eq!(*parsed.references()[0].target(), base);
        for prerequisite in [
            fixture.tip,
            git_object_id(format, ObjectType::Commit, b"absent"),
        ] {
            let request = node.request_context();
            let mut bytes = Vec::new();
            assert!(
                node.runtime()
                    .block_on(node.export_incremental_git_bundle_stream_in(
                        &request,
                        &[RefName::try_new(b"refs/heads/main").unwrap()],
                        &[prerequisite],
                        &visibility,
                        query(),
                        &mut bytes,
                    ))
                    .is_err()
            );
            assert!(bytes.is_empty());
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn optional_cache_and_representation_limits_fall_back_to_identical_default_bytes() {
    for format in FORMATS {
        for budget in [0, 1, CACHE_BYTES] {
            let scratch = Scratch::new();
            let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, false);
            let node = node(&scratch.0.join("node"), format, budget);
            assert_committed(&import(&node, &fixture.root, b"stream-optional-cache"));
            let (_, baseline) = export(
                &node,
                StreamBundleExportQuery::default(),
                &RefVisibility::default(),
            );
            let mut limited = query();
            if budget == CACHE_BYTES {
                limited.limits.pack.max_delta_depth = 0;
            }
            let (report, bytes) = export(&node, limited, &RefVisibility::default());
            assert_eq!(report.reuse(), StreamBundleReuse::Miss);
            assert!(report.receipt().encoded().is_some());
            assert_eq!(bytes, baseline);
            // This representation fits the pack ceiling but not header+pack.
            // Preflight must give the smaller deterministic encoding a chance.
            let mut envelope = query();
            envelope.limits.pack.max_input_bytes = fixture.packs[0].len();
            envelope.limits.envelope.max_bundle_bytes = baseline.len();
            assert!(fixture.packs[0].len() > baseline.len());
            let (report, bytes) = export(&node, envelope, &RefVisibility::default());
            assert_eq!(report.reuse(), StreamBundleReuse::Miss);
            assert_eq!(bytes, baseline);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn corrupted_durable_custody_is_a_miss_without_changing_source_selection() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, false);
        let node = node(&root, format, CACHE_BYTES);
        assert_committed(&import(&node, &fixture.root, b"stream-corrupt-cache"));
        let (before, baseline) = export(
            &node,
            StreamBundleExportQuery::default(),
            &RefVisibility::default(),
        );
        node.shutdown().unwrap();
        let retained = slots(&root);
        assert!(
            !retained.is_empty(),
            "native import did not persist pack custody"
        );
        for slot in retained {
            let mut bytes = fs::read(&slot).unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            fs::write(slot, bytes).unwrap();
        }
        let node = reopen(&root, format, CACHE_BYTES);
        let (report, bytes) = export(&node, query(), &RefVisibility::default());
        assert_eq!(report.reuse(), StreamBundleReuse::Miss);
        assert_eq!(report.head(), before.head());
        assert_eq!(report.generation(), before.generation());
        assert_eq!(bytes, baseline);
        node.shutdown().unwrap();
    }
}

struct StopWriter<'a> {
    live: &'a Cell<bool>,
    bytes: Vec<u8>,
}
impl Write for StopWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        self.live.set(false);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("node must not publish")
    }
}

#[test]
fn selected_bounds_and_cancellation_remain_fatal_with_no_fallback_after_output() {
    for format in FORMATS {
        let scratch = Scratch::new();
        let fixture = fixture(&scratch.0.join("source"), format, Layout::Ofs, false);
        let node = node(&scratch.0.join("node"), format, CACHE_BYTES);
        assert_committed(&import(&node, &fixture.root, b"stream-stop"));
        let total: usize = fixture.objects.values().map(|(_, body)| body.len()).sum();
        let mut exact = query();
        exact.limits.pack.max_total_expanded_bytes = total;
        exact.limits.max_compression_work = 0;
        let (before, baseline) = export(&node, exact.clone(), &RefVisibility::default());
        assert_eq!(before.reuse(), StreamBundleReuse::Reused);
        for object_count in [false, true] {
            let mut limited = exact.clone();
            if object_count {
                limited.limits.pack.max_entries = fixture.objects.len() as u32 - 1;
            } else {
                limited.limits.pack.max_total_expanded_bytes = total - 1;
            }
            let request = node.request_context();
            let mut bytes = Vec::new();
            assert!(
                node.runtime()
                    .block_on(node.export_full_git_bundle_stream_in(
                        &request,
                        &RefVisibility::default(),
                        limited,
                        &mut bytes,
                    ))
                    .is_err()
            );
            assert!(bytes.is_empty());
        }
        let live = Cell::new(true);
        let mut sink = StopWriter {
            live: &live,
            bytes: Vec::new(),
        };
        let request = node.request_context();
        let result = node
            .runtime()
            .block_on(node.export_full_git_bundle_stream_controlled_in(
                &request,
                &RefVisibility::default(),
                query(),
                &mut sink,
                &mut || live.get(),
            ));
        assert!(
            matches!(result, Err(StreamBundleExportRefusal::Cancelled { .. })),
            "{result:?}"
        );
        assert!(!sink.bytes.is_empty());
        assert!(baseline.starts_with(&sink.bytes));
        assert!(sink.bytes.len() < baseline.len());
        let (after, bytes) = export(&node, query(), &RefVisibility::default());
        assert_eq!(after.head(), before.head());
        assert_eq!(bytes, baseline);
        node.shutdown().unwrap();
    }
}

struct Held<'a>(&'a Objects);
impl ExternalBaseLookup for Held<'_> {
    fn lookup(&self, id: &GitOid) -> Option<&[u8]> {
        self.0.get(id).map(|(_, body)| body.as_slice())
    }
    fn lookup_typed(&self, id: &GitOid) -> Option<(ObjectType, &[u8])> {
        self.0.get(id).map(|(kind, body)| (*kind, body.as_slice()))
    }
}

fn offset(entry: &PackObject) -> u64 {
    match entry {
        PackObject::Base { offset, .. } | PackObject::TypedBase { offset, .. } => *offset,
        PackObject::Delta(delta) => delta.offset,
    }
}

fn decode_with_held(bytes: &[u8], format: GitHashAlgorithm, held: &Objects) -> Objects {
    let limits = PackLimits::default();
    let parsed = read_verified_pack(
        bytes,
        format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
    )
    .unwrap();
    let mut entries = parsed.into_scalar_objects(|_| None).unwrap();
    let mut resolved = BTreeMap::new();
    let held = Held(held);
    for _ in 0..entries.len() {
        let resolver = ScalarResolver::new(&entries, &held, &limits, &mut || true).unwrap();
        let mut learned = Vec::new();
        for entry in &entries {
            let at = offset(entry);
            if resolved.contains_key(&at) {
                continue;
            }
            match resolver.resolve_offset_typed(at, &mut || true) {
                Ok((kind, body)) => {
                    learned.push((at, git_object_id(format, kind, &body), kind, body))
                }
                Err(PackError::MissingDeltaBase) => {}
                Err(error) => panic!("bundle refused native reconstruction: {error:?}"),
            }
        }
        assert!(!learned.is_empty());
        for (at, id, kind, body) in learned {
            match entries
                .iter_mut()
                .find(|entry| offset(entry) == at)
                .unwrap()
            {
                PackObject::Base { id: slot, .. } | PackObject::TypedBase { id: slot, .. } => {
                    *slot = Some(id)
                }
                PackObject::Delta(delta) => delta.id = Some(id),
            }
            assert!(resolved.insert(at, (id, kind, body)).is_none());
        }
        if resolved.len() == entries.len() {
            break;
        }
    }
    assert_eq!(resolved.len(), entries.len());
    resolved
        .into_values()
        .map(|(id, kind, body)| (id, (kind, body)))
        .collect()
}
