//! Real native objects and authority; legacy layouts are staged explicitly.
use super::*;
use crate::NodeConfig;
use fgit_crypto::git_object_id;
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-symbol-directory-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn loose(root: &Path, format: Format, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let size = u16::try_from(raw.len()).unwrap();
    let mut z = vec![0x78, 0x01, 0x01];
    z.extend(size.to_le_bytes());
    z.extend((!size).to_le_bytes());
    z.extend(&raw);
    let (a, b) = raw.iter().fold((1u32, 0u32), |(a, b), x| {
        let a = (a + u32::from(*x)) % 65521;
        (a, (b + a) % 65521)
    });
    z.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    let parent = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&parent).unwrap();
    fs::write(parent.join(&hex[2..]), z).unwrap();
    id
}
fn fixture(scratch: &Scratch, format: Format) -> (OneNode, NodeConfig) {
    let root = scratch.0.join("git");
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        Format::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        Format::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let mut tree = Vec::new();
    for (path, bytes) in [
        ("a.rs", b"fn Alpha() {}\n".as_slice()),
        ("z.rs", b"fn Zebra() {}\n"),
    ] {
        let blob = loose(&root, format, GitObjectKind::Blob, "blob", bytes);
        tree.extend(format!("100644 {path}\0").as_bytes());
        tree.extend(blob.as_bytes());
    }
    let tree = loose(&root, format, GitObjectKind::Tree, "tree", &tree);
    let commit = loose(&root,format,GitObjectKind::Commit,"commit",format!(
        "tree {tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\ndirectory\n").as_bytes());
    fs::write(root.join("refs/heads/main"), format!("{commit}\n")).unwrap();
    let config = NodeConfig::new(
        scratch.0.join("node"),
        TenantId::from_bytes([0xe1; 16]),
        RepositoryId::from_bytes([0xe2; 16]),
    )
    .with_object_format(format)
    .with_worker_threads(2);
    let (mut node, _) = OneNode::init(config.clone()).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let result = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.outbox_delivery_context(),
            &root,
            PrincipalId::from_bytes([0xe3; 16]),
            b"directory-fixture",
        ))
        .unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    (node, config)
}
fn reopen(config: NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config).unwrap();
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(head.receipt().generation())
        .unwrap();
    node
}
fn search(
    node: &OneNode,
    name: &[u8],
    minimum: Option<&GenerationActivation>,
) -> Result<data::Report, Failure> {
    let query = SymbolQuery::new(
        name,
        fgit_forge::source_symbols::SymbolMatchMode::Exact,
        &[],
        &[],
        fgit_forge::source_symbols::MAX_SYMBOL_WORK,
    )
    .unwrap();
    node.runtime()
        .block_on(node.search_source_symbols_index_snapshot_local_in(
            &node.request_context(),
            &reference(),
            None,
            None,
            minimum,
            &query,
            Default::default(),
            data::MAX_INDEX_BYTES,
        ))
}
fn active(node: &OneNode) -> fgit_graph::SelectedGeneration {
    node.runtime()
        .block_on(
            GenerationAuthority::new(&node.authority, node.symbol_head_key(&reference()).unwrap())
                .read_active_async(
                    node.request_context().authority(),
                    view().unwrap(),
                    None,
                    Default::default(),
                    &mut || true,
                ),
        )
        .unwrap()
        .unwrap()
}
fn legacy_build(node: &OneNode) -> GenerationActivation {
    let request = node.outbox_delivery_context();
    let query = Build(
        SourceQuery::new(b"symbols", SearchCase::Exact, &[]).unwrap(),
        None,
    );
    let (head, forge, result) = node
        .runtime()
        .block_on(async {
            match node.object_format {
                Format::Sha1 => {
                    node.select_source_local_format::<Sha1, _>(
                        &request,
                        &reference(),
                        None,
                        None,
                        &query,
                        Default::default(),
                    )
                    .await
                }
                Format::Sha256 => {
                    node.select_source_local_format::<Sha256, _>(
                        &request,
                        &reference(),
                        None,
                        None,
                        &query,
                        Default::default(),
                    )
                    .await
                }
            }
        })
        .unwrap();
    let corpus = result.unwrap();
    let selected = corpus.source();
    let source = data::Source {
        tenant: node.tenant_id,
        repository: node.repository_id,
        incarnation: node.repository_incarnation_id(),
        format: node.object_format,
        reference: reference(),
        head,
        rcr: selected.source_rcr,
        forge,
        commit: selected.source_commit,
        tree: selected.source_tree,
    };
    let (manifest, tables) = corpus.finish(source.clone(), &|| false).unwrap();
    let manifest = manifest.encode(&|| false).unwrap();
    node.runtime().block_on(async {
        for payload in tables.iter().chain(std::iter::once(&manifest)) {
            assert!(matches!(
                AsyncAuthorityStore::put_if_absent(
                    &node.authority,
                    request.authority(),
                    &node.symbol_payload_key(payload.root).unwrap(),
                    &payload.bytes
                )
                .await
                .unwrap(),
                PutOutcome::Created | PutOutcome::IdenticalRetry
            ));
        }
        GenerationAuthority::new(&node.authority, node.symbol_head_key(&reference()).unwrap())
            .stage_and_activate_async(
                request.authority(),
                &generation_body(&source, manifest.root, None, None).unwrap(),
            )
            .await
            .unwrap()
    })
}

#[test]
fn legacy_generation_reopens_and_refreshes_to_directory_without_rescanning_blobs() {
    for format in [Format::Sha1, Format::Sha256] {
        let scratch = Scratch::new();
        let (node, config) = fixture(&scratch, format);
        let first = legacy_build(&node);
        let old = search(&node, b"Alpha", None).unwrap();
        assert_eq!(old.tables_read, 2);
        assert!(
            symbol_directory_root(active(&node).body())
                .unwrap()
                .is_none()
        );
        node.shutdown().unwrap();
        let node = reopen(config.clone());
        assert_eq!(
            search(&node, b"Alpha", Some(&first)).unwrap().matches,
            old.matches
        );
        let (source, second, stats) = node
            .runtime()
            .block_on(node.refresh_source_symbol_index_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                None,
                None,
                first.generation_id,
                Default::default(),
            ))
            .unwrap();
        assert_eq!(stats.source_blobs_read, 0);
        assert_eq!(stats.reused_files, 2);
        assert_eq!(source, old.source);
        assert!(
            symbol_directory_root(active(&node).body())
                .unwrap()
                .is_some()
        );
        let fast = search(&node, b"Alpha", Some(&first)).unwrap();
        assert_eq!(fast.tables_read, 1);
        assert_eq!(fast.matches, old.matches);
        assert_eq!(
            fast.generation,
            *second.generation_id.as_internal_object_id()
        );
        let absent = search(&node, b"Missing", None).unwrap();
        assert_eq!(absent.tables_read, 0);
        assert!(absent.complete && absent.matches.is_empty());
        node.shutdown().unwrap();
        let node = reopen(config);
        assert_eq!(
            search(&node, b"Alpha", Some(&second)).unwrap().matches,
            old.matches
        );
        assert_eq!(search(&node, b"Alpha", None).unwrap().tables_read, 1);
        node.shutdown().unwrap();
    }
}
#[test]
fn missing_or_substituted_directory_never_falls_back_in_queries_refresh_or_reconcile() {
    for missing in [true, false] {
        let scratch = Scratch::new();
        let (node, _) = fixture(&scratch, Format::Sha256);
        let first = node
            .runtime()
            .block_on(node.build_source_symbol_index_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                None,
                None,
                None,
                Default::default(),
            ))
            .unwrap();
        let original = active(&node);
        let root = symbol_manifest_root(original.body()).unwrap();
        let selected_root = if missing { first.0.forge } else { root };
        // Authentic generation, but absent backing or a manifest substituted
        // for the required directory. Real immutable store, no storage mock.
        let bad = generation_body(
            &first.0,
            root,
            Some(selected_root),
            Some(first.1.generation_id),
        )
        .unwrap();
        let activation = node
            .runtime()
            .block_on(
                GenerationAuthority::new(
                    &node.authority,
                    node.symbol_head_key(&reference()).unwrap(),
                )
                .stage_and_activate_async(node.outbox_delivery_context().authority(), &bad),
            )
            .unwrap();
        let error = search(&node, b"Missing", None).unwrap_err();
        if missing {
            assert!(matches!(error,Failure::Missing(id) if id == selected_root));
        } else {
            assert!(matches!(error, Failure::Index(_)));
        }
        let mut called = false;
        assert!(
            node.runtime()
                .block_on(node.refresh_source_symbol_index_guarded_local_in(
                    &node.outbox_delivery_context(),
                    &reference(),
                    None,
                    None,
                    activation.generation_id,
                    Default::default(),
                    &mut |_| {
                        called = true;
                        Ok(())
                    }
                ))
                .is_err()
        );
        assert!(!called);
        assert!(
            node.runtime()
                .block_on(node.reconcile_source_symbol_index_local_in(
                    &node.outbox_delivery_context(),
                    &reference(),
                    None,
                    Some(&activation),
                    Default::default(),
                    Default::default()
                ))
                .is_err()
        );
        assert_eq!(active(&node).activation(), &activation);
        node.shutdown().unwrap();
    }
}
#[test]
fn schema_profile_pairs_are_closed_and_legacy_edges_cannot_hide_a_directory() {
    let scratch = Scratch::new();
    let (node, _) = fixture(&scratch, Format::Sha1);
    let (source, _) = node
        .runtime()
        .block_on(node.build_source_symbol_index_local_in(
            &node.outbox_delivery_context(),
            &reference(),
            None,
            None,
            None,
            Default::default(),
        ))
        .unwrap();
    let current = active(&node);
    let root = symbol_manifest_root(current.body()).unwrap();
    for (s, p, edges) in [
        (schema(), data::DIRECTORY_PROFILE, root),
        (directory_schema(), data::INDEX_PROFILE, root),
        (schema(), data::INDEX_PROFILE, source.forge),
    ] {
        let body = GraphGenerationBody::new(
            view().unwrap(),
            s,
            GraphAuthorityClass::DeterministicDerived,
            GraphSourceStamp {
                source_rcr_id: source.rcr,
                source_forge_position_root: source.forge,
                builder_profile: BuilderProfileId::try_new(p.as_bytes()).unwrap(),
                parser_model_root: data::profile_root().unwrap(),
            },
            root,
            edges,
            root,
            root,
            None,
        );
        assert!(symbol_manifest_root(&body).is_err());
    }
    node.shutdown().unwrap();
}
