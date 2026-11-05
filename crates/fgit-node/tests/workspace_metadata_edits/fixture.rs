//! Real embedded-node fixtures and independently encoded Git tree expectations.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_crypto::{
    GitHashAlgorithm as HashAlgorithm, GitObjectKind, Sha1, Sha256, git_object_id,
};
use fgit_node::{NodeConfig, NodeRequestContext, NodeWorkspaceRefusal, OneNode};
use fgit_treefs::{
    BasisEntry, EntryClass, ExportLimits, FileMode, IntentLog, TreeCapability, TreeEditIntent,
    TreePath, WorkspaceId,
};
use fgit_types::{
    GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryAuthorityHeadId,
    RepositoryId, TenantId,
};
use fgit_wire::visibility::RefVisibility;

const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0xc2; 16]);
pub(super) const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0xc3; 16]);
static NEXT: AtomicU64 = AtomicU64::new(0);

pub(super) fn path(value: &str) -> TreePath {
    TreePath::parse_default(value.as_bytes()).unwrap()
}

pub(super) fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}

pub(super) fn capability(reads: &[&str], writes: &[&str]) -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([0xc4; 16]),
        REPOSITORY,
        reads.iter().map(|value| path(value)).collect(),
        writes.iter().map(|value| path(value)).collect(),
    )
}

pub(super) fn complete_capability() -> TreeCapability {
    let scope = ["dst", "link", "module", "new", "src", "untouched.txt"];
    capability(&scope, &scope)
}

pub(super) fn basis(oid: GitOid, mode: FileMode) -> BasisEntry {
    BasisEntry {
        oid: oid.as_bytes().to_vec(),
        mode,
    }
}

pub(super) fn rename(from: &str, to: &str, basis_entry: Option<BasisEntry>) -> TreeEditIntent {
    TreeEditIntent::Rename {
        from: path(from),
        to: path(to),
        basis_entry,
    }
}

pub(super) fn chmod(
    target: &str,
    basis_entry: Option<BasisEntry>,
    after: FileMode,
) -> TreeEditIntent {
    TreeEditIntent::Chmod {
        path: path(target),
        basis_entry,
        after,
    }
}

pub(super) fn write(target: &str, content: &[u8], mode: FileMode) -> TreeEditIntent {
    TreeEditIntent::Write {
        path: path(target),
        content: content.to_vec(),
        mode,
        entry_class: EntryClass::Content,
    }
}

pub(super) fn intents(entries: impl IntoIterator<Item = TreeEditIntent>) -> IntentLog {
    let mut log = IntentLog::new();
    for entry in entries {
        log.push(entry);
    }
    log
}

fn tree(entries: &[(&str, &str, GitOid)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (mode, name, oid) in entries {
        body.extend(mode.as_bytes());
        body.push(b' ');
        body.extend(name.as_bytes());
        body.push(0);
        body.extend(oid.as_bytes());
    }
    body
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(format, kind, body);
    let raw = [format!("{} {}\0", kind.label(), body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).expect("one stored DEFLATE block");
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1u32, 0u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = oid.to_string();
    let directory = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&hex[2..]), encoded).unwrap();
    oid
}

pub(super) struct Fixture {
    root: PathBuf,
    node: Option<OneNode>,
    pub(super) format: GitHashAlgorithm,
    pub(super) commit: GitOid,
    pub(super) root_tree: GitOid,
    pub(super) file: GitOid,
    pub(super) file_bytes: usize,
    pub(super) occupied: GitOid,
    pub(super) untouched: GitOid,
    keep: GitOid,
    link: GitOid,
    module: GitOid,
}

impl Fixture {
    pub(super) fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fgit-workspace-metadata-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        let body = b"immutable workspace source\n".repeat(1024);
        let file = loose(&source, format, GitObjectKind::Blob, &body);
        let occupied = loose(&source, format, GitObjectKind::Blob, b"previous destination\n");
        let keep = loose(&source, format, GitObjectKind::Blob, b"directory sibling\n");
        let untouched = loose(&source, format, GitObjectKind::Blob, b"root sibling\n");
        let link = loose(&source, format, GitObjectKind::Blob, b"src/tool.sh");
        // Gitlinks name another repository's commit and never grant traversal.
        let module = git_object_id(format, GitObjectKind::Commit, b"external repository");
        let src = loose(
            &source,
            format,
            GitObjectKind::Tree,
            &tree(&[("100644", "keep.txt", keep), ("100644", "tool.sh", file)]),
        );
        let dst = loose(
            &source,
            format,
            GitObjectKind::Tree,
            &tree(&[
                ("100644", "keep.txt", keep),
                ("100644", "occupied.sh", occupied),
            ]),
        );
        let root_tree = loose(
            &source,
            format,
            GitObjectKind::Tree,
            &tree(&[
                ("40000", "dst", dst),
                ("120000", "link", link),
                ("160000", "module", module),
                ("40000", "src", src),
                ("100644", "untouched.txt", untouched),
            ]),
        );
        let commit = loose(
            &source,
            format,
            GitObjectKind::Commit,
            format!(
                "tree {root_tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nworkspace source\n"
            )
            .as_bytes(),
        );
        fs::write(source.join("refs/heads/main"), format!("{commit}\n")).unwrap();
        let (mut node, _) = OneNode::init(
            NodeConfig::new(root.join("node"), TenantId::from_bytes([0xc1; 16]), REPOSITORY)
                .with_object_format(format)
                .with_worker_threads(2),
        )
        .unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        node.runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &source,
                PRINCIPAL,
                b"workspace-metadata-source",
            ))
            .unwrap();
        Self {
            root,
            node: Some(node),
            format,
            commit,
            root_tree,
            file,
            file_bytes: body.len(),
            occupied,
            untouched,
            keep,
            link,
            module,
        }
    }

    pub(super) fn node(&self) -> &OneNode {
        self.node.as_ref().unwrap()
    }

    pub(super) fn head(&self) -> RepositoryAuthorityHeadId {
        let node = self.node();
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(selected.snapshot().refs[&reference()], self.commit);
        selected.basis().id()
    }

    pub(super) fn original_basis(&self) -> BasisEntry {
        basis(self.file, FileMode::Regular)
    }

    /// Encode the expected tree independently of the workspace exporter.
    /// Destination files must be provided in Git's canonical name order.
    pub(super) fn expected_tree(
        &self,
        source: Option<(FileMode, GitOid)>,
        destination: &[(&str, FileMode, GitOid)],
    ) -> GitOid {
        let mut src_entries = vec![("100644", "keep.txt", self.keep)];
        if let Some((mode, oid)) = source {
            src_entries.push((mode_label(mode), "tool.sh", oid));
        }
        let src = git_object_id(self.format, GitObjectKind::Tree, &tree(&src_entries));
        let mut dst_entries = vec![("100644", "keep.txt", self.keep)];
        dst_entries.extend(
            destination
                .iter()
                .map(|(name, mode, oid)| (mode_label(*mode), *name, *oid)),
        );
        let dst = git_object_id(self.format, GitObjectKind::Tree, &tree(&dst_entries));
        git_object_id(
            self.format,
            GitObjectKind::Tree,
            &tree(&[
                ("40000", "dst", dst),
                ("120000", "link", self.link),
                ("160000", "module", self.module),
                ("40000", "src", src),
                ("100644", "untouched.txt", self.untouched),
            ]),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.node.take().unwrap().shutdown().unwrap();
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn mode_label(mode: FileMode) -> &'static str {
    match mode {
        FileMode::Regular => "100644",
        FileMode::Executable => "100755",
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ExportObservation {
    pub(super) tree: GitOid,
    pub(super) paths: Vec<TreePath>,
    pub(super) objects: BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>,
    pub(super) reused: usize,
}

pub(super) fn export(
    fixture: &Fixture,
    request: &NodeRequestContext,
    expected_commit: GitOid,
    capability: &mut TreeCapability,
    log: &IntentLog,
    limits: ExportLimits,
) -> Result<ExportObservation, NodeWorkspaceRefusal> {
    match fixture.format {
        GitHashAlgorithm::Sha1 => {
            export_as::<Sha1>(fixture, request, expected_commit, capability, log, limits)
        }
        GitHashAlgorithm::Sha256 => {
            export_as::<Sha256>(fixture, request, expected_commit, capability, log, limits)
        }
    }
}

fn export_as<A: HashAlgorithm>(
    fixture: &Fixture,
    request: &NodeRequestContext,
    expected_commit: GitOid,
    capability: &mut TreeCapability,
    log: &IntentLog,
    limits: ExportLimits,
) -> Result<ExportObservation, NodeWorkspaceRefusal> {
    let node = fixture.node();
    let result = node
        .runtime()
        .block_on(node.export_workspace_edits_in::<A>(
            request,
            &reference(),
            expected_commit,
            &RefVisibility::new(),
            capability,
            log,
            0,
            limits,
        ))?;
    assert!(result.plan.verify_all());
    assert_eq!(result.source_commit.erase(), fixture.commit);
    Ok(ExportObservation {
        tree: (*result.plan.root_tree()).erase(),
        paths: result.changed_paths,
        objects: result
            .plan
            .objects()
            .map(|object| ((*object.oid()).erase(), (object.kind(), object.body().to_vec())))
            .collect(),
        reused: result.plan.reused_base_objects(),
    })
}

pub(super) fn export_default(
    fixture: &Fixture,
    log: &IntentLog,
) -> Result<ExportObservation, NodeWorkspaceRefusal> {
    export(
        fixture,
        &fixture.node().request_context(),
        fixture.commit,
        &mut complete_capability(),
        log,
        ExportLimits::default(),
    )
}
