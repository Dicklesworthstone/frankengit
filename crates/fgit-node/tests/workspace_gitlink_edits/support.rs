//! Independent expected-tree oracle shared by native gitlink integration tests.

use std::collections::BTreeMap;

use fgit_crypto::{
    GitHashAlgorithm as HashAlgorithm, GitObjectKind, NativeObjectIdentity, Sha1, Sha256,
    git_object_id,
};
use fgit_node::{NodeRequestContext, NodeWorkspaceRefusal};
use fgit_treefs::{ExportLimits, IntentLog, TreeCapability, TreeEditIntent};
use fgit_types::{GitHashAlgorithm, GitOid};
use fgit_wire::visibility::RefVisibility;

use super::fixture::{ExportObservation, Fixture, path, reference};

pub(super) const FORMATS: [GitHashAlgorithm; 2] =
    [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];

pub(super) fn pointer(format: GitHashAlgorithm, label: &[u8]) -> GitOid {
    // Deliberately absent from the parent node. A successful operation cannot
    // depend on fetching, parsing or inheriting access to this foreign object.
    git_object_id(format, GitObjectKind::Commit, label)
}

pub(super) fn original_pointer(fixture: &Fixture) -> GitOid {
    pointer(fixture.format, b"external repository")
}

pub(super) fn update(target: &str, oid: GitOid) -> TreeEditIntent {
    TreeEditIntent::UpdateSubmodule {
        path: path(target),
        after_oid: oid.as_bytes().to_vec(),
    }
}

pub(super) fn delete(target: &str) -> TreeEditIntent {
    TreeEditIntent::Delete { path: path(target) }
}

pub(super) fn export_gitlinks(
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
        .block_on(node.export_workspace_gitlink_edits_in::<A>(
            request,
            &reference(),
            expected_commit,
            &RefVisibility::new(),
            capability,
            log,
            0,
            limits,
        ))?;
    Ok(ExportObservation {
        tree: (*result.plan.root_tree()).erase(),
        paths: result.changed_paths,
        objects: result
            .plan
            .objects()
            .map(|object| {
                (
                    (*object.oid()).erase(),
                    (object.kind(), object.body().to_vec()),
                )
            })
            .collect(),
        reused: result.plan.reused_base_objects(),
    })
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

/// Construct Git tree bytes independently of the production parser/exporter.
/// Every untouched sibling and original entry mode participates in the result.
pub(super) fn expected_tree(
    fixture: &Fixture,
    edits: &[(&str, Option<(&'static str, GitOid)>)],
) -> GitOid {
    let keep = git_object_id(fixture.format, GitObjectKind::Blob, b"directory sibling\n");
    let link = git_object_id(fixture.format, GitObjectKind::Blob, b"src/tool.sh");
    let mut leaves: BTreeMap<String, (&'static str, GitOid)> = [
        ("dst/keep.txt", ("100644", keep)),
        ("dst/occupied.sh", ("100644", fixture.occupied)),
        ("link", ("120000", link)),
        ("module", ("160000", original_pointer(fixture))),
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
            assert!(!child.contains('/'), "bounded independent fixture oracle");
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
