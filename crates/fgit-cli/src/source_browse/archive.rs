//! Complete read-only source archives through the existing verified node reader.
//! All directory pages and file ranges share one authority/source pin. A tar file
//! is a derived export, not a repository capsule or a new publication authority.
mod tar;

use super::{Options, collect_file, emit, head_token, hex, optional_hex, quote};
use super::{NodeConfig, OneNode, SourceBrowseAction, SourceBrowseContent, SourceBrowseQuery};
use super::{SourceBrowseReport, SourceEntryKind, publish_new_bundle, require_absent};
use fgit_types::{GitOid, HeadGeneration, RepositoryAuthorityHeadId, RepositoryCommitId};
use std::path::Path;

const MAX_ENTRIES: usize = 100_000;
const MAX_READS: usize = 200_000;
const MAX_DEPTH: usize = 64;
const MAX_PATH_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pin {
    head: RepositoryAuthorityHeadId,
    rcr: RepositoryCommitId,
    commit: GitOid,
    tree: GitOid,
}

struct Selection {
    pin: Option<Pin>,
    root: Option<GitOid>,
    reads: usize,
}
impl Selection {
    fn query(&self, options: &Options, path: Option<Vec<u8>>, action: SourceBrowseAction) -> SourceBrowseQuery {
        SourceBrowseQuery {
            path,
            expected_head: self.pin.map(|pin| pin.head).or(options.query.expected_head),
            expected_commit: self.pin.map(|pin| pin.commit).or(options.query.expected_commit),
            action,
        }
    }

    fn read(
        &mut self,
        options: &Options,
        query: &SourceBrowseQuery,
        expected_object: Option<GitOid>,
        reader: &mut impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, String>,
    ) -> Result<SourceBrowseReport, String> {
        if self.reads >= MAX_READS {
            return Err("source archive exceeds the total read budget".into());
        }
        self.reads += 1;
        let report = reader(query)?;
        let observed = Pin {
            head: report.source_head,
            rcr: report.source_rcr,
            commit: report.source_commit,
            tree: report.root_tree,
        };
        if report.repository_id != options.repository || report.path != query.path
            || self.pin.is_some_and(|pin| pin != observed)
            || query.expected_head.is_some_and(|head| head != report.source_head)
            || query.expected_commit.is_some_and(|commit| commit != report.source_commit)
            || expected_object.is_some_and(|object| object != report.object_id)
            || [report.source_commit, report.root_tree, report.object_id].iter()
                .any(|oid| oid.is_zero() || oid.algorithm() != options.format)
            || (query.path.is_none() && report.object_id != report.root_tree)
        {
            return Err("source archive snapshot, path or parent-selected object changed".into());
        }
        if self.pin.is_none() {
            self.pin = Some(observed);
            self.root = Some(report.object_id);
        }
        Ok(report)
    }
}

struct Task {
    source: Option<Vec<u8>>,
    path: Vec<u8>,
    object: Option<GitOid>,
    kind: SourceEntryKind,
    depth: usize,
}

struct Archive {
    pin: Pin,
    root: GitOid,
    bytes: Vec<u8>,
    entries: usize,
    gitlinks: usize,
    reads: usize,
}

fn complete_query(options: &Options) -> Result<u16, String> {
    match &options.query.action {
        SourceBrowseAction::List { after: None, limit } if (1..=1000).contains(limit) => Ok(*limit),
        _ => Err("tree --output requires a complete directory, without --after-hex".into()),
    }
}

fn collect(
    options: &Options,
    mut reader: impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, String>,
) -> Result<Archive, String> {
    let limit = complete_query(options)?;
    let mut selection = Selection { pin: None, root: None, reads: 0 };
    let mut stack = vec![Task {
        source: options.query.path.clone(), path: b"source".to_vec(),
        object: None, kind: SourceEntryKind::Directory, depth: 0,
    }];
    let mut output = tar::Tar::default();
    let mut entries = 1_usize;
    let mut path_bytes = 0_usize;
    let mut gitlinks = 0_usize;
    while let Some(task) = stack.pop() {
        match task.kind {
            SourceEntryKind::Directory => {
                let mut after = None;
                let mut object = task.object;
                let mut children = Vec::new();
                loop {
                    let query = selection.query(options, task.source.clone(), SourceBrowseAction::List { after: after.clone(), limit });
                    let report = selection.read(options, &query, object, &mut reader)?;
                    object = Some(report.object_id);
                    let SourceBrowseContent::Directory { entries: page, next_after } = report.content else {
                        return Err("source archive expected a directory selected by its parent".into());
                    };
                    if page.len() > usize::from(limit) {
                        return Err("source archive directory exceeded its requested page size".into());
                    }
                    let mut previous = after.clone();
                    for child in page.iter() {
                        tar::validate_component(&child.name)?;
                        if previous.as_ref().is_some_and(|name| *name >= child.name)
                            || child.oid.is_zero() || child.oid.algorithm() != options.format
                        {
                            return Err("source archive directory is unordered or has invalid identities".into());
                        }
                        previous = Some(child.name.clone());
                        let mut path = task.path.clone();
                        path.push(b'/');
                        path.extend_from_slice(&child.name);
                        let mut source = task.source.clone().unwrap_or_default();
                        if !source.is_empty() { source.push(b'/'); }
                        source.extend_from_slice(&child.name);
                        if path.len() > 256 || source.len() > 4096 || task.depth >= MAX_DEPTH {
                            return Err("source archive path or depth exceeds the bounded profile".into());
                        }
                        entries = entries.checked_add(1).filter(|count| *count <= MAX_ENTRIES)
                            .ok_or("source archive exceeds 100000 entries")?;
                        path_bytes = path_bytes.checked_add(path.len()).and_then(|n| n.checked_add(source.len()))
                            .filter(|n| *n <= MAX_PATH_BYTES).ok_or("source archive exceeds its path-byte budget")?;
                        children.try_reserve(1).map_err(|_| "cannot allocate archive traversal")?;
                        children.push(Task { source: Some(source), path, object: Some(child.oid), kind: child.kind, depth: task.depth + 1 });
                    }
                    if let Some(next) = next_after {
                        if page.len() != usize::from(limit) || previous.as_ref() != Some(&next)
                            || after.as_ref().is_some_and(|old| *old >= next)
                        {
                            return Err("source archive directory cursor did not advance exactly".into());
                        }
                        after = Some(next);
                    } else {
                        break;
                    }
                }
                output.append(&task.path, task.kind, b"")?;
                // Depth-first order is independent of directory page size. Each
                // directory precedes its children; raw names retain byte order.
                stack.try_reserve(children.len()).map_err(|_| "cannot allocate archive traversal")?;
                stack.extend(children.into_iter().rev());
            }
            SourceEntryKind::Gitlink => {
                // A gitlink belongs to another repository. Do not clone, fetch,
                // reinterpret its OID as a blob, or delegate our credentials.
                output.append(&task.path, task.kind, b"")?;
                gitlinks += 1;
            }
            kind => {
                let query = selection.query(options, task.source, SourceBrowseAction::Read { offset: 0, limit: 1024 * 1024 });
                let file_options = Options {
                    storage: options.storage.clone(), tenant: options.tenant, repository: options.repository,
                    reference: options.reference.clone(), format: options.format, query,
                };
                let remaining = output.remaining_payload() as u64;
                let file = collect_file(&file_options, |query| {
                    let report = selection.read(options, query, task.object, &mut reader)?;
                    match &report.content {
                        SourceBrowseContent::Blob { kind: observed, total_bytes, .. }
                            if *observed == kind && *total_bytes <= remaining => {}
                        _ => return Err("source archive file kind changed or its payload exceeds the remaining budget".into()),
                    }
                    Ok(report)
                })?;
                output.append(&task.path, kind, &file.bytes)?;
            }
        }
    }
    Ok(Archive {
        pin: selection.pin.ok_or("source archive has no authenticated source")?,
        root: selection.root.ok_or("source archive has no selected tree")?,
        bytes: output.finish()?, entries, gitlinks, reads: selection.reads,
    })
}

fn after_shutdown(result: Result<Archive, String>, cleanup: Option<String>) -> Result<Archive, String> {
    match (result, cleanup) {
        (Ok(archive), None) => Ok(archive),
        (result, cleanup) => Err(format!("no source archive published{}{}",
            result.err().map_or_else(String::new, |error| format!("; read: {error}")),
            cleanup.map_or_else(String::new, |error| format!("; shutdown: {error}")))),
    }
}

pub(super) fn export_tree(options: &Options, destination: &Path) -> Result<u8, String> {
    complete_query(options)?;
    require_absent(destination)?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    ).map_err(|error| format!("cannot open source archive node: {error}"))?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        // One request owns the complete traversal, rather than resetting its
        // budget for every directory or file range.
        let request = fgit_cli::command_request_context(&node);
        collect(options, |query| node.runtime()
            .block_on(node.browse_source_local_in(&request, &options.reference, query))
            .map_err(|error| error.to_string()))
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let archive = after_shutdown(result, cleanup)?;
    publish_new_bundle(destination, &archive.bytes)?;
    let receipt = format!(concat!(
        "{{\"type\":\"source_tree_export\",\"schema_version\":1,\"profile\":\"ustar-source-v1\",",
        "\"tenant_id\":{},\"repository_id\":{},\"reference_hex\":{},\"object_format\":{},",
        "\"source_head\":{},\"snapshot_token\":{},\"source_rcr\":{},\"source_commit\":{},",
        "\"root_tree\":{},\"selected_tree\":{},\"path_hex\":{},\"archive_prefix\":\"source/\",",
        "\"bytes_written\":{},\"entries\":{},\"gitlink_directories\":{},\"reads\":{},",
        "\"output_created\":true,\"node_closed\":true,\"repository_changed\":false,",
        "\"symlink_followed\":false,\"submodules_materialized\":false,\"git_attributes_applied\":false}}"
    ), quote(&options.tenant.to_string()), quote(&options.repository.to_string()),
        quote(&hex(options.reference.as_bytes())), quote(options.format.as_str()),
        quote(&archive.pin.head.to_string()), quote(&head_token(archive.pin.head)),
        quote(&archive.pin.rcr.to_string()), quote(&archive.pin.commit.to_string()),
        quote(&archive.pin.tree.to_string()), quote(&archive.root.to_string()),
        optional_hex(options.query.path.as_deref()), archive.bytes.len(), archive.entries,
        archive.gitlinks, archive.reads);
    emit(&mut std::io::stdout().lock(), &receipt)
        .map_err(|error| format!("complete source archive was created, but receipt failed: {error}"))?;
    Ok(0)
}

#[cfg(test)]
mod tests;
