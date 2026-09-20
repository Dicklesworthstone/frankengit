//! Complete, bounded native TreeFS enumeration. These are temporary builder
//! inputs, not storage or a caller-supplied claim of tree completeness.
use std::collections::BTreeMap;
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, NativeObjectIdentity};
use fgit_treefs::{BaseEntry, BaseError, BaseView, ObjectSource, TreeCapability, TreePath};
use fgit_types::{GitHashAlgorithm as Format, GitOid};
use super::super::{LocalSearch, SearchCompletion, SearchError, SearchLimits, SourceQuery, SourceSearchReport};

pub(super) struct Document {
    pub path: Vec<u8>,
    pub blob: GitOid,
    pub bytes: Vec<u8>,
}
pub(super) struct Inventory {
    pub source: SourceSearchReport,
    pub documents: Vec<Document>,
}
pub(super) struct InventoryRequest(pub SourceQuery);

fn check(cancelled: &dyn Fn() -> bool) -> Result<(), SearchError> {
    if cancelled() { Err(SearchError::Cancelled) } else { Ok(()) }
}
fn native<A: GitHashAlgorithm>(oid: &fgit_crypto::GitOid<A>) -> Result<GitOid, SearchError> {
    let format = match A::DIGEST_LEN {
        20 => Format::Sha1, 32 => Format::Sha256,
        _ => return Err(SearchError::InvalidObjectFormat),
    };
    let hex: String = oid.digest_bytes().iter().map(|b| format!("{b:02x}")).collect();
    GitOid::from_hex(format, &hex).map_err(|_| SearchError::InvalidObjectFormat)
}
struct Discovery<A: GitHashAlgorithm> {
    files: BTreeMap<TreePath, fgit_crypto::GitOid<A>>,
    entries: usize,
    path_bytes: usize,
    excluded: usize,
}
impl LocalSearch for InventoryRequest {
    type Report = Inventory;
    fn scope(&self) -> &SourceQuery { &self.0 }
    fn empty(&self, source: SourceSearchReport) -> Inventory {
        Inventory { source, documents: Vec::new() }
    }
    fn run<A: GitHashAlgorithm, S: ObjectSource<A>>(&self,
        base: &BaseView<A>, source: &S, capability: &mut TreeCapability, now: u64,
        limits: SearchLimits, cancelled: &dyn Fn() -> bool,
    ) -> Result<Inventory, SearchError> {
        limits.validate()?;
        check(cancelled)?;
        capability.authorize_root(now).map_err(SearchError::Capability)?;
        let mut discovery = Discovery { files: BTreeMap::new(), entries: 0, path_bytes: 0, excluded: 0 };
        discover(base, source, capability, now, limits, cancelled, None, 0, &mut discovery)?;
        let mut inventory = self.empty(SourceSearchReport {
            repository: base.repository_id(), source_rcr: base.base_rcr_id(),
            source_commit: native(base.base_commit_oid())?, source_tree: native(base.base_tree_oid())?,
            matches: Vec::new(), completion: SearchCompletion::Complete,
            files_selected: discovery.files.len(), files_read: 0, bytes_read: 0,
            bytes_searched: 0, non_regular_entries: discovery.excluded,
        });
        for (path, blob) in discovery.files {
            check(cancelled)?;
            let grant = capability.authorize_read(&path, now).map_err(SearchError::Capability)?;
            let body = base.read_object(source, &blob, GitObjectKind::Blob, &grant)
                .map_err(|error| SearchError::Source(Box::new(error)))?;
            check(cancelled)?;
            capability.charge_fetch(body.len() as u64).map_err(SearchError::Capability)?;
            if body.len() > limits.max_file_bytes { return Err(SearchError::Budget("index file bytes")); }
            inventory.source.bytes_read = inventory.source.bytes_read.checked_add(body.len())
                .filter(|n| *n <= limits.max_total_bytes).ok_or(SearchError::Budget("index source bytes"))?;
            inventory.source.files_read += 1;
            inventory.documents.push(Document { path: path.as_bytes().to_vec(), blob: native(&blob)?, bytes: body });
        }
        check(cancelled)?;
        inventory.documents.sort_unstable_by(|a, b| a.path.cmp(&b.path));
        check(cancelled)?;
        Ok(inventory)
    }
}

#[expect(clippy::too_many_arguments, reason = "one capability and one shared discovery budget span recursive tree traversal")]
fn discover<A: GitHashAlgorithm, S: ObjectSource<A>>(
    base: &BaseView<A>, source: &S, capability: &mut TreeCapability, now: u64,
    limits: SearchLimits, cancelled: &dyn Fn() -> bool, directory: Option<&TreePath>,
    depth: usize, found: &mut Discovery<A>,
) -> Result<(), SearchError> {
    check(cancelled)?;
    if depth > limits.max_depth { return Err(SearchError::Budget("index tree depth")); }
    let children = base.list(source, capability, directory, now)
        .map_err(|error| SearchError::Base(Box::new(error)))?;
    for (name, entry) in children {
        check(cancelled)?;
        found.entries += 1;
        if found.entries > limits.max_entries { return Err(SearchError::Budget("index tree entries")); }
        let path = match directory {
            Some(parent) => parent.join(&name, base.path_policy()),
            None => TreePath::parse(&name, base.path_policy()),
        }.map_err(|error| SearchError::Base(Box::new(BaseError::Path(error))))?;
        match entry {
            BaseEntry::Directory { .. } => {
                discover(base, source, capability, now, limits, cancelled, Some(&path), depth + 1, found)?;
            }
            BaseEntry::File { oid, mode } => {
                if mode != b"100644" && mode != b"100755" {
                    return Err(SearchError::Budget("unsupported index file mode"));
                }
                // The local selector grants every root of this exact tree.
                // Never claim completeness after silently excluding a file.
                if !capability.admits_disclosure(&path) {
                    return Err(SearchError::Budget("incomplete index scope"));
                }
                if found.files.len() == limits.max_files { return Err(SearchError::Budget("index files")); }
                found.path_bytes = found.path_bytes.checked_add(path.as_bytes().len())
                    .filter(|n| *n <= 8 * 1024 * 1024).ok_or(SearchError::Budget("index path bytes"))?;
                if found.files.insert(path, oid).is_some() { return Err(SearchError::Budget("duplicate index path")); }
            }
            BaseEntry::Symlink { .. } | BaseEntry::Submodule { .. } => found.excluded += 1,
        }
    }
    Ok(())
}
