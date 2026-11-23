//! Resolve one selected source ref namespace into an immutable import snapshot.
//!
//! Packed refs, loose overrides and the chosen worktree's private refs must all
//! be selected before resolution. Targets are names in that map, never paths to
//! read. The resulting aliases are independent direct refs in the destination;
//! this does not add symbolic-ref authority or change the destination's HEAD.

use super::{BTreeMap, GitOid, ImportControl, LooseGitImportRefusal, Path, PathBuf, RefName};

pub(super) const MAX_SYMBOLIC_REF_DEPTH: usize = 32;

#[derive(Debug)]
pub(super) enum SourceRef {
    Direct(GitOid),
    Symbolic { target: RefName, path: PathBuf },
}

pub(super) fn resolve(
    refs: &BTreeMap<RefName, SourceRef>,
    control: &ImportControl<'_>,
) -> Result<BTreeMap<RefName, GitOid>, LooseGitImportRefusal> {
    // Memoize both identity and remaining depth. Remembering only identity
    // would let a long chain bypass the hop limit when its tail sorts first.
    let mut resolved = BTreeMap::<RefName, (GitOid, usize)>::new();
    for name in refs.keys() {
        control.checkpoint()?;
        if resolved.contains_key(name) {
            continue;
        }
        let mut chain: [Option<(&RefName, &Path)>; MAX_SYMBOLIC_REF_DEPTH] =
            [None; MAX_SYMBOLIC_REF_DEPTH];
        let mut length = 0usize;
        let mut current = name;
        let (identity, mut depth) = loop {
            control.checkpoint()?;
            if let Some(result) = resolved.get(current) {
                break *result;
            }
            match refs.get(current) {
                Some(SourceRef::Direct(identity)) => {
                    resolved.insert(current.clone(), (*identity, 0));
                    break (*identity, 0);
                }
                Some(SourceRef::Symbolic { target, path }) => {
                    if chain[..length]
                        .iter()
                        .flatten()
                        .any(|(visited, _)| *visited == current)
                    {
                        return Err(LooseGitImportRefusal::SymbolicRefCycle(Box::new(
                            path.clone(),
                        )));
                    }
                    if length == MAX_SYMBOLIC_REF_DEPTH {
                        return Err(LooseGitImportRefusal::SymbolicRefDepthExceeded {
                            path: Box::new(path.clone()),
                            limit: MAX_SYMBOLIC_REF_DEPTH,
                        });
                    }
                    chain[length] = Some((current, path.as_path()));
                    length += 1;
                    current = target;
                }
                None => {
                    // Only an alias can lead outside the selected map: the
                    // outer loop itself visits its existing keys exclusively.
                    let path = chain[..length]
                        .last()
                        .and_then(|step| *step)
                        .map_or_else(PathBuf::new, |(_, path)| path.to_path_buf());
                    return Err(LooseGitImportRefusal::SymbolicRefTargetMissing {
                        path: Box::new(path),
                        target: current.clone(),
                    });
                }
            }
        };
        for (alias, path) in chain[..length].iter().rev().flatten() {
            control.checkpoint()?;
            depth += 1;
            if depth > MAX_SYMBOLIC_REF_DEPTH {
                return Err(LooseGitImportRefusal::SymbolicRefDepthExceeded {
                    path: Box::new(path.to_path_buf()),
                    limit: MAX_SYMBOLIC_REF_DEPTH,
                });
            }
            resolved.insert((*alias).clone(), (identity, depth));
        }
    }
    let mut snapshot = BTreeMap::new();
    for (name, (identity, _)) in resolved {
        control.checkpoint()?;
        snapshot.insert(name, identity);
    }
    control.checkpoint()?;
    Ok(snapshot)
}
