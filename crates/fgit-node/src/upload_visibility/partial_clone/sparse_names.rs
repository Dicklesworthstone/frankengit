//! Resolve bounded ref:path pattern names within the authenticated projection.
//!
//! Neither a revision-expression evaluator nor the object store participates:
//! refs are the current session's visible advertisement, and every traversed
//! edge/name came from the same native-verified graph used for want admission.

use fgit_types::RefName;
use fgit_wire::sparse::SparseLimits;

use super::{
    AdvertisedRef, BTreeMap, BTreeSet, FilterObject, GitOid, NodePackMaterializationRefusal,
    ObjectType, RefusalCode, Work, disclosure_refusal,
};
use crate::upload_visibility::WalkFacts;

fn expression(name: &[u8]) -> Option<(&[u8], &[u8])> {
    let separator = name.iter().position(|byte| *byte == b':')?;
    let (reference, suffix) = name.split_at(separator);
    let path = &suffix[1..];
    if RefName::try_new_one_level(reference).is_err()
        || path.is_empty()
        || path.len() > SparseLimits::default().max_path_bytes
        || path.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
        || path
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || matches!(component, b"." | b".."))
    {
        return None;
    }
    Some((reference, path))
}

/// Syntax-only preflight must not depend on whether a ref or path exists.
pub(super) fn supported(name: &[u8]) -> bool {
    expression(name).is_some()
}

fn unavailable() -> NodePackMaterializationRefusal {
    NodePackMaterializationRefusal::UnsupportedFetch(
        "sparse filter requires a visible ref:path blob",
    )
}

fn invalid() -> NodePackMaterializationRefusal {
    disclosure_refusal(RefusalCode::EvidenceInvalid)
}

fn matches_reference(advertised: &[u8], requested: &[u8]) -> bool {
    if requested == b"HEAD" || requested.starts_with(b"refs/") {
        advertised == requested
    } else {
        advertised.strip_prefix(b"refs/heads/") == Some(requested)
            || advertised.strip_prefix(b"refs/tags/") == Some(requested)
    }
}

pub(super) fn resolve(
    name: &[u8],
    objects: &BTreeMap<GitOid, FilterObject>,
    facts: &BTreeMap<GitOid, WalkFacts>,
    refs: &[AdvertisedRef],
    work: &mut Work<'_, impl FnMut() -> bool>,
) -> Result<GitOid, NodePackMaterializationRefusal> {
    let (reference, path) = expression(name).ok_or(
        NodePackMaterializationRefusal::UnsupportedFetch("sparse filters"),
    )?;
    let mut target = None;
    for advertised in refs {
        work.tick()?;
        if matches_reference(&advertised.name, reference) {
            // A short name shared by a branch and tag is ambiguous even when
            // both currently point to the same object. Require its full name.
            if target.replace(advertised.oid).is_some() {
                return Err(unavailable());
            }
        }
    }
    let mut target = target.ok_or_else(unavailable)?;
    let mut seen = BTreeSet::new();
    loop {
        work.tick()?;
        work.count(seen.len().saturating_add(1))?;
        if !seen.insert(target) {
            return Err(invalid());
        }
        let item = objects.get(&target).ok_or_else(unavailable)?;
        match item.kind {
            ObjectType::Tag => {
                let [(child, kind)] = item.edges.as_slice() else {
                    return Err(invalid());
                };
                work.tick()?;
                if objects.get(child).is_none_or(|object| object.kind != *kind) {
                    return Err(invalid());
                }
                target = *child;
            }
            ObjectType::Commit => {
                let mut tree = None;
                for &(child, kind) in &item.edges {
                    work.tick()?;
                    if kind == ObjectType::Tree && tree.replace(child).is_some() {
                        return Err(invalid());
                    }
                }
                target = tree.ok_or_else(invalid)?;
                if objects
                    .get(&target)
                    .is_none_or(|object| object.kind != ObjectType::Tree)
                {
                    return Err(invalid());
                }
                break;
            }
            ObjectType::Tree => break,
            ObjectType::Blob => return Err(unavailable()),
        }
    }
    for component in path.split(|byte| *byte == b'/') {
        work.tick()?;
        let item = objects.get(&target).ok_or_else(unavailable)?;
        if item.kind != ObjectType::Tree {
            return Err(unavailable());
        }
        let names = &facts.get(&target).ok_or_else(invalid)?.names;
        if names.len() != item.edges.len() {
            return Err(invalid());
        }
        let mut found = None;
        for (entry_name, &(child, kind)) in names.iter().zip(&item.edges) {
            work.tick()?;
            if entry_name == component {
                if found.replace(child).is_some()
                    || objects.get(&child).is_none_or(|object| object.kind != kind)
                {
                    return Err(invalid());
                }
            }
        }
        target = found.ok_or_else(unavailable)?;
    }
    work.tick()?;
    if objects
        .get(&target)
        .is_some_and(|object| object.kind == ObjectType::Blob)
    {
        Ok(target)
    } else {
        Err(unavailable())
    }
}
