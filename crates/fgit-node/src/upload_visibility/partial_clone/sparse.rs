//! Sparse blob omission over one authenticated visible graph.
//!
//! Pattern objects are not new traversal roots. All requested pattern identities
//! are checked against the existing graph before the first body read. Tree names
//! came from the same verified bodies; a path-dependent walk revisits shared
//! subtrees without retaining complete paths or consulting physical storage.

use fgit_wire::sparse::{SparseError, SparseLimits, SparsePatterns};

use super::{
    BTreeMap, BTreeSet, FilterObject, GitOid, NodePackMaterializationRefusal, ObjectType,
    PackLimits, PatternLoader, RefusalCode, Work, disclosure_refusal, object,
};
use crate::upload_visibility::WalkFacts;

const MAX_DOCUMENTS: usize = 32;

fn budget() -> NodePackMaterializationRefusal {
    disclosure_refusal(RefusalCode::ResourceBudgetExceeded)
}

fn invalid() -> NodePackMaterializationRefusal {
    disclosure_refusal(RefusalCode::EvidenceInvalid)
}

fn pattern_refusal(
    error: SparseError<NodePackMaterializationRefusal>,
) -> NodePackMaterializationRefusal {
    match error {
        SparseError::Checkpoint(error) => error,
        SparseError::Limit(_) => budget(),
        SparseError::Unsupported { feature, .. } => {
            NodePackMaterializationRefusal::UnsupportedFetch(feature)
        }
        SparseError::InvalidPath => invalid(),
    }
}

pub(super) fn select(
    objects: &BTreeMap<GitOid, FilterObject>,
    facts: &BTreeMap<GitOid, WalkFacts>,
    selected: &BTreeSet<GitOid>,
    explicit: &BTreeSet<GitOid>,
    patterns: &BTreeSet<GitOid>,
    limits: &PackLimits,
    load_pattern: &mut PatternLoader<'_>,
    work: &mut Work<'_, impl FnMut() -> bool>,
) -> Result<Option<BTreeSet<GitOid>>, NodePackMaterializationRefusal> {
    if patterns.is_empty() {
        return Ok(None);
    }
    if patterns.len() > MAX_DOCUMENTS {
        return Err(budget());
    }
    let defaults = SparseLimits::default();
    let maximum_bytes = defaults
        .max_blob_bytes
        .min(limits.max_object_bytes)
        .min(limits.max_total_expanded_bytes);
    let mut total_bytes = 0_usize;
    // Validate the complete request before a body-capable source is called.
    // Unknown, foreign and hidden IDs all take the same non-disclosing refusal.
    for id in patterns {
        work.tick()?;
        let Some(item) = objects.get(id).filter(|item| item.kind == ObjectType::Blob) else {
            return Err(NodePackMaterializationRefusal::UnsupportedFetch(
                "sparse filter requires a visible blob OID",
            ));
        };
        total_bytes = total_bytes.checked_add(item.size).ok_or_else(budget)?;
        if total_bytes > maximum_bytes {
            return Err(budget());
        }
    }
    let roots = roots(objects, selected, explicit, work)?;
    let mut intersection: Option<BTreeSet<GitOid>> = None;
    let mut patterns_left = defaults.max_patterns;
    for &id in patterns {
        work.tick()?;
        let loaded = load_pattern(id, maximum_bytes);
        work.tick()?;
        let (kind, body) = loaded?;
        if kind != ObjectType::Blob || body.len() != object(objects, id)?.size {
            return Err(invalid());
        }
        let pattern_limits = SparseLimits {
            max_blob_bytes: maximum_bytes,
            max_patterns: patterns_left,
            ..defaults
        };
        let compiled = SparsePatterns::compile(&body, pattern_limits, &mut || work.tick())
            .map_err(pattern_refusal)?;
        patterns_left = patterns_left
            .checked_sub(compiled.pattern_count())
            .ok_or_else(budget)?;
        let matches = walk(
            objects,
            facts,
            selected,
            &roots,
            &compiled,
            defaults.max_path_bytes,
            work,
        )?;
        if let Some(previous) = &mut intersection {
            let mut retained = BTreeSet::new();
            for &id in previous.iter() {
                work.tick()?;
                if matches.contains(&id) {
                    retained.insert(id);
                }
            }
            *previous = retained;
        } else {
            intersection = Some(matches);
        }
    }
    work.tick()?;
    Ok(intersection)
}

fn roots(
    objects: &BTreeMap<GitOid, FilterObject>,
    selected: &BTreeSet<GitOid>,
    explicit: &BTreeSet<GitOid>,
    work: &mut Work<'_, impl FnMut() -> bool>,
) -> Result<BTreeSet<GitOid>, NodePackMaterializationRefusal> {
    let mut roots = BTreeSet::new();
    let mut seen_tags = BTreeSet::new();
    for &id in selected {
        work.tick()?;
        let item = object(objects, id)?;
        match item.kind {
            ObjectType::Commit => {
                for &(child, kind) in &item.edges {
                    work.tick()?;
                    if kind == ObjectType::Tree && selected.contains(&child) {
                        roots.insert(child);
                    }
                }
            }
            ObjectType::Tree if explicit.contains(&id) => {
                roots.insert(id);
            }
            ObjectType::Tag => {
                let mut target = id;
                loop {
                    work.tick()?;
                    let item = object(objects, target)?;
                    if item.kind != ObjectType::Tag {
                        if item.kind == ObjectType::Tree && selected.contains(&target) {
                            roots.insert(target);
                        }
                        break;
                    }
                    if !seen_tags.insert(target) {
                        break;
                    }
                    let [(child, _)] = item.edges.as_slice() else {
                        return Err(invalid());
                    };
                    target = *child;
                }
            }
            _ => {}
        }
        work.count(roots.len())?;
    }
    Ok(roots)
}

struct Frame {
    tree: GitOid,
    next: usize,
    path_bytes: usize,
    inherited: bool,
}

fn walk(
    objects: &BTreeMap<GitOid, FilterObject>,
    facts: &BTreeMap<GitOid, WalkFacts>,
    selected: &BTreeSet<GitOid>,
    roots: &BTreeSet<GitOid>,
    patterns: &SparsePatterns,
    max_path_bytes: usize,
    work: &mut Work<'_, impl FnMut() -> bool>,
) -> Result<BTreeSet<GitOid>, NodePackMaterializationRefusal> {
    let mut matched = BTreeSet::new();
    let mut path = Vec::new();
    let mut stack = Vec::new();
    for &root in roots {
        work.tick()?;
        path.clear();
        stack.try_reserve(1).map_err(|_| budget())?;
        stack.push(Frame {
            tree: root,
            next: 0,
            path_bytes: 0,
            inherited: patterns.root_included(),
        });
        while let Some(frame) = stack.last_mut() {
            work.tick()?;
            let item = object(objects, frame.tree)?;
            let names = &facts.get(&frame.tree).ok_or_else(invalid)?.names;
            if item.kind != ObjectType::Tree || item.edges.len() != names.len() {
                return Err(invalid());
            }
            path.truncate(frame.path_bytes);
            if frame.next == item.edges.len() {
                stack.pop();
                continue;
            }
            let (child, kind) = item.edges[frame.next];
            let name = &names[frame.next];
            frame.next += 1;
            if !selected.contains(&child) {
                continue;
            }
            if !matches!(kind, ObjectType::Tree | ObjectType::Blob)
                || name.is_empty()
                || name.contains(&b'/')
            {
                return Err(invalid());
            }
            let extra = name
                .len()
                .checked_add(usize::from(!path.is_empty()))
                .ok_or_else(budget)?;
            if path.len().checked_add(extra).ok_or_else(budget)? > max_path_bytes {
                return Err(budget());
            }
            path.try_reserve(extra).map_err(|_| budget())?;
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name);
            let included = patterns
                .matches_entry(
                    &path,
                    kind == ObjectType::Tree,
                    frame.inherited,
                    &mut || work.tick(),
                )
                .map_err(pattern_refusal)?;
            if kind == ObjectType::Tree {
                work.count(stack.len().checked_add(1).ok_or_else(budget)?)?;
                stack.try_reserve(1).map_err(|_| budget())?;
                stack.push(Frame {
                    tree: child,
                    next: 0,
                    path_bytes: path.len(),
                    inherited: included,
                });
            } else if included {
                work.count(
                    matched
                        .len()
                        .saturating_add(usize::from(!matched.contains(&child))),
                )?;
                matched.insert(child);
            }
        }
    }
    work.tick()?;
    Ok(matched)
}
