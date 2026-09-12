//! Resolve relative depth inside the same verified graph and work ledger.
use super::*;

pub(super) const INFINITE_DEPTH: u32 = 2_147_483_647;

pub(super) fn effective_depth(
    objects: &BTreeMap<GitOid, FilterObject>,
    request: &PackRequest,
    old: &BTreeSet<GitOid>,
    work: &mut Work<'_, impl FnMut() -> bool>,
) -> Result<Option<u32>, NodePackMaterializationRefusal> {
    if !request.options.deepen_relative() { return Ok(request.deepen); }
    let Some(increment @ 1..=INFINITE_DEPTH) = request.deepen else {
        return Err(NodePackMaterializationRefusal::UnsupportedFetch("relative deepening requires a positive bounded depth"));
    };
    if request.deepen_since.is_some() || !request.deepen_not.is_empty() {
        return Err(NodePackMaterializationRefusal::UnsupportedFetch("relative deepening cannot combine time/ref boundaries"));
    }
    if increment == INFINITE_DEPTH { return Ok(Some(INFINITE_DEPTH)); }
    // Git 2.54.0 uses the nearest reachable client boundary's generation
    // from the wanted tips, then adds the requested increment. It does NOT
    // advance every supplied marker independently. Unknown markers were
    // removed by the parent; no storage lookup or new authority occurs here.
    let mut depths = BTreeMap::new();
    let mut pending = BTreeSet::new();
    if !old.is_empty() {
        for &id in &request.wants { enqueue(&mut depths, &mut pending, id, 1, work)?; }
    }
    let mut offset = 0;
    while let Some((depth, id)) = pending.pop_first() {
        work.tick()?;
        if depths.get(&id) != Some(&depth) { continue; }
        let item = object(objects, id)?;
        match item.kind {
            ObjectType::Commit => {
                if old.contains(&id) { offset = depth; break; }
                let next = depth.checked_add(1).ok_or_else(budget)?;
                for &(parent, kind) in &item.edges {
                    work.tick()?;
                    if kind == ObjectType::Commit { enqueue(&mut depths, &mut pending, parent, next, work)?; }
                }
            }
            ObjectType::Tag => {
                let [(target, _)] = item.edges.as_slice() else {
                    return Err(disclosure_refusal(RefusalCode::EvidenceInvalid));
                };
                enqueue(&mut depths, &mut pending, *target, depth, work)?;
            }
            ObjectType::Tree | ObjectType::Blob => {}
        }
    }
    work.tick()?;
    let depth = increment.checked_add(offset).filter(|depth| *depth <= INFINITE_DEPTH).ok_or_else(budget)?;
    Ok(Some(depth))
}
