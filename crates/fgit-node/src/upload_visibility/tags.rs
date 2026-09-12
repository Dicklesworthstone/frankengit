//! Annotated-tag projections derived only from the verified visible graph.
use super::*;

pub(crate) struct TagProjection {
    pub(super) peels: BTreeMap<GitOid, GitOid>,
    followers: BTreeMap<GitOid, Vec<GitOid>>,
}

impl TagProjection {
    pub(super) fn new(
        targets: &BTreeMap<GitOid, GitOid>,
        refs: &[AdvertisedRef],
        mut checkpoint: impl FnMut() -> Result<(), NodePackMaterializationRefusal>,
    ) -> Result<Self, NodePackMaterializationRefusal> {
        let mut peels = BTreeMap::new();
        for &root in targets.keys() {
            checkpoint()?;
            if peels.contains_key(&root) {
                continue;
            }
            let mut path = Vec::new();
            let mut visiting = BTreeSet::new();
            let mut current = root;
            let leaf = loop {
                checkpoint()?;
                if let Some(&leaf) = peels.get(&current) {
                    break leaf;
                }
                let Some(&target) = targets.get(&current) else {
                    break current;
                };
                if !visiting.insert(current) {
                    return Err(disclosure_refusal(RefusalCode::EvidenceInvalid));
                }
                path.push(current);
                current = target;
            };
            for tag in path.into_iter().rev() {
                checkpoint()?;
                peels.insert(tag, leaf);
            }
        }
        // Only current visible refs/tags roots authorize automatic tag following.
        // A stored or historically admitted tag pointing at a public commit
        // does not acquire a new route to disclosure here.
        let mut eligible = BTreeSet::new();
        let mut followers = BTreeMap::<GitOid, Vec<GitOid>>::new();
        for reference in refs
            .iter()
            .filter(|reference| reference.name.starts_with(b"refs/tags/"))
        {
            let mut tag = reference.oid;
            while let Some(&target) = targets.get(&tag) {
                checkpoint()?;
                if !eligible.insert(tag) {
                    break;
                }
                followers.entry(target).or_default().push(tag);
                tag = target;
            }
        }
        for tags in followers.values_mut() {
            tags.sort_unstable();
        }
        checkpoint()?;
        Ok(Self { peels, followers })
    }

    pub(crate) fn extend_selected(
        &self,
        ids: &mut Vec<GitOid>,
        limits: &PackLimits,
        is_live: &mut impl FnMut() -> bool,
    ) -> Result<(), NodePackMaterializationRefusal> {
        let maximum = usize::try_from(limits.max_entries).unwrap_or(usize::MAX);
        let checkpoint = |is_live: &mut dyn FnMut() -> bool| {
            if is_live() {
                Ok(())
            } else {
                Err(NodePackMaterializationRefusal::from(PackWriteError::from(
                    PackError::DeadlineExceeded,
                )))
            }
        };
        checkpoint(is_live)?;
        if ids.len() > maximum {
            return Err(entry_limit_error(ids.len(), limits).into());
        }
        let mut selected: BTreeSet<_> = ids.iter().copied().collect();
        let mut frontier = selected.clone();
        while let Some(target) = frontier.pop_first() {
            checkpoint(is_live)?;
            for &tag in self.followers.get(&target).into_iter().flatten() {
                checkpoint(is_live)?;
                if selected.contains(&tag) {
                    continue;
                }
                if selected.len() == maximum {
                    return Err(entry_limit_error(selected.len().saturating_add(1), limits).into());
                }
                selected.insert(tag);
                frontier.insert(tag);
            }
        }
        let mut result = Vec::new();
        result.try_reserve_exact(selected.len()).map_err(|_| {
            PackWriteError::from(PackError::AllocationFailed {
                requested: selected.len(),
            })
        })?;
        result.extend(selected);
        checkpoint(is_live)?;
        // Publish the expanded selection only after the complete bounded walk.
        *ids = result;
        Ok(())
    }
}

/// Expand only legacy advertisements. Protocol v2 uses the peeled attribute,
/// never synthesized refs with a ^{} suffix in the repository's actual view.
pub(crate) fn legacy_advertised_refs(
    repository: &impl UploadPackRepository,
    limits: &WireLimits,
) -> Result<Vec<AdvertisedRef>, WireError> {
    let references = repository.advertised_refs();
    if references.len() > limits.max_advertised_refs {
        return Err(WireError::TooManyAdvertisedRefs {
            limit: limits.max_advertised_refs,
        });
    }
    let existing: BTreeSet<&[u8]> = references
        .iter()
        .map(|reference| reference.name.as_slice())
        .collect();
    let mut output = Vec::new();
    output
        .try_reserve_exact(references.len())
        .map_err(|_| WireError::AllocationFailure)?;
    let mut append = |reference: AdvertisedRef| -> Result<(), WireError> {
        if output.len() == limits.max_advertised_refs {
            return Err(WireError::TooManyAdvertisedRefs {
                limit: limits.max_advertised_refs,
            });
        }
        output
            .try_reserve(1)
            .map_err(|_| WireError::AllocationFailure)?;
        output.push(reference);
        Ok(())
    };
    for reference in references {
        append(reference.clone())?;
        if !reference.name.starts_with(b"refs/") || reference.name.ends_with(b"^{}") {
            continue;
        }
        let Some(target) = repository.peeled(reference.oid) else {
            continue;
        };
        let length = reference
            .name
            .len()
            .checked_add(3)
            .ok_or(WireError::AllocationFailure)?;
        let mut name = Vec::new();
        name.try_reserve_exact(length)
            .map_err(|_| WireError::AllocationFailure)?;
        name.extend_from_slice(&reference.name);
        name.extend_from_slice(b"^{}");
        if !existing.contains(name.as_slice()) {
            append(AdvertisedRef::new(target, &name, limits)?)?;
        }
    }
    output.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
        GitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
    }
    #[test]
    fn nested_peels_follow_only_visible_tag_roots_and_obey_atomic_bounds() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let [leaf, inner, outer, unrelated] = [1, 2, 3, 4].map(|byte| oid(format, byte));
            let refs = vec![
                AdvertisedRef::new(outer, b"refs/tags/release", &WireLimits::default()).unwrap(),
            ];
            let projection = TagProjection::new(
                &BTreeMap::from([(inner, leaf), (outer, inner), (unrelated, leaf)]),
                &refs,
                || Ok(()),
            )
            .unwrap();
            assert_eq!(projection.peels.get(&outer), Some(&leaf));
            let mut ids = vec![leaf];
            projection
                .extend_selected(
                    &mut ids,
                    &PackLimits {
                        max_entries: 3,
                        ..PackLimits::default()
                    },
                    &mut || true,
                )
                .unwrap();
            assert_eq!(ids, vec![leaf, inner, outer]);
            assert!(!ids.contains(&unrelated));
            let mut bounded = vec![leaf];
            assert!(
                projection
                    .extend_selected(
                        &mut bounded,
                        &PackLimits {
                            max_entries: 2,
                            ..PackLimits::default()
                        },
                        &mut || true
                    )
                    .is_err()
            );
            assert_eq!(
                bounded,
                vec![leaf],
                "failed expansion never publishes a partial selected set"
            );
            assert!(
                projection
                    .extend_selected(&mut bounded, &PackLimits::default(), &mut || false)
                    .is_err()
            );
            assert_eq!(bounded, vec![leaf]);
        }
    }
    #[test]
    fn cyclic_or_cancelled_tag_metadata_never_produces_a_projection() {
        let a = oid(GitHashAlgorithm::Sha1, 1);
        let b = oid(GitHashAlgorithm::Sha1, 2);
        assert!(matches!(
            TagProjection::new(&BTreeMap::from([(a, b), (b, a)]), &[], || Ok(())),
            Err(NodePackMaterializationRefusal::DisclosureGraph(
                RefusalCode::EvidenceInvalid
            ))
        ));
        assert!(
            TagProjection::new(&BTreeMap::from([(a, b)]), &[], || Err(disclosure_refusal(
                RefusalCode::CancellationInProgress
            )))
            .is_err()
        );
    }
}

/// Negotiation must use the same expanded advertisement the legacy client saw.
/// In particular, a peeled target in a tag-only repository is an advertised
/// legacy want, not an exception to the unadvertised-ancestor restriction.
pub(crate) struct LegacyTagRepository<'a, R: UploadPackRepository> {
    source: &'a R,
    refs: Vec<AdvertisedRef>,
}
impl<'a, R: UploadPackRepository> LegacyTagRepository<'a, R> {
    pub(crate) fn new(source: &'a R, limits: &WireLimits) -> Result<Self, WireError> {
        Ok(Self {
            source,
            refs: legacy_advertised_refs(source, limits)?,
        })
    }
}
impl<R: UploadPackRepository> UploadPackRepository for LegacyTagRepository<'_, R> {
    fn object_format(&self) -> GitHashAlgorithm {
        self.source.object_format()
    }
    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }
    fn contains_want(&self, oid: AnyGitOid) -> bool {
        self.source.contains_want(oid)
    }
    fn is_common(&self, oid: AnyGitOid) -> bool {
        self.source.is_common(oid)
    }
    fn supports_shallow(&self) -> bool {
        self.source.supports_shallow()
    }
    fn shallow_update(
        &self,
        request: &PackRequest,
    ) -> Result<fgit_wire::closure::ShallowUpdate, WireError> {
        self.source.shallow_update(request)
    }
    fn symref_target(&self, name: &[u8]) -> Option<&[u8]> {
        self.source.symref_target(name)
    }
    fn unborn_symref_target(&self) -> Option<&[u8]> {
        self.source.unborn_symref_target()
    }
    fn peeled(&self, oid: AnyGitOid) -> Option<AnyGitOid> {
        self.source.peeled(oid)
    }
}
