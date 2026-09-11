import pathlib,sys
root=pathlib.Path.cwd(); payload=pathlib.Path(sys.argv[1])
def replace(path,old,new):
    p=root/path; text=p.read_text(); assert text.count(old)==1,(path,old[:100],text.count(old)); p.write_text(text.replace(old,new))
v='crates/fgit-node/src/upload_visibility.rs'
replace(v,'pub(super) mod tags;','pub(super) mod tags;\nmod partial_clone;')
replace(v,'    pub(super) tags: tags::TagProjection,','    pub(super) tags: tags::TagProjection,\n    objects: BTreeMap<GitOid, partial_clone::FilterObject>,')
replace(v,'            repository,\n            tags,','            repository,\n            tags,\n            objects: graph.objects,')
replace(v,'    tag_targets: BTreeMap<GitOid, GitOid>,\n}', '    tag_targets: BTreeMap<GitOid, GitOid>,\n    objects: BTreeMap<GitOid, partial_clone::FilterObject>,\n}')
replace(v,'    let mut tag_targets = BTreeMap::new();','    let mut tag_targets = BTreeMap::new();\n    let mut objects = BTreeMap::new();')
replace(v,'        for (child, expected) in edges {','        for &(child, expected) in &edges {')
replace(v,'''                &mut pending,
            )?;
        }
    }
    source.checkpoint()?;
    Ok(VisibleGraph { closure: PermittedObjectClosure::new(known.into_keys().collect()), tag_targets })''','''                &mut pending,
            )?;
        }
        objects.insert(id, partial_clone::FilterObject { kind, size: body.len(), edges });
    }
    source.checkpoint()?;
    Ok(VisibleGraph { closure: PermittedObjectClosure::new(known.into_keys().collect()), tag_targets, objects })''')
replace(v,'impl VisibleUploadPack {','''impl VisibleUploadPack {
    pub(super) fn select_partial(
        &self, ids: &mut Vec<GitOid>, request: &PackRequest,
        limits: &PackLimits, live: &mut impl FnMut() -> bool,
    ) -> Result<(), NodePackMaterializationRefusal> {
        partial_clone::apply_selection(&self.objects, ids, request, limits, live)
    }
''')
p='crates/fgit-node/src/lib.rs'
replace(p,'pub enum NodePackMaterializationRefusal {','pub enum NodePackMaterializationRefusal {\n    /// A parsed fetch control has no implemented production pack semantics.\n    UnsupportedFetch(&\'static str),')
replace(p,'            Self::DisclosureGraph(code) => write!(', '            Self::UnsupportedFetch(feature) => write!(formatter, "unsupported fetch feature: {feature}"),\n            Self::DisclosureGraph(code) => write!(')
replace(p,'            Self::DisclosureGraph(_)\n', '            Self::UnsupportedFetch(_)\n            | Self::DisclosureGraph(_)\n')
replace(p,'        include_tags: Option<&upload_visibility::VisibleUploadPack>,','        fetch: Option<(&upload_visibility::VisibleUploadPack, &PackRequest)>,')
replace(p,'''        if let Some(scope) = include_tags {
            scope.closure_for(materialized)?;
            scope.tags.extend_selected(&mut ids, &limits, is_live)?;
        }''','''        if let Some((scope, request)) = fetch {
            scope.closure_for(materialized)?;
            scope.select_partial(&mut ids, request, &limits, is_live)?;
            if request.options.include_tag() {
                scope.tags.extend_selected(&mut ids, &limits, is_live)?;
            }
        }''')
replace(p,'                        pack_request.options.include_tag().then_some(&disclosure),','                        Some((&disclosure, pack_request)),')
text=(root/p).read_text(); old='include-tag side-band-64k agent=frankengit-node'; assert text.count(old)>=5
(root/p).write_text(text.replace(old,'allow-reachable-sha1-in-want filter include-tag side-band-64k agent=frankengit-node'))
replace(p,'''            request,
            repository,
            limits,
            session_deadline,
            build_pack,
        );''','''            request,
            repository,
            capabilities.contains(b"filter"),
            limits,
            session_deadline,
            build_pack,
        );''')
text=(root/p).read_text(); start=text.index('fn serve_v2_upload_pack_after_greeting<'); end=text.index('    limits: WireLimits,',start); text=text[:end]+'    supports_filter: bool,\n'+text[end:]; (root/p).write_text(text)
replace(p,'        Packet::Data(b"fetch\\n".to_vec()),','        Packet::Data(if supports_filter { b"fetch=filter\\n".to_vec() } else { b"fetch\\n".to_vec() }),')
t='crates/fgit-node/src/upload_visibility/tests.rs'
text=(root/t).read_text(); start=text.index('            if version != 2 {\n                // Legacy wants remain advertisement-bound:'); end=text.index('            assert!(\n                matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),\n                "v2 visible historical commit remains fetchable:',start)
text=text[:start]+text[end:]; text=text.replace('"v2 visible historical commit remains fetchable:', '"negotiated reachable historical commit remains fetchable:'); (root/t).write_text(text)
path=root/'crates/fgit-node/src/upload_visibility/partial_clone.rs'; assert not path.exists(); path.write_text((payload/'partial_clone.rs').read_text())
print('Production filter controls now drive exact selected objects, after current disclosure and before include-tag and native pack planning')
