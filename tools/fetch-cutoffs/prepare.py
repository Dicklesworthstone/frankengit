import os,pathlib,re,subprocess,tempfile
root=pathlib.Path.cwd();base='e55985db39808836824a672c96b61d857449d190'
def git(*args,cwd=root):return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-cutoffs-source-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),base)
    def edit(name,old,new,count=1):
        path=work/name;text=path.read_text();assert text.count(old)==count,(name,old[:80],text.count(old));path.write_text(text.replace(old,new))
    node='crates/fgit-node/src/'
    v=node+'upload_visibility.rs';s=node+'upload_visibility/shallow.rs';p=node+'upload_visibility/partial_clone.rs';w='crates/fgit-wire/src/lib.rs'
    assert git('rev-parse',f'{base}:{w}')=='2d194d7ac795d38e84dc9388bbbc244d4a7333cc'
    assert git('rev-parse',f'{base}:{p}')=='da3e424c450fe34c2c9fb9684ac3e145a4ac5150'
    # Adapt only pre-existing internal graph literal constructors. New metadata
    # is None in non-temporal fixtures; their existing behavior is unchanged.
    literals=[]
    for path in [work/v,*sorted((work/node/'upload_visibility').rglob('*.rs'))]:
        text=path.read_text();pattern=r'(?<!struct )FilterObject\s*\{'
        updated,count=re.subn(pattern,lambda m:m.group(0)+' commit_time: None,',text)
        if count:path.write_text(updated);literals.append((str(path.relative_to(work)),count))
    print('GRAPH_LITERAL_METADATA',literals,flush=True)
    edit(p,'    pub(super) kind: ObjectType,','    pub(super) kind: ObjectType,\n    pub(super) commit_time: Option<i64>,')
    edit(v,'        let edges = if kind == ObjectType::Blob {','        let mut commit_time = None;\n        let edges = if kind == ObjectType::Blob {')
    edit(v,'            let parsed = parsed.map_err(|_| disclosure_refusal(RefusalCode::ObjectHeaderInvalid))?;', '            let parsed = parsed.map_err(|_| disclosure_refusal(RefusalCode::ObjectHeaderInvalid))?;\n            commit_time = shallow::cutoffs::committer_time(&parsed);')
    edit(v,'FilterObject { commit_time: None,','FilterObject { commit_time,')
    edit(s,'mod relative;','mod relative;\npub(super) mod cutoffs;')
    edit(s,'''    if request.deepen_since.is_some() || !request.deepen_not.is_empty() {
        return Err(NodePackMaterializationRefusal::UnsupportedFetch(
            "time/ref shallow boundaries",
        ));
    }
''','')
    edit(s,'    let effective_depth = relative::effective_depth(objects, request, &old, work)?;', '    if cutoffs::requested(request) {\n        return cutoffs::history(objects, request, old, work);\n    }\n    let effective_depth = relative::effective_depth(objects, request, &old, work)?;')
    edit(node+'upload_visibility/shallow/tests.rs','"time/ref shallow boundaries"','"depth and time/ref cutoffs cannot be combined"')
    edit(w,'mod filter_syntax;','mod filter_syntax;\nmod cutoff_ref;')
    edit(w,'''            let name = parse_ref_name(rest, &self.limits)?;
            let oid = repository
                .resolve_ref(&name)
                .ok_or(WireError::UnknownDeepenNotRef { name })?;''','''            let oid = cutoff_ref::resolve(repository, rest, &self.limits)?;''',2)
    edit(node+'lib.rs','shallow deepen-relative filter include-tag','shallow deepen-relative deepen-since deepen-not filter include-tag')
    # Assertions compare the real advertised capability string; retain their
    # exact-byte requirement while adding the newly implemented capabilities.
    for path in sorted((work/node/'upload_visibility').rglob('*.rs')):
        text=path.read_text()
        if 'shallow deepen-relative filter' in text:
            path.write_text(text.replace('shallow deepen-relative filter','shallow deepen-relative deepen-since deepen-not filter'))
    for source,target in [('cutoffs.rs',node+'upload_visibility/shallow/cutoffs.rs'),('cutoff_ref.rs','crates/fgit-wire/src/cutoff_ref.rs')]:
        path=work/target;assert not path.exists();path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((root/'tools/fetch-cutoffs'/source).read_bytes())
    changed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    allowed={v,s,p,w,node+'lib.rs',node+'upload_visibility/shallow/tests.rs',node+'upload_visibility/tests/partial_clone.rs',node+'upload_visibility/shallow/cutoffs.rs','crates/fgit-wire/src/cutoff_ref.rs'}|{name for name,_ in literals}
    assert changed<=allowed,(changed-allowed)
    for name in sorted(changed):
        if name.endswith('.rs') and not name.endswith('/src/lib.rs'):
            subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',name],cwd=work,check=True,timeout=180)
    git('diff','--check',cwd=work);git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*sorted(changed),cwd=work)
    git('commit','-m','feat(fetch): implement native time and ref shallow cutoffs','-m','Derive bounded date metadata from already verified commit bytes. Resolve exclusion names only among advertised refs; reject ambiguity. Select revision boundaries using shared cancellable work accounting, preserve merge-wide parent cuts and old-boundary have semantics, and compose with existing partial-clone pack selection. Expose working legacy deepen-since/deepen-not capabilities. No new dependency or canonical schema.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work);branch='tooling/fetch-cutoffs-result-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as output:output.write('source='+source+'\n')
    print('PRODUCT_SOURCE',source,branch,'FILES',sorted(changed),flush=True)
