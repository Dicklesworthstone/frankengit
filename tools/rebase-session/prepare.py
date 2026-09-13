import json, os, pathlib, re, subprocess, tempfile
ROOT=pathlib.Path.cwd()
BASE='9f0e2d6f51849cba19a88417a616bdbfab8dcf19'
def git(*args,cwd=ROOT):return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-rebase-core-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
    guards={'crates/fgit-forge/src/preparation.rs':'eb0edadce06053475dbf93435852af6990043060',
        'crates/fgit-forge/src/preparation/replay.rs':'74dc17e42cdd92a148402dc034b2bd95a36f8ad6',
        'crates/fgit-forge/src/preparation/resolution.rs':'94f8acd0e9800a6bc158af885d8b631de26a1483'}
    for path,sha in guards.items():assert git('rev-parse',f'{BASE}:{path}')==sha
    def replace(path,old,new,count=1):
        p=work/path;t=p.read_text();assert t.count(old)==count,(path,old[:100],t.count(old));p.write_text(t.replace(old,new))
    p='crates/fgit-forge/src/preparation.rs'
    replace(p,'pub mod replay;','pub mod replay;\npub mod rebase;')
    for path in guards:
        replace(path,'objects: BTreeMap::new(), conflicts: Vec::new(), resolutions: BTreeMap::new(),','objects: BTreeMap::new(), trees: BTreeMap::new(), conflicts: Vec::new(), resolutions: BTreeMap::new(),')
    replace(p,'    objects: BTreeMap<GitOid, PlannedMergeObject>,','    objects: BTreeMap<GitOid, PlannedMergeObject>,\n    // Parsed metadata for our own generated trees; bounded by generation and\n    // tree-entry budgets. Never used as authority for original object reads.\n    trees: BTreeMap<GitOid, Vec<MergeEntry>>,')
    replace(p,"impl<S: MergeObjectSource> Planner<'_, S> {",'''impl<'a, S: MergeObjectSource> Planner<'a, S> {
    fn new(source: &'a S, format: GitHashAlgorithm, limits: PreparationLimits) -> Self {
        Self { source, format, limits, entries: 0, content_merges: 0, output_bytes: 0,
            objects: BTreeMap::new(), trees: BTreeMap::new(), conflicts: Vec::new(), resolutions: BTreeMap::new() }
    }

    fn blob(&self, id: GitOid) -> Result<Vec<u8>, PreparationError> {
        self.source.checkpoint()?;
        if let Some(object) = self.objects.get(&id) {
            if object.kind != GitObjectKind::Blob { return Err(PreparationError::InvalidTree); }
            return Ok(object.body.clone());
        }
        Ok(self.source.blob(id)?)
    }
''')
    replace(p,'        let entries = self.source.tree(id)?;','        let entries = match self.trees.get(&id) {\n            Some(entries) => entries.clone(),\n            None => self.source.tree(id)?,\n        };')
    replace(p,'        self.emit(GitObjectKind::Tree, body).map(Some)','        let id = self.emit(GitObjectKind::Tree, body)?;\n        self.trees.insert(id, result);\n        Ok(Some(id))')
    replace(p,'let b = match base { Some(b) => self.source.blob(b.oid)?, None => Vec::new() };','let b = match base { Some(b) => self.blob(b.oid)?, None => Vec::new() };')
    replace(p,'let o_bytes = self.source.blob(o.oid)?;','let o_bytes = self.blob(o.oid)?;')
    replace(p,'let t_bytes = self.source.blob(t.oid)?;','let t_bytes = self.blob(t.oid)?;')
    for source,target in [('rebase.rs','crates/fgit-forge/src/preparation/rebase.rs'),('tests.rs','crates/fgit-forge/src/preparation/rebase/tests.rs')]:
        dest=work/target;assert not dest.exists();dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((ROOT/'tools/rebase-session'/source).read_bytes())
        subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',str(dest)],cwd=work,check=True,timeout=180)
    paths=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    expected=set(guards)|{'crates/fgit-forge/src/preparation/rebase.rs','crates/fgit-forge/src/preparation/rebase/tests.rs'}
    assert paths==expected,paths
    git('diff','--check',cwd=work)
    # Context from the actual tracker and plan, not a fabricated ready-state.
    for line in (work/'.beads/issues.jsonl').read_text().splitlines():
        try:item=json.loads(line)
        except ValueError:continue
        if 'rebase' in (str(item.get('title',''))+' '+str(item.get('description',''))).lower():
            print('REBASE_BEAD',json.dumps(item)[:16000],flush=True)
    git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*sorted(expected),cwd=work)
    git('commit','-m','feat(rebase): replay a bounded commit series with shared native merge state','-m','Add linear-suffix selection, author/message/encoding preservation, explicit newly-empty behavior, original-empty retention and no-partial-candidate conflict stops. Reuse one existing path/content planner across the entire series; retain generated tree metadata and blob bytes for subsequent steps within the same budgets. Add native-identity fixtures for both hash domains, sequence budget boundaries, cancellation, malformed histories and metadata.',cwd=work)
    result=git('rev-parse','HEAD',cwd=work);branch='tooling/rebase-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',result+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+result+'\n')
    print('PRODUCT_SOURCE',result,branch,flush=True)
