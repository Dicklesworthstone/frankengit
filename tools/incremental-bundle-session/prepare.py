import json, os, pathlib, subprocess, tempfile
ROOT=pathlib.Path.cwd()
BASE='6f111e9d3f4491853f0fd9d20be0cf4ef675b47a'
ORIGINAL='5a84924788fc00c014e77080469342ec0a595e00'
PRODUCT='84b704b534d45a2d5e144fb163a0058d48bf8e60'
LIB='crates/fgit-node/src/lib.rs'
NODE='crates/fgit-node/src/treefs_workspace/full_bundle.rs'
def git(*args,cwd=ROOT):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
def body(ref,path):return subprocess.check_output(['git','show',ref+':'+path],cwd=ROOT)
def oid(ref,path):
    p=subprocess.run(['git','rev-parse','--verify',ref+':'+path],cwd=ROOT,text=True,capture_output=True)
    return p.stdout.strip() if p.returncode==0 else None
paths=set(git('diff','--name-only',ORIGINAL,PRODUCT).splitlines())-{LIB}
assert len(paths)==14
for path in paths-{NODE}:assert oid(BASE,path)==oid(ORIGINAL,path),(path,oid(BASE,path),oid(ORIGINAL,path))
# Retain the concurrently committed implementation of the shared byte/edge
# adapter, including its blob fast path. Do not overwrite its lib.rs changes.
current=body(BASE,NODE).decode()
start=current.index('/// The ordinary selected-pack source intentionally omits closure hints')
end=current.index('impl OneNode {',start)
adapter=current[start:end]
assert adapter.count('struct BundleObjectSource')==1 and '.references_from_body(kind, &body)' in adapter
with tempfile.TemporaryDirectory(prefix='fg-incremental-reconciled-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
    for name in paths:
        path=work/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body(PRODUCT,name))
        if name.endswith('.sh'):path.chmod(0o755)
    path=work/NODE;text=path.read_text()
    marker='\n// Bundle writers verify closure independently from the selected-ID traversal.'
    assert text.count(marker)==1
    text,discarded=text.split(marker)
    assert discarded.count('struct BundleObjectSource')==1 and discarded.rstrip().endswith('}')
    old='    BundleReference, Deadline, PackPlanner, PackWriteProfile, PackWriter, QuarantinedPack,'
    new='    BundleReference, CanonicalObjectSource, CanonicalPackObject, Deadline, PackPlanner,\n    PackWriteError, PackWriteProfile, PackWriter, QuarantinedPack,'
    assert text.count(old)==1 and text.count('impl OneNode {')==1
    text=text.replace(old,new).replace('impl OneNode {',adapter+'impl OneNode {')
    assert text.count('struct BundleObjectSource')==1
    assert 'object_references_from_body' not in text
    path.write_text(text)
    assert (work/LIB).read_bytes()==body(BASE,LIB)
    changed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    assert changed==paths,changed
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    results={'core':'5a84924788fc00c014e77080469342ec0a595e00'}
    for label,group,title in [
      ('node',sorted(p for p in changed if p.startswith('crates/fgit-node/')),'feat(node): synchronize incremental bundles through prerequisite-scoped admission'),
      ('cli',sorted(p for p in changed if not p.startswith('crates/fgit-node/')),'feat(cli): expose incremental bundle synchronization with explicit old-tip leases')]:
        before=git('rev-parse','HEAD',cwd=work)
        git('add','--',*group,cwd=work)
        git('commit','-m',title,'-m','Reuse the original bundle engine and shared native edge adapter, retaining concurrent full-export, mapped-fetch and cancellation work. Borrow only complete declared-prerequisite history visible at the selected head; validate exact old-tip leases and publish through ordinary atomic admission and mandatory review protection. Bound original-input, pack and graph work. Preserve legacy command and advertisement limits. Native verification is separately recorded, not asserted by this commit.',cwd=work)
        sha=git('rev-parse','HEAD',cwd=work);assert set(git('diff','--name-only',before,sha,cwd=work).splitlines())==set(group)
        branch='tooling/incremental-bundle-'+label+'-'+os.environ['GITHUB_SHA'][:12]
        git('push','origin',sha+':refs/heads/'+branch,cwd=work);results[label]=sha
        print('PRODUCT_COMMIT',label,sha,branch,flush=True)
    assert not git('status','--porcelain',cwd=work)
    print('PRODUCT_FILES',json.dumps({p:git('rev-parse','HEAD:'+p,cwd=work) for p in sorted(changed)}),flush=True)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:
        for label,sha in results.items():out.write(label+'='+sha+'\n')
        out.write('source='+results['cli']+'\n')
