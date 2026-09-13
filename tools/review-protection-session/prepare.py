import bz2, hashlib, json, os, pathlib, re, subprocess, tempfile
ROOT=pathlib.Path.cwd()
BASE='968865466a81babae250e3a55d2505395ddd1afa'
ORIGINAL='09ab8325931e82c3e43b3cc7aa7897eb3676f7e0'
PATCH_SHA='dfd88f0ea05f1372870d7b4a11353ce8bc0d765ab9ad8cc9aac55d0ffa34bb49'
def git(*args,cwd=ROOT):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
def oid(ref,path):
    result=subprocess.run(['git','rev-parse','--verify',f'{ref}:{path}'],cwd=ROOT,text=True,capture_output=True)
    return result.stdout.strip() if result.returncode==0 else None
payload=pathlib.Path(__file__).resolve().parent
packed=b''.join((payload/f'part{i}').read_bytes() for i in range(5))
patch=bz2.decompress(packed)
assert len(patch)==117351 and hashlib.sha256(patch).hexdigest()==PATCH_SHA
paths=[]
for a,b in re.findall(rb'^diff --git a/([^\n ]+) b/([^\n ]+)$',patch,re.M):
    assert a==b
    path=a.decode('ascii')
    assert not pathlib.PurePosixPath(path).is_absolute() and '..' not in pathlib.PurePosixPath(path).parts
    assert oid(BASE,path)==oid(ORIGINAL,path),(path,oid(BASE,path),oid(ORIGINAL,path))
    paths.append(path)
assert len(paths)==26 and len(set(paths))==26
subprocess.run(['git','merge-base','--is-ancestor',ORIGINAL,BASE],check=True)
with tempfile.TemporaryDirectory(prefix='fg-review-product-') as td:
    work=pathlib.Path(td)/'source';patch_path=pathlib.Path(td)/'review.patch';patch_path.write_bytes(patch)
    git('worktree','add','--detach',str(work),BASE)
    subprocess.run(['git','apply','--check','--whitespace=error',str(patch_path)],cwd=work,check=True)
    subprocess.run(['git','apply','--whitespace=error',str(patch_path)],cwd=work,check=True)
    observed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    assert observed==set(paths),observed
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    groups=[('core',[p for p in paths if p.startswith(('crates/fgit-forge/','crates/fgit-reference/','crates/fgit-txn/','crates/fgit-admission/'))],'feat(protection): publish administrator-owned exact-review policies (FG-043r)'),('node',[p for p in paths if p.startswith('crates/fgit-node/')],'feat(node): enforce mandatory review policy across publication routes (FG-043r)'),('cli',[p for p in paths if p.startswith(('crates/fgit-cli/','docs/','scripts/'))],'feat(cli): administer mandatory review protection with recoverable receipts (FG-043r)')]
    assert set(p for _,group,_ in groups for p in group)==set(paths)
    outputs={}
    for label,group,title in groups:
        before=git('rev-parse','HEAD',cwd=work)
        git('add','--',*group,cwd=work)
        git('commit','-m',title,'-m','Recover the complete saved implementation with exact-original-file guards. Policy administration and enforcement use the existing forge frontier, sealed identity, authority-head CAS and exact-candidate review gate. Preserve concurrent rebase work, existing native domains and dependencies. Native verification is recorded by a separate read-only job; no passing gate or bead closure is claimed by this commit.',cwd=work)
        sha=git('rev-parse','HEAD',cwd=work)
        assert set(git('diff','--name-only',before,sha,cwd=work).splitlines())==set(group)
        branch='tooling/review-protection-'+label+'-'+os.environ['GITHUB_SHA'][:12]
        git('push','origin',sha+':refs/heads/'+branch,cwd=work)
        outputs[label]=sha
        print('PRODUCT_COMMIT',label,sha,branch,flush=True)
    assert not git('status','--porcelain',cwd=work)
    print('PRODUCT_FILES',json.dumps({p:git('rev-parse','HEAD:'+p,cwd=work) for p in paths}),flush=True)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:
        for label,sha in outputs.items():out.write(f'{label}={sha}\n')
        out.write('source='+outputs['cli']+'\n')
