import os, pathlib, subprocess, tempfile
ROOT=pathlib.Path.cwd()
BASE='845ea759d2ef2bf1f0f55b4ee0afaa6fc56bf203'
PATH='crates/fgit-node/src/quarantine_validator/typed_closure/tests/ref_roots.rs'
EXPECTED='3f3ca8dda2cfb04e418ed13db4314278ebd8d54a'
def git(*args,cwd=ROOT):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-ref-kind-fix-') as td:
    work=pathlib.Path(td)/'source'
    git('worktree','add','--detach',str(work),BASE)
    assert git('rev-parse',BASE+':'+PATH)==EXPECTED
    path=work/PATH
    text=path.read_text()
    old='.capabilities.push(b"atomic".to_vec());'
    new='.capabilities.push(fgit_wire::Capability::parse(b"atomic", &fgit_wire::WireLimits::default()).unwrap());'
    assert text.count(old)==2
    path.write_text(text.replace(old,new))
    assert git('diff','--name-only',cwd=work)==PATH
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',PATH,cwd=work)
    git('commit','-m','test(receive): construct native atomic capabilities in ref-root regressions (FG-019)','-m','Native all-target compilation found two Vec<u8> values where ReceiveRequest requires typed Capability values. Parse both through the production bounded capability parser. Keep every branch-kind, authorization, zero-staging and reopen assertion and all production code unchanged. Preserve the intervening source-browse implementation.',cwd=work)
    result=git('rev-parse','HEAD',cwd=work)
    assert git('diff','--name-only',BASE,result,cwd=work)==PATH
    assert not git('status','--porcelain',cwd=work)
    branch='tooling/ref-kind-fix-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',result+':refs/heads/'+branch,cwd=work)
    print('PRODUCT_COMMIT',result,branch,flush=True)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+result+'\n')
