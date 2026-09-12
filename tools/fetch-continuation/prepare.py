import os,pathlib,subprocess,tempfile
ROOT=pathlib.Path.cwd();BASE='7de2c6cbcbb9334312d18180377b2602638531ad'
PATH='crates/fgit-node/src/upload_visibility/tests/partial_clone.rs'
def git(*args,cwd=ROOT):return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-relative-advertisement-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
    assert git('rev-parse',f'{BASE}:{PATH}')=='c7693cbddcc63f283e25aa3771f4671e76345791'
    path=work/PATH;text=path.read_text();old='b"allow-reachable-sha1-in-want shallow filter".as_slice()'
    assert text.count(old)==1
    path.write_text(text.replace(old,'b"allow-reachable-sha1-in-want shallow deepen-relative filter".as_slice()'))
    assert git('diff','--name-only',cwd=work)==PATH;git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',PATH,cwd=work)
    git('commit','-m','test(fetch): require the newly implemented relative-depth advertisement','-m','The broad native run passed 253 tests and failed only this old contiguous legacy-capability expectation. Update its exact expected byte string to include deepen-relative in the implemented position; retain all actual filtered-pack, lazy-read, visibility and retention assertions. Production source is byte-identical to 7de2c6cbcbb9334312d18180377b2602638531ad.',cwd=work)
    sha=git('rev-parse','HEAD',cwd=work);branch='tooling/fetch-progress-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',sha+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+sha+'\n')
    print('PRODUCT_SOURCE',sha,branch,flush=True)
