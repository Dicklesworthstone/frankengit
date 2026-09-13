import os,pathlib,subprocess,tempfile
ROOT=pathlib.Path.cwd();BASE='d28f41ded65312d6adbfbafe785881d1870580d6';PATH='crates/fgit-forge/src/preparation/rebase/tests.rs'
def git(*args,cwd=ROOT):return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-rebase-test-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
    assert git('rev-parse',f'{BASE}:{PATH}')=='44f4b89c965f3d3edff8de09363eacc02e1b1720'
    path=work/PATH;text=path.read_text()
    assert text.count('fn commit(&mut self,')==1 and text.count('fn tree(&mut self,')==1
    text=text.replace('fn commit(&mut self,','fn store_commit(&mut self,').replace('source.commit(','source.store_commit(')
    text=text.replace('fn tree(&mut self,','fn store_tree(&mut self,').replace('self.tree(bytes)','self.store_tree(bytes)')
    path.write_text(text)
    assert git('diff','--name-only',cwd=work)==PATH;git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',PATH,cwd=work);git('commit','-m','test(rebase): distinguish fixture writers from native source readers',cwd=work)
    result=git('rev-parse','HEAD',cwd=work);branch='tooling/rebase-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',result+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+result+'\n')
    print('PRODUCT_SOURCE',result,branch,flush=True)
