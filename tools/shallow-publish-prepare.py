import os, pathlib, subprocess, tempfile
root=pathlib.Path.cwd()
base='9736155637c00ba051962f739a922aee1ac66ab6'
wire='crates/fgit-wire/src/lib.rs'
test='crates/fgit-wire/tests/v2_ref_prefixes.rs'
def git(*args,cwd=root):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-shallow-product-') as td:
    work=pathlib.Path(td)/'source'
    git('worktree','add','--detach',str(work),base)
    assert git('rev-parse',f'{base}:{wire}')=='9319ad6e80c8e10aedbee35220b4367ad9c0c52d'
    assert git('rev-parse',f'{base}:{test}')=='139abe4194f9b3c188803ebb04d4bbbb532e09be'
    path=work/wire;text=path.read_text()
    old='''        self.ref_prefixes.clear();
        self.ls_refs = LsRefsOptions::default();
        self.state = V2State::AwaitCommand;'''
    new='''        self.ref_prefixes.clear();
        self.ls_refs = LsRefsOptions::default();
        self.request_capabilities = Capabilities::default();
        self.state = V2State::AwaitCommand;'''
    assert text.count(old)==1
    path.write_text(text.replace(old,new))
    path=work/test
    path.write_bytes(path.read_bytes()+(root/'tools/shallow-capability-reset-test.rs').read_bytes())
    subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',test],cwd=work,check=True,timeout=180)
    assert set(git('diff','--name-only',cwd=work).splitlines())=={wire,test}
    assert not git('ls-files','--others','--exclude-standard',cwd=work)
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',wire,test,cwd=work)
    git('commit','-m','fix(wire): scope v2 client capabilities to each completed command','-m','The new repeated-command regression at 9736155637c00ba051962f739a922aee1ac66ab6 exposed capabilities retained after ls-refs: a second command correctly specifying object-format was falsely rejected as duplicate. Clear only completed command capability state together with existing prefix/attribute state, after the bounded response succeeds. Keep duplicates inside one command refused and add an explicit same-command refusal/new-command acceptance regression. Existing native and boundary assertions remain unchanged.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work)
    assert set(git('diff','--name-only',base,source,cwd=work).splitlines())=={wire,test}
    branch='tooling/shallow-complete-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as output: output.write('source='+source+'\n')
    print('PRODUCT_SOURCE',source,branch,flush=True)
