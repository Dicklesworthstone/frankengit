import os,pathlib,subprocess,tempfile
ROOT=pathlib.Path.cwd();BASE='7e92a29b03b832712ae4f0b4aec6395fa02a135e';SOURCE='5cef75af0b81438b39ef36398aaf8d78e6e7c8fc';ORIGINAL='7ab59dc11d542e26f34dc861a84cbe184ab251dc'
def git(*args,cwd=ROOT):return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
paths={'crates/fgit-node/src/treefs_workspace/merge_prepare.rs','crates/fgit-node/src/treefs_workspace/rebase.rs','crates/fgit-node/src/treefs_workspace/rebase/tests.rs','crates/fgit-cli/src/main.rs','crates/fgit-cli/src/commit_replay.rs','crates/fgit-cli/src/rebase.rs'}
with tempfile.TemporaryDirectory(prefix='fg-rebase-merge-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
    assert set(git('diff','--name-only',ORIGINAL,SOURCE).splitlines())==paths
    concurrent=set(git('diff','--name-only',ORIGINAL,BASE).splitlines())
    assert concurrent=={'crates/fgit-cli/src/branches.rs','crates/fgit-cli/src/branches/options.rs','crates/fgit-cli/src/main.rs'},concurrent
    main='crates/fgit-cli/src/main.rs'
    for path in sorted(paths-{main}):
        p=work/path
        try:old=git('rev-parse',ORIGINAL+':'+path)
        except subprocess.CalledProcessError:old=None
        if old is None:assert not p.exists(),path
        else:assert git('rev-parse',BASE+':'+path)==old,path
        content=subprocess.check_output(['git','show',SOURCE+':'+path]);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(content)
    p=work/main;original=p.read_text();text=original
    anchor='mod commit_replay;';assert text.count(anchor)==1;text=text.replace(anchor,anchor+'\nmod rebase;')
    anchor='    if arguments.first().is_some_and(|argument| argument == "issue") {'
    insertion='''    if arguments.first().is_some_and(|argument| argument == "rebase") {
        return match rebase::run(&arguments[1..]) {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
'''
    assert text.count(anchor)==1;text=text.replace(anchor,insertion+anchor)
    assert text.replace('mod rebase;\n','').replace(insertion,'')==original
    p.write_text(text)
    changed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    assert changed==paths,changed
    git('diff','--check',cwd=work);git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*sorted(paths),cwd=work)
    tree=git('write-tree',cwd=work)
    code=git('commit-tree',tree,'-p',BASE,'-p',SOURCE,'-m','feat(rebase): integrate authenticated bundles and CLI without losing concurrent branch commands',cwd=work)
    git('update-ref','HEAD',code,cwd=work)
    assert not git('status','--porcelain',cwd=work)
    print('PRODUCT_CODE',code,flush=True)
    doc='docs/NATIVE_LINEAR_REBASE.md';p=work/doc;assert not p.exists();p.write_bytes((ROOT/'tools/rebase-session/guide.md').read_bytes())
    git('add','--',doc,cwd=work);git('commit','-m','docs(rebase): document exact-input linear replay, complete bundles and separate publication',cwd=work)
    result=git('rev-parse','HEAD',cwd=work);branch='tooling/rebase-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',result+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+result+'\n')
    print('PRODUCT_SOURCE',result,branch,flush=True)
