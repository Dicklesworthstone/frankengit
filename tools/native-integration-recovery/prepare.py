import os, pathlib, subprocess, tempfile
root=pathlib.Path.cwd()
base='06c70c5682ffa143ea7cb9334fb41b6496130d1b'
path='crates/fgit-reference/src/intent.rs'
def git(*args,cwd=root):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-native-recovery-') as td:
    work=pathlib.Path(td)/'source'
    git('worktree','add','--detach',str(work),base)
    assert git('rev-parse',f'{base}:{path}')=='f743866a55a9d0f4cb924c010f8ec09ee3131fae'
    target=work/path
    text=target.read_text()
    old='''    /// The complete decision and subject are bound by the actual event batch.
    /// Issue lifecycle or discussion changed; detailed action/text are sealed in its event batch.
    IssueChanged { issue: ForgeEntityId },
    PullRequestReviewed {'''
    new='''    /// The complete decision and subject are bound by the actual event batch.
    PullRequestReviewed {'''
    assert text.count(old)==1 and text.count('    IssueChanged { issue: ForgeEntityId },')==2
    target.write_text(text.replace(old,new))
    assert git('diff','--name-only',cwd=work)==path
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',path,cwd=work)
    git('commit','-m','fix(reference): remove duplicate issue intent without reordering existing variants','-m','Restore a single IssueChanged variant after PullRequestReviewed. A duplicated insertion before reviews made the canonical intent enum uncompilable and disturbed its documented append-only ordering. Retain the complete issue event and both existing match arms; do not replace the issue functionality or change canonical encoding.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work)
    branch='tooling/native-integration-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
    print('PRODUCT_SOURCE',source,branch,flush=True)
