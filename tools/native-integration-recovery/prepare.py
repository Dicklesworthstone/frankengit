import os, pathlib, subprocess, tempfile
root=pathlib.Path.cwd()
base='f9bc63561b3666c90b0b3ba0cd29cb42c24e0ebf'
path='crates/fgit-txn/src/lib.rs'
tests='crates/fgit-txn/src/issue_normal_form_tests.rs'
def git(*args,cwd=root):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-native-recovery-') as td:
    work=pathlib.Path(td)/'source'
    git('worktree','add','--detach',str(work),base)
    assert git('rev-parse',f'{base}:{path}')=='08e094352c7c752065ef4080eae45279a6b8b5dd'
    target=work/path;text=target.read_text()
    old='''        ForgeEventKind::PullRequestReviewed { review, target } => {
            out.write_raw_byte(5);
            out.write_text("ForgeEntityId", review.label().as_str())?;
            out.write_ref_name(target)?;
        }
'''
    new=old+'''        ForgeEventKind::IssueChanged { issue } => {
            out.write_raw_byte(6);
            out.write_text("ForgeEntityId", issue.label().as_str())?;
        }
'''
    anchor='''#[cfg(test)]
mod tests {
    use super::*;
'''
    assert text.count(old)==1 and text.count(anchor)==1
    target.write_text(text.replace(old,new).replace(anchor,anchor+'    include!("issue_normal_form_tests.rs");\n'))
    assert not (work/tests).exists()
    (work/tests).write_bytes((root/'tools/native-integration-recovery/issue_normal_form_tests.rs').read_bytes())
    assert set(git('diff','--name-only',cwd=work).splitlines())=={path}
    assert git('ls-files','--others','--exclude-standard',cwd=work)==tests
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',path,tests,cwd=work)
    git('commit','-m','fix(txn): bind issue changes into canonical normal-form evidence','-m','Complete the missing issue lifecycle consumer with the existing reference trace tag 6. Preserve tags 1-5 and test exact event identities, ordered issue/comment folds with outbox effects, statement mismatch behavior, and issue-versus-PR effect separation through the real shared evaluator. No wildcard refusal or dropped issue effect.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work)
    branch='tooling/native-integration-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
    print('PRODUCT_SOURCE',source,branch,flush=True)
