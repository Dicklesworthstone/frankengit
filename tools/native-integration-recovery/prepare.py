import os, pathlib, subprocess, tempfile
root=pathlib.Path.cwd()
base='99dbd4679192ead4d95a09ede4b21146ca6dba78'
main='crates/fgit-cli/src/main.rs'
files={
 'issues.rs':'crates/fgit-cli/src/issues.rs',
 'options.rs':'crates/fgit-cli/src/issues/options.rs',
 'output.rs':'crates/fgit-cli/src/issues/output.rs',
 'tests.rs':'crates/fgit-cli/src/issues/tests.rs',
 'native_issue_smoke.rs':'crates/fgit-cli/tests/native_issue_smoke.rs',
 'issue_smoke.py':'scripts/e2e/issue_smoke.py',
}
def git(*args,cwd=root):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-issue-cli-product-') as td:
    work=pathlib.Path(td)/'source'
    git('worktree','add','--detach',str(work),base)
    assert git('rev-parse',f'{base}:{main}')=='713a821cd5e5c28d2eabee0f671466963564a118'
    path=work/main;text=path.read_text()
    anchor='    let arguments = std::env::args().skip(1).collect::<Vec<_>>();\n'
    insert='''    if arguments.first().is_some_and(|argument| argument == "issue") {
        return match issues::run(&arguments[1..]) {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
'''
    assert text.count('mod commit_replay;\n')==1 and text.count(anchor)==1
    path.write_text(text.replace('mod commit_replay;\n','mod commit_replay;\nmod issues;\n').replace(anchor,anchor+insert))
    for source,dest in files.items():
        target=work/dest
        assert not target.exists(),dest
        target.parent.mkdir(parents=True,exist_ok=True)
        text=(root/'tools/native-integration-recovery/issue-cli'/source).read_text()
        if source=='issue_smoke.py':
            assert text.count("'--key', 'open-stable-private-key'")==1
            text=text.replace("'--key', 'open-stable-private-key'","'--idempotency-key', 'open-stable-private-key'")
            assert text.count("value['tx_id'] == opened['tx_id']")==1
            text=text.replace("value['tx_id'] == opened['tx_id']","value['transaction']['tx_id'] == opened['tx_id']")
        target.write_text(text)
    for dest in files.values():
        if dest.endswith('.rs'):
            subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',dest],cwd=work,check=True,timeout=180)
    assert git('diff','--name-only',cwd=work)==main
    assert set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())==set(files.values())
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',main,*files.values(),cwd=work)
    git('commit','-m','feat(cli): expose durable issue lifecycle and snapshot-pinned discussion history','-m','Wire open/edit/close/reopen/comment/list/show to the existing issue admission and authenticated replay APIs. Preserve omitted edit fields, explicit canonical labels, exact versions, scoped idempotency and historical outcomes after intake changes. Bound and validate UTF-8 body files before opening the node, preserve terminal identity on output/cleanup failures, and validate page range/aggregate/cursor contracts before JSON emission. Add nine parser/presentation/file tests and a fresh-process two-hash native lifecycle/recovery campaign. No issue DB, Git subprocess, or new dependency.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work)
    branch='tooling/native-integration-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
    print('PRODUCT_SOURCE',source,branch,flush=True)
