import os,pathlib,runpy,subprocess,tempfile
root=pathlib.Path.cwd();payload=root/'tools/fetch-cutoffs';base='30e72bc974af608267c6ff0af3f57dbac480752a'
def git(*args,cwd=root):return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-cutoffs-oracle-source-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),base)
    os.chdir(work)
    assert git('rev-parse',f'{base}:scripts/e2e/oracle/partial_clone_client.py')=='883d8caeaa70bdcc212c99722f221e426bcde63d'
    paths={
        'cutoff_oracle.rs':'crates/fgit-node/src/upload_visibility/tests/shallow_oracle/cutoff_oracle.rs',
        'cutoff_client.py':'scripts/e2e/oracle/cutoff_client.py',
        'cutoff_client_tests.py':'scripts/e2e/oracle/cutoff_client_tests.py',
    }
    for source,target in paths.items():
        path=work/target;assert not path.exists();path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((payload/source).read_bytes())
    runpy.run_path(str(payload/'oracle_apply.py'),run_name='__main__')
    changed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    expected=set(paths.values())|{'scripts/e2e/oracle/partial_clone_client.py','crates/fgit-node/src/upload_visibility/tests/shallow_oracle.rs'}
    assert changed==expected,(changed,expected)
    for name in sorted(changed):
        if name.endswith('.rs'):subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',name],cwd=work,check=True,timeout=180)
    subprocess.run(['python3','-m','unittest','discover','-s','scripts/e2e/oracle','-p','cutoff_client_tests.py'],cwd=work,check=True)
    git('diff','--check',cwd=work);git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*sorted(changed),cwd=work);git('commit','-m','test(fetch): exercise pinned time/ref cutoff clone and widening lifecycles','-m','Add eighteen real Git 2.54.0 scenarios over both hash domains and all wire versions: date-only blobless, ref-only ordinary, and combined treeless clones. Check exact boundaries and initial object inventories, lazy checkout bytes, cutoff widening, unshallow, strict fsck, deleted-object exclusion and unchanged native authority basis. Keep source/binary verification and Bubblewrap; no ambient Git fallback.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work);branch='tooling/fetch-cutoffs-result-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
    print('PRODUCT_SOURCE',source,branch,flush=True)
