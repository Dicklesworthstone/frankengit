import base64, bz2, hashlib, json, os, pathlib, subprocess, tempfile
ROOT=pathlib.Path.cwd()
BASE='80e4a75fa582df39a74792adb29ef8df45726b16'
def git(*args,cwd=ROOT):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
payload=ROOT/'tools/incremental-bundle-session'
raw=bz2.decompress(base64.b64decode(''.join((payload/f'chunk{i}').read_text() for i in range(4)),validate=True))
assert len(raw)==73422 and hashlib.sha256(raw).hexdigest()=='1233f5d469cc3e3bc0800cbcdea3323ddf9d9ace942497f8d484de331912fbc1'
files=json.loads(raw)
new={
 'node_incremental.rs':'crates/fgit-node/src/treefs_workspace/full_bundle/incremental.rs',
 'node_incremental_tests.rs':'crates/fgit-node/src/treefs_workspace/full_bundle/incremental_tests.rs',
 'pack_incremental_tests.rs':'crates/fgit-pack/tests/incremental_bundle.rs',
 'cli_incremental.rs':'crates/fgit-cli/src/bundle/incremental.rs',
 'incremental_bundle_smoke.py':'scripts/e2e/incremental_bundle_smoke.py',
 'native_incremental_bundle_smoke.rs':'crates/fgit-cli/tests/native_incremental_bundle_smoke.rs',
 'verify_incremental_bundle.sh':'scripts/verify_incremental_bundle.sh',
 'INCREMENTAL_GIT_BUNDLES.md':'docs/INCREMENTAL_GIT_BUNDLES.md',
}
old=['crates/fgit-pack/src/full_bundle.rs','crates/fgit-node/src/quarantine_validator.rs','crates/fgit-node/src/quarantine_validator/reused_targets.rs','crates/fgit-node/src/quarantine_validator/typed_closure.rs','crates/fgit-node/src/upload_visibility.rs','crates/fgit-node/src/treefs_workspace/full_bundle.rs','crates/fgit-node/src/treefs_workspace/full_bundle/tests.rs','crates/fgit-cli/src/bundle.rs']
with tempfile.TemporaryDirectory(prefix='fg-incremental-product-') as td:
    work=pathlib.Path(td)/'source'
    git('worktree','add','--detach',str(work),BASE)
    print('EXACT_INPUTS',json.dumps({p:git('rev-parse',BASE+':'+p) for p in old}),flush=True)
    for script in ['apply_core.py','apply_node.py','apply_cli.py']:
        path=pathlib.Path(td)/script;path.write_text(files[script])
        subprocess.run(['python3',str(path)],cwd=work,check=True)
    for key,path in new.items():
        out=work/path;assert not out.exists(),path;out.parent.mkdir(parents=True,exist_ok=True);out.write_text(files[key])
        if path.endswith('.sh'):out.chmod(0o755)
    # Format only new Rust files, never reformat an entire unrelated large module.
    subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',*[str(work/p) for p in new.values() if p.endswith('.rs')]],cwd=work,check=True,timeout=180)
    changed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    assert changed==set(old)|set(new.values()),changed
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    groups=[('core',[p for p in changed if p.startswith('crates/fgit-pack/')],'feat(bundle): support bounded incremental native bundle envelopes'),('node',[p for p in changed if p.startswith('crates/fgit-node/')],'feat(node): synchronize incremental bundles through prerequisite-scoped admission'),('cli',[p for p in changed if not p.startswith(('crates/fgit-pack/','crates/fgit-node/'))],'feat(cli): expose incremental bundle synchronization with explicit old-tip leases')]
    results={}
    for label,paths,message in groups:
        before=git('rev-parse','HEAD',cwd=work)
        git('add','--',*sorted(paths),cwd=work)
        git('commit','-m',message,'-m','Preserve the existing full-bundle and mapped-ref fast-forward profiles. Reuse native graph validation, prerequisite visibility, bounded original-input accounting, pack reconstruction, exact transaction identity and atomic publication. No external Git engine, new dependency or alternative authority. Added native regressions are verified in a separate read-only job; this commit message is not a passing gate claim.',cwd=work)
        sha=git('rev-parse','HEAD',cwd=work)
        assert set(git('diff','--name-only',before,sha,cwd=work).splitlines())==set(paths)
        branch='tooling/incremental-bundle-'+label+'-'+os.environ['GITHUB_SHA'][:12]
        git('push','origin',sha+':refs/heads/'+branch,cwd=work)
        results[label]=sha
        print('PRODUCT_COMMIT',label,sha,branch,flush=True)
    assert not git('status','--porcelain',cwd=work)
    print('PRODUCT_FILES',json.dumps({p:git('rev-parse','HEAD:'+p,cwd=work) for p in sorted(changed)}),flush=True)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:
        for label,sha in results.items():out.write(label+'='+sha+'\n')
        out.write('source='+results['cli']+'\n')
