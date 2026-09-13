import base64, gzip, hashlib, json, os, pathlib, subprocess, tempfile
root = pathlib.Path.cwd()
base = '80e4a75fa582df39a74792adb29ef8df45726b16'
patch = gzip.decompress(base64.b64decode(''.join((root / f'tools/core-fetch-cli/part{i}').read_text() for i in range(7)), validate=True))
assert hashlib.sha256(patch).hexdigest() == '9f9b7e13d2bb7616811fd94448da4fea4afc9158e4c5d195082b73a8de66dbc7', 'transport mismatch'
allowed = {'crates/fgit-cli/src/bundle.rs','crates/fgit-cli/src/bundle/fetch.rs','crates/fgit-cli/src/bundle/fetch/tests.rs','crates/fgit-cli/tests/native_bundle_fetch_smoke.rs','crates/fgit-node/src/lib.rs','crates/fgit-node/src/treefs_workspace/mandatory_protection_tests.rs','crates/fgit-node/src/treefs_workspace/bundle_fetch_protection_tests.rs','crates/fgit-node/tests/workspace_patch.rs','scripts/e2e/bundle_fetch_smoke.py','scripts/verify_native_bundle.sh','docs/NATIVE_GIT_BUNDLES.md'}
work = pathlib.Path(tempfile.mkdtemp(prefix='fg-fetch-cli-source-'))
def git(*args, cwd=work):
    return subprocess.check_output(['git', *args], cwd=cwd, text=True).strip()
git('worktree','add','--detach',str(work),base,cwd=root)
git('config','user.name','Jeff Emanuel')
git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com')
subprocess.run(['git','am'],input=patch,cwd=work,check=True)
assert set(git('diff','--name-only',base,'HEAD').splitlines()) == allowed
assert not git('status','--porcelain')
git('diff','--check',base,'HEAD')
commits=git('rev-list','--reverse',f'{base}..HEAD').splitlines()
assert len(commits)==2
result=[{'sha':s,'parent':git('rev-parse',s+'^'),'tree':git('rev-parse',s+'^{tree}'),'subject':git('show','-s','--format=%s',s)} for s in commits]
branch='tooling/core-fetch-cli-result-80e4a75f'
git('push','origin',f'HEAD:refs/heads/{branch}')
print('PREPARED_RESULT='+json.dumps({'base':base,'commits':result,'ref':branch,'native_tests':'unrun'}))
with open(os.environ['GITHUB_OUTPUT'],'a') as out: out.write('source='+commits[-1]+'\n')
