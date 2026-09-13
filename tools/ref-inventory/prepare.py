import base64, gzip, hashlib, json, os, pathlib, subprocess, tempfile
root = pathlib.Path.cwd()
base = '397912d541364d4c9ee35638bae034b57d5385d2'
encoded = ''.join((root / f'tools/ref-inventory/part{i}').read_text() for i in range(4))
# Repair one exact transport transcription; the decoded source still must
# equal its independently computed SHA-256 before anything can be applied.
encoded = encoded.replace('JxAFI7s+Y+dPPvf7W2LPmVm6v12', 'JxAFI7s+Y+dPPvf7WwLM6nV6v12')
patch = gzip.decompress(base64.b64decode(encoded, validate=True))
assert hashlib.sha256(patch).hexdigest() == '2a516e5871f5f2ad7bcfb67885f47e26720aefaf4a7318948878746efb41ff78', 'transport mismatch'
allowed = {'crates/fgit-cli/src/branches.rs','crates/fgit-cli/src/branches/options.rs','crates/fgit-cli/src/branches/inventory.rs','crates/fgit-cli/src/main.rs','crates/fgit-node/src/treefs_workspace/branches.rs','crates/fgit-node/src/treefs_workspace/full_bundle/tests/fetch.rs','scripts/e2e/bundle_fetch_smoke.py','scripts/verify_native_bundle.sh','docs/NATIVE_GIT_BUNDLES.md','crates/fgit-node/src/lib.rs','crates/fgit-node/src/treefs_workspace/full_bundle.rs'}
work = pathlib.Path(tempfile.mkdtemp(prefix='fg-ref-inventory-'))
def git(*args, cwd=work): return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
git('worktree','add','--detach',str(work),base,cwd=root)
git('config','user.name','Jeff Emanuel')
git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com')
subprocess.run(['git','am',str(root/'tools/ref-inventory/fix-export.patch')],cwd=work,check=True)
subprocess.run(['git','am'],input=patch,cwd=work,check=True)
assert set(git('diff','--name-only',base,'HEAD').splitlines()) == allowed
assert not git('status','--porcelain')
git('diff','--check',base,'HEAD')
commits=git('rev-list','--reverse',f'{base}..HEAD').splitlines()
assert len(commits)==2
result=[{'sha':s,'parent':git('rev-parse',s+'^'),'tree':git('rev-parse',s+'^{tree}'),'subject':git('show','-s','--format=%s',s)} for s in commits]
branch='tooling/refs-inventory-result-397912d'
git('push','origin',f'HEAD:refs/heads/{branch}')
print('PREPARED_RESULT='+json.dumps({'base':base,'commits':result,'ref':branch,'native_tests':'unrun'}))
with open(os.environ['GITHUB_OUTPUT'],'a') as out: out.write('source='+commits[-1]+'\n')
