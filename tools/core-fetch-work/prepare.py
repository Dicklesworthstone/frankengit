import base64, gzip, hashlib, json, os, pathlib, subprocess, tempfile
root = pathlib.Path.cwd()
base = '9c8d052127a03dd7a78a6731fa3fb7d41e985c84'
parts = [root / f'tools/core-fetch-work/part{i}' for i in range(5)]
patch = gzip.decompress(base64.b64decode(''.join(p.read_text() for p in parts), validate=True))
assert hashlib.sha256(patch).hexdigest() == 'a6eb4eaa4e311223878dcc056c9426ff94a05dc6321c52b342ef45fb3be581c3', 'transport mismatch'
allowed = {'crates/fgit-node/src/treefs_workspace/patch.rs', 'crates/fgit-node/src/quarantine_validator/typed_closure.rs', 'crates/fgit-node/src/treefs_workspace/full_bundle.rs', 'crates/fgit-node/src/treefs_workspace/full_bundle/tests.rs', 'crates/fgit-node/src/treefs_workspace/full_bundle/tests/fetch.rs', 'crates/fgit-pack/src/full_bundle.rs', 'crates/fgit-pack/src/full_bundle/fetch.rs', 'crates/fgit-pack/tests/full_bundle.rs', 'crates/fgit-pack/tests/full_bundle/fetch.rs'}
work = pathlib.Path(tempfile.mkdtemp(prefix='fg-fetch-source-'))
def git(*args, cwd=work):
    return subprocess.check_output(['git', *args], cwd=cwd, text=True).strip()
git('worktree', 'add', '--detach', str(work), base, cwd=root)
git('config', 'user.name', 'Jeff Emanuel')
git('config', 'user.email', '35050222+Dicklesworthstone@users.noreply.github.com')
subprocess.run(['git', 'am'], input=patch, cwd=work, check=True)
assert set(git('diff', '--name-only', base, 'HEAD').splitlines()) == allowed
assert not git('status', '--porcelain')
git('diff', '--check', base, 'HEAD')
commits = git('rev-list', '--reverse', f'{base}..HEAD').splitlines()
assert len(commits) == 2
result = [{'sha': sha, 'parent': git('rev-parse', sha+'^'), 'tree': git('rev-parse', sha+'^{tree}'), 'subject': git('show','-s','--format=%s',sha)} for sha in commits]
branch = 'tooling/core-fetch-result-9c8d0521'
git('push', 'origin', f'HEAD:refs/heads/{branch}')
print('PREPARED_RESULT=' + json.dumps({'base':base,'commits':result,'ref':branch,'native_tests':'unrun'}))
with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
    output.write('source=' + commits[-1] + '\n')
