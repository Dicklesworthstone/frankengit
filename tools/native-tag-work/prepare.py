import base64, hashlib, os, pathlib, subprocess, zlib
base = '4ff367973c805f98a6e81ed32fb469bce31c2e97'
source = pathlib.Path('tools/native-tag-work/patch.b64').read_bytes()
assert source[4429:4430] == b'f' and source[6844:6849] == b'cPvbn'
source = source[:6844] + b'zq' + source[6849:]
source = source[:4429] + b'/' + source[4430:]
patch = zlib.decompress(base64.b64decode(source, validate=True))
assert hashlib.sha256(patch).hexdigest() == '7a8a721e6c12787b9b883653795049ca0a6da70f78ab873e706a29cb7bb3fed9', 'saved source digest mismatch'
p = pathlib.Path(os.environ['RUNNER_TEMP'])/'tags.patch'; p.write_bytes(patch)
w = pathlib.Path(os.environ['RUNNER_TEMP'])/'tags-source'
def run(*args): return subprocess.check_output(args, text=True).strip()
run('git','worktree','add','--detach',str(w),base)
os.chdir(w)
run('git','apply','--index',str(p))
run('git','diff','--cached','--check')
expected = ['crates/fgit-node/src/treefs_workspace.rs','crates/fgit-node/src/treefs_workspace/branches.rs','crates/fgit-node/src/treefs_workspace/tags.rs','crates/fgit-node/src/treefs_workspace/tags/tests.rs','scripts/verify_native_tags.sh']
assert run('git','diff','--cached','--name-only').splitlines() == sorted(expected)
run('git','-c','user.name=Jeff Emanuel','-c','user.email=35050222+Dicklesworthstone@users.noreply.github.com','commit','-m','feat(node): connect native tag lifecycle and verified peeling (FG-051a, FG-097)','-m','Use existing tag contracts, production quarantine, exact-basis admission, and visibility-bound original objects. Recover exact terminal requests before intake gates. Add both-hash file-backed lifecycle, retry, namespace, original-kind, disclosure, resource and cancellation tests. Native validation is recorded separately; no bead closure or full conformance claim.')
sha=run('git','rev-parse','HEAD')
run('git','push','origin',sha+':refs/heads/tooling/native-tag-product-node-4ff36797')
with open(os.environ['GITHUB_OUTPUT'],'a') as f: f.write('source='+sha+'\n')
print('SOURCE_COMMIT='+sha)
