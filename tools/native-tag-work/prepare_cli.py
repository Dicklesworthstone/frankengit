import base64, hashlib, os, pathlib, subprocess, zlib
base = '03c33db850299ed003045a1cd53e7f1f5debe40b'
source = b''.join(pathlib.Path(f'tools/native-tag-work/cli.{n}').read_bytes() for n in range(7))
patch = zlib.decompress(base64.b64decode(source, validate=True))
assert hashlib.sha256(patch).hexdigest() == 'b5f53da7580562586985e24d81f8b1021bc56a6e3be3c741e00fd158c557d79c', 'saved source digest mismatch'
p = pathlib.Path(os.environ['RUNNER_TEMP'])/'tags-cli.patch'; p.write_bytes(patch)
w = pathlib.Path(os.environ['RUNNER_TEMP'])/'tags-cli-source'
def run(*args): return subprocess.check_output(args, text=True).strip()
run('git','worktree','add','--detach',str(w),base)
os.chdir(w)
run('git','apply','--index',str(p))
run('git','diff','--cached','--check')
expected = ['crates/fgit-cli/src/main.rs','crates/fgit-cli/src/tags.rs','crates/fgit-cli/src/tags/options.rs','crates/fgit-cli/src/tags/tests.rs','crates/fgit-cli/tests/native_tag_smoke.rs','docs/NATIVE_TAG_LIFECYCLE.md','scripts/e2e/tag_smoke.py','scripts/verify_native_tags.sh']
assert run('git','diff','--cached','--name-only').splitlines() == sorted(expected)
run('git','-c','user.name=Jeff Emanuel','-c','user.email=35050222+Dicklesworthstone@users.noreply.github.com','commit','-m','feat(cli): expose native tag lifecycle, inspection and bundle transfer tests (FG-051a, FG-097)','-m','Add explicit trusted-local create/annotate/delete/list/show with byte-exact references, bounded message files and retry keys, snapshot pagination, recursive native inspection, and terminal receipts retaining cleanup/output failures. Add both-hash fresh-process tag and bundle transfer coverage. Preserve existing authority/policy paths and dependencies; native results are recorded separately.')
sha=run('git','rev-parse','HEAD')
run('git','push','origin',sha+':refs/heads/tooling/native-tag-product-cli-03c33db8')
with open(os.environ['GITHUB_OUTPUT'],'a') as f: f.write('source='+sha+'\n')
print('SOURCE_COMMIT='+sha)
