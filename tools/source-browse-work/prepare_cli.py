from pathlib import Path
import base64, gzip, hashlib, os, subprocess
ROOT=Path.cwd()
BASE='845ea759d2ef2bf1f0f55b4ee0afaa6fc56bf203'
def git(*args,cwd=ROOT): return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
encoded=(ROOT/'tools/source-browse-work/cli.b64').read_text()
assert encoded.count('uXoU/jp6L8OTyh')==1
encoded=encoded.replace('uXoU/jp6L8OTyh','uXoU/jp6L8OPyh')
patch=gzip.decompress(base64.b64decode(encoded,validate=True))
assert hashlib.sha256(patch).hexdigest()=='7a90d88c9ac3827c0bc831d3f4a0d57d2ea5ff3ff53054dfafb7ce4d3a37b50e'
work=Path(os.environ['RUNNER_TEMP'])/'source-browse-cli-product'
git('worktree','add','--detach',str(work),BASE)
def commit(message):
    git('diff','--cached','--check',cwd=work)
    git('-c','user.name=Jeff Emanuel','-c','user.email=35050222+Dicklesworthstone@users.noreply.github.com','commit','-m',message,cwd=work)
    return git('rev-parse','HEAD',cwd=work)
path='crates/fgit-node/src/treefs_workspace/source_browse.rs'
assert git('hash-object',path,cwd=work)=='74bc7452d9665f2cfce0464226f1e9a4d5446ea8'
p=work/path;s=p.read_text()
s=s.replace('bounded.read_object::<A>(id, kind)?','bounded.read_object::<A>(id, kind, grant)?')
s=s.replace('oid(entry.oid(),','oid::<A>(entry.oid(),').replace('oid(base.base_commit_oid(),','oid::<A>(base.base_commit_oid(),').replace('oid(base.base_tree_oid(),','oid::<A>(base.base_tree_oid(),')
p.write_text(s)
assert git('hash-object',path,cwd=work)=='25532adafc238dd0b189b2d39d740fcd560a7fd2'
git('add',path,cwd=work)
fixed=commit('fix(node): carry read grants and explicit native hash types through bounded browsing (FG-051a)')
f=Path(os.environ['RUNNER_TEMP'])/'cli.patch';f.write_bytes(patch)
git('apply','--check',str(f),cwd=work);git('apply','--index',str(f),cwd=work)
expected={'crates/fgit-cli/src/main.rs','crates/fgit-cli/src/source_browse.rs','crates/fgit-cli/src/source_browse/options.rs','crates/fgit-cli/src/source_browse/tests.rs','crates/fgit-cli/tests/native_source_browse_smoke.rs','docs/NATIVE_SOURCE_BROWSING.md','scripts/e2e/source_browse_smoke.py','scripts/verify_source_browse.sh'}
assert set(git('diff','--cached','--name-only',cwd=work).splitlines())==expected
source=commit('feat(cli): connect exact tree and file reads to the native read-patch-publish loop (FG-051a)\n\nAdd fg tree and fg show with bounded byte-exact names, binary ranges, snapshot continuations, independently pinned commits, read-only trusted-local authentication, and cleanup/output failure semantics. Include parser/receipt tests, both-hash fresh-process read-to-patch publication, and the repository-owned native campaign. No dependencies or authority changes. Native compilation and test execution are recorded separately.')
git('push','origin','HEAD:refs/heads/tooling/source-browse-product-cli',cwd=work)
print('FIX_RESULT='+fixed+'\nCLI_RESULT='+source,flush=True)
with open(os.environ['GITHUB_OUTPUT'],'a') as output: output.write('source='+source+'\n')
