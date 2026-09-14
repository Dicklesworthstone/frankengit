from pathlib import Path
import base64,gzip,hashlib,os,subprocess
root=Path.cwd()
def git(*args,cwd=root):return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
patch=gzip.decompress(base64.b64decode((root/'tools/source-browse-work/bounds.b64').read_text(),validate=True))
assert hashlib.sha256(patch).hexdigest()=='e893cbb6259de64ca22958f7259b76639ba213a085fe542af6e7886a282f50fb'
work=Path(os.environ['RUNNER_TEMP'])/'bounds-source'
git('worktree','add','--detach',str(work),'d80f6f9ee5c1d7d4b8f9ae9fbd6616f2599339f7')
p=Path(os.environ['RUNNER_TEMP'])/'bounds.patch';p.write_bytes(patch)
git('apply','--check',str(p),cwd=work);git('apply','--index',str(p),cwd=work)
git('diff','--cached','--check',cwd=work)
assert set(git('diff','--cached','--name-only',cwd=work).splitlines())=={'crates/fgit-node/src/treefs_workspace.rs','crates/fgit-node/src/treefs_workspace/source_browse.rs','scripts/verify_source_browse.sh'}
git('-c','user.name=Jeff Emanuel','-c','user.email=35050222+Dicklesworthstone@users.noreply.github.com','commit','-m','fix(node): share source metadata and traversal read budgets (FG-051a)','-m','Apply the hard per-object limit before scoped commit metadata decoding, carry consumed metadata into the operation-wide byte/object budget, and cap subsequent decoding by the remaining aggregate allowance. Preserve the existing capability quotas and non-browsing workspace defaults. Add arithmetic edge and permitted/refused budget tests; native verification is recorded separately.',cwd=work)
git('push','origin','HEAD:refs/heads/tooling/source-browse-product-bounds',cwd=work)
print('BOUNDS_RESULT='+git('rev-parse','HEAD',cwd=work),flush=True)
