from pathlib import Path
import base64, gzip, hashlib, os, subprocess
ROOT=Path.cwd()
BASE='e1b8180e604fb65d0796af3bcc1026f3f5545ee7'
def git(*args, cwd=ROOT):
    return subprocess.check_output(['git', *args],cwd=cwd,text=True).strip()
patch=gzip.decompress(base64.b64decode((ROOT/'tools/source-browse-work/node.b64').read_text(),validate=True))
assert hashlib.sha256(patch).hexdigest()=='875bf92e751b86847b4c79d68e45664c6baf301269cb90cef3f2f986ea5ba1e3'
work=Path(os.environ['RUNNER_TEMP'])/'source-browse-product'
git('worktree','add','--detach',str(work),BASE)
file=Path(os.environ['RUNNER_TEMP'])/'node.patch'; file.write_bytes(patch)
git('apply','--check',str(file),cwd=work)
git('apply','--index',str(file),cwd=work)
git('diff','--cached','--check',cwd=work)
expected={'crates/fgit-forge/src/lib.rs','crates/fgit-forge/src/source_browse.rs','crates/fgit-node/src/treefs_workspace.rs','crates/fgit-node/src/treefs_workspace/source_browse.rs','crates/fgit-node/tests/source_browse.rs','scripts/verify_source_browse.sh'}
assert set(git('diff','--cached','--name-only',cwd=work).splitlines())==expected
git('-c','user.name=Jeff Emanuel','-c','user.email=35050222+Dicklesworthstone@users.noreply.github.com','commit','-m','feat(node): add capability-scoped snapshot-pinned source browsing (FG-051a)','-m','Read exact directory entries and binary file ranges through verified TreeFS objects. Preserve one authority head across pages, caller path capabilities, bounded reads, symlink-data semantics, and opaque gitlinks. Include both-hash file-backed read, visibility, budget, cancellation, stale-snapshot and restart tests. No publication or host process path; native verification is recorded separately.',cwd=work)
sha=git('rev-parse','HEAD',cwd=work)
git('push','origin','HEAD:refs/heads/tooling/source-browse-product-node',cwd=work)
print('SOURCE_RESULT='+sha,flush=True)
with open(os.environ['GITHUB_OUTPUT'],'a') as output: output.write('source='+sha+'\n')
