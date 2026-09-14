import hashlib, os, pathlib, subprocess
base = '1449dfdb3698cf78ced619272491b34b50382d02'
extra = pathlib.Path('tools/native-tag-work/races.rs').read_bytes()
assert hashlib.sha256(extra).hexdigest() == '9e0770e3d79899fce2418f2b870d8432db7f509c63d323d8224ad391cd21b852'
def run(*args): return subprocess.check_output(args, text=True).strip()
w = pathlib.Path(os.environ['RUNNER_TEMP'])/'tags-final-source'
run('git','worktree','add','--detach',str(w),base); os.chdir(w)
p = pathlib.Path('crates/fgit-node/src/treefs_workspace/tags/tests.rs')
assert hashlib.sha256(p.read_bytes()).hexdigest() == 'c82eb5b3d1972520462e1db852bc2f30c00689c0175ecb6b4a1ea679b766193e'
p.write_bytes(p.read_bytes()+extra)
p = pathlib.Path('crates/fgit-node/src/treefs_workspace/tags.rs')
assert hashlib.sha256(p.read_bytes()).hexdigest() == 'cbb4b66a6d9c075d47f30eca5b822de837f131f9f8c2f55c170dc349b867a5ff'
p.write_text(p.read_text().replace('object.id, ObjectType::Tag, object.body, vec![], 0, 0,','object.id, ObjectType::Tag, object.body, vec![object.target], 0, 0,'))
paths = ['crates/fgit-node/src/treefs_workspace/tags.rs','crates/fgit-node/src/treefs_workspace/tags/tests.rs','crates/fgit-cli/src/tags.rs','crates/fgit-cli/src/tags/options.rs','crates/fgit-cli/src/tags/tests.rs']
run('rustfmt','--edition','2024','--config','skip_children=true',*paths)
run('git','diff','--check');run('git','add',*paths)
assert run('git','diff','--cached','--name-only').splitlines() == sorted(paths)
run('git','-c','user.name=Jeff Emanuel','-c','user.email=35050222+Dicklesworthstone@users.noreply.github.com','commit','-m','test(tags): exercise concurrent creation and unauthenticated publication (FG-051a, FG-097)','-m','Add overlapping real-node creation with stable replay and authenticated/anonymous twins. Preserve the declared target edge in the generated canonical pack object while selecting only newly created bytes. Format the owned tag implementation and tests. Native execution is captured separately; no full release or compatibility claim.')
sha=run('git','rev-parse','HEAD');run('git','push','origin',sha+':refs/heads/tooling/native-tag-product-final-1449dfdb')
with open(os.environ['GITHUB_OUTPUT'],'a') as f:f.write('source='+sha+'\n')
print('SOURCE_COMMIT='+sha)
