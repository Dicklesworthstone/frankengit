import os,pathlib,subprocess,tempfile
root=pathlib.Path.cwd();base='d85fd2ee61e4640ff7d180ff368495928356703b'
def git(*args,cwd=root):return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-protection-product-') as td:
 work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),base)
 paths=pathlib.Path(td)/'paths'
 subprocess.run(['python3',str(root/'tools/repository-protection-work/apply.py'),str(root/'tools/repository-protection-work'),str(paths)],cwd=work,check=True)
 intended=set(paths.read_text().splitlines())
 actual=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
 assert intended==actual,(intended,actual)
 git('diff','--check',cwd=work)
 git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
 git('add','--',*sorted(intended),cwd=work)
 git('commit','-m','feat(protection): activate durable repository review requirements and enforce publication','-m','Canonical singleton policy administration, exact-version/epoch updates and administrator succession share the forge/outbox/head-CAS path. Native merge publication reuses exact-candidate review validation on every basis. Direct receive, import, workspace and legacy materialization cannot bypass named branch protection. Preserve old event encodings, native object retention and historical merge recovery. Add real embedded-node regressions; no test pass is asserted by this preparation commit.',cwd=work)
 source=git('rev-parse','HEAD',cwd=work)
 assert set(git('diff','--name-only',base,source,cwd=work).splitlines())==intended
 branch='tooling/repository-protection-source-'+os.environ['GITHUB_SHA'][:12]
 git('push','origin',source+':refs/heads/'+branch,cwd=work)
 with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
 print('PRODUCT_SOURCE',source,branch,flush=True)
