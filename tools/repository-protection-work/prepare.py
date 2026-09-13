import os,pathlib,subprocess,tempfile
root=pathlib.Path.cwd();base='09ab8325931e82c3e43b3cc7aa7897eb3676f7e0'
def git(*args,cwd=root):return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
def commit(work,base,expected,message):
 actual=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
 assert actual==expected,(actual,expected)
 git('diff','--check',cwd=work);git('add','--',*sorted(expected),cwd=work);git('commit','-m',message,cwd=work)
 result=git('rev-parse','HEAD',cwd=work);assert set(git('diff','--name-only',base,result,cwd=work).splitlines())==expected
 return result
with tempfile.TemporaryDirectory(prefix='fg-protection-product-') as td:
 work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),base)
 git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
 payload=root/'tools/repository-protection-work';paths=pathlib.Path(td)/'paths'
 subprocess.run(['python3',str(payload/'apply.py'),str(payload),str(paths)],cwd=work,check=True)
 subprocess.run(['python3',str(payload/'improve.py'),str(payload)],cwd=work,check=True)
 intended=set(paths.read_text().splitlines())|{'crates/fgit-forge/tests/atomic_merge.rs','crates/fgit-node/src/treefs_workspace/protection_race.rs'}
 core=commit(work,base,intended,'feat(protection): enforce durable repository-owned review policy at publication')
 subprocess.run(['python3',str(payload/'cli_apply.py'),str(payload)],cwd=work,check=True)
 intended={'crates/fgit-cli/src/main.rs','crates/fgit-cli/src/protection.rs','crates/fgit-cli/tests/native_protection_smoke.rs','scripts/e2e/protection_smoke.py'}
 for name in sorted(intended-{'crates/fgit-cli/src/main.rs','scripts/e2e/protection_smoke.py'}):
  subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',name],cwd=work,check=True,timeout=180)
 source=commit(work,core,intended,'feat(cli): administer canonical repository protection with exact version and epoch leases')
 branch='tooling/repository-protection-source-'+os.environ['GITHUB_SHA'][:12];git('push','origin',source+':refs/heads/'+branch,cwd=work)
 with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
 print('PRODUCT_CORE',core,'PRODUCT_SOURCE',source,branch,flush=True)
