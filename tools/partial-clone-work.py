import os,pathlib,subprocess,tempfile
ROOT=pathlib.Path.cwd(); BASE='b9fcbd2d406ee96717aafcf191d493991569a96f'
def git(*args,cwd=ROOT): return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-partial-wire-') as td:
    work=pathlib.Path(td)/'source'
    subprocess.run(['git','worktree','add','--detach',str(work),BASE],check=True)
    subprocess.run(['python3',str(ROOT/'tools/partial-payload/apply-wire.py'),str(ROOT/'tools/partial-payload')],cwd=work,check=True)
    paths=['crates/fgit-wire/src/lib.rs','crates/fgit-wire/src/filter_syntax.rs','crates/fgit-wire/tests/partial_clone_filter_syntax.rs']
    for path in paths[1:]: subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',path],cwd=work,check=True)
    subprocess.run(['git','diff','--check'],cwd=work,check=True)
    git('config','user.name','Jeff Emanuel',cwd=work); git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*paths,cwd=work)
    git('commit','-m','feat(wire): parse bounded compound filters and authorize negotiated lazy wants','-m','Accept checked scaled blob sizes and percent-encoded compound filters, bound total leaf terms and nesting, and preserve typed grammar refusals. Legacy unadvertised wants require an explicit server capability AND repository permission; client capability text cannot grant access. Production advertisement remains unchanged until node integration.',cwd=work)
    result=git('rev-parse','HEAD',cwd=work); branch='tooling/partial-result-'+os.environ['GITHUB_SHA'][:12]
    subprocess.run(['git','push','origin',f'{result}:refs/heads/{branch}'],cwd=work,check=True)
    print('PRODUCT_RESULT',result,branch,flush=True)
    command=['cargo','test','--locked','-p','fgit-wire','--all-targets']; log=pathlib.Path(td)/'test.log'
    with log.open('w') as out:
        p=subprocess.run(command,cwd=work,stdout=out,stderr=subprocess.STDOUT,timeout=600)
    lines=log.read_text().splitlines()
    print('VERIFICATION',result,'EXIT',p.returncode,'COMMAND',' '.join(command),flush=True)
    print('\n'.join(lines[-180:] if p.returncode else [line for line in lines if line.startswith('test result:') or 'partial_clone_filter_syntax' in line]),flush=True)
    assert not git('status','--porcelain',cwd=work)
    raise SystemExit(p.returncode)
