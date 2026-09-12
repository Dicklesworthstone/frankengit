import json,os,pathlib,signal,subprocess,tempfile,sys
ROOT=pathlib.Path.cwd()
BASE='01c98e7dea2e1efdd0fb5febfae777ac68f39cb7'
def git(*args,cwd=ROOT): return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
def verify(work,label,command,seconds=800):
    log=work.parent/(label+'.log')
    with log.open('w') as out:
        p=subprocess.Popen(command,cwd=work,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
        try: code=p.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
            code=124
    lines=log.read_text().splitlines()
    print('VERIFICATION',json.dumps({'label':label,'revision':git('rev-parse','HEAD',cwd=work),'command':command,'exit':code,'summaries':[x for x in lines if x.startswith('test result:')]}),flush=True)
    print('\n'.join(lines[-200:] if code else [x for x in lines if x.startswith('test result:') or 'shallow' in x or x.startswith('error')]),flush=True)
    return code
with tempfile.TemporaryDirectory(prefix='fg-shallow-node-') as td:
    work=pathlib.Path(td)/'source'
    subprocess.run(['git','worktree','add','--detach',str(work),BASE],check=True)
    # The saved initializer context occurs in a second, unrelated snapshot
    # constructor. Restrict this edit to the actual upload-pack repository.
    applier=ROOT/'tools/shallow-apply.py'
    code=applier.read_text()
    old="edit(n,'            tag_peels: BTreeMap::new(),\\n        })','            tag_peels: BTreeMap::new(),\\n            shallow_proof: None,\\n        })')"
    new="edit(n,'            closure_objects: BTreeSet::new(),\\n            tag_peels: BTreeMap::new(),\\n        })','            closure_objects: BTreeSet::new(),\\n            tag_peels: BTreeMap::new(),\\n            shallow_proof: None,\\n        })')"
    assert code.count(old)==1
    code=code.replace(old,new)
    sys.argv=[str(applier),str(work),'node']
    exec(compile(code,str(applier),'exec'),{'__name__':'__main__','__file__':str(applier)})
    files=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    assert len(files)==9 and all(p.startswith('crates/fgit-node/') for p in files),files
    for path in sorted(files):
        if path.endswith('.rs') and not path.endswith('/src/lib.rs'):
            subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',str(work/path)],cwd=work,check=True)
    subprocess.run(['git','diff','--check'],cwd=work,check=True)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*sorted(files),cwd=work)
    git('commit','-m','feat(fetch): serve native depth-limited history and unshallow','-m','Resolve boundaries and transfer selection from one exact-head visible graph. Clip wanted history at the new boundary and common history at the old boundary, retain tree contents, compose partial filters and lazy roots, and preserve canonical retention. Forward the provider through the legacy tag adapter; do not attach it to unrelated snapshot constructors. Includes eleven graph and two real-socket regression tests; execution is recorded separately.',cwd=work)
    sha=git('rev-parse','HEAD',cwd=work)
    branch='tooling/shallow-node-'+os.environ['GITHUB_SHA'][:12]
    subprocess.run(['git','push','origin',sha+':refs/heads/'+branch],cwd=work,check=True)
    print('PRODUCT_SOURCE',sha,branch,sorted(files),flush=True)
    if verify(work,'cli-check',['cargo','check','--locked','-p','fgit-cli','--all-targets']):raise SystemExit(1)
    if verify(work,'node-shallow',['cargo','test','--locked','-p','fgit-node','--lib','shallow','--','--nocapture']):raise SystemExit(1)
    if verify(work,'node-library',['cargo','test','--locked','-p','fgit-node','--lib']):raise SystemExit(1)
    assert not git('status','--porcelain',cwd=work)
    print('NODE_READY',sha,flush=True)
