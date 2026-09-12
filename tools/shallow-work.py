import hashlib,json,os,pathlib,signal,subprocess,tempfile
ROOT=pathlib.Path.cwd()
BASE='eafff2458062884b92e50da13b49e9e7b7ceafea'
def git(*args,cwd=ROOT): return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
def verify(work,label,command,seconds=600):
    log=work.parent/(label+'.log')
    with log.open('w') as out:
        p=subprocess.Popen(command,cwd=work,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
        try: code=p.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid,signal.SIGTERM)
            try: p.wait(timeout=10)
            except subprocess.TimeoutExpired: os.killpg(p.pid,signal.SIGKILL);p.wait()
            code=124
    lines=log.read_text().splitlines()
    print('VERIFICATION',json.dumps({'label':label,'revision':git('rev-parse','HEAD',cwd=work),'command':command,'exit':code,'summaries':[x for x in lines if x.startswith('test result:')]}),flush=True)
    print('\n'.join(lines[-180:] if code else [x for x in lines if x.startswith('test result:') or 'shallow' in x or x.startswith('error')]),flush=True)
    return code
def commit(work,label,message):
    files=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    assert files and all(p.startswith('crates/fgit-'+label+'/') for p in files),files
    for p in sorted(files):
        if p.endswith('.rs') and not p.endswith('/src/lib.rs'):
            subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',str(work/p)],cwd=work,check=True)
    subprocess.run(['git','diff','--check'],cwd=work,check=True)
    git('add','--',*sorted(files),cwd=work)
    git('commit','-m',message,cwd=work)
    sha=git('rev-parse','HEAD',cwd=work)
    branch='tooling/shallow-'+label+'-'+os.environ['GITHUB_SHA'][:12]
    subprocess.run(['git','push','origin',sha+':refs/heads/'+branch],cwd=work,check=True)
    print('PRODUCT_SOURCE',label,sha,branch,sorted(files),flush=True)
    return sha
with tempfile.TemporaryDirectory(prefix='fg-shallow-') as td:
    work=pathlib.Path(td)/'source'
    subprocess.run(['git','worktree','add','--detach',str(work),BASE],check=True)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    for name in ['COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md','docs/NORMATIVE_PROTOCOL_CONTRACTS.md','docs/GIT_COMPATIBILITY_MATRIX.md']:
        lines=(work/name).read_text().splitlines()
        selected=set()
        for i,line in enumerate(lines):
            if 'shallow' in line.lower(): selected.update(range(max(0,i-5),min(len(lines),i+12)))
        print('SPEC',name,'\n'+'\n'.join(f'{i+1}: {lines[i]}' for i in sorted(selected)),flush=True)
    issues=work/'.beads/issues.jsonl'
    if issues.exists():
        count=0
        for line in issues.read_text().splitlines():
            row=json.loads(line)
            hay=' '.join(str(row.get(k,'')) for k in ['title','description','acceptance_criteria'])
            if 'shallow' in hay.lower():
                print('BEAD',json.dumps(row),flush=True);count+=1
                if count==8:break
    subprocess.run(['python3',str(ROOT/'tools/shallow-apply.py'),str(work),'wire'],check=True)
    wire=commit(work,'wire','feat(wire): resolve bounded shallow updates before pack negotiation\n\nRecover the saved shallow response implementation with eight wire regressions. Preserve parser-only adapters by default; opt-in providers validate exact update identities, authorization and old-boundary membership before emission. Legacy clients receive their shallow flush before sending haves. Verification is reported by the workbench, not inferred from this commit.')
    if verify(work,'wire-check',['cargo','check','--locked','-p','fgit-wire','--all-targets']):raise SystemExit(1)
    if verify(work,'wire-tests',['cargo','test','--locked','-p','fgit-wire','--all-targets']):raise SystemExit(1)
    print('WIRE_READY',wire,flush=True)
    subprocess.run(['python3',str(ROOT/'tools/shallow-apply.py'),str(work),'node'],check=True)
    node=commit(work,'node','feat(fetch): serve native depth-limited history and unshallow\n\nResolve boundaries and transfer selection from one exact-head visible graph. Clip wanted history at the new boundary and common history at the old boundary, retain tree contents, compose partial filters and lazy roots, and preserve canonical retention. Forward the provider through the legacy tag adapter. Includes eleven graph and two real-socket regression tests; test execution is recorded separately.')
    if verify(work,'cli-check',['cargo','check','--locked','-p','fgit-cli','--all-targets']):raise SystemExit(1)
    if verify(work,'node-shallow',['cargo','test','--locked','-p','fgit-node','--lib','shallow','--','--nocapture'],800):raise SystemExit(1)
    if verify(work,'node-library',['cargo','test','--locked','-p','fgit-node','--lib'],800):raise SystemExit(1)
    assert not git('status','--porcelain',cwd=work)
    print('NODE_READY',node,flush=True)
