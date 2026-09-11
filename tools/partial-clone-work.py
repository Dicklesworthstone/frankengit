import concurrent.futures,hashlib,json,os,pathlib,re,shutil,signal,subprocess,tempfile,urllib.request
ROOT=pathlib.Path.cwd(); BASE='7207128f639669b65e2d51eb6ba71b7181751107'
def git(*args,cwd=ROOT): return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
def run(work,td,label,command,timeout=720,env=None):
    log=pathlib.Path(td)/(label+'.log')
    with log.open('w') as out:
        process=subprocess.Popen(command,cwd=work,stdout=out,stderr=subprocess.STDOUT,start_new_session=True,env=env)
        try: code=process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGTERM)
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGKILL); process.wait()
            code=124
    lines=log.read_text(errors='replace').splitlines()
    summaries=[line for line in lines if line.startswith('test result:')]
    item={'label':label,'command':' '.join(command),'revision':BASE,'exit':code,'summaries':summaries}
    print('VERIFICATION',json.dumps(item),flush=True)
    print('\n'.join(lines[-180:] if code else [line for line in lines if line.startswith('test result:') or 'Finished ' in line or 'PINNED_PARTIAL_CELL' in line or 'FGIT_ORACLE_' in line]),flush=True)
    return item
with tempfile.TemporaryDirectory(prefix='fg-partial-complete-') as td:
    work=pathlib.Path(td)/'source'
    subprocess.run(['git','worktree','add','--detach',str(work),BASE],check=True)
    evidence=[]
    if not shutil.which('bwrap'):
        for label,cmd in [('sandbox-index',['sudo','apt-get','update','-qq']),('sandbox-install',['sudo','apt-get','install','-y','bubblewrap'])]:
            item=run(work,td,label,cmd,180); evidence.append(item)
            if item['exit']: raise SystemExit(item['exit'])
    oracle_root=pathlib.Path('/tmp')/('fg-partial-verified-'+os.environ['GITHUB_SHA'][:12]); oracle_root.mkdir(exist_ok=False)
    env=os.environ.copy(); env['FGIT_ORACLE_ROOT']=str(oracle_root); env['FGIT_ORACLE_JOBS']='2'
    def build_oracle():
        pin=next(line.split('\t') for line in (work/'scripts/e2e/oracle/pins.tsv').read_text().splitlines() if line.startswith('git-2.54.0\t'))
        url,expected,filename=pin[4:7]; download=oracle_root/'downloads'/filename; download.parent.mkdir()
        req=urllib.request.Request(url,headers={'User-Agent':'OpenAI File Downloader, XaiImageApiFetch/1.0'}); digest=hashlib.sha256(); count=0
        with urllib.request.urlopen(req,timeout=60) as response,download.open('xb') as out:
            while chunk:=response.read(1024*1024):
                count+=len(chunk); assert count<=128*1024*1024; out.write(chunk); digest.update(chunk)
        assert digest.hexdigest()==expected,(digest.hexdigest(),expected)
        print('ORACLE_SOURCE',url,'SHA256',expected,'BYTES',count,flush=True)
        return run(work,td,'oracle-build',['scripts/e2e/oracle/oracle.sh','build','git-2.54.0'],900,env)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        oracle=pool.submit(build_oracle)
        for label,cmd,seconds in [('cli-check',['cargo','check','--locked','-p','fgit-cli','--all-targets'],600),('node-library',['cargo','test','--locked','-p','fgit-node','--lib'],900),('wire',['cargo','test','--locked','-p','fgit-wire','--all-targets'],240)]:
            item=run(work,td,label,cmd,seconds); evidence.append(item)
        try: evidence.append(oracle.result())
        except Exception as error:
            print('ORACLE_SETUP_EXCEPTION',repr(error),flush=True)
            evidence.append({'label':'oracle-build','exit':69,'summaries':[],'command':'pinned source/build setup','revision':BASE})
    if evidence[-1]['exit']==0:
        evidence.append(run(work,td,'pinned-client',['cargo','test','--locked','-p','fgit-node','--lib','pinned_git_partial_clone_promisor_and_lazy_read_round_trip','--','--ignored','--nocapture'],900,env))
    for receipt in sorted((oracle_root/'runs').glob('*/transcripts/*.json')):
        print('PINNED_RECEIPT',receipt.read_text().strip(),flush=True)
    for log in sorted((oracle_root/'runs').glob('*/transcripts/*.packets')):
        lines=log.read_text(errors='replace').splitlines()
        print('WIRE_TRACE',log.name,'\n'.join(lines[-80:]),flush=True)
    assert not git('status','--porcelain',cwd=work)
    print('FINAL_EVIDENCE',json.dumps({'revision':BASE,'commands':evidence}),flush=True)
    path=work/'docs/PARTIAL_CLONE_SERVING.md'
    text=path.read_text()+'\n## Revision-bound verification follow-through\n\nSource: `'+BASE+'`. Runner: Ubuntu 22.04, repository-pinned nightly and locked dependencies.\n\n'
    text+='The previous Ubuntu 24.04 attempt at `cb40dd242a53f80a07fa961a27656110568cfc78` completed 235 node library tests, 27 daemon integration tests and 230 wire tests with no failures, but the separate pinned-client campaign stopped with exit 69 because Bubblewrap could not establish its namespace. This run retains the same sandbox requirement; no guard, assertion or isolation check was bypassed.\n\n'
    text+='| Command | Exit | Completed target summaries |\n|---|---:|---|\n'
    for item in evidence:
        text+='| `'+item['command']+'` | '+str(item['exit'])+' | '+'; '.join(item['summaries'])+' |\n'
    text+='\nAn unavailable or timed-out oracle is not a passing campaign. The six existing ignored wire-oracle tests are not covered by a normal all-targets run. These are command observations, not a full workspace, lint, release, security or independent batch gate.\n'
    path.write_text(text)
    git('config','user.name','Jeff Emanuel',cwd=work); git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--','docs/PARTIAL_CLONE_SERVING.md',cwd=work)
    git('commit','-m','docs(fetch): retain revision-bound partial-clone and pinned-client outcomes',cwd=work)
    result=git('rev-parse','HEAD',cwd=work); branch='tooling/partial-result-'+os.environ['GITHUB_SHA'][:12]
    subprocess.run(['git','push','origin',f'{result}:refs/heads/{branch}'],cwd=work,check=True)
    print('PRODUCT_RESULT',result,branch,flush=True)
    raise SystemExit(0 if all(item['exit']==0 for item in evidence) else 1)
