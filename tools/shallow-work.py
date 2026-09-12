import concurrent.futures,hashlib,json,os,pathlib,re,shutil,signal,subprocess,tempfile,urllib.request
ROOT=pathlib.Path.cwd(); BASE='1bb686322d8bf905f17ecfa6d15c6a90f34f70e2'
def git(*args,cwd=ROOT):return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
def run(work,td,label,command,timeout=800,env=None):
    log=pathlib.Path(td)/(label+'.log')
    with log.open('w') as out:
        p=subprocess.Popen(command,cwd=work,stdout=out,stderr=subprocess.STDOUT,start_new_session=True,env=env)
        try:code=p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
            code=124
    lines=log.read_text(errors='replace').splitlines(); summaries=[x for x in lines if x.startswith('test result:')]
    item={'label':label,'command':' '.join(command),'revision':git('rev-parse','HEAD',cwd=work),'exit':code,'summaries':summaries}
    print('VERIFICATION',json.dumps(item),flush=True)
    print('\n'.join(lines[-200:] if code else [x for x in lines if x.startswith('test result:') or 'PINNED_SHALLOW_CELL' in x or 'FGIT_ORACLE_' in x or 'Finished ' in x]),flush=True)
    return item
with tempfile.TemporaryDirectory(prefix='fg-shallow-oracle-') as td:
    work=pathlib.Path(td)/'source';subprocess.run(['git','worktree','add','--detach',str(work),BASE],check=True)
    subprocess.run(['python3',str(ROOT/'tools/shallow-oracle-payload/apply.py'),str(work)],check=True)
    paths=['crates/fgit-node/src/upload_visibility/tests.rs','crates/fgit-node/src/upload_visibility/tests/partial_oracle.rs','crates/fgit-node/src/upload_visibility/tests/shallow_oracle.rs','scripts/e2e/oracle/partial_clone_client.py']
    for path in paths:
        if path.endswith('.rs'):subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',path],cwd=work,check=True)
    script=work/paths[-1];compile(script.read_text(),str(script),'exec')
    files=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    assert files==set(paths),files
    subprocess.run(['git','diff','--check'],cwd=work,check=True)
    git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*paths,cwd=work)
    git('commit','-m','test(fetch): exercise complete shallow lifecycles with the pinned Git client','-m','Reuse the existing source/binary-verified, Bubblewrap-contained oracle and bounded live TCP sessions. Verify depth-one clone, exact inventories, ordinary checkout, depth change on a common tip, subsequent server advancement and incremental fetch, unshallow, native ancestry and strict fsck. Cover both hashes, three protocols, and full/blobless/treeless profiles without a production Git subprocess or relaxed isolation.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work); branch='tooling/shallow-oracle-'+os.environ['GITHUB_SHA'][:12]
    subprocess.run(['git','push','origin',source+':refs/heads/'+branch],cwd=work,check=True)
    print('PRODUCT_SOURCE',source,branch,flush=True)
    evidence=[]
    if not shutil.which('bwrap'):
        for label,cmd in [('sandbox-index',['sudo','apt-get','update','-qq']),('sandbox-install',['sudo','apt-get','install','-y','bubblewrap'])]:
            item=run(work,td,label,cmd,180);evidence.append(item)
            if item['exit']:raise SystemExit(item['exit'])
    oracle_root=pathlib.Path('/tmp')/('fg-shallow-verified-'+os.environ['GITHUB_SHA'][:12]);oracle_root.mkdir(exist_ok=False)
    env=os.environ.copy();env['FGIT_ORACLE_ROOT']=str(oracle_root);env['FGIT_ORACLE_JOBS']='2'
    def build_oracle():
        pin=next(line.split('\t') for line in (work/'scripts/e2e/oracle/pins.tsv').read_text().splitlines() if line.startswith('git-2.54.0\t'))
        url,expected,filename=pin[4:7];download=oracle_root/'downloads'/filename;download.parent.mkdir()
        req=urllib.request.Request(url,headers={'User-Agent':'OpenAI File Downloader, XaiImageApiFetch/1.0'});digest=hashlib.sha256();count=0
        with urllib.request.urlopen(req,timeout=60) as response,download.open('xb') as out:
            while chunk:=response.read(1024*1024):
                count+=len(chunk);assert count<=128*1024*1024;out.write(chunk);digest.update(chunk)
        assert digest.hexdigest()==expected,(digest.hexdigest(),expected)
        print('ORACLE_SOURCE',url,'SHA256',expected,'BYTES',count,flush=True)
        return run(work,td,'oracle-build',['scripts/e2e/oracle/oracle.sh','build','git-2.54.0'],900,env)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        oracle=pool.submit(build_oracle)
        for label,cmd in [('cli-check',['cargo','check','--locked','-p','fgit-cli','--all-targets']),('node-shallow',['cargo','test','--locked','-p','fgit-node','--lib','shallow','--','--nocapture'])]:
            item=run(work,td,label,cmd);evidence.append(item)
            if item['exit']:break
        evidence.append(oracle.result())
    if all(item['exit']==0 for item in evidence):
        evidence.append(run(work,td,'pinned-shallow',['cargo','test','--locked','-p','fgit-node','--lib','pinned_git_shallow_clone_deepen_incremental_fetch_and_unshallow','--','--ignored','--nocapture'],1000,env))
    for log in sorted((oracle_root/'runs').glob('*/transcripts/*.packets')):
        print('WIRE_TRACE',log.name,'\n'.join(log.read_text(errors='replace').splitlines()[-60:]),flush=True)
    for receipt in sorted((oracle_root/'runs').glob('*/transcripts/*.json')):
        print('PINNED_RECEIPT',receipt.read_text().strip(),flush=True)
    assert not git('status','--porcelain',cwd=work)
    print('FINAL_EVIDENCE',json.dumps({'revision':source,'commands':evidence}),flush=True)
    if any(item['exit'] for item in evidence):raise SystemExit(1)
    print('ORACLE_READY',source,flush=True)
