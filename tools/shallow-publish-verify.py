import concurrent.futures, hashlib, json, os, pathlib, re, shutil, signal, subprocess, sys, tempfile, urllib.request
work=pathlib.Path(sys.argv[1]).resolve()
source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=work,text=True).strip()
evidence=[]
def run(td,label,args,env=None,timeout=900):
    log=pathlib.Path(td)/(label+'.log')
    with log.open('w') as out:
        child=subprocess.Popen(args,cwd=work,env=env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
        try: code=child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGTERM)
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
            code=124
    lines=log.read_text(errors='replace').splitlines()
    summaries=[line for line in lines if line.startswith('test result:')]
    counts=[tuple(map(int,match)) for line in summaries for match in re.findall(r'(\d+) passed; (\d+) failed; (\d+) ignored;',line)]
    item={'label':label,'command':' '.join(args),'revision':source,'exit':code,'totals':[sum(row[i] for row in counts) for i in range(3)],'summaries':summaries}
    print('VERIFICATION',json.dumps(item),flush=True)
    print('\n'.join(lines[-160:] if code else [line for line in lines if line.startswith('test result:') or 'PINNED_SHALLOW_' in line or 'PINNED_PARTIAL_CELL' in line or 'FGIT_ORACLE_OK' in line or 'Finished ' in line]),flush=True)
    return item
with tempfile.TemporaryDirectory(prefix='fg-shallow-complete-') as td:
    oracle_root=pathlib.Path(td)/'oracle';oracle_root.mkdir()
    env=os.environ.copy();env.update(FGIT_ORACLE_ROOT=str(oracle_root),FGIT_ORACLE_JOBS='2')
    def build_oracle():
        if not shutil.which('bwrap'):
            for label,args in [('sandbox-index',['sudo','apt-get','update','-qq']),('sandbox-install',['sudo','apt-get','install','-y','bubblewrap'])]:
                item=run(td,label,args,timeout=180)
                if item['exit']:return item
        pin=next(line.split('\t') for line in (work/'scripts/e2e/oracle/pins.tsv').read_text().splitlines() if line.startswith('git-2.54.0\t'))
        url,expected,name=pin[4:7];target=oracle_root/'downloads'/name;target.parent.mkdir()
        request=urllib.request.Request(url,headers={'User-Agent':'OpenAI File Downloader, XaiImageApiFetch/1.0'})
        digest=hashlib.sha256();count=0
        with urllib.request.urlopen(request,timeout=60) as response,target.open('xb') as out:
            while chunk:=response.read(1024*1024):
                count+=len(chunk)
                if count>128*1024*1024:raise ValueError('oracle archive exceeds bound')
                out.write(chunk);digest.update(chunk)
        if digest.hexdigest()!=expected:raise ValueError('oracle digest mismatch')
        print('PINNED_SOURCE',expected,count,flush=True)
        return run(td,'oracle-build',['scripts/e2e/oracle/oracle.sh','build','git-2.54.0'],env,720)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        oracle=pool.submit(build_oracle)
        for label,args in [
            ('wire',['cargo','test','--locked','-p','fgit-wire','--all-targets']),
            ('cli-check',['cargo','check','--locked','-p','fgit-cli','--all-targets']),
            ('node-library',['cargo','test','--locked','-p','fgit-node','--lib']),
            ('daemon-integration',['cargo','test','--locked','-p','fgit-node','--test','git_daemon_deadline','--test','git_daemon_receive_transport','--test','git_daemon_v1','--test','git_daemon_v2','--test','hidden_ref_policy_end_to_end','--no-fail-fast'])]:
            item=run(td,label,args);evidence.append(item)
            if item['exit']:break
        evidence.append(oracle.result())
    if all(item['exit']==0 for item in evidence):
        evidence.append(run(td,'pinned-multi',['cargo','test','--locked','-p','fgit-node','--lib','pinned_git_unshallow','--','--ignored','--nocapture','--test-threads=1'],env,180))
    if all(item['exit']==0 for item in evidence):
        evidence.append(run(td,'pinned-shallow-lifecycle',['cargo','test','--locked','-p','fgit-node','--lib','pinned_git_shallow_clone','--','--ignored','--nocapture','--test-threads=1'],env,900))
    if all(item['exit']==0 for item in evidence):
        evidence.append(run(td,'pinned-partial',['cargo','test','--locked','-p','fgit-node','--lib','pinned_git_partial_clone','--','--ignored','--nocapture','--test-threads=1'],env,180))
    print('FINAL_EVIDENCE',json.dumps({'revision':source,'commands':evidence}),flush=True)
    for path in sorted((oracle_root/'runs').glob('*/transcripts/*.json')):
        item=json.loads(path.read_text())
        if item['exit']:
            print('FAILED_RECEIPT',json.dumps(item),flush=True)
            trace=pathlib.Path(item['packet_transcript'])
            print('FAILED_WIRE_TRACE',trace.read_text(errors='replace') if trace.exists() else 'not generated',flush=True)
    if subprocess.check_output(['git','status','--porcelain'],cwd=work,text=True).strip():raise RuntimeError('verification changed product source')
    raise SystemExit(0 if all(item['exit']==0 for item in evidence) else 1)
