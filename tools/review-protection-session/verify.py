import json, os, pathlib, re, signal, subprocess, sys, tempfile
root=pathlib.Path(sys.argv[1]).resolve()
source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
env=os.environ.copy();env.update(RCH_CARGO_WRAPPER_BYPASS='1',CARGO_BUILD_JOBS='1',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0')
evidence=[]
with tempfile.TemporaryDirectory(prefix='fg-review-verification-') as td:
    def run(label,args,timeout=720):
        log=pathlib.Path(td)/(label+'.log')
        with log.open('w') as out:
            child=subprocess.Popen(args,cwd=root,env=env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGTERM)
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
                code=124
        lines=log.read_text(errors='replace').splitlines()
        summaries=[line for line in lines if line.startswith('test result:')]
        counts=[tuple(map(int,match)) for line in summaries for match in re.findall(r'(\d+) passed; (\d+) failed; (\d+) ignored;',line)]
        entry={'label':label,'revision':source,'command':' '.join(args),'exit':code,'summaries':summaries,'totals':[sum(row[i] for row in counts) for i in range(3)]}
        evidence.append(entry)
        print('VERIFICATION',json.dumps(entry),flush=True)
        print('\n'.join(lines[-180:] if code else [line for line in lines if line.startswith('test result:') or 'PROTECTION_' in line or 'mandatory_' in line or 'protection::' in line or 'Finished ' in line]),flush=True)
        return code
    commands=[('fetch',['cargo','fetch','--locked']),('cli-check',['cargo','check','--offline','--locked','-p','fgit-cli','--all-targets']),('core',['cargo','test','--offline','--locked','-p','fgit-forge','-p','fgit-reference','-p','fgit-txn','--all-targets']),('admission',['cargo','test','--offline','--locked','-p','fgit-admission','--all-targets']),('node-library',['cargo','test','--offline','--locked','-p','fgit-node','--lib']),('cli-unit',['cargo','test','--offline','--locked','-p','fgit-cli','--bin','fg']),('protection-process',['cargo','test','--offline','--locked','-p','fgit-cli','--test','native_protection_smoke','--','--nocapture'])]
    for label,args in commands:
        if run(label,args):break
    print('FINAL_EVIDENCE',json.dumps({'source':source,'commands':evidence}),flush=True)
    assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip(),'verification modified source'
    raise SystemExit(0 if len(evidence)==len(commands) and all(item['exit']==0 for item in evidence) else 1)
