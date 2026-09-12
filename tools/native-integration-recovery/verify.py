import json, os, pathlib, re, signal, subprocess, sys, tempfile
work=pathlib.Path(sys.argv[1]).resolve()
revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=work,text=True).strip()
commands=[('cli-check',['cargo','check','--locked','-p','fgit-cli','--all-targets']),('canonical-tests',['cargo','test','--locked','-p','fgit-reference','-p','fgit-txn','-p','fgit-forge','--all-targets','--no-fail-fast']),('issue-admission',['cargo','test','--locked','-p','fgit-admission','--all-targets','issue','--','--nocapture']),('issue-node',['cargo','test','--locked','-p','fgit-node','--lib','issue','--','--nocapture'])]
evidence=[]
with tempfile.TemporaryDirectory(prefix='fg-recovery-logs-') as td:
    for label,args in commands:
        log=pathlib.Path(td)/(label+'.log')
        with log.open('w') as out:
            child=subprocess.Popen(args,cwd=work,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=child.wait(timeout=900)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGTERM)
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
                code=124
        lines=log.read_text(errors='replace').splitlines()
        summaries=[line for line in lines if line.startswith('test result:')]
        item={'label':label,'revision':revision,'command':' '.join(args),'exit':code,'summaries':summaries}
        evidence.append(item)
        print('VERIFICATION',json.dumps(item),flush=True)
        print('\n'.join(lines[-200:] if code else [line for line in lines if line.startswith('test result:') or 'Finished ' in line or 'issue' in line]),flush=True)
        if code:break
    print('FINAL_EVIDENCE',json.dumps(evidence),flush=True)
    assert not subprocess.check_output(['git','status','--porcelain'],cwd=work,text=True).strip()
    raise SystemExit(0 if all(item['exit']==0 for item in evidence) else 1)
