import json, os, pathlib, re, signal, subprocess, sys, tempfile
work=pathlib.Path(sys.argv[1]).resolve()
revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=work,text=True).strip()
commands=[
 ('cli-check',['cargo','check','--locked','-p','fgit-cli','--all-targets']),
 ('issue-cli-unit',['cargo','test','--locked','-p','fgit-cli','--bin','fg','issues::','--','--nocapture']),
 ('issue-cli-process',['cargo','test','--locked','-p','fgit-cli','--test','native_issue_smoke','--','--nocapture']),
 ('issue-node',['cargo','test','--locked','-p','fgit-node','--lib','issues','--','--nocapture']),
 ('canonical-tests',['cargo','test','--locked','-p','fgit-reference','-p','fgit-txn','-p','fgit-forge','--all-targets','--no-fail-fast']),
]
evidence=[]
with tempfile.TemporaryDirectory(prefix='fg-issue-cli-logs-') as td:
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
        counts=[tuple(map(int,match)) for line in summaries for match in re.findall(r'(\d+) passed; (\d+) failed; (\d+) ignored;',line)]
        item={'label':label,'revision':revision,'command':' '.join(args),'exit':code,'totals':[sum(row[i] for row in counts) for i in range(3)],'summaries':summaries}
        evidence.append(item)
        print('VERIFICATION',json.dumps(item),flush=True)
        print('\n'.join(lines[-200:] if code else [line for line in lines if line.startswith('test result:') or 'Finished ' in line or 'issue' in line]),flush=True)
        if code:break
    print('FINAL_EVIDENCE',json.dumps(evidence),flush=True)
    assert not subprocess.check_output(['git','status','--porcelain'],cwd=work,text=True).strip()
    raise SystemExit(0 if all(item['exit']==0 for item in evidence) else 1)
