import json, os, pathlib, re, signal, subprocess, sys, tempfile
root=pathlib.Path(sys.argv[1]).resolve()
source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
assert source=='ec949642f9a7e7c3943a86605cb374846890db9b'
evidence=[]
with tempfile.TemporaryDirectory(prefix='fg-ref-kind-verify-') as td:
    def run(label,args,timeout=720):
        log=pathlib.Path(td)/(label+'.log')
        with log.open('w') as output:
            child=subprocess.Popen(args,cwd=root,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGTERM)
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
                code=124
        lines=log.read_text(errors='replace').splitlines()
        summaries=[line for line in lines if line.startswith('test result:')]
        counts=[tuple(map(int,m)) for line in summaries for m in re.findall(r'(\d+) passed; (\d+) failed; (\d+) ignored;',line)]
        item={'revision':source,'label':label,'command':' '.join(args),'exit':code,'totals':[sum(row[i] for row in counts) for i in range(3)],'summaries':summaries}
        evidence.append(item)
        print('VERIFICATION',json.dumps(item),flush=True)
        print('\n'.join(lines[-240:] if code else [line for line in lines if line.startswith('test result:') or 'ref_roots::' in line or 'Finished ' in line]),flush=True)
        return code
    commands=[('object',['cargo','test','--locked','-p','fgit-git-object','--all-targets']),('node-check',['bash','scripts/verify_ref_target_integrity.sh','check']),('intake',['bash','scripts/verify_ref_target_integrity.sh','test']),('node-library',['cargo','test','--locked','-p','fgit-node','--lib','--no-fail-fast']),('bundle-regression',['cargo','test','--locked','-p','fgit-node','--lib','full_bundle','--','--nocapture'])]
    # Independent targets retain their own outcome if another target refuses;
    # the complete job still fails on any nonzero exit or interrupted command.
    for label,args in commands:
        run(label,args)
    print('FINAL_EVIDENCE',json.dumps({'source':source,'commands':evidence}),flush=True)
    assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip(),'verification changed source'
    raise SystemExit(0 if len(evidence)==len(commands) and all(item['exit']==0 for item in evidence) else 1)
