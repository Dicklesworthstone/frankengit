import json, os, pathlib, re, shutil, signal, subprocess, sys, tempfile
work=pathlib.Path(sys.argv[1]).resolve()
revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=work,text=True).strip()
for name in ['br','bv']:
    print('TRACKER_AVAILABLE',name,bool(shutil.which(name)),flush=True)
for name,headings in [('COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md',['## 25.','## 32.']),('docs/NORMATIVE_PROTOCOL_CONTRACTS.md',['## 10.','## 20.'])]:
    lines=(work/name).read_text().splitlines()
    selected=False
    for i,line in enumerate(lines):
        if line.startswith('## '):selected=any(line.startswith(heading) for heading in headings)
        if selected:print('CONTRACT',name,i+1,line,flush=True)
for line in (work/'.beads/issues.jsonl').read_text().splitlines():
    item=json.loads(line)
    if item.get('id') in ['frankengit-fg043r','frankengit-asa3'] or ('protection' in item.get('title','').lower() and item.get('status')!='closed'):
        print('BEAD_READ_ONLY',json.dumps(item),flush=True)
commands=[('cli-check',['cargo','check','--locked','-p','fgit-cli','--all-targets']),('reference-tests',['cargo','test','--locked','-p','fgit-reference','--all-targets']),('forge-tests',['cargo','test','--locked','-p','fgit-forge','--all-targets'])]
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
        print('\n'.join(lines[-180:] if code else [line for line in lines if line.startswith('test result:') or 'Finished ' in line]),flush=True)
        if code:break
    print('FINAL_EVIDENCE',json.dumps(evidence),flush=True)
    assert not subprocess.check_output(['git','status','--porcelain'],cwd=work,text=True).strip()
    raise SystemExit(0 if all(item['exit']==0 for item in evidence) else 1)
