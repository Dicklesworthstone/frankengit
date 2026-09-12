import json,os,pathlib,re,signal,subprocess,sys,tempfile
work=pathlib.Path(sys.argv[1]).resolve();source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=work,text=True).strip()
commands=[['cargo','check','--locked','-p','fgit-cli','--all-targets'],['cargo','test','--locked','-p','fgit-node','--lib','treefs_workspace::issues','--','--nocapture'],['cargo','test','--locked','-p','fgit-forge','-p','fgit-reference','-p','fgit-schema','--all-targets','--no-fail-fast'],['cargo','test','--locked','-p','fgit-node','--lib','treefs_workspace::pull_request']]
with tempfile.TemporaryDirectory(prefix='fg-issue-verify-') as td:
    for index,args in enumerate(commands):
        log=pathlib.Path(td)/f'{index}.log'
        with log.open('w') as output:
            p=subprocess.Popen(args,cwd=work,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=p.wait(timeout=900)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid,signal.SIGTERM)
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
                code=124
        lines=log.read_text().splitlines();summaries=[s for s in lines if s.startswith('test result:')]
        counts=[tuple(map(int,m)) for s in summaries for m in re.findall(r'(\d+) passed; (\d+) failed; (\d+) ignored;',s)]
        print('VERIFICATION',json.dumps({'source':source,'command':' '.join(args),'exit':code,'totals':[sum(c[i] for c in counts) for i in range(3)],'summaries':summaries}),flush=True)
        print('\n'.join(lines[-220:] if code else [s for s in lines if 'issues::' in s or 'issue::' in s or 'Finished ' in s]),flush=True)
        if code:raise SystemExit(code)
    assert not subprocess.check_output(['git','status','--porcelain'],cwd=work,text=True).strip()
