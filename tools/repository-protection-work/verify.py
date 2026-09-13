import json,os,pathlib,signal,subprocess,sys,tempfile,re
work=pathlib.Path(sys.argv[1]).resolve();source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=work,text=True).strip()
commands=[('fetch',['cargo','fetch','--locked']),('check',['cargo','check','--locked','--offline','-p','fgit-cli','--all-targets']),('protection',['cargo','test','--locked','--offline','-p','fgit-node','--lib','repository_protection','--','--nocapture']),('forge',['cargo','test','--locked','--offline','-p','fgit-forge','-p','fgit-reference','-p','fgit-txn','--all-targets']),('cli',['cargo','test','--locked','--offline','-p','fgit-cli','--bin','fg','protection::']),('process',['cargo','test','--locked','--offline','-p','fgit-cli','--test','native_protection_smoke','--','--nocapture'])]
with tempfile.TemporaryDirectory(prefix='fg-protection-logs-') as td:
 for label,command in commands:
  log=pathlib.Path(td)/(label+'.log')
  with log.open('w') as out:
   process=subprocess.Popen(command,cwd=work,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
   try:code=process.wait(timeout=720)
   except subprocess.TimeoutExpired:
    os.killpg(process.pid,signal.SIGTERM)
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
    code=124
  lines=log.read_text(errors='replace').splitlines();summaries=[line for line in lines if line.startswith('test result:')]
  counts=[tuple(map(int,x)) for line in summaries for x in re.findall(r'(\d+) passed; (\d+) failed; (\d+) ignored;',line)]
  print('VERIFICATION',json.dumps({'revision':source,'command':command,'exit':code,'totals':[sum(x[i] for x in counts) for i in range(3)],'summaries':summaries}),flush=True)
  print('\n'.join(lines[-220:] if code else [line for line in lines if line.startswith('test result:') or 'Finished ' in line or 'repository_protection' in line or 'PROTECTION_CLI' in line]),flush=True)
  if code:raise SystemExit(code)
 assert not subprocess.check_output(['git','status','--porcelain'],cwd=work,text=True).strip()
