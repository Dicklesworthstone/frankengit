import json,os,pathlib,signal,subprocess,sys,tempfile
work=pathlib.Path(sys.argv[1]).resolve();source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=work,text=True).strip()
commands=[('fetch',['cargo','fetch','--locked']),('check',['cargo','check','--locked','--offline','-p','fgit-node','--all-targets']),('forge',['cargo','test','--locked','--offline','-p','fgit-forge','--all-targets']),('protection',['cargo','test','--locked','--offline','-p','fgit-node','--lib','repository_protection','--','--nocapture'])]
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
  lines=log.read_text(errors='replace').splitlines()
  print('VERIFICATION',json.dumps({'revision':source,'command':command,'exit':code}),flush=True)
  print('\n'.join(lines[-180:] if code else [line for line in lines if line.startswith('test result:') or 'Finished ' in line or 'repository_protection' in line]),flush=True)
  if code:raise SystemExit(code)
 assert not subprocess.check_output(['git','status','--porcelain'],cwd=work,text=True).strip()
