import json, os, pathlib, re, signal, subprocess, sys, tempfile
root=pathlib.Path(sys.argv[1]).resolve()
source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
assert source=='8262f91d25dbdd054a8e117afb3560286deeca17'
env=os.environ.copy();env.update(RCH_CARGO_WRAPPER_BYPASS='1',CARGO_BUILD_JOBS='1',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0')
commands={
 'fetch':['cargo','fetch','--locked'],
 'cli-check':['cargo','check','--offline','--locked','-p','fgit-cli','--all-targets'],
 'node-check':['cargo','check','--offline','--locked','-p','fgit-node','--all-targets'],
 'core':['cargo','test','--offline','--locked','-p','fgit-forge','-p','fgit-reference','-p','fgit-txn','--all-targets'],
 'admission':['cargo','test','--offline','--locked','-p','fgit-admission','--all-targets'],
 'node-library':['cargo','test','--offline','--locked','-p','fgit-node','--lib'],
 'cli-unit':['cargo','test','--offline','--locked','-p','fgit-cli','--bin','fg'],
 'protection-process':['cargo','test','--offline','--locked','-p','fgit-cli','--test','native_protection_smoke','--','--nocapture'],
}
label=sys.argv[2];args=commands[label]
with tempfile.TemporaryDirectory(prefix='fg-review-verification-') as td:
    log=pathlib.Path(td)/'output.log'
    with log.open('w') as out:
        child=subprocess.Popen(args,cwd=root,env=env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
        try:code=child.wait(timeout=900)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGTERM)
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
            code=124
    lines=log.read_text(errors='replace').splitlines()
    summaries=[line for line in lines if line.startswith('test result:')]
    counts=[tuple(map(int,match)) for line in summaries for match in re.findall(r'(\d+) passed; (\d+) failed; (\d+) ignored;',line)]
    entry={'label':label,'revision':source,'command':' '.join(args),'exit':code,'summaries':summaries,'totals':[sum(row[i] for row in counts) for i in range(3)]}
    print('VERIFICATION',json.dumps(entry),flush=True)
    print('\n'.join(lines[-220:] if code else [line for line in lines if line.startswith('test result:') or 'PROTECTION_' in line or 'mandatory_' in line or 'protection::' in line or 'Finished ' in line]),flush=True)
    assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip(),'verification modified source'
    raise SystemExit(code)
