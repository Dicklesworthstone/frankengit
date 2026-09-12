import concurrent.futures, hashlib, json, os, pathlib, shutil, subprocess, tempfile, urllib.request
root=pathlib.Path.cwd()
path=root/'crates/fgit-node/src/upload_visibility/tests/partial_oracle.rs'
text=path.read_text()
needle='    let output = output.expect("pinned client wrapper launches");'
assert text.count(needle)==1
path.write_text(text.replace(needle,'    eprintln!("NATIVE_SESSION_RESULTS {results:?}");\n'+needle))
if not shutil.which('bwrap'):
    subprocess.run(['sudo','apt-get','update','-qq'],check=True,timeout=180)
    subprocess.run(['sudo','apt-get','install','-y','bubblewrap'],check=True,timeout=180)
with tempfile.TemporaryDirectory(prefix='fg-shallow-oracle-') as td:
    oracle_root=pathlib.Path(td)
    env=os.environ.copy();env.update(FGIT_ORACLE_ROOT=str(oracle_root),FGIT_ORACLE_JOBS='2')
    def build_oracle():
        pin=next(line.split('\t') for line in (root/'scripts/e2e/oracle/pins.tsv').read_text().splitlines() if line.startswith('git-2.54.0\t'))
        url,expected,name=pin[4:7]
        target=oracle_root/'downloads'/name;target.parent.mkdir()
        request=urllib.request.Request(url,headers={'User-Agent':'OpenAI File Downloader, XaiImageApiFetch/1.0'})
        digest=hashlib.sha256();count=0
        with urllib.request.urlopen(request,timeout=60) as response,target.open('xb') as out:
            while chunk:=response.read(1024*1024):
                count+=len(chunk)
                if count>128*1024*1024:raise ValueError('oracle source exceeds bound')
                out.write(chunk);digest.update(chunk)
        if digest.hexdigest()!=expected:raise ValueError('oracle source digest mismatch')
        subprocess.run(['scripts/e2e/oracle/oracle.sh','build','git-2.54.0'],env=env,check=True,timeout=600)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        oracle=pool.submit(build_oracle)
        subprocess.run(['cargo','test','--locked','-p','fgit-node','--lib','pinned_git_unshallow','--no-run'],check=True,timeout=720)
        oracle.result()
    result=subprocess.run(['cargo','test','--locked','-p','fgit-node','--lib','pinned_git_unshallow','--','--ignored','--nocapture','--test-threads=1'],env=env,timeout=180)
    for receipt in sorted((oracle_root/'runs').glob('*/transcripts/*.json')):
        item=json.loads(receipt.read_text())
        if item['exit']:
            print('FAILED_RECEIPT',json.dumps(item),flush=True)
            trace=pathlib.Path(item['packet_transcript'])
            print('FAILED_WIRE_TRACE',trace.read_text(errors='replace') if trace.exists() else 'not generated',flush=True)
    print('DIAGNOSTIC_EXIT',result.returncode,flush=True)
    raise SystemExit(result.returncode)
