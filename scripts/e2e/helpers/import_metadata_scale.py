"""Real fg import, bounded failures, source-free recovery and exact cold exports."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from import_metadata_fixture import build
FG, ROOT = sys.argv[1], Path(sys.argv[2]).resolve()
COUNT = int(os.environ.get('FGE_IMPORT_FILES', '100000'))
assert 64 <= COUNT <= 100000
ROOT.mkdir(parents=True, exist_ok=True)
TENANT, REPO, PRINCIPAL = 'd1'*16, 'd2'*16, 'd3'*16
SEQUENCE, RESULTS = 0, []
ENV = {**os.environ, 'GIT_CONFIG_NOSYSTEM':'1', 'GIT_CONFIG_GLOBAL':'/dev/null', 'GIT_TERMINAL_PROMPT':'0', 'LC_ALL':'C'}
def invoke(label, args, code=0, timeout=1900, stdin=None):
    global SEQUENCE
    SEQUENCE += 1
    out, err = (ROOT / f'{SEQUENCE:03d}-{label}.{suffix}' for suffix in ('out','err'))
    start = time.monotonic()
    with out.open('wb') as stdout, err.open('wb') as stderr:
        done = subprocess.run(list(map(str,args)), stdout=stdout, stderr=stderr, stdin=stdin, env=ENV, timeout=timeout)
    diagnostic = err.read_bytes()
    if diagnostic: sys.stderr.buffer.write(diagnostic); sys.stderr.buffer.flush()
    assert done.returncode == code, (label, done.returncode, diagnostic[-4000:], out.read_bytes()[-4000:])
    return out, diagnostic, time.monotonic()-start

def record(fmt, case, **values):
    row = dict(format=fmt, case=case, **values)
    RESULTS.append(row); print(json.dumps(row), flush=True)

def exact_objects(repository, expected):
    out,_,_=invoke('all-exported-objects',['git','-C',repository,'cat-file','--batch-all-objects','--batch'],timeout=180)
    seen=set()
    with out.open('rb') as stream:
        while line:=stream.readline():
            oid,kind,length=line.decode().rstrip('\n').split(' ');length=int(length)
            assert oid not in seen and oid in expected and 0<=length<=128*1024
            body=stream.read(length);assert stream.read(1)==b'\n'
            assert (kind,body)==expected[oid],oid
            seen.add(oid)
    assert seen==set(expected),(len(seen),len(expected))

version,_,_=invoke('git-version',['git','--version'],timeout=10)
print(json.dumps({'client':version.read_text().strip(),'profile':'ordinary stock test client, not pinned Tier A oracle','files':COUNT}),flush=True)
for fmt in ('sha1','sha256'):
    root=ROOT/fmt;root.mkdir();source,node=root/'source',root/'node';source.mkdir()
    tip,objects,source_pack=build(source,fmt,COUNT);scope=[node,TENANT,REPO]
    invoke('init',[FG,'init',*scope,fmt],timeout=30)
    refs=lambda label:invoke(label,[FG,'at',*scope,'latest','refs'],timeout=30)[0].read_bytes()
    before=refs('refs-before')
    for label,extra in [('global-only',[]),('both-deadlines',['--timeout-secs','1800']),('explicit-profile',['--max-expanded-mib','512','--timeout-secs','1800'])]:
        out,error,_=invoke(label,[FG,'--timeout-secs','0.000000001','import',*scope,PRINCIPAL,'strict-global',root/'absent-source',*extra,'--json'],code=2,timeout=10)
        assert b'source import interrupted' in error and b'Deadline' in error and not out.read_bytes()
        assert refs('refs-after-deadline')==before
        record(fmt,label,no_source_read=True,refs_unchanged=True)
    if sum(len(body) for _,body in objects.values())>1024*1024:
        _,error,_=invoke('expanded-limit',[FG,'import',*scope,PRINCIPAL,'too-small-payload',source,'--max-expanded-mib','1','--json'],code=2)
        assert b'byte' in error.lower() and refs('refs-after-expanded-limit')==before
        record(fmt,'expanded-payload-bound-remains-independent',refs_unchanged=True)
    args=['import',*scope,PRINCIPAL,'metadata-scale-import',source,'--json']
    output,_,seconds=invoke('large-import',[FG,'--timeout-secs','1800',*args])
    terminal=json.loads(output.read_text());assert terminal['state']=='committed' and terminal['atomic'] and terminal['node_closed']
    assert terminal['command_count']==1 and tip.encode()in refs('refs-after-import')
    record(fmt,'native-large-publication',objects=len(objects),files=COUNT,source_tip=tip,source_pack=source_pack,elapsed_seconds=seconds)
    again,_,_=invoke('identical-import-retry',[FG,'--timeout-secs','1800',*args])
    assert json.loads(again.read_text())==terminal
    record(fmt,'identical-key-preserves-terminal-decision',tx_id=terminal['tx_id'],decision_sequence=terminal['decision_sequence'])
    source.rename(root/'source-offline')
    assert not source.exists()
    outcome,_,_=invoke('source-free-recovery',[FG,'outcome',*scope,'--trusted-local','--principal',PRINCIPAL,'--idempotency-key','metadata-scale-import','--object-format',fmt],timeout=30)
    json.loads(outcome.read_text());assert terminal['tx_id']in outcome.read_text() and 'committed'in outcome.read_text()
    record(fmt,'cold-source-free-outcome-recovery',original_source_path_absent=True)
    exported=root/'native.pack';invoke('native-export',[FG,'--timeout-secs','300','export',*scope,exported],timeout=330)
    imported=root/'export-consumer';invoke('init-export-consumer',['git','init','--bare',f'--object-format={fmt}',imported],timeout=20)
    with exported.open('rb')as stream:invoke('index-export',['git','-C',imported,'index-pack','--stdin','--strict'],stdin=stream,timeout=180)
    exact_objects(imported,objects)
    invoke('export-ref',['git','-C',imported,'update-ref','refs/heads/main',tip],timeout=10)
    invoke('export-fsck',['git','-C',imported,'fsck','--strict'],timeout=180)
    record(fmt,'cold-export-all-object-bytes',verified_objects=len(objects),pack_sha256=hashlib.sha256(exported.read_bytes()).hexdigest())
(ROOT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
