import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import zlib

FG, ROOT = sys.argv[1], Path(sys.argv[2]).resolve()
BASELINE = len(sys.argv) > 3 and sys.argv[3] == '--baseline'
ROOT.mkdir(parents=True, exist_ok=True)
T, R, P, REF = '91'*16, '92'*16, '93'*16, 'refs/heads/main'
SEQ, RESULTS = 0, []
def run(label, args, timeout='60', expected=0):
    global SEQ
    SEQ += 1
    cmd = [FG] + (['--timeout-secs', timeout] if timeout is not None else []) + list(map(str, args))
    proc = subprocess.run(cmd, capture_output=True, timeout=45)
    (ROOT/f'{SEQ:03d}-{label}.out').write_bytes(proc.stdout)
    (ROOT/f'{SEQ:03d}-{label}.err').write_bytes(proc.stderr)
    if proc.stderr: sys.stderr.buffer.write(proc.stderr); sys.stderr.buffer.flush()
    assert expected is None or (proc.returncode != 0 if expected == 'fail' else proc.returncode == expected), (label,proc.returncode,proc.stdout,proc.stderr)
    return proc

def record(fmt, case, **facts):
    row = dict(format=fmt, case=case, **facts); RESULTS.append(row); print(json.dumps(row), flush=True)
def one(proc): return json.loads(proc.stdout)
def fixture(fmt, label):
    root = ROOT/(fmt+'-'+label); root.mkdir()
    source, node = root/'source', root/'node'
    (source/'refs/heads').mkdir(parents=True)
    (source/'HEAD').write_text(f'ref: {REF}\n')
    (source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('1\n[extensions]\nobjectformat=sha256\n' if fmt=='sha256' else '0\n'))
    def obj(kind, body):
        raw = kind.encode()+b' '+str(len(body)).encode()+b'\0'+body
        oid = hashlib.new(fmt, raw).hexdigest(); path=source/'objects'/oid[:2]/oid[2:]
        path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(zlib.compress(raw)); return oid
    blob=obj('blob', b'pub fn Needle() {}\n')
    tree=obj('tree', b'100644 lib.rs\0'+bytes.fromhex(blob))
    tree=obj('tree', b'40000 src\0'+bytes.fromhex(tree))
    tip=obj('commit',f'tree {tree}\nauthor Test <a@example.invalid> 1 +0000\ncommitter Test <a@example.invalid> 1 +0000\n\nfixture\n'.encode())
    (source/REF).write_text(tip+'\n')
    scope=[node,T,R];run('init',['init',*scope,fmt]);run('import',['import',*scope,P,'seed',source])
    return root,scope,[*scope,fmt,REF]

for fmt in ('sha1','sha256'):
    root,scope,base=fixture(fmt,'normal')
    authority=run('refs-before',['at',*scope,'latest','refs']).stdout
    if BASELINE:
        for command in (['index'],['index','symbols']):
            p=run('baseline-expired-build',[*command,*base,'build','genesis'],'0.000000001',None)
            record(fmt,'expired-budget-was-ignored',command=command,exit=p.returncode,activation=p.stdout.decode().strip())
            assert p.returncode==0 and b'activation' in p.stdout
        continue
    for command,alias,query in [(['index'],['index'],['query','content','needle']),(['index','symbols'],['symbol-index'],['query','exact','Needle'])]:
        kind=command[-1]
        for spelling in [command,alias]:
            p=run('expired-build',[*spelling,*base,'build','genesis'],'0.000000001','fail')
            assert b'ResourceBudgetExceeded' in p.stderr and b'activation' not in p.stdout
        built=one(run('permitted-build',[*command,*base,'build','genesis']))
        token=built['index_token'];assert built['index_number']==1
        record(fmt,kind+'-expired-genesis-does-not-publish',number=built['index_number'])
        for action in [['refresh',token],['recover',token],query]:
            p=run('expired-operation',[*alias,*base,*action],'0.000000001','fail');assert b'ResourceBudgetExceeded' in p.stderr
        before=one(run('query-before',[*alias,*base,*query]));assert before['index_token']==token
        assert one(run('recover-original',[*alias,*base,'recover',token]))['state']=='active'
        refreshed=one(run('refresh-original',[*command,*base,'refresh',token]))
        assert one(run('query-refreshed',[*alias,*base,*query]))['index_token']==refreshed['index_token']
        record(fmt,kind+'-expiry-preserves-original-generation-and-recovery')
    records=root/'records';records.mkdir(mode=0o700);candidate=records/'candidate.json'
    scoped=['build',*base,'--trusted-local','--prefix','src','--candidate-file',candidate]
    for spelling in [['index','scope'],['index-scope']]:
        run('expired-scoped',[*spelling,*scoped],'0.000000001','fail');assert not candidate.exists()
    built=one(run('build-scoped',['index','scope',*scoped]));assert built['index_published'] and candidate.exists()
    token=built['index_token']; saved=candidate.read_bytes()
    scopedbase=[*base,'--trusted-local','--prefix','src']
    for action,flags in [('search',['--term','needle']),('recover',['--candidate',token])]:
        run('expired-scoped-'+action,['index-scope',action,*scopedbase,*flags],'0.000000001','fail')
        result=one(run('scoped-'+action,['index','scope',action,*scopedbase,*flags]))
        if action=='recover':assert result['state']=='active'
    assert candidate.read_bytes()==saved
    record(fmt,'scoped-expiry-preserves-candidate-and-original-recovery')
    for symbols in (False,True):
        state=root/('symbol-state' if symbols else 'lexical-state');state.mkdir(mode=0o700)
        arguments=(['--symbols'] if symbols else [])+[*scope,fmt,state,'init','1','0',REF]
        for spelling in [['index','maintain'],['index-maintain']]:
            run('expired-maintenance',[*spelling,*arguments],'0.000000001','fail')
            assert not (state/'checkpoint').exists() and not (state/'run.lock').exists()
        run('maintenance-init',['index','maintain',*arguments])
        before=(state/'checkpoint').read_bytes()
        arguments[-4:]=['resume','2','30',REF]
        started=time.monotonic()
        p=run('maintenance-idle-expiry',['index-maintain',*arguments],'2','fail')
        assert time.monotonic()-started<8 and b'ResourceBudgetExceeded' in p.stderr
        observations=[json.loads(l) for l in p.stdout.splitlines()]
        assert len(observations)==1 and observations[0]['state']=='observed_current'
        assert (state/'checkpoint').read_bytes()==before and not (state/'run.lock').exists()
        arguments[-4:]=['resume','1','0',REF]
        run('maintenance-resume',['index','maintain',*arguments])
        assert (state/'checkpoint').read_bytes()==before
        record(fmt,('symbol' if symbols else 'lexical')+'-whole-maintenance-deadline-includes-idle-with-clean-resume')
    assert run('refs-after',['at',*scope,'latest','refs']).stdout==authority
    record(fmt,'all-derived-work-leaves-canonical-refs-unchanged')
(ROOT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
