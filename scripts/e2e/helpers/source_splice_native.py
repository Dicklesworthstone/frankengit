"""Actual Node file-plan CLI -> native fg prepare -> ordinary admission and recovery.
Fixture encoders and bundle verification use Python stdlib; no Git oracle or mock service.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patch_smoke import loose, tree, oid, bundle_objects
FG, ROOT = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
NODE = os.environ.get('NODE_BIN') or shutil.which('node')
assert NODE, 'explicit NODE_BIN or node on PATH required'
CLI = Path(__file__).resolve().parents[2] / 'fg_source_patch.mjs'
ROOT.mkdir(parents=True, exist_ok=True)
SEQUENCE, RESULTS = 0, []
def run(label, binary, args, code=0):
    global SEQUENCE
    SEQUENCE += 1
    out, err = (ROOT / f'{SEQUENCE:03d}-{label}.{suffix}' for suffix in ('out','err'))
    with out.open('wb') as stdout, err.open('wb') as stderr:
        done = subprocess.run([binary, *map(str,args)], stdout=stdout, stderr=stderr, timeout=120)
    diagnostic=err.read_bytes()
    if diagnostic: sys.stderr.buffer.write(diagnostic); sys.stderr.buffer.flush()
    assert done.returncode == code, (label, done.returncode, out.read_bytes()[-3000:], diagnostic[-3000:])
    return out.read_bytes()
def case(fmt, profile, name, **values):
    row=dict(format=fmt, profile=profile, case=name, **values); RESULTS.append(row);print(json.dumps(row),flush=True)
def private(path, data):
    path.write_bytes(data);path.chmod(0o600);return str(path)
print(json.dumps({'node_version':run('node-version',NODE,['--version']).decode().strip()}),flush=True)
for fmt in ('sha1','sha256'):
    for profile in ('literal','delta','delta-runs'):
        home=ROOT/(fmt+'-'+profile);home.mkdir(mode=0o700)
        source,node=home/'source',home/'node';(source/'refs/heads').mkdir(parents=True)
        (source/'HEAD').write_text('ref: refs/heads/main\n')
        (source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('0\n' if fmt=='sha1' else '1\n[extensions]\nobjectformat=sha256\n'))
        original=bytearray(b'\0a\r\n' if profile=='literal' else b'\0'+b'a'*(1048576-1))
        positions=[1] if profile=='literal' else [524288] if profile=='delta' else [100, len(original)-100]
        replacement=b'b'*400000 if profile=='literal' else b'b'
        desired=bytes(original)
        for pos in reversed(positions):desired=desired[:pos]+replacement+desired[pos+1:]
        old=loose(source,fmt,'blob',bytes(original));keep=loose(source,fmt,'blob',b'untouched\0sibling')
        base_tree=loose(source,fmt,'tree',tree([('asset.bin','100644',old),('keep.bin','100644',keep)]))
        author='Native Splice <test@example.invalid>'
        base=loose(source,fmt,'commit',f'tree {base_tree}\nauthor {author} 1 +0000\ncommitter {author} 1 +0000\n\nbase\n'.encode())
        (source/'refs/heads/main').write_text(base+'\n')
        scope=[node,'e1'*16,'e2'*16];principal='e3'*16
        run('init',FG,['init',*scope,fmt]);run('import',FG,['import',*scope,principal,'fixture',source])
        put=lambda name,data:private(home/name,data)
        plan={'schema':'frankengit-source-splice-files-v1','object_format':fmt,'files':[{
            'path_hex':b'asset.bin'.hex(),'before':{'file':put('original',bytes(original)),'blob':old,'mode':0o100644},'after_mode':0o100755,
            'edits':[{'byte_start':pos,'before':{'file':put(f'before-{pos}',bytes([original[pos]]))},'after':{'file':put(f'after-{pos}',replacement)}}for pos in positions]}]}
        plan_path=put('plan.json',json.dumps(plan).encode());patch=home/'edit.patch'
        compiled=json.loads(run('compile',NODE,[CLI,'splice','--splices-file',plan_path,'--output',patch,'--binary',profile]))
        assert compiled['splice_plan_sha256']==hashlib.sha256(Path(plan_path).read_bytes()).hexdigest()
        if profile=='literal':assert compiled['inserted_bytes']==400000 and Path(plan_path).stat().st_size<2048
        bundle=home/'candidate.bundle'
        args=['patch','prepare',*scope,'refs/heads/main',patch,bundle,'--trusted-local','--profile','exact-binary-v1',
            '--workspace-id','e4'*16,'--expected-base',base,'--author',author,'--timestamp','2','--message','binary splice\n']
        text_only=list(args);text_only[text_only.index('--profile')+1]='exact-v1'
        run('text-refuses-binary',FG,text_only,2);assert not bundle.exists()
        case(fmt,profile,'old-text-profile-remains-closed')
        prepared=json.loads(run('prepare',FG,args))
        new=oid(fmt,'blob',bytes(desired));result_tree=tree([('asset.bin','100755',new),('keep.bin','100644',keep)])
        new_tree=oid(fmt,'tree',result_tree)
        commit_body=f'tree {new_tree}\nparent {base}\nauthor {author} 2 +0000\ncommitter {author} 2 +0000\n\nbinary splice\n'.encode()
        candidate=oid(fmt,'commit',commit_body)
        assert prepared['profile']=='exact-binary-v1' and prepared['root_tree']==new_tree and prepared['candidate_commit']==candidate
        assert not prepared['published_to_repository'] and prepared['node_closed']
        packed=bundle_objects(bundle.read_bytes(),fmt,base,candidate)
        assert packed[candidate]==('commit',commit_body) and packed[new]==('blob',bytes(desired)) and packed[new_tree]==('tree',result_tree)
        case(fmt,profile,'actual-native-bytes-match-independent-tree',patch_bytes=patch.stat().st_size)
        again=list(args);again[7]=home/'same.bundle';assert json.loads(run('reopen-prepare',FG,again))==prepared
        assert again[7].read_bytes()==bundle.read_bytes();case(fmt,profile,'reopen-deterministic-candidate')
        # Corrupt the reverse encoded member while retaining its record structure.
        broken=patch.read_bytes(); marker=broken.index(b'GIT binary patch\n');tail=broken[marker:]
        member_lines=tail.splitlines(keepends=True);end=max(i for i,l in enumerate(member_lines)if l.strip())
        line=bytearray(member_lines[end]);line[1]=ord('0')if line[1]!=ord('0')else ord('1');member_lines[end]=bytes(line)
        corrupt=home/'corrupt.patch';corrupt.write_bytes(broken[:marker]+b''.join(member_lines))
        bad=list(args);bad[6]=corrupt;bad[7]=home/'corrupt.bundle'
        run('reverse-corruption',FG,bad,2);assert not bad[7].exists();case(fmt,profile,'corrupt-reverse-refuses-no-bundle')
        budget=list(args);budget[7]=home/'budget.bundle';budget+=['--max-input-bytes',str(patch.stat().st_size-1)]
        run('input-budget',FG,budget,2);assert not budget[7].exists();case(fmt,profile,'exact-wire-bound')
        apply=['patch','apply',*scope,'refs/heads/main',bundle,'--trusted-local','--principal',principal,'--idempotency-key','publish-binary',
            '--expected-base',base,'--expected-commit',candidate]
        wrong=list(apply);wrong[-1]=keep;run('wrong-reviewed-id',FG,wrong,2)
        terminal=json.loads(run('apply',FG,apply));assert terminal['outcome']=='committed' and terminal['candidate_commit']==candidate
        assert json.loads(run('reopen-original-outcome',FG,apply))==terminal
        case(fmt,profile,'ordinary-admission-and-exact-restart-recovery')
        stale=list(args);stale[7]=home/'stale.bundle';run('stale-base',FG,stale,2);assert not stale[7].exists()
        case(fmt,profile,'source-movement-refuses-preparation')
(ROOT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
