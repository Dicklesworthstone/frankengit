#!/usr/bin/env python3
"""Actual fg resolution/inspection/publication campaign; other modes are fixture checks only."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

TENANT, REPOSITORY, PRINCIPAL = 'c1' * 16, 'c2' * 16, 'c3' * 16
TARGET, SOURCE = 'refs/heads/main', 'refs/heads/topic'
AUTHOR = 'Test <test@example.invalid>'
MESSAGE = b'resolved replay\r\nraw end \xff'
RESOLUTION = b'manual resolution\0\xff\r\nend'


def require(value, message):
    if not value:
        raise AssertionError(message)


def same(actual, expected, field):
    require(type(actual) is type(expected), f'{field}: type')
    if isinstance(expected, dict):
        require(actual.keys() == expected.keys(), f'{field}: keys')
        for k, v in expected.items():
            same(actual[k], v, f'{field}.{k}')
    elif isinstance(expected, list):
        require(len(actual) == len(expected), f'{field}: length')
        for i, (a, e) in enumerate(zip(actual, expected)):
            same(a, e, f'{field}[{i}]')
    else:
        require(actual == expected, f'{field}: value')


def oid(algorithm, kind, body):
    return hashlib.new(algorithm, f'{kind} {len(body)}\0'.encode() + body).hexdigest()


def tree(entries):
    return b''.join(f'{mode:o} '.encode() + name + b'\0' + bytes.fromhex(identity)
        for name, mode, identity in sorted(entries, key=lambda e: e[0] + (b'/' if e[1] == 0o40000 else b'\0')))


def commit(identity, parents, message, timestamp=1):
    return (f'tree {identity}\n' + ''.join(f'parent {p}\n' for p in parents) +
        f'author {AUTHOR} {timestamp} +0000\ncommitter {AUTHOR} {timestamp} +0000\n\n').encode() + message


def write_object(root, algorithm, kind, body):
    identity = oid(algorithm, kind, body)
    path = root / 'objects' / identity[:2] / identity[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(f'{kind} {len(body)}\0'.encode() + body))
    return identity


def fixture(root, algorithm):
    objects = {}
    def put(kind, body):
        identity = write_object(root, algorithm, kind, body)
        objects[identity] = kind, body
        return identity
    (root / 'refs/heads').mkdir(parents=True)
    (root / 'HEAD').write_text(f'ref: {TARGET}\n')
    (root / 'config').write_text('[core]\nbare=true\nrepositoryformatversion=' +
        ('1\n[extensions]\nobjectformat=sha256\n' if algorithm == 'sha256' else '0\n'))
    contents = dict(keep=b'unchanged\0\xff\r\n', gone=b'delete this\n', old=b'base\n', ours=b'target\n',
                    theirs=b'source\n', borrowed=b'source-only\n', target=b'target-only\n', later=b'not selected\n')
    ids = {key: put('blob', body) for key, body in contents.items()}
    b = [(b'gone',0o100644,ids['gone']),(b'keep',0o100644,ids['keep']),(b'text',0o100644,ids['old'])]
    o = b[:-1] + [(b'target',0o100644,ids['target']),(b'text',0o100755,ids['ours'])]
    t = [(b'keep',0o100644,ids['keep']),(b'selected',0o100755,ids['borrowed']),(b'text',0o100644,ids['theirs'])]
    bt = put('tree', tree(b)); base = put('commit', commit(bt, [], b'base\n'))
    ot = put('tree', tree(o)); target = put('commit', commit(ot, [base], b'target\n'))
    st = put('tree', tree(t)); selected = put('commit', commit(st, [base], b'selected\n'))
    lt = put('tree', tree(t + [(b'later',0o100644,ids['later'])])); source = put('commit', commit(lt, [selected], b'later\n'))
    for name, value in ((TARGET,target),(SOURCE,source)):
        (root / name).write_text(value + '\n')
    parent_ids = [base,target,bt,ot,ids['gone'],ids['keep'],ids['old'],ids['ours'],ids['target']]
    manual = oid(algorithm,'blob',RESOLUTION)
    entries = [(b'keep',0o100644,ids['keep']),(b'selected',0o100755,ids['borrowed']),
               (b'target',0o100644,ids['target']),(b'text',0o100755,manual)]
    rt_body = tree(entries); rt = oid(algorithm,'tree',rt_body)
    body = commit(rt, [target], MESSAGE, 2); candidate = oid(algorithm,'commit',body)
    packed = {manual:('blob',RESOLUTION),ids['borrowed']:objects[ids['borrowed']],rt:('tree',rt_body),candidate:('commit',body)}
    entry = lambda key, mode: dict(mode=mode,oid=ids[key])
    row = dict(conflict=dict(path_hex=b'text'.hex(),kind='Content',base=entry('old',0o100644),
               ours=entry('ours',0o100755),theirs=entry('theirs',0o100644)), choice='file',result=dict(mode=0o100755,oid=manual))
    return dict(algorithm=algorithm,objects=objects,parent_objects={i:objects[i] for i in parent_ids},base=base,
        target=target,source=source,selected=selected,candidate=candidate,tree=rt,packed=packed,row=row,ids=ids)


def bundle_bytes(f):
    data = bytearray(b'PACK' + struct.pack('>II',2,len(f['packed'])))
    for _, (kind, body) in sorted(f['packed'].items()):
        size = len(body); byte = ({'commit':1,'tree':2,'blob':3}[kind] << 4) | (size & 15); size >>= 4
        while size:
            data.append(byte | 128); byte = size & 127; size >>= 7
        data.append(byte); data.extend(zlib.compress(body))
    data.extend(hashlib.new(f['algorithm'],data).digest())
    return (f'# v3 git bundle\n@object-format={f["algorithm"]}\n-{f["target"]} target\n'
            f'{f["candidate"]} {TARGET}\n\n').encode() + data


def unpack(data, f):
    header, packed = data.split(b'\n\n',1); lines = header.splitlines(); signature = lines.pop(0)
    require(signature in (b'# v2 git bundle',b'# v3 git bundle'), 'bundle signature')
    if signature == b'# v3 git bundle':
        require(lines.pop(0) == f'@object-format={f["algorithm"]}'.encode(), 'object format')
    else:
        require(f['algorithm'] == 'sha1','v2 format')
    require(len(lines) == 2 and lines[0].split(b' ')[0] == b'-' + f['target'].encode(), 'target-only prerequisite')
    require(lines[1] == f'{f["candidate"]} {TARGET}'.encode(), 'candidate/ref')
    width = hashlib.new(f['algorithm']).digest_size
    require(hashlib.new(f['algorithm'],packed[:-width]).digest() == packed[-width:], 'pack checksum')
    require(packed[:8] == b'PACK\0\0\0\2', 'pack version')
    count = struct.unpack('>I',packed[8:12])[0]; require(0 < count <= 10000,'bounded object count')
    at, result = 12, {}
    for _ in range(count):
        byte = packed[at]; at += 1; kind, size, shift = byte >> 4 & 7, byte & 15, 4
        while byte & 128:
            require(shift < 64,'size bound'); byte = packed[at]; at += 1
            size |= (byte & 127) << shift; shift += 7
        require(kind in (1,2,3) and size <= 32*1024*1024,'bounded no-delta profile')
        reader = zlib.decompressobj(); body = reader.decompress(packed[at:-width],size+1)
        require(reader.eof and len(body) == size,'complete object')
        at = len(packed)-width-len(reader.unused_data)
        name = {1:'commit',2:'tree',3:'blob'}[kind]; identity = oid(f['algorithm'],name,body)
        require(identity not in result,'duplicate object'); result[identity] = name, body
    require(at == len(packed)-width,'trailing pack data')
    return result


def report(f, data):
    return dict(type='commit_replay_resolution',schema_version=1,profile='path-v1',operation='cherry-pick',outcome='prepared',
        tenant_id=TENANT,repository_id=REPOSITORY,object_format=f['algorithm'],expected_target=f['target'],expected_source=f['source'],
        selected_commit=f['selected'],selected_parent=f['base'],mainline=1,candidate_commit=f['candidate'],root_tree=f['tree'],
        author=AUTHOR,committer=AUTHOR,timestamp=2,message_hex=MESSAGE.hex(),bundle_created=True,objects_staged=False,
        published_to_repository=False,approval_granted=False,node_closed=True,generated_objects=3,pack_objects=4,borrowed_objects=1,
        bundle_bytes=len(data),bundle_sha256=hashlib.sha256(data).hexdigest(),resolutions=[f['row']])


def validate(actual, data, f):
    for key, value in report(f,data).items():
        require(key in actual,f'missing {key}'); same(actual[key],value,key)
    require(unpack(data,f) == f['packed'],'exact candidate object bytes and source-only closure')


def invoke(binary, args, code=0, env=None):
    result = subprocess.run([str(binary), *map(str,args)],capture_output=True,timeout=240,env=env)
    require(result.returncode == code,f'exit {result.returncode} != {code}: {result.stderr!r}; {result.stdout!r}')
    return result


def run(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix='fg-resolution-smoke-') as directory:
        root=Path(directory); f=fixture(root/'source',algorithm); node=root/'node'; output=root/'resolved.bundle'
        (root/'message').write_bytes(MESSAGE); (root/'resolution').write_bytes(RESOLUTION)
        invoke(binary,['init',node,TENANT,REPOSITORY,algorithm])
        invoke(binary,['import',node,TENANT,REPOSITORY,PRINCIPAL,'resolution-fixture',root/'source'])
        state=['at',node,TENANT,REPOSITORY,'latest']; before=invoke(binary,state).stdout
        args=['cherry-pick','resolve',node,TENANT,REPOSITORY,TARGET,output,'--trusted-local','--profile','path-v1',
            '--source-ref',SOURCE,'--expected-target',f['target'],'--expected-source',f['source'],'--commit',f['selected'],
            '--author',AUTHOR,'--timestamp','2','--message-file',root/'message','--file','text','100755',root/'resolution']
        automatic=args[:-4].copy(); automatic[1]='prepare'; automatic[6]=root/'conflict.bundle'
        conflict=json.loads(invoke(binary,automatic,3).stdout)
        require(conflict['outcome']=='conflicted' and not automatic[6].exists(),'automatic conflict boundary')
        for suffix in ([],['--ours','keep'],['--ours','text','--theirs','text'],['--theirs','missing']):
            bad=args[:-4].copy(); bad[6]=root/'bad.bundle'; bad.extend(suffix)
            require(not invoke(binary,bad,2).stdout and not bad[6].exists(),'invalid choices emitted output')
        actual=json.loads(invoke(binary,args).stdout); data=output.read_bytes(); validate(actual,data,f)
        require(invoke(binary,state).stdout==before,'resolution mutated repository')
        second=args.copy(); second[6]=root/'same.bundle'; validate(json.loads(invoke(binary,second).stdout),second[6].read_bytes(),f)
        require(second[6].read_bytes()==data,'non-deterministic resolved bundle')
        require(not invoke(binary,args,2).stdout and output.read_bytes()==data,'overwrote existing artifact')
        inspect=['workspace','inspect',node,TENANT,REPOSITORY,TARGET,output,'--trusted-local','--expected-base',f['target'],'--expected-commit',f['candidate']]
        inspected=json.loads(invoke(binary,inspect).stdout)
        require(inspected['parents']==[f['target']] and inspected['prerequisites']==[f['target']],'single-parent inspection')
        require(invoke(binary,state).stdout==before,'inspection mutated repository')
        publish=['workspace','apply',node,TENANT,REPOSITORY,TARGET,output,'--trusted-local','--principal',PRINCIPAL,
            '--idempotency-key','resolved-pick','--expected-base',f['target'],'--expected-commit',f['candidate']]
        first=json.loads(invoke(binary,publish).stdout); require(first['outcome']=='committed','publication')
        noop=args[:-4].copy(); noop[6]=root/'noop.bundle'; noop[noop.index('--expected-target')+1]=f['candidate']; noop+=['--ours','text']
        nochange=json.loads(invoke(binary,noop).stdout)
        require(nochange['type']=='commit_replay_resolution' and nochange['outcome']=='no_change'
            and nochange['bundle_created'] is False and not noop[6].exists(),'resolved no-change created an empty commit')
        stale=args.copy(); stale[6]=root/'stale.bundle'
        require(not invoke(binary,stale,2).stdout and not stale[6].exists(),'stale target admitted')
        inverse=noop[:-2].copy(); inverse[0]='revert'; inverse[6]=root/'inverse.bundle'; inverse+=['--theirs','text']
        reverted=json.loads(invoke(binary,inverse).stdout)
        ids=f['ids']; inverse_tree=tree([(b'gone',0o100644,ids['gone']),(b'keep',0o100644,ids['keep']),
            (b'target',0o100644,ids['target']),(b'text',0o100644,ids['old'])])
        inverse_tree_id=oid(algorithm,'tree',inverse_tree); inverse_body=commit(inverse_tree_id,[f['candidate']],MESSAGE,2)
        inverse_id=oid(algorithm,'commit',inverse_body)
        require(reverted['candidate_commit']==inverse_id and reverted['root_tree']==inverse_tree_id,'revert side semantics')
        require(reverted['resolutions'][0]['choice']=='theirs' and reverted['resolutions'][0]['result']==dict(mode=0o100644,oid=ids['old']),'revert parent side')
        fi=dict(f,target=f['candidate'],candidate=inverse_id)
        require(unpack(inverse[6].read_bytes(),fi)=={inverse_tree_id:('tree',inverse_tree),inverse_id:('commit',inverse_body)},'complete inverse bundle')
        publish_inverse=publish.copy(); publish_inverse[6]=inverse[6]
        for flag,value in (('--idempotency-key','resolved-inverse'),('--expected-base',f['candidate']),('--expected-commit',inverse_id)):
            publish_inverse[publish_inverse.index(flag)+1]=value
        require(json.loads(invoke(binary,publish_inverse).stdout)['outcome']=='committed','inverse publication')
        after=invoke(binary,state).stdout; retry=json.loads(invoke(binary,publish).stdout)
        require(retry['tx_id']==first['tx_id'] and retry['outcome']=='committed','historical retry')
        require(invoke(binary,state).stdout==after,'retry rolled back a later inverse')
        print(json.dumps(dict(type='replay_resolution_smoke',object_format=algorithm,rust_executed=True,passed=True)))


def self_test():
    rejected=0
    for algorithm in ('sha1','sha256'):
        with tempfile.TemporaryDirectory() as directory:
            f=fixture(Path(directory),algorithm); data=bundle_bytes(f); expected=report(f,data); validate(expected,data,f)
            mutations=[]
            for key,value in [('type','commit_replay_preparation'),('operation','revert'),('outcome','no_change'),('mainline',True),
                ('expected_target',f['base']),('selected_commit',f['source']),('generated_objects',0),('borrowed_objects',0),
                ('bundle_created',False),('objects_staged',True),('approval_granted',True),('published_to_repository',True),
                ('bundle_sha256','00'*32),('candidate_commit',f['target']),('node_closed',False)]:
                wrong=copy.deepcopy(expected); wrong[key]=value; mutations.append(wrong)
            for key,value in [('choice','ours'),('result',None),('conflict',{} )]:
                wrong=copy.deepcopy(expected); wrong['resolutions'][0][key]=value; mutations.append(wrong)
            wrong=copy.deepcopy(expected); wrong['resolutions'][0]['result']['mode']=0o100644; mutations.append(wrong)
            wrong=copy.deepcopy(expected); wrong['resolutions']=[]; mutations.append(wrong)
            for wrong in mutations:
                try: validate(wrong,data,f)
                except AssertionError: rejected+=1
                else: raise AssertionError('checker accepted corrupted receipt')
            for damaged in (data[:-1],data[:-1]+bytes([data[-1]^1])):
                wrong=copy.deepcopy(expected); wrong['bundle_bytes']=len(damaged); wrong['bundle_sha256']=hashlib.sha256(damaged).hexdigest()
                try: validate(wrong,damaged,f)
                except (AssertionError,ValueError,IndexError,zlib.error): rejected+=1
                else: raise AssertionError('checker accepted corrupt bundle')
    print(json.dumps(dict(type='replay_resolution_checker_selftest',negative_cases=rejected,rust_executed=False,passed=True)))


def git_oracle(binary):
    version=invoke(binary,['--version']).stdout.decode().strip()
    for algorithm in ('sha1','sha256'):
        with tempfile.TemporaryDirectory(prefix='fg-resolution-oracle-') as directory:
            root=Path(directory); f=fixture(root/'source',algorithm); dest=root/'target.git'; bundle=root/'candidate.bundle'
            bundle.write_bytes(bundle_bytes(f))
            env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
            env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,HOME=str(root),LC_ALL='C')
            invoke(binary,['init','--bare',f'--object-format={algorithm}',dest],env=env)
            for kind,body in f['parent_objects'].values(): write_object(dest,algorithm,kind,body)
            (dest/TARGET).write_text(f['target']+'\n'); prefix=[f'--git-dir={dest}']
            invoke(binary,prefix+['bundle','verify',bundle],env=env)
            invoke(binary,prefix+['fetch',bundle,f'{TARGET}:refs/heads/inspected'],env=env)
            require(invoke(binary,prefix+['cat-file','commit',f['candidate']],env=env).stdout==f['packed'][f['candidate']][1],'native candidate bytes')
            require(invoke(binary,prefix+['rev-parse',TARGET],env=env).stdout.strip().decode()==f['target'],'oracle moved original ref')
            print(json.dumps(dict(type='replay_resolution_fixture_oracle',git_version=version,object_format=algorithm,rust_executed=False,passed=True)))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--self-test',action='store_true'); group.add_argument('--fg',type=Path); group.add_argument('--git-oracle',type=Path)
    options=parser.parse_args()
    if options.self_test: self_test()
    elif options.git_oracle: git_oracle(options.git_oracle.resolve(strict=True))
    else:
        binary=options.fg.resolve(strict=True)
        print(json.dumps(dict(type='binary_identity',path=str(binary),sha256=hashlib.sha256(binary.read_bytes()).hexdigest())))
        for algorithm in ('sha1','sha256'): run(binary,algorithm)
