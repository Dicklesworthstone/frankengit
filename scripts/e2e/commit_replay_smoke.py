#!/usr/bin/env python3
"""Real-binary replay campaign; self-test/oracle modes execute no FrankenGit."""
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
MESSAGE = b'explicit replay\r\nraw final byte \xff'


def require(value, message):
    if not value:
        raise AssertionError(message)


def oid(algorithm, kind, body):
    return hashlib.new(algorithm, f'{kind} {len(body)}\0'.encode() + body).hexdigest()


def commit(tree, parents, message, timestamp=1):
    return (f'tree {tree}\n' + ''.join(f'parent {p}\n' for p in parents) +
            f'author {AUTHOR} {timestamp} +0000\ncommitter {AUTHOR} {timestamp} +0000\n\n').encode() + message


def tree(entries):
    return b''.join(f'{mode:o} '.encode() + name + b'\0' + bytes.fromhex(identity)
                    for name, mode, identity in sorted(entries, key=lambda e: e[0] + (b'/' if e[1] == 0o40000 else b'\0')))


def write_object(path, algorithm, kind, body):
    identity = oid(algorithm, kind, body)
    output = path / 'objects' / identity[:2] / identity[2:]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(zlib.compress(f'{kind} {len(body)}\0'.encode() + body))
    return identity


def fixture(root, algorithm, conflict=False):
    objects = {}
    def put(kind, body):
        identity = write_object(root, algorithm, kind, body)
        objects[identity] = kind, body
        return identity
    (root / 'refs/heads').mkdir(parents=True)
    (root / 'HEAD').write_text(f'ref: {TARGET}\n')
    (root / 'config').write_text('[core]\nbare=true\nrepositoryformatversion=' +
        ('1\n[extensions]\nobjectformat=sha256\n' if algorithm == 'sha256' else '0\n'))
    keep = put('blob', b'unchanged\0\xff\r\n')
    old = put('blob', b'one\ntwo\nthree\nfour\nfive\n')
    ours = put('blob', b'ONE\ntwo\nthree\nfour\nfive\n')
    incoming = put('blob', b'CONFLICT\ntwo\nthree\nfour\nfive\n' if conflict else b'one\ntwo\nthree\nfour\nFIVE\n')
    borrowed = put('blob', b'source-only file\r\n')
    target_only = put('blob', b'target-only file\n')
    later_only = put('blob', b'later source is not part of the selected change\n')
    base_tree = put('tree', tree([(b'keep',0o100644,keep),(b'text',0o100644,old)]))
    base = put('commit', commit(base_tree, [], b'base\n'))
    target_tree = put('tree', tree([(b'keep',0o100644,keep),(b'target',0o100644,target_only),(b'text',0o100755,ours)]))
    target = put('commit', commit(target_tree, [base], b'target\n'))
    selected_tree = put('tree', tree([(b'keep',0o100644,keep),(b'selected',0o100755,borrowed),(b'text',0o100644,incoming)]))
    selected = put('commit', commit(selected_tree, [base], b'selected\n'))
    source_tree = put('tree', tree([(b'keep',0o100644,keep),(b'later',0o100644,later_only),
        (b'selected',0o100755,borrowed),(b'text',0o100644,incoming)]))
    source = put('commit', commit(source_tree, [selected], b'later\n'))
    for name, identity in [(TARGET,target),(SOURCE,source)]:
        (root / name).write_text(identity + '\n')
    parent_objects = {i: objects[i] for i in [keep,old,ours,target_only,base_tree,base,target_tree,target]}
    merged_bytes = b'ONE\ntwo\nthree\nfour\nFIVE\n'
    merged = oid(algorithm, 'blob', merged_bytes)
    result_tree_bytes = tree([(b'keep',0o100644,keep),(b'selected',0o100755,borrowed),
        (b'target',0o100644,target_only),(b'text',0o100755,merged)])
    result_tree = oid(algorithm, 'tree', result_tree_bytes)
    result_commit_bytes = commit(result_tree, [target], MESSAGE, 2)
    result = oid(algorithm, 'commit', result_commit_bytes)
    packed = {merged: ('blob',merged_bytes), borrowed: objects[borrowed],
              result_tree: ('tree',result_tree_bytes), result: ('commit',result_commit_bytes)}
    return dict(algorithm=algorithm, objects=objects, parent_objects=parent_objects, base=base, target=target,
                source=source, selected=selected, target_tree=target_tree, borrowed=borrowed,
                candidate=result, tree=result_tree, packed=packed, conflict=conflict)


def pack_bytes(algorithm, objects):
    data = bytearray(b'PACK' + struct.pack('>II', 2, len(objects)))
    for _, (kind, body) in sorted(objects.items()):
        size = len(body)
        byte = ({'commit':1,'tree':2,'blob':3}[kind] << 4) | (size & 15)
        size >>= 4
        while size:
            data.append(byte | 128)
            byte = size & 127
            size >>= 7
        data.append(byte)
        data.extend(zlib.compress(body))
    data.extend(hashlib.new(algorithm, data).digest())
    return bytes(data)


def bundle_bytes(f):
    return (f'# v3 git bundle\n@object-format={f["algorithm"]}\n-{f["target"]} target\n'
            f'{f["candidate"]} {TARGET}\n\n').encode() + pack_bytes(f['algorithm'], f['packed'])


def unpack_bundle(data, algorithm, target, candidate):
    header, packed = data.split(b'\n\n', 1)
    lines = header.splitlines()
    signature = lines.pop(0)
    require(signature in (b'# v2 git bundle', b'# v3 git bundle'), 'bundle signature')
    if signature == b'# v3 git bundle':
        require(lines.pop(0) == f'@object-format={algorithm}'.encode(), 'bundle object format')
    else:
        require(algorithm == 'sha1', 'v2 is SHA-1')
    require(len(lines) == 2 and lines[0].split(b' ')[0] == b'-' + target.encode(), 'target-only prerequisite')
    require(lines[1] == f'{candidate} {TARGET}'.encode(), 'advertised candidate/ref')
    width = hashlib.new(algorithm).digest_size
    require(hashlib.new(algorithm, packed[:-width]).digest() == packed[-width:], 'pack checksum')
    require(packed[:8] == b'PACK\x00\x00\x00\x02', 'pack version')
    count = struct.unpack('>I', packed[8:12])[0]
    require(0 < count <= 10000, 'bounded pack count')
    at, result = 12, {}
    for _ in range(count):
        byte = packed[at]; at += 1
        kind, size, shift = byte >> 4 & 7, byte & 15, 4
        while byte & 128:
            require(shift < 64, 'entry size bound')
            byte = packed[at]; at += 1
            size |= (byte & 127) << shift; shift += 7
        require(kind in (1,2,3), 'no-delta creation profile')
        require(size <= 32 * 1024 * 1024, 'bounded object bytes')
        reader = zlib.decompressobj()
        body = reader.decompress(packed[at:-width], size + 1)
        require(reader.eof and len(body) == size, 'complete exact zlib member')
        at = len(packed) - width - len(reader.unused_data)
        name = {1:'commit',2:'tree',3:'blob'}[kind]
        identity = oid(algorithm, name, body)
        require(identity not in result, 'no duplicate objects')
        result[identity] = name, body
    require(at == len(packed) - width, 'exact pack boundary')
    return result


def validate(report, data, f, operation='cherry-pick', target=None, source=None, selected=None,
             parent=None, expected_tree=None, candidate=None, message=MESSAGE, timestamp=2,
             expected_objects=None, generated=3, borrowed=1):
    target = target or f['target']; source = source or f['source']; selected = selected or f['selected']
    parent = parent or f['base']; expected_tree = expected_tree or f['tree']; candidate = candidate or f['candidate']
    expected = dict(type='commit_replay_preparation', schema_version=1, profile='path-v1', operation=operation,
        outcome='prepared', tenant_id=TENANT, repository_id=REPOSITORY, object_format=f['algorithm'],
        target_reference_hex=TARGET.encode().hex(), source_reference_hex=(TARGET if operation == 'revert' else SOURCE).encode().hex(),
        expected_target=target, expected_source=source, selected_commit=selected, selected_parent=parent, mainline=1,
        author=AUTHOR, committer=AUTHOR, timestamp=timestamp, message_hex=message.hex(), bundle_created=True,
        published_to_repository=False, objects_staged=False, approval_granted=False, node_closed=True,
        candidate_commit=candidate, root_tree=expected_tree, generated_objects=generated, borrowed_objects=borrowed,
        bundle_bytes=len(data), bundle_sha256=hashlib.sha256(data).hexdigest())
    for key, value in expected.items():
        require(report.get(key) == value and type(report.get(key)) is type(value), f'report field {key}')
    require(report['source_head'] and report['snapshot_token'].startswith('alg:'), 'authority snapshot')
    require(isinstance(report['bundle_path'], str) and report['bundle_path'], 'published artifact path')
    objects = unpack_bundle(data, f['algorithm'], target, candidate)
    require(type(report['pack_objects']) is int and report['pack_objects'] == len(objects), 'pack accounting')
    require(objects == (f['packed'] if expected_objects is None else expected_objects), 'exact complete object bytes')
    require(objects[candidate] == ('commit', commit(expected_tree, [target], message, timestamp)), 'exact single-parent commit metadata')
    return objects


def invoke(binary, args, code=0, env=None):
    result = subprocess.run([str(binary), *map(str,args)], capture_output=True, timeout=240, env=env)
    require(result.returncode == code, f'exit {result.returncode} != {code}: {result.stderr!r}; {result.stdout!r}')
    return result


def arguments(node, path, f):
    return ['cherry-pick','prepare',node,TENANT,REPOSITORY,TARGET,path,'--trusted-local','--profile','path-v1',
            '--source-ref',SOURCE,'--expected-target',f['target'],'--expected-source',f['source'],
            '--commit',f['selected'],'--author',AUTHOR,'--timestamp','2','--message-file',path.parent / 'message']


def run(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix='fg-replay-smoke-') as directory:
        root = Path(directory); f = fixture(root / 'source', algorithm)
        node, artifact = root / 'node', root / 'candidate.bundle'
        (root / 'message').write_bytes(MESSAGE)
        invoke(binary,['init',node,TENANT,REPOSITORY,algorithm])
        invoke(binary,['import',node,TENANT,REPOSITORY,PRINCIPAL,'replay-fixture',root / 'source'])
        state = ['at',node,TENANT,REPOSITORY,'latest']
        before = invoke(binary,state).stdout
        args = arguments(node, artifact, f)
        report = json.loads(invoke(binary,args).stdout)
        data = artifact.read_bytes(); validate(report, data, f)
        require(invoke(binary,state).stdout == before, 'preparation mutated authority')
        same = args.copy(); same[6] = root / 'second.bundle'
        duplicate = json.loads(invoke(binary,same).stdout)
        validate(duplicate, same[6].read_bytes(), f)
        require(same[6].read_bytes() == data, 'deterministic bundle')
        require(not invoke(binary,args,2).stdout and artifact.read_bytes() == data, 'existing artifact was overwritten')
        for flag,value in [('--expected-target',f['base']),('--commit',f['target']),('--expected-source',f['selected'])]:
            bad = args.copy(); bad[6] = root / 'bad.bundle'; bad[bad.index(flag)+1] = value
            require(not invoke(binary,bad,2).stdout and not bad[6].exists(), 'invalid replay emitted artifact')
        for extra in [('--max-commits','1'),('--max-output-bytes','1'),('--mainline','0')]:
            bad = args.copy(); bad[6] = root / 'bounded.bundle'; bad.extend(extra)
            require(not invoke(binary,bad,2).stdout and not bad[6].exists(), 'budget/mainline error emitted artifact')
        inspect = ['workspace','inspect',node,TENANT,REPOSITORY,TARGET,artifact,'--trusted-local',
                   '--expected-base',f['target'],'--expected-commit',f['candidate']]
        inspected = json.loads(invoke(binary,inspect).stdout)
        require(inspected['parents'] == [f['target']] and inspected['prerequisites'] == [f['target']], 'independent inspection')
        require(invoke(binary,state).stdout == before, 'inspection mutated authority')
        apply = ['workspace','apply',node,TENANT,REPOSITORY,TARGET,artifact,'--trusted-local',
                 '--principal',PRINCIPAL,'--idempotency-key','picked','--expected-base',f['target'],'--expected-commit',f['candidate']]
        published = json.loads(invoke(binary,apply).stdout)
        require(published['outcome'] == 'committed', 'source publication')
        same[6] = root / 'noop.bundle'; same[same.index('--expected-target')+1] = f['candidate']
        pinned = same.copy(); pinned[6] = root / 'pinned.bundle'
        pinned += ['--expected-head',report['snapshot_token']]
        require(not invoke(binary,pinned,2).stdout and not pinned[6].exists(), 'stale authority pin admitted')
        noop = json.loads(invoke(binary,same).stdout)
        require(noop['outcome'] == 'no_change' and noop['bundle_created'] is False and not same[6].exists(), 'no empty commit')
        reverse = ['revert','prepare',node,TENANT,REPOSITORY,TARGET,root / 'revert.bundle','--trusted-local','--profile','path-v1',
                   '--source-ref',TARGET,'--expected-target',f['candidate'],'--expected-source',f['candidate'],
                   '--commit',f['candidate'],'--author',AUTHOR,'--timestamp','3','--message','inverse\n']
        response = json.loads(invoke(binary,reverse).stdout)
        reverse_body = commit(f['target_tree'], [f['candidate']], b'inverse\n', 3)
        inverse = oid(algorithm,'commit',reverse_body)
        validate(response, reverse[6].read_bytes(), f, operation='revert', target=f['candidate'], source=f['candidate'],
            selected=f['candidate'], parent=f['target'], expected_tree=f['target_tree'], candidate=inverse,
            message=b'inverse\n', timestamp=3, expected_objects={inverse:('commit',reverse_body)}, generated=1, borrowed=0)
        apply_reverse = apply.copy(); apply_reverse[6] = reverse[6]
        for flag,value in [('--idempotency-key','reverted'),('--expected-base',f['candidate']),('--expected-commit',inverse)]:
            apply_reverse[apply_reverse.index(flag)+1] = value
        require(json.loads(invoke(binary,apply_reverse).stdout)['outcome'] == 'committed', 'revert publication')
        after = invoke(binary,state).stdout
        retry = json.loads(invoke(binary,apply).stdout)
        require(retry['tx_id'] == published['tx_id'] and retry['outcome'] == 'committed', 'original outcome recovery')
        require(invoke(binary,state).stdout == after, 'retry rolled back a descendant')
        conflict = fixture(root / 'conflict-source',algorithm,True)
        cnode = root / 'conflict-node'
        invoke(binary,['init',cnode,TENANT,REPOSITORY,algorithm])
        invoke(binary,['import',cnode,TENANT,REPOSITORY,PRINCIPAL,'conflict-fixture',root / 'conflict-source'])
        cstate = ['at',cnode,TENANT,REPOSITORY,'latest']; old = invoke(binary,cstate).stdout
        cpath = root / 'conflict.bundle'
        result = json.loads(invoke(binary,arguments(cnode,cpath,conflict),3).stdout)
        require(result['outcome'] == 'conflicted' and result['bundle_created'] is False and not cpath.exists(), 'conflict manufactured a commit')
        require(any(bytes.fromhex(c['path_hex']) == b'text' for c in result['conflicts']), 'actual conflicting path absent')
        require(invoke(binary,cstate).stdout == old, 'conflict mutated authority')
        print(json.dumps(dict(type='commit_replay_smoke', object_format=algorithm, rust_executed=True, passed=True)))


def self_test():
    negatives = 0
    for algorithm in ('sha1','sha256'):
        with tempfile.TemporaryDirectory() as directory:
            f = fixture(Path(directory),algorithm); data = bundle_bytes(f)
            report = dict(type='commit_replay_preparation',schema_version=1,profile='path-v1',operation='cherry-pick',outcome='prepared',
                tenant_id=TENANT,repository_id=REPOSITORY,object_format=algorithm,source_head='fixture',snapshot_token='alg:1:'+'ab'*32,
                target_reference_hex=TARGET.encode().hex(),source_reference_hex=SOURCE.encode().hex(),expected_target=f['target'],expected_source=f['source'],
                selected_commit=f['selected'],selected_parent=f['base'],mainline=1,author=AUTHOR,committer=AUTHOR,timestamp=2,message_hex=MESSAGE.hex(),
                bundle_created=True,bundle_path='fixture.bundle',published_to_repository=False,objects_staged=False,approval_granted=False,node_closed=True,
                candidate_commit=f['candidate'],root_tree=f['tree'],generated_objects=3,pack_objects=4,borrowed_objects=1,bundle_bytes=len(data),
                bundle_sha256=hashlib.sha256(data).hexdigest())
            validate(report,data,f)
            for key,value in [('operation','revert'),('outcome','no_change'),('expected_target',f['base']),('expected_source',f['selected']),
                ('selected_commit',f['source']),('selected_parent',f['target']),('mainline',2),('timestamp',3),('message_hex',''),
                ('candidate_commit',f['source']),('root_tree',f['target_tree']),('generated_objects',2),('borrowed_objects',0),('pack_objects',3),
                ('bundle_bytes',0),('bundle_sha256','00'*32),('objects_staged',True),('approval_granted',True),('published_to_repository',True),
                ('node_closed',False),('bundle_created',False),('tenant_id',PRINCIPAL)]:
                wrong = copy.deepcopy(report); wrong[key] = value
                try: validate(wrong,data,f)
                except AssertionError: negatives += 1
                else: raise AssertionError(f'checker accepted altered {key}')
            for bad in [data[:-1],data[:-1]+bytes([data[-1]^1]),data.replace(f'-{f["target"]} target'.encode(),f'-{f["source"]} target'.encode())]:
                try: unpack_bundle(bad,algorithm,f['target'],f['candidate'])
                except (AssertionError,ValueError,IndexError,zlib.error,struct.error): negatives += 1
                else: raise AssertionError('checker accepted damaged bundle')
    print(json.dumps(dict(type='commit_replay_checker',negative_cases=negatives,rust_executed=False,passed=True)))


def oracle(git):
    env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,GIT_TERMINAL_PROMPT='0',GIT_ATTR_NOSYSTEM='1',GIT_ALLOW_PROTOCOL='file')
    def call(args): return invoke(git,args,env=env)
    version = call(['--version']).stdout.decode().strip()
    for algorithm in ('sha1','sha256'):
        with tempfile.TemporaryDirectory(prefix='fg-replay-git-oracle-') as directory:
            root = Path(directory); f = fixture(root / 'source',algorithm)
            target = root / 'target-only'
            call(['init','--bare',f'--object-format={algorithm}',target])
            for _,(kind,body) in f['parent_objects'].items(): write_object(target,algorithm,kind,body)
            call(['--git-dir',target,'update-ref',TARGET,f['target']])
            path = root / 'candidate.bundle'; path.write_bytes(bundle_bytes(f))
            call(['--git-dir',target,'bundle','verify',path])
            call(['--git-dir',target,'fetch',path,f'{TARGET}:refs/heads/reviewed'])
            require(call(['--git-dir',target,'rev-parse',TARGET]).stdout.strip().decode() == f['target'], 'oracle changed original ref')
            require(call(['--git-dir',target,'cat-file','-p',f['candidate']]).stdout == f['packed'][f['candidate']][1], 'candidate bytes')
            require(call(['--git-dir',target,'show',f'{f["candidate"]}:text']).stdout == b'ONE\ntwo\nthree\nfour\nFIVE\n','merged bytes')
            absent = subprocess.run([str(git),'--git-dir',str(target),'cat-file','-e',f['selected']],capture_output=True,env=env,timeout=30)
            require(absent.returncode != 0,'source commit leaked into target-only bundle')
            call(['--git-dir',target,'fsck','--strict','--full'])
            # Separate real Git content oracle, with full original source history.
            work = root / 'work'; call(['clone',root / 'source',work])
            call(['-C',work,'config','user.name','Oracle'])
            call(['-C',work,'config','user.email','oracle@example.invalid'])
            call(['-C',work,'cherry-pick','--no-commit',f['selected']])
            require(call(['-C',work,'write-tree']).stdout.strip().decode() == f['tree'],'upstream cherry-pick tree')
            call(['-C',work,'reset','--hard',f['target']])
            call(['-C',work,'fetch',path,f'{TARGET}:refs/heads/reviewed'])
            call(['-C',work,'reset','--hard',f['candidate']])
            call(['-C',work,'revert','--no-commit',f['candidate']])
            require(call(['-C',work,'write-tree']).stdout.strip().decode() == f['target_tree'],'upstream revert tree')
            print(json.dumps(dict(type='commit_replay_fixture_oracle',git=version,object_format=algorithm,rust_executed=False,passed=True)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fg',type=Path)
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--git-oracle',type=Path)
    args = parser.parse_args()
    if not (args.fg or args.self_test or args.git_oracle): parser.error('select --fg, --self-test or --git-oracle')
    if args.self_test: self_test()
    if args.git_oracle: oracle(args.git_oracle.resolve(strict=True))
    if args.fg:
        binary = args.fg.resolve(strict=True)
        require(binary.is_file() and os.access(binary,os.X_OK),'executable fg required')
        print(json.dumps(dict(type='binary_identity',path=str(binary),sha256=hashlib.sha256(binary.read_bytes()).hexdigest())))
        for algorithm in ('sha1','sha256'): run(binary,algorithm)


if __name__ == '__main__':
    main()
