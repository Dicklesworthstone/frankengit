#!/usr/bin/env python3
"""Real fg artifact-inspection campaign. Self-test exercises only fixtures/checker."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

TENANT, REPO, PRINCIPAL = '81' * 16, '82' * 16, '83' * 16
TARGET, SOURCE = 'refs/heads/main', 'refs/heads/topic'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def oid(algorithm, kind, body):
    return hashlib.new(algorithm, f'{kind} {len(body)}\0'.encode() + body).hexdigest()


def commit(tree, parents, label):
    return (f'tree {tree}\n' + ''.join(f'parent {p}\n' for p in parents) +
            'author Fixture <fixture@example.invalid> 1 +0000\n'
            'committer Fixture <fixture@example.invalid> 1 +0000\n\n' + label + '\n').encode()


def tree(file, keep):
    return b'100644 file\0' + bytes.fromhex(file) + b'100644 keep\0' + bytes.fromhex(keep)


def fixture(root, algorithm):
    objects = {}
    def put(kind, body):
        identity = oid(algorithm, kind, body)
        objects[identity] = kind, body
        path = root / 'objects' / identity[:2] / identity[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f'{kind} {len(body)}\0'.encode() + body))
        return identity
    (root / 'refs/heads').mkdir(parents=True)
    (root / 'HEAD').write_text(f'ref: {TARGET}\n')
    (root / 'config').write_text('[core]\nbare = true\nrepositoryformatversion = ' +
        ('1\n[extensions]\nobjectformat = sha256\n' if algorithm == 'sha256' else '0\n'))
    old = b'original\nsecond\n'
    original = put('blob', old)
    keep = put('blob', b'preserved sibling\n')
    base_tree = put('tree', tree(original, keep))
    base = put('commit', commit(base_tree, [], 'base'))
    target = put('commit', commit(base_tree, [base], 'target'))
    incoming_blob = put('blob', b'source-side only\nsecond\n')
    incoming_tree = put('tree', tree(incoming_blob, keep))
    incoming = put('commit', commit(incoming_tree, [base], 'incoming'))
    secret_bytes = b'unrelated secret\n'
    secret = put('blob', secret_bytes)
    secret_tree = put('tree', tree(secret, keep))
    private = put('commit', commit(secret_tree, [], 'private'))
    for reference, identity in [(TARGET, target), (SOURCE, incoming), ('refs/heads/private', private)]:
        (root / reference).write_text(identity + '\n')
    return dict(objects=objects, original=original, old=old, keep=keep, base=base, target=target,
                source=incoming, secret=secret, secret_bytes=secret_bytes, before_tree=base_tree)


def encode_pack(algorithm, entries):
    data = bytearray(b'PACK' + struct.pack('>II', 2, len(entries)))
    offsets = []
    for kind, body, dependency in entries:
        at = len(data)
        offsets.append(at)
        size = len(body)
        byte = (kind << 4) | (size & 15)
        size >>= 4
        while size:
            data.append(byte | 128)
            byte = size & 127
            size >>= 7
        data.append(byte)
        if kind == 7:
            data.extend(bytes.fromhex(dependency))
        elif kind == 6:
            distance = at - offsets[dependency]
            encoded = [distance & 127]
            distance >>= 7
            while distance:
                distance -= 1
                encoded.append(128 | (distance & 127))
                distance >>= 7
            data.extend(reversed(encoded))
        data.extend(zlib.compress(body))
    data.extend(hashlib.new(algorithm, data).digest())
    return bytes(data)


def candidate(f, algorithm, merging=False, mode='direct', extra=False):
    if mode in ('thin', 'hidden'):
        base = f['old'] if mode == 'thin' else f['secret_bytes']
    elif mode in ('forward', 'ofs'):
        base = b'transport-only base\n'
    else:
        base = None
    content = base + b'!' if base is not None else b'actual reviewed result\nsecond\n'
    file = oid(algorithm, 'blob', content)
    tree_body = tree(file, f['keep'])
    after_tree = oid(algorithm, 'tree', tree_body)
    parents = [f['target'], f['source']] if merging else [f['target']]
    commit_body = commit(after_tree, parents, 'exact metadata \u202e remains data')
    identity = oid(algorithm, 'commit', commit_body)
    entries = [(3, content, None), (2, tree_body, None), (1, commit_body, None)]
    if base is not None:
        require(len(base) < 127, 'small literal fixture')
        delta = bytes([len(base), len(base) + 1, 0x90, len(base), 1, ord('!')])
        base_id = oid(algorithm, 'blob', base)
        if mode == 'ofs':
            entries[0] = (6, delta, 0)
            entries.insert(0, (3, base, None))
        else:
            entries[0] = (7, delta, base_id)
            if mode == 'forward':
                entries.append((3, base, None))
    if extra:
        entries.append((3, b'unrelated extra uploaded object', None))
    pack = encode_pack(algorithm, entries)
    header = (f'# v3 git bundle\n@object-format={algorithm}\n-{f["target"]} parent\n'
              f'{identity} {TARGET}\n\n').encode()
    return dict(bytes=header + pack, pack_bytes=len(pack), commit=identity, body=commit_body,
                file=file, tree=after_tree, content=content, parents=parents, merging=merging,
                count=len(entries), transport=int(mode in ('forward', 'ofs')), mode=mode,
                expanded=len(content) + len(tree_body) + len(commit_body) + (len(base) if mode in ('forward', 'ofs') else 0))


def validate(report, f, c, algorithm):
    for key, value in dict(type='candidate_review', schema_version=1, profile='verified-bundle-v1',
                           candidate_origin='untrusted_bundle', kind='merge' if c['merging'] else 'workspace',
                           published_to_repository=False, approval_granted=False, objects_staged=False,
                           node_closed=True, bundle_sha256=hashlib.sha256(c['bytes']).hexdigest(),
                           bundle_bytes=len(c['bytes']), pack_bytes=c['pack_bytes'], pack_objects=c['count'],
                           expanded_bytes=c['expanded'], transport_only_objects=c['transport'],
                           candidate_commit=c['commit'], parents=c['parents'],
                           candidate_commit_hex=c['body'].hex(), candidate_commit_text=c['body'].decode(),
                           prerequisites=[f['target']], merge_base=f['base'] if c['merging'] else None,
                           source_reference_hex=SOURCE.encode().hex() if c['merging'] else None).items():
        require(report[key] == value and type(report[key]) is type(value), f'candidate binding: {key}')
    require(report['closure_objects'] == (11 if c['merging'] else 8), 'complete native graph count')
    r = report['review']
    for key, value in dict(type='source_review', complete=True, node_closed=True, tenant_id=TENANT,
                           repository_id=REPO, object_format=algorithm, before_reference_hex=TARGET.encode().hex(),
                           after_reference_hex=TARGET.encode().hex(), comparison='direct',
                           requested_before=f['target'], requested_after=c['commit'], compared_before=f['target'],
                           before_tree=f['before_tree'], after_tree=c['tree'], pull_request=None,
                           entry_count=1, line_origin=0, path_prefixes_hex=[]).items():
        require(r[key] == value and type(r[key]) is type(value), f'review binding: {key}')
    require(r['source_head'] and r['snapshot_token'].startswith('alg:'), 'pinned authority identity')
    require(len(r['entries']) == 1, 'one changed path')
    e = r['entries'][0]
    require(e['path_hex'] == b'file'.hex() and e['change'] == 'Modified', 'actual file comparison')
    require(e['before'] == dict(oid=f['original'], mode='100644'), 'old blob identity')
    require(e['after'] == dict(oid=c['file'], mode='100644'), 'actual new blob identity')
    content = e['content']
    require(content['kind'] == 'text' and content['before_bytes'] == len(f['old'])
            and content['after_bytes'] == len(c['content']), 'blob lengths')
    out, cursor = bytearray(), 0
    for h in content['hunks']:
        old, new = h['old'], h['new']
        a, b = old['byte_start'], old['byte_end']
        require(0 <= cursor <= a <= b <= len(f['old']), 'ordered exact old span')
        require(bytes.fromhex(h['before_hex']) == f['old'][a:b], 'hunk old bytes')
        require(bytes.fromhex(h['after_hex']) == c['content'][new['byte_start']:new['byte_end']], 'hunk new bytes')
        require(old['line_start'] == f['old'].count(b'\n', 0, a), 'old line origin')
        require(new['line_start'] == c['content'].count(b'\n', 0, new['byte_start']), 'new line origin')
        out.extend(f['old'][cursor:a]); out.extend(bytes.fromhex(h['after_hex'])); cursor = b
    out.extend(f['old'][cursor:])
    require(bytes(out) == c['content'], 'hunks reconstruct actual candidate, not source-side changes')


def invoke(binary, args, code=0):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=180)
    require(result.returncode == code, f'fg exit {result.returncode}, expected {code}: {result.stderr!r}; {result.stdout!r}')
    return result


def run(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix='fg-candidate-inspect-') as directory:
        root = Path(directory)
        source, node = root / 'source', root / 'node'
        f = fixture(source, algorithm)
        invoke(binary, ['init', node, TENANT, REPO, algorithm])
        invoke(binary, ['import', node, TENANT, REPO, PRINCIPAL, 'inspect-fixture', source])
        state = ['at', node, TENANT, REPO, 'latest']
        before = invoke(binary, state).stdout
        queries = 0
        for merging in (False, True):
            for mode in ('direct', 'thin', 'forward', 'ofs'):
                c = candidate(f, algorithm, merging, mode)
                path = root / 'candidate.bundle'; path.write_bytes(c['bytes'])
                args = ['merge' if merging else 'workspace', 'inspect', node, TENANT, REPO, TARGET, path,
                        '--trusted-local', '--expected-target' if merging else '--expected-base', f['target'],
                        '--expected-commit', c['commit']]
                if merging:
                    args += ['--source-ref', SOURCE, '--expected-source', f['source'], '--merge-base', f['base']]
                result = invoke(binary, args)
                require(b'\x1b' not in result.stdout and '\u202e'.encode() not in result.stdout, 'terminal-safe commit metadata')
                validate(json.loads(result.stdout), f, c, algorithm)
                require(invoke(binary, args).stdout == result.stdout, 'deterministic candidate receipt')
                require(invoke(binary, state).stdout == before, 'inspection changed canonical state')
                for bad in (c['bytes'][:-1] + bytes([c['bytes'][-1] ^ 1]),
                            candidate(f, algorithm, merging, 'hidden')['bytes'],
                            candidate(f, algorithm, merging, 'direct', extra=True)['bytes']):
                    path.write_bytes(bad)
                    # Bind each deliberate malformed candidate to its actual header ID,
                    # so negatives exercise pack/scope validation, not a stale expected ID.
                    broken = args.copy(); position = broken.index('--expected-commit') + 1
                    broken[position] = bad.split(b'\n\n', 1)[0].splitlines()[-1].split()[0].decode()
                    require(not invoke(binary, broken, 2).stdout, 'invalid artifact produced a successful report')
                path.write_bytes(c['bytes'])
                for extra in (['--comparison', 'merge-base'], ['--max-diff-work', '1'],
                              ['--expected-head', 'alg:1:' + '00' * 32]):
                    require(not invoke(binary, args + extra, 2).stdout, 'invalid scope/pin produced a successful report')
                queries += 1
        require(invoke(binary, state).stdout == before, 'failed inspection changed canonical state')
        print(json.dumps(dict(type='candidate_review_smoke', format=algorithm, queries=queries,
                              passed=True, rust_executed=True)))


def self_test():
    negatives = 0
    for algorithm in ('sha1', 'sha256'):
        with tempfile.TemporaryDirectory() as directory:
            f = fixture(Path(directory), algorithm)
            for mode in ('direct', 'thin', 'forward', 'ofs'):
                c = candidate(f, algorithm, mode=mode)
                pack = c['bytes'].split(b'\n\n', 1)[1]
                width = hashlib.new(algorithm).digest_size
                require(hashlib.new(algorithm, pack[:-width]).digest() == pack[-width:], 'independent pack checksum')
            c = candidate(f, algorithm)
            report = dict(type='candidate_review', schema_version=1, profile='verified-bundle-v1',
                          candidate_origin='untrusted_bundle', kind='workspace', published_to_repository=False,
                          approval_granted=False, objects_staged=False, node_closed=True,
                          bundle_sha256=hashlib.sha256(c['bytes']).hexdigest(), bundle_bytes=len(c['bytes']),
                          pack_bytes=c['pack_bytes'], pack_objects=c['count'], expanded_bytes=c['expanded'],
                          closure_objects=8, transport_only_objects=0, candidate_commit=c['commit'],
                          parents=c['parents'], candidate_commit_hex=c['body'].hex(), candidate_commit_text=c['body'].decode(),
                          prerequisites=[f['target']], merge_base=None, source_reference_hex=None)
            old, new = f['old'], c['content']
            span = lambda b: dict(byte_start=0, byte_end=len(b), line_start=0, line_count=len(b.splitlines()))
            report['review'] = dict(type='source_review', complete=True, node_closed=True, tenant_id=TENANT, repository_id=REPO,
                object_format=algorithm, before_reference_hex=TARGET.encode().hex(), after_reference_hex=TARGET.encode().hex(),
                comparison='direct', requested_before=f['target'], requested_after=c['commit'], compared_before=f['target'],
                before_tree=f['before_tree'], after_tree=c['tree'], pull_request=None, entry_count=1, line_origin=0,
                path_prefixes_hex=[], source_head='fixture-head', snapshot_token='alg:1:' + 'ab' * 32,
                entries=[dict(path_hex=b'file'.hex(), change='Modified', before=dict(oid=f['original'], mode='100644'),
                    after=dict(oid=c['file'], mode='100644'), content=dict(kind='text', before_bytes=len(old), after_bytes=len(new),
                    hunks=[dict(old=span(old), new=span(new), before_hex=old.hex(), after_hex=new.hex())]))])
            validate(report, f, c, algorithm)
            mutations = [('candidate_commit', f['source']), ('bundle_sha256', '00' * 32), ('parents', [f['source']]),
                         ('objects_staged', True), ('approval_granted', True), ('published_to_repository', True),
                         ('candidate_commit_hex', ''), ('pack_objects', 0), ('closure_objects', 0),
                         ('transport_only_objects', 1), ('node_closed', False), ('candidate_origin', 'canonical')]
            for key, value in mutations:
                bad = copy.deepcopy(report); bad[key] = value
                try:
                    validate(bad, f, c, algorithm)
                except AssertionError:
                    negatives += 1
                else:
                    raise AssertionError(f'checker accepted corrupt {key}')
            for key, value in [('comparison', 'merge-base'), ('requested_after', f['source']), ('complete', False)]:
                bad = copy.deepcopy(report); bad['review'][key] = value
                try:
                    validate(bad, f, c, algorithm)
                except AssertionError:
                    negatives += 1
                else:
                    raise AssertionError(f'checker accepted corrupt review {key}')
            bad = copy.deepcopy(report)
            bad['review']['entries'][0]['content']['hunks'][0]['after_hex'] = b'wrong merge result'.hex()
            try:
                validate(bad, f, c, algorithm)
            except AssertionError:
                negatives += 1
            else:
                raise AssertionError('checker accepted wrong resulting content')
    print(json.dumps(dict(type='candidate_review_checker_self_test', corrupted_reports_rejected=negatives, rust_executed=False)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--self-test', action='store_true')
    group.add_argument('--fg', type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test()
    else:
        binary = options.fg.resolve(strict=True)
        print(json.dumps(dict(type='binary_identity', path=str(binary), sha256=hashlib.sha256(binary.read_bytes()).hexdigest())))
        for format in ('sha1', 'sha256'):
            run(binary, format)
