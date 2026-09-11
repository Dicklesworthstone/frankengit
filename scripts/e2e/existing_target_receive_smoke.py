#!/usr/bin/env python3
"""Existing-object receive fixtures; Git oracle and real-fg modes are separate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

TENANT, REPOSITORY, PRINCIPAL = '71' * 16, '72' * 16, '73' * 16


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def object_bytes(algorithm, kind, body):
    return hashlib.new(algorithm, f'{kind} {len(body)}\0'.encode() + body).hexdigest(), kind, body


def commit(algorithm, tree, parents, message):
    body = (f'tree {tree}\n' + ''.join(f'parent {parent}\n' for parent in parents) +
        'author T <t@example.invalid> 1 +0000\ncommitter T <t@example.invalid> 1 +0000\n\n' + message + '\n').encode()
    return object_bytes(algorithm, 'commit', body)


def fixture(root, algorithm):
    blob = object_bytes(algorithm, 'blob', b'existing file\r\n\xff')
    tree = object_bytes(algorithm, 'tree', b'100644 file\0' + bytes.fromhex(blob[0]))
    base = commit(algorithm, tree[0], [], 'root')
    tip = commit(algorithm, tree[0], [base[0]], 'visible tip')
    def tag(target, label):
        return object_bytes(algorithm, 'tag', (f'object {target[0]}\ntype {target[1]}\ntag {label}\n'
            f'tagger T <t@example.invalid> 1 +0000\n\n{label}\n').encode())
    inner = tag(tip, 'inner')
    outer = tag(inner, 'outer')
    orphan = commit(algorithm, tree[0], [], 'not selected by any ref')
    new = commit(algorithm, tree[0], [tip[0]], 'new upload')
    junk = object_bytes(algorithm, 'blob', b'not part of any requested root')
    (root / 'refs/heads').mkdir(parents=True)
    (root / 'refs/tags').mkdir(parents=True)
    (root / 'HEAD').write_bytes(b'ref: refs/heads/main\n')
    (root / 'config').write_text('[core]\nbare=true\nrepositoryformatversion=' +
        ('1\n[extensions]\nobjectformat=sha256\n' if algorithm == 'sha256' else '0\n'))
    for identity, kind, body in [blob, tree, base, tip, inner, outer, orphan]:
        path = root / 'objects' / identity[:2] / identity[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f'{kind} {len(body)}\0'.encode() + body))
    (root / 'refs/heads/main').write_text(tip[0] + '\n')
    (root / 'refs/tags/outer').write_text(outer[0] + '\n')
    return dict(blob=blob, tree=tree, base=base, tip=tip, inner=inner, outer=outer,
                orphan=orphan, new=new, junk=junk)


def pack(algorithm, objects=()):
    data = bytearray(b'PACK' + struct.pack('>II', 2, len(objects)))
    for _, kind, body in objects:
        size = len(body)
        byte = ({'commit': 1, 'tree': 2, 'blob': 3, 'tag': 4}[kind] << 4) | (size & 15)
        size >>= 4
        while size:
            data.append(byte | 128)
            byte, size = size & 127, size >> 7
        data.append(byte)
        data.extend(zlib.compress(body))
    data.extend(hashlib.new(algorithm, data).digest())
    return bytes(data)


def check_empty_pack(algorithm, data):
    width = hashlib.new(algorithm).digest_size
    require(len(data) == 12 + width, 'exact zero-object pack length')
    require(data[:12] == b'PACK\0\0\0\x02\0\0\0\0', 'zero-object pack header')
    require(data[12:] == hashlib.new(algorithm, data[:12]).digest(), 'zero-object pack checksum')


def pkt(body):
    require(len(body) + 4 <= 65520, 'bounded pkt-line')
    return f'{len(body) + 4:04x}'.encode() + body


def parse_report(data):
    require(len(data) <= 1024 * 1024, 'bounded report')
    at, packets = 0, []
    while True:
        field = data[at:at + 4]
        require(len(field) == 4 and all(byte in b'0123456789abcdefABCDEF' for byte in field), 'report header')
        size = int(field, 16)
        at += 4
        if size == 0:
            require(at == len(data), 'trailing report bytes')
            return packets
        require(4 < size <= 65520 and at + size - 4 <= len(data), 'complete report packet')
        packets.append(data[at:at + size - 4])
        at += size - 4


def check_report(data, references, accepted):
    packets = parse_report(data)
    require(packets and packets[0].startswith(b'unpack '), 'unpack status required')
    require(len(packets) == len(references) + 1, 'one explicit status per requested ref')
    if accepted:
        require(packets[0] == b'unpack ok\n', 'successful unpack')
        require(packets[1:] == [f'ok {name}\n'.encode() for name in references], 'exact ref acknowledgements')
    else:
        for name, packet in zip(references, packets[1:]):
            require(packet.startswith(f'ng {name} '.encode()) and packet.endswith(b'\n'), 'explicit ref refusal')


def invoke(binary, args, **kwargs):
    return subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=240, **kwargs)


def self_test():
    count = 0
    for algorithm in ('sha1', 'sha256'):
        data = pack(algorithm)
        check_empty_pack(algorithm, data)
        for at in range(len(data)):
            bad = bytearray(data)
            bad[at] ^= 1
            try:
                check_empty_pack(algorithm, bytes(bad))
            except AssertionError:
                count += 1
            else:
                raise AssertionError('checker accepted changed empty-pack bytes')
        for bad in (data[:-1], data + b'\0', b''):
            try:
                check_empty_pack(algorithm, bad)
            except AssertionError:
                count += 1
            else:
                raise AssertionError('checker accepted non-exact empty pack')
    good = pkt(b'unpack ok\n') + pkt(b'ok refs/heads/copied\n') + b'0000'
    check_report(good, ['refs/heads/copied'], True)
    refused = pkt(b'unpack object closure incomplete\n') + pkt(b'ng refs/heads/copied object closure incomplete\n') + b'0000'
    check_report(refused, ['refs/heads/copied'], False)
    for bad in (good[:-1], good + b'x', b'0000', pkt(b'unpack ok\n') + b'0000',
                good.replace(b'copied', b'secret'), refused, b'xxxx'):
        try:
            check_report(bad, ['refs/heads/copied'], True)
        except AssertionError:
            count += 1
        else:
            raise AssertionError('checker accepted a corrupt positive report')
    print(json.dumps(dict(type='existing_target_checker', rejected=count, rust_executed=False)))


def git_oracle(binary):
    version = invoke(binary, ['--version'])
    require(version.returncode == 0, version.stderr)
    count = 0
    with tempfile.TemporaryDirectory(prefix='fg-existing-target-git-') as directory:
        home = Path(directory)
        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        env.update(HOME=str(home), GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
        for algorithm in ('sha1', 'sha256'):
            root = home / algorithm
            f = fixture(root, algorithm)
            cases = [('tip', f['tip'], []), ('historical', f['base'], []),
                     ('nested-tag', f['inner'], []), ('blob-tag', f['blob'], []),
                     ('new-child', f['new'], [f['new']])]
            for label, target, objects in cases:
                reference = f'refs/tags/{label}' if 'tag' in label else f'refs/heads/{label}'
                zeros = '0' * len(target[0])
                command = pkt(f'{zeros} {target[0]} {reference}\0report-status object-format={algorithm}\n'.encode())
                result = invoke(binary, ['receive-pack', '--stateless-rpc', root], input=command + b'0000' + pack(algorithm, objects), env=env)
                require(result.returncode == 0, result.stderr)
                check_report(result.stdout, [reference], True)
                observed = invoke(binary, ['-C', root, 'rev-parse', '--verify', reference], env=env)
                require(observed.returncode == 0 and observed.stdout.strip().decode() == target[0], 'Git published exact target')
                count += 1
    print(json.dumps(dict(type='existing_target_git_oracle', git=version.stdout.decode().strip(),
                         cases=count, rust_executed=False)))


def run_fg(binary):
    # Reuse the existing process-owned raw git-daemon client. It neither asks
    # Git to manufacture a pack nor lets a client pre-reject malformed inputs.
    from quarantine_typed_graph_smoke import receive, TENANT as client_tenant, REPO as client_repo
    require(client_tenant == TENANT and client_repo == REPOSITORY, 'fixture/client repository binding')
    count = 0
    with tempfile.TemporaryDirectory(prefix='fg-existing-target-') as directory:
        for algorithm in ('sha1', 'sha256'):
            root = Path(directory) / algorithm
            source, storage = root / 'source', root / 'node'
            f = fixture(source, algorithm)
            for args in (['init', storage, TENANT, REPOSITORY, algorithm],
                         ['import', storage, TENANT, REPOSITORY, PRINCIPAL, 'existing-fixture', source]):
                result = invoke(binary, args)
                require(result.returncode == 0, result.stderr)
            cases = [('tip', f['tip'], []), ('historical', f['base'], []),
                     ('nested-tag', f['inner'], []), ('blob-tag', f['blob'], []),
                     ('ignore-upload', f['tip'], [f['junk']]), ('new-child', f['new'], [f['new']])]
            for label, target, objects in cases:
                reference = f'refs/tags/{label}' if 'tag' in label else f'refs/heads/{label}'
                report = receive(binary, storage, algorithm, reference, target[0], pack(algorithm, objects))
                check_report(report, [reference], True)
                refs = invoke(binary, ['at', storage, TENANT, REPOSITORY, 'latest', 'refs'])
                require(refs.returncode == 0 and f'  {reference} -> {target[0]}\n'.encode() in refs.stdout,
                        f'exact canonical ref absent: {refs.stdout!r}; {refs.stderr!r}')
                count += 1
            state_args = ['at', storage, TENANT, REPOSITORY, 'latest']
            before = invoke(binary, state_args)
            require(before.returncode == 0, before.stderr)
            for label, target in [('orphan', f['orphan'][0]), ('missing', '1' * len(f['tip'][0]))]:
                reference = f'refs/heads/refused-{label}'
                report = receive(binary, storage, algorithm, reference, target, pack(algorithm))
                check_report(report, [reference], False)
                after = invoke(binary, state_args)
                require(after.returncode == 0 and after.stdout == before.stdout, 'refused target changed authority')
                count += 1
            probe = invoke(binary, ['doctor', storage, TENANT, REPOSITORY, f['junk'][0]])
            require(probe.returncode != 0, 'unrelated uploaded object became authority-selected')
    print(json.dumps(dict(type='existing_target_raw_receive', cases=count, rust_executed=True,
                         binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--self-test', action='store_true')
    group.add_argument('--git-oracle', type=Path)
    group.add_argument('--fg', type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.git_oracle:
        git_oracle(args.git_oracle.resolve())
    else:
        run_fg(args.fg.resolve())


if __name__ == '__main__':
    main()
