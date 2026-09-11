#!/usr/bin/env python3
"""Actual fg import campaign; fixture checks do not execute FrankenGit."""
import argparse
import binascii
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

TENANT, REPOSITORY, PRINCIPAL = 'd1' * 16, 'd2' * 16, 'd3' * 16
REF = 'refs/heads/main'
CASES = ('valid', 'padded-gitlink', 'commit-tree', 'parent-tree', 'directory-blob',
         'file-tree', 'symlink-tree', 'tag-kind', 'duplicate-tree', 'continued-parent', 'missing-child')
KINDS = {1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag'}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(algorithm, data):
    return hashlib.new(algorithm, data).digest()


def oid(algorithm, kind, body):
    return digest(algorithm, f'{kind} {len(body)}\0'.encode() + body).hex()


def tree(entries):
    ordered = sorted(entries, key=lambda e: e[0] + (b'/' if int(e[1], 8) & 0o170000 == 0o40000 else b'\0'))
    return b''.join(mode.encode() + b' ' + name + b'\0' + bytes.fromhex(identity)
                    for name, mode, identity in ordered)


def commit(tree_id, parents=(), extra=b''):
    return (f'tree {tree_id}\n' + ''.join(f'parent {p}\n' for p in parents)).encode() + extra + (
        b'author Test <test@example.invalid> 1 +0000\n'
        b'committer Test <test@example.invalid> 1 +0000\n\nimport graph\n')


def fixture(algorithm, case):
    objects = {}
    def put(kind, body):
        identity = oid(algorithm, kind, body)
        objects[identity] = kind, body
        return identity
    blob = put('blob', b'raw content\0\xff\r\n')
    empty = put('tree', b'')
    external = oid(algorithm, 'commit', b'commit in a different repository')
    mode = '0160000' if case == 'padded-gitlink' else '160000'
    root_tree = put('tree', tree([(b'file', '100755', blob), (b'link', '120000', blob), (b'submodule', mode, external)]))
    root = put('commit', commit(root_tree))
    if case == 'commit-tree':
        root = put('commit', commit(blob))
    elif case == 'parent-tree':
        root = put('commit', commit(root_tree, [empty]))
    elif case in ('directory-blob', 'file-tree', 'symlink-tree'):
        mode, child = {'directory-blob': ('40000', blob), 'file-tree': ('100644', empty),
                       'symlink-tree': ('120000', empty)}[case]
        root = put('commit', commit(put('tree', tree([(b'entry', mode, child)]))))
    elif case == 'tag-kind':
        root = put('tag', f'object {blob}\ntype commit\ntag wrong\ntagger Test <test@example.invalid> 1 +0000\n\nwrong kind\n'.encode())
    elif case == 'duplicate-tree':
        root = put('commit', commit(root_tree, extra=f'tree {root_tree}\n'.encode()))
    elif case == 'continued-parent':
        root = put('commit', commit(root_tree, [root], b' discarded continuation\n'))
    elif case == 'missing-child':
        missing = oid(algorithm, 'blob', b'not supplied')
        root = put('commit', commit(put('tree', tree([(b'missing', '100644', missing)]))))
    require(case in CASES, 'known fixture case')
    junk = put('blob', b'unreachable and not a local dependency')
    return dict(algorithm=algorithm, case=case, objects=objects, root=root, external=external, junk=junk)


def encode_pair(algorithm, objects):
    pack = bytearray(b'PACK' + struct.pack('>II', 2, len(objects)))
    entries = []
    for identity, (kind, body) in sorted(objects.items()):
        offset = len(pack)
        size = len(body)
        byte = (next(code for code, label in KINDS.items() if label == kind) << 4) | (size & 15)
        size >>= 4
        while size:
            pack.append(byte | 128)
            byte = size & 127
            size >>= 7
        pack.append(byte)
        pack.extend(zlib.compress(body))
        entries.append((identity, binascii.crc32(pack[offset:]) & 0xffffffff, offset))
    checksum = digest(algorithm, pack)
    pack.extend(checksum)
    index = bytearray(b'\xfftOc' + struct.pack('>I', 2))
    for byte in range(256):
        index.extend(struct.pack('>I', sum(bytes.fromhex(identity)[0] <= byte for identity, _, _ in entries)))
    index.extend(b''.join(bytes.fromhex(identity) for identity, _, _ in entries))
    index.extend(b''.join(struct.pack('>I', crc) for _, crc, _ in entries))
    index.extend(b''.join(struct.pack('>I', offset) for _, _, offset in entries))
    index.extend(checksum)
    index.extend(digest(algorithm, index))
    return bytes(pack), bytes(index)


def decode_pair(algorithm, pack, index):
    width = hashlib.new(algorithm).digest_size
    require(pack[:8] == b'PACK\0\0\0\2', 'pack header')
    require(digest(algorithm, pack[:-width]) == pack[-width:], 'pack checksum')
    count = struct.unpack('>I', pack[8:12])[0]
    require(0 < count < 1000, 'fixture pack count')
    at, entries, objects = 12, {}, {}
    for _ in range(count):
        start = at
        byte = pack[at]; at += 1
        kind, size, shift = byte >> 4 & 7, byte & 15, 4
        while byte & 128:
            require(shift < 64, 'object varint bound')
            byte = pack[at]; at += 1
            size |= (byte & 127) << shift; shift += 7
        require(kind in KINDS and size < 1 << 20, 'bounded fixture object')
        reader = zlib.decompressobj()
        body = reader.decompress(pack[at:-width], size + 1)
        require(reader.eof and len(body) == size, 'exact zlib member')
        at = len(pack) - width - len(reader.unused_data)
        identity = oid(algorithm, KINDS[kind], body)
        require(identity not in objects, 'unique native identities')
        objects[identity] = KINDS[kind], body
        entries[identity] = binascii.crc32(pack[start:at]) & 0xffffffff, start
    require(at == len(pack) - width, 'exact pack boundary')
    require(index[:8] == b'\xfftOc\0\0\0\2', 'index header')
    require(len(index) == 8 + 1024 + count * (width + 8) + width * 2, 'index length')
    require(digest(algorithm, index[:-width]) == index[-width:], 'index checksum')
    require(index[-2 * width:-width] == pack[-width:], 'index pack binding')
    identities = sorted(objects)
    for byte in range(256):
        require(struct.unpack_from('>I', index, 8 + 4 * byte)[0] ==
                sum(bytes.fromhex(i)[0] <= byte for i in identities), 'index fanout')
    at = 1032
    require(index[at:at + count * width] == b''.join(bytes.fromhex(i) for i in identities), 'index identities')
    for n, identity in enumerate(identities):
        crc = struct.unpack_from('>I', index, at + count * width + 4 * n)[0]
        offset = struct.unpack_from('>I', index, at + count * (width + 4) + 4 * n)[0]
        require((crc, offset) == entries[identity], 'index offset and CRC')
    return objects


def write_source(root, f, storage):
    (root / 'refs/heads').mkdir(parents=True)
    (root / 'objects').mkdir()
    (root / 'HEAD').write_bytes(b'ref: refs/heads/main\n')
    (root / REF).write_text(f['root'] + '\n')
    (root / 'config').write_text('[core]\nbare=true\nrepositoryformatversion=' +
        ('1\n[extensions]\nobjectformat=sha256\n' if f['algorithm'] == 'sha256' else '0\n'))
    objects = f['objects']
    if storage in ('packed', 'mixed'):
        packed = {i: body for i, body in objects.items() if storage == 'packed' or i != f['root']}
        pack, index = encode_pair(f['algorithm'], packed)
        require(decode_pair(f['algorithm'], pack, index) == packed, 'independent pack round-trip')
        directory = root / 'objects/pack'; directory.mkdir()
        (directory / 'fixture.pack').write_bytes(pack)
        (directory / 'fixture.idx').write_bytes(index)
    for identity, (kind, body) in objects.items():
        if storage == 'packed' or (storage == 'mixed' and identity != f['root']):
            continue
        path = root / 'objects' / identity[:2] / identity[2:]
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(zlib.compress(f'{kind} {len(body)}\0'.encode() + body))


def invoke(binary, arguments, expected=0, env=None):
    result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True, timeout=240, env=env)
    require(result.returncode == expected,
            f'exit {result.returncode} != {expected}: stdout={result.stdout!r}; stderr={result.stderr!r}')
    return result


def run_fg(binary):
    fingerprint = hashlib.sha256(binary.read_bytes()).hexdigest()
    for algorithm in ('sha1', 'sha256'):
        for storage in ('loose', 'packed', 'mixed'):
            for case in CASES:
                with tempfile.TemporaryDirectory(prefix='fg-import-graph-') as temporary:
                    root = Path(temporary)
                    f = fixture(algorithm, case)
                    write_source(root / 'source', f, storage)
                    node = root / 'node'
                    invoke(binary, ['init', node, TENANT, REPOSITORY, algorithm])
                    state = ['at', node, TENANT, REPOSITORY, 'latest']
                    before = invoke(binary, state).stdout
                    arguments = ['import', node, TENANT, REPOSITORY, PRINCIPAL, 'typed-import', root / 'source']
                    if case in ('valid', 'padded-gitlink'):
                        report = invoke(binary, arguments).stdout
                        require(report == b'published 1 source-import ref commands\n', 'explicit import result')
                        after = invoke(binary, state).stdout
                        require(after != before, 'import must publish authority')
                        references = invoke(binary, state + ['refs']).stdout
                        require(f'  {REF} -> {f["root"]}\n'.encode() in references, 'exact imported ref')
                        require(invoke(binary, arguments).stdout == report, 'identical import retry')
                        require(invoke(binary, state).stdout == after, 'retry must not republish')
                        invoke(binary, ['doctor', node, TENANT, REPOSITORY, f['root']])
                        invoke(binary, ['doctor', node, TENANT, REPOSITORY, f['external']], 2)
                        invoke(binary, ['doctor', node, TENANT, REPOSITORY, f['junk']], 2)
                    else:
                        failed = invoke(binary, arguments, 2)
                        require(not failed.stdout and failed.stderr, 'invalid import is not success')
                        require(invoke(binary, state).stdout == before, 'invalid source changed canonical state')
                        invoke(binary, ['doctor', node, TENANT, REPOSITORY, f['root']], 2)
        print(json.dumps(dict(type='source_import_graph_smoke', algorithm=algorithm,
            fg_sha256=fingerprint, cases=3 * len(CASES), rust_executed=True, passed=True)))


def git_oracle(binary):
    version = invoke(binary, ['--version']).stdout.decode().strip()
    checked = 0
    for algorithm in ('sha1', 'sha256'):
        for storage in ('loose', 'packed', 'mixed'):
            for case in CASES:
                with tempfile.TemporaryDirectory(prefix='fg-import-git-fixture-') as temporary:
                    root = Path(temporary)
                    home = root / 'home'; home.mkdir()
                    env = dict(os.environ)
                    for name in list(env):
                        if name.startswith('GIT_'):
                            del env[name]
                    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM='1',
                               GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
                    f = fixture(algorithm, case)
                    source = root / 'source'
                    write_source(source, f, storage)
                    result = subprocess.run([str(binary), '-C', str(source), 'fsck', '--full', '--strict'],
                        capture_output=True, timeout=60, env=env)
                    # Strict fsck rejects padded modes that GitCompatibleImport
                    # intentionally preserves. Check that precise distinction,
                    # not a blanket equivalence claim or a weakened fsck lane.
                    strict_valid = case == 'valid'
                    require((result.returncode == 0) == strict_valid,
                            f'{algorithm}/{storage}/{case}: {result.returncode}; {result.stdout!r}; {result.stderr!r}')
                    if case == 'padded-gitlink':
                        require(b'zeroPaddedFilemode' in result.stderr, 'strict padded-mode diagnostic')
                        ordinary = invoke(binary, ['-C', source, 'fsck', '--full'], env=env)
                        require(b'zeroPaddedFilemode' in ordinary.stderr, 'ordinary import warning retained')
                    if case in ('valid', 'padded-gitlink'):
                        actual = invoke(binary, ['-C', source, 'cat-file', '-p', f['root']], env=env).stdout
                        require(actual == f['objects'][f['root']][1], 'exact original commit bytes')
                    checked += 1
    print(json.dumps(dict(type='source_import_fixture_oracle', git=version, cases=checked, rust_executed=False)))


def self_test():
    rejected = 0
    for algorithm in ('sha1', 'sha256'):
        for case in CASES:
            f = fixture(algorithm, case)
            pack, index = encode_pair(algorithm, f['objects'])
            require(decode_pair(algorithm, pack, index) == f['objects'], 'fixture object identity')
        f = fixture(algorithm, 'valid'); pack, index = encode_pair(algorithm, f['objects'])
        width = hashlib.new(algorithm).digest_size
        bad_inputs = [(pack[:n], index) for n in (0, 4, 8, 12, len(pack) - 1)]
        bad_inputs += [(pack, index[:n]) for n in (0, 8, 100, 1032, len(index) - 1)]
        bad_inputs += [(pack + b'x', index), (pack, index + b'x')]
        for offset in (8, 1028, 1032, len(index) - 2 * width):
            changed = bytearray(index); changed[offset] ^= 1
            changed[-width:] = digest(algorithm, changed[:-width])
            bad_inputs.append((pack, bytes(changed)))
        for changed_pack, changed_index in bad_inputs:
            try:
                decode_pair(algorithm, changed_pack, changed_index)
            except (AssertionError, IndexError, struct.error, zlib.error):
                rejected += 1
            else:
                raise AssertionError('corrupted fixture accepted')
    print(json.dumps(dict(type='source_import_fixture_self_test', rejected=rejected, rust_executed=False)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--self-test', action='store_true')
    group.add_argument('--git-oracle', type=Path)
    group.add_argument('--fg', type=Path)
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
    elif arguments.git_oracle:
        git_oracle(arguments.git_oracle.resolve(strict=True))
    else:
        run_fg(arguments.fg.resolve(strict=True))


if __name__ == '__main__':
    main()
