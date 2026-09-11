#!/usr/bin/env python3
"""Checksum-valid graph fixtures and the actual raw receive-pack boundary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import zlib

TENANT, REPO, PRINCIPAL = '71' * 16, '72' * 16, '73' * 16


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def object_bytes(algorithm, kind, body):
    identity = hashlib.new(algorithm, f'{kind} {len(body)}\0'.encode() + body).hexdigest()
    return identity, kind, body


def tree(algorithm, entries):
    body = b''.join(f'{mode} {name}\0'.encode() + bytes.fromhex(identity)
                    for mode, name, identity in entries)
    return object_bytes(algorithm, 'tree', body)


def commit(algorithm, tree_id, parents=()):
    body = (f'tree {tree_id}\n' + ''.join(f'parent {p}\n' for p in parents) +
            'author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nfixture\n').encode()
    return object_bytes(algorithm, 'commit', body)


def tag(algorithm, identity, declared):
    return object_bytes(algorithm, 'tag', (f'object {identity}\ntype {declared}\ntag checked\n'
        'tagger Test <test@example.invalid> 1 +0000\n\nfixture\n').encode())


def fixtures(algorithm):
    blob = object_bytes(algorithm, 'blob', b'exact bytes\r\n\xff')
    empty = tree(algorithm, [])
    good_tree = tree(algorithm, [('100644', 'file', blob[0])])
    good_commit = commit(algorithm, good_tree[0])
    good_tag = tag(algorithm, good_commit[0], 'commit')
    bad_tree_commit = commit(algorithm, blob[0])
    bad_parent_commit = commit(algorithm, empty[0], [blob[0]])
    bad_directory = tree(algorithm, [('40000', 'directory', blob[0])])
    bad_file = tree(algorithm, [('100644', 'file', empty[0])])
    bad_tag = tag(algorithm, blob[0], 'commit')
    links = tree(algorithm, [('100755', 'executable', blob[0]), ('160000', 'submodule',
        '1' * (40 if algorithm == 'sha1' else 64)), ('120000', 'symlink', blob[0])])
    link_commit = commit(algorithm, links[0])
    return [
        ('commit-tree-kind', False, bad_tree_commit, [blob, bad_tree_commit]),
        ('commit-parent-kind', False, bad_parent_commit, [blob, empty, bad_parent_commit]),
        ('directory-kind', False, bad_directory, [blob, bad_directory]),
        ('file-kind', False, bad_file, [empty, bad_file]),
        ('tag-target-kind', False, bad_tag, [blob, bad_tag]),
        ('valid-commit', True, good_commit, [blob, good_tree, good_commit]),
        ('valid-tag-chain', True, good_tag, [blob, good_tree, good_commit, good_tag]),
        ('valid-modes-and-gitlink', True, link_commit, [blob, links, link_commit]),
    ]


def pack(algorithm, objects):
    data = bytearray(b'PACK' + struct.pack('>II', 2, len(objects)))
    for _, kind, body in sorted(objects):
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


def unpack_fixture(algorithm, data):
    width = hashlib.new(algorithm).digest_size
    require(len(data) >= 12 + width, 'pack truncated')
    require(data[:8] == b'PACK\0\0\0\x02', 'pack signature/version')
    require(hashlib.new(algorithm, data[:-width]).digest() == data[-width:], 'pack checksum')
    count = struct.unpack('>I', data[8:12])[0]
    require(0 < count <= 32, 'fixture count')
    at, objects = 12, []
    for _ in range(count):
        byte = data[at]; at += 1
        kind, size, shift = byte >> 4 & 7, byte & 15, 4
        while byte & 128:
            require(shift <= 28, 'bounded size')
            byte = data[at]; at += 1
            size |= (byte & 127) << shift; shift += 7
        require(kind in (1, 2, 3, 4) and size <= 65536, 'fixture object bounds')
        reader = zlib.decompressobj()
        body = reader.decompress(data[at:-width], size + 1)
        require(reader.eof and len(body) == size, 'complete object')
        at = len(data) - width - len(reader.unused_data)
        objects.append(object_bytes(algorithm, {1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag'}[kind], body))
    require(at == len(data) - width, 'trailing pack data')
    return objects


def invoke(binary, arguments, **kwargs):
    return subprocess.run([str(binary), *map(str, arguments)], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=240, **kwargs)


def self_test():
    rejected = 0
    for algorithm in ('sha1', 'sha256'):
        for _, _, _, objects in fixtures(algorithm):
            data = pack(algorithm, objects)
            require(unpack_fixture(algorithm, data) == sorted(objects), 'exact fixture objects')
            for bad in (data[:-1], data[:11], b'FAIL' + data[4:]):
                try:
                    unpack_fixture(algorithm, bad)
                except (AssertionError, IndexError, zlib.error):
                    rejected += 1
                else:
                    raise AssertionError('fixture checker accepted corruption')
    status = pkt(b'unpack ok\n') + pkt(b'ok refs/heads/main\n') + b'0000'
    require(status_packets(status) == [b'unpack ok\n', b'ok refs/heads/main\n'], 'status parser positive')
    for bad in (status[:-1], status + b'extra', b'0000', b'xxxx', b'0008oops0000'):
        try:
            status_packets(bad)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError('status parser accepted incomplete report')
    print(json.dumps(dict(type='quarantine_fixture_self_test', corruptions_rejected=rejected,
                         rust_executed=False)))


def git_oracle(binary):
    version = invoke(binary, ['--version'])
    require(version.returncode == 0, version.stderr)
    passed = 0
    with tempfile.TemporaryDirectory(prefix='fg-quarantine-oracle-') as directory:
        base = Path(directory)
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update(HOME=str(base), GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_TERMINAL_PROMPT='0')
        for algorithm in ('sha1', 'sha256'):
            for name, valid, _, objects in fixtures(algorithm):
                repo = base / f'{algorithm}-{name}'
                init = invoke(binary, ['init', '--bare', '--quiet', f'--object-format={algorithm}', repo], env=env)
                require(init.returncode == 0, init.stderr)
                result = invoke(binary, ['-C', repo, 'index-pack', '--strict', '--stdin'],
                                input=pack(algorithm, objects), env=env)
                require((result.returncode == 0) == valid,
                        f'{algorithm}/{name}: {result.returncode}: {result.stderr!r}')
                passed += 1
    print(json.dumps(dict(type='quarantine_git_fixture_oracle', git=version.stdout.decode().strip(),
                         cases=passed, rust_executed=False)))


def pkt(payload):
    return f'{len(payload) + 4:04x}'.encode() + payload


def status_packets(data):
    at, packets = 0, []
    while True:
        require(at + 4 <= len(data), 'truncated status header')
        field = data[at:at + 4]
        require(all(b in b'0123456789abcdefABCDEF' for b in field), 'invalid status length')
        size = int(field, 16); at += 4
        if size == 0:
            require(at == len(data), 'data after status flush')
            require(packets and packets[0].startswith(b'unpack '), 'missing unpack status')
            return packets
        require(4 <= size <= 65520 and at + size - 4 <= len(data), 'truncated status packet')
        packets.append(data[at:at + size - 4]); at += size - 4


def read_exact(connection, n):
    result = bytearray()
    while len(result) != n:
        part = connection.recv(n - len(result))
        require(part, 'truncated pkt-line')
        result.extend(part)
    return bytes(result)


def receive(binary, storage, algorithm, reference, tip, data):
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    process = subprocess.Popen([str(binary), 'serve', str(storage), TENANT, REPO,
        f'127.0.0.1:{port}', '--receive-principal', PRINCIPAL],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        connection = None
        while connection is None and time.monotonic() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                raise AssertionError(f'server exited before connection: {stdout!r}; {stderr!r}')
            try:
                connection = socket.create_connection(('127.0.0.1', port), timeout=1)
            except ConnectionRefusedError:
                time.sleep(0.05)
        require(connection is not None, 'server startup deadline')
        with connection:
            connection.settimeout(240)
            connection.sendall(pkt(f'git-receive-pack /{REPO}.git\0host=127.0.0.1:{port}\0'.encode()))
            advertisement = []
            while True:
                size = int(read_exact(connection, 4), 16)
                if size == 0:
                    break
                require(4 <= size <= 65520, 'advertisement packet length')
                advertisement.append(read_exact(connection, size - 4))
            capabilities = b''.join(advertisement).split(b'\0', 1)[-1].split()
            require(b'report-status' in capabilities, 'report-status must be advertised')
            selected = b'report-status'
            object_format = f'object-format={algorithm}'.encode()
            require(object_format in capabilities, 'exact advertised object format')
            selected += b' ' + object_format
            old = '0' * (40 if algorithm == 'sha1' else 64)
            connection.sendall(pkt(f'{old} {tip} {reference}\0'.encode() + selected + b'\n') + b'0000' + data)
            connection.shutdown(socket.SHUT_WR)
            chunks = []
            size = 0
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                size += len(chunk)
                require(size <= 1024 * 1024, 'bounded receive report')
                chunks.append(chunk)
        stdout, stderr = process.communicate(timeout=240)
        require(process.returncode == 0, f'server did not close cleanly: {stdout!r}; {stderr!r}')
        report = b''.join(chunks)
        require(report and (b'unpack ' in report or b'ng ' in report),
                f'no complete receive status: {report!r}; {stdout!r}; {stderr!r}')
        return report
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.communicate()


def run_fg(binary):
    count = 0
    with tempfile.TemporaryDirectory(prefix='fg-typed-quarantine-') as directory:
        for algorithm in ('sha1', 'sha256'):
            for name, valid, root, objects in fixtures(algorithm):
                storage = Path(directory) / f'{algorithm}-{name}'
                init = invoke(binary, ['init', storage, TENANT, REPO, algorithm])
                require(init.returncode == 0, init.stderr)
                state_args = ['at', storage, TENANT, REPO, 'latest']
                before = invoke(binary, state_args)
                require(before.returncode == 0, before.stderr)
                reference = 'refs/heads/main' if root[1] == 'commit' else 'refs/tags/checked'
                report = receive(binary, storage, algorithm, reference, root[0], pack(algorithm, objects))
                packets = status_packets(report)
                acknowledged = packets[0] == b'unpack ok\n' and packets[1:] == [f'ok {reference}\n'.encode()]
                require(acknowledged == valid, f'{algorithm}/{name}: {report!r}')
                after = invoke(binary, state_args)
                require(after.returncode == 0, after.stderr)
                require((after.stdout != before.stdout) == valid,
                        f'{algorithm}/{name}: canonical state did not match the terminal status')
                count += 1
    print(json.dumps(dict(type='quarantine_raw_receive_smoke', cases=count, rust_executed=True,
                         binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest())))


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
