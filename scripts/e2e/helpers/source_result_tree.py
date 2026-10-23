"""Real fg HTTP preparation with independently computed complete result identities."""
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patch_smoke import oid, loose, bundle_objects

TENANT, REPOSITORY, PRINCIPAL = 'a1' * 16, 'a2' * 16, 'a3' * 16
AUTHOR = 'Result <test@example.invalid>'
MESSAGE = 'reviewed refactor\n'
RESULTS = []

def record(fmt, case, **details):
    row = dict(format=fmt, case=case, **details)
    RESULTS.append(row)
    print(json.dumps(row), flush=True)

def tree_bytes(rows):
    return b''.join(mode + b' ' + name + b'\0' + bytes.fromhex(identity)
                    for name, mode, identity in sorted(rows, key=lambda r: r[0] + (b'/' if r[1] == b'40000' else b'')))

def complete_tree(fmt, files, emit):
    def directory(prefix):
        rows = []
        for name in {p[len(prefix):].split(b'/', 1)[0] for p in files if p.startswith(prefix)}:
            path = prefix + name
            if path in files:
                mode, data = files[path]
                identity = emit('blob', data)
            else:
                mode, identity = b'40000', directory(path + b'/')
            rows.append((name, mode, identity))
        return emit('tree', tree_bytes(rows))
    return directory(b'')

def quoted(path):
    return '"' + ''.join(chr(b) if 33 <= b <= 126 and b not in (34, 92) else '\\' + format(b, '03o') for b in path) + '"'

def move(source, target, before, after=None):
    a, b = quoted(b'a/' + source), quoted(b'b/' + target)
    return (f'diff --git {a} {b}\n' + ('old mode 100644\nnew mode 100755\n' if after else '') +
            f'similarity index {50 if after else 100}%\nrename from {quoted(source)}\nrename to {quoted(target)}\n' +
            f'index {before}..{after or before}' + ('' if after else ' 100644') + '\n' +
            (f'--- {a}\n+++ {b}\n@@ -1 +1 @@\n-before\n+after\n' if after else '')).encode()

class Fixture:
    def __init__(self, fg, root, fmt):
        self.fg, self.root, self.fmt, self.sequence = fg, root / fmt, fmt, 0
        self.root.mkdir(parents=True)
        self.source, self.node = self.root / 'source', self.root / 'node'
        self.scope = [self.node, TENANT, REPOSITORY]
        self.files = {b'keep.bin': (b'100644', b'\0keep\xff'), b'src/edit.txt': (b'100644', b'before\n'), b'src/raw\xff.bin': (b'100644', b'\0binary\xff\r\n')}
        (self.source / 'refs/heads').mkdir(parents=True)
        (self.source / 'HEAD').write_text('ref: refs/heads/main\n')
        (self.source / 'config').write_text('[core]\nbare=true\nrepositoryformatversion=' + ('0\n' if fmt == 'sha1' else '1\n[extensions]\nobjectformat=sha256\n'))
        self.old_tree = complete_tree(fmt, self.files, lambda k, b: loose(self.source, fmt, k, b))
        self.base = loose(self.source, fmt, 'commit', f'tree {self.old_tree}\nauthor {AUTHOR} 1 +0000\ncommitter {AUTHOR} 1 +0000\n\nbase\n'.encode())
        (self.source / 'refs/heads/main').write_text(self.base + '\n')
        self.expected_files = {b'keep.bin': self.files[b'keep.bin'], b'lib/run.txt': (b'100755', b'after\n'), b'lib/data.bin': self.files[b'src/raw\xff.bin']}
        self.objects = {}
        def expect(kind, body):
            identity = oid(fmt, kind, body)
            self.objects[identity] = (kind, body)
            return identity
        self.expected_tree = complete_tree(fmt, self.expected_files, expect)
        self.commit_body = f'tree {self.expected_tree}\nparent {self.base}\nauthor {AUTHOR} 2 +0000\ncommitter {AUTHOR} 2 +0000\n\n{MESSAGE}'.encode()
        self.candidate = expect('commit', self.commit_body)
        self.patch = move(b'src/edit.txt', b'lib/run.txt', oid(fmt, 'blob', b'before\n'), oid(fmt, 'blob', b'after\n')) + move(b'src/raw\xff.bin', b'lib/data.bin', oid(fmt, 'blob', self.files[b'src/raw\xff.bin'][1]))
        self.extra_patch = self.patch + b'diff --git a/keep.bin b/keep.bin\nold mode 100644\nnew mode 100755\n'
        alternate = dict(self.expected_files)
        alternate[b'keep.bin'] = (b'100755', alternate[b'keep.bin'][1])
        self.alternate_tree = complete_tree(fmt, alternate, lambda k, b: oid(fmt, k, b))
        self.command('init', ['init', *self.scope, fmt])
        imported = json.loads(self.command('import', ['import', *self.scope, PRINCIPAL, 'fixture', self.source, '--json']))
        self.incarnation = imported['repository_incarnation_id']
        self.token = secrets.token_hex(32)
        header = self.command('header', ['serve-http', *self.scope, '127.0.0.1:0', '--trusted-local', '--print-credentials-header']).decode().strip()
        self.grants = self.root / 'grants'
        self.grants.write_text(header + '\n' + hashlib.sha256(self.token.encode()).hexdigest() + f' {PRINCIPAL} read,receive,outcomes-read\n')
        self.grants.chmod(0o600)
    def command(self, label, args, data=None):
        self.sequence += 1
        result = subprocess.run([self.fg, *map(str, args)], input=data, capture_output=True, timeout=120)
        prefix = self.root / f'{self.sequence:03d}-{label}'
        prefix.with_suffix('.out').write_bytes(result.stdout)
        prefix.with_suffix('.err').write_bytes(result.stderr)
        if result.stderr: sys.stderr.buffer.write(result.stderr); sys.stderr.buffer.flush()
        assert result.returncode == 0, (label, result.returncode, result.stdout[-2000:], result.stderr[-2000:])
        return result.stdout
    def basis(self):
        return self.command('basis', ['pr', 'list', *self.scope, '--trusted-local', '--object-format', self.fmt])
    def form(self):
        return dict(object_format=self.fmt, ref='refs/heads/main', expected_commit=self.base, author=AUTHOR, committer=AUTHOR, timestamp='2', message=MESSAGE)
    def validate(self, metadata, bundle):
        assert metadata['root_tree'] == self.expected_tree and metadata['candidate_commit'] == self.candidate
        assert metadata['source_commit'] == self.base and not metadata['published'] and not metadata['objects_staged']
        assert metadata['bundle'] == dict(bytes=len(bundle), sha256=hashlib.sha256(bundle).hexdigest())
        packed = bundle_objects(bundle, self.fmt, self.base, self.candidate)
        for identity, value in packed.items(): assert self.objects[identity] == value
        assert packed[self.candidate] == ('commit', self.commit_body)
        assert packed[self.expected_tree] == self.objects[self.expected_tree]
        assert {bytes.fromhex(p['path_hex']) for p in metadata['paths']} == {b'src/edit.txt', b'src/raw\xff.bin', b'lib/run.txt', b'lib/data.bin'}

class HTTP:
    def __init__(self, fixture, label):
        self.f, self.label = fixture, label
    def __enter__(self):
        f = self.f
        self.stop = f.root / (self.label + '.stop')
        self.out, self.err = f.root / (self.label + '.out'), f.root / (self.label + '.err')
        args = [f.fg, 'serve-http', *f.scope, '127.0.0.1:0', '--trusted-local', '--credentials-file', f.grants, '--allow-source', '--allow-receive', '--allow-outcomes', '--continuous', '--stop-file', self.stop]
        with self.out.open('wb') as out, self.err.open('wb') as err:
            self.process = subprocess.Popen(list(map(str, args)), stdout=out, stderr=err)
        end = time.monotonic() + 40
        try:
            while time.monotonic() < end:
                assert self.process.poll() is None, self.err.read_bytes()
                for line in self.out.read_text().splitlines():
                    if line.startswith('{') and 'smart_http_listening' in line:
                        self.url = urlsplit(json.loads(line)['url'])
                        return self
                time.sleep(.02)
            raise AssertionError('HTTP readiness expired')
        except BaseException:
            self.__exit__(None, None, None)
            raise
    def __exit__(self, *args):
        self.stop.touch()
        try: code = self.process.wait(timeout=40)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(); raise
        finally:
            data = self.err.read_bytes()
            if data: sys.stderr.buffer.write(data); sys.stderr.buffer.flush()
        assert code == 0, (code, self.out.read_bytes()[-1500:])
    def request(self, action, fields, payload, code=200, chunked=False, key=None, token=None):
        boundary = 'result-tree-test'
        parts = [('command', 'application/x-www-form-urlencoded', urlencode(fields).encode()), ('patch' if action == 'prepare' else 'bundle', 'text/x-diff' if action == 'prepare' else 'application/x-git-bundle', payload)]
        if chunked: parts.reverse()
        body = b''.join(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="ignored"\r\nContent-Type: {media}\r\n\r\n'.encode() + data + b'\r\n' for name, media, data in parts) + f'--{boundary}--\r\n'.encode()
        connection = http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=90)
        headers = {'Authorization': 'Bearer ' + (token or self.f.token), 'Content-Type': f'multipart/form-data; boundary={boundary}'}
        if key: headers['Idempotency-Key'] = key
        try:
            connection.request('POST', self.url.path.rstrip('/') + '/api/v1/source/' + action,
                               body=(body[i:i+37] for i in range(0, len(body), 37)) if chunked else body,
                               headers=headers, encode_chunked=chunked)
            reply = connection.getresponse(); data = reply.read()
            assert len(data) == int(reply.getheader('Content-Length'))
            assert reply.status == code, (action, reply.status, data[-2000:])
            self.f.sequence += 1
            (self.f.root / f'{self.f.sequence:03d}-http-response.bin').write_bytes(data)
            if code != 200:
                assert 'multipart/mixed' not in reply.getheader('Content-Type', '')
                assert b'candidate_commit' not in data and b'publication_arguments' not in data
                return data
            if action != 'prepare': return json.loads(data)
            boundary = reply.getheader('Content-Type').split('boundary=')[1].encode()
            parts = data.split(b'--' + boundary)
            assert len(parts) == 4 and parts[0] == b'' and parts[-1] == b'--\r\n'
            meta = json.loads(parts[1].split(b'\r\n\r\n', 1)[1][:-2])
            bundle = parts[2].split(b'\r\n\r\n', 1)[1][:-2]
            return meta, bundle
        finally: connection.close()

def http_campaign(f):
    before = f.basis(); form = f.form(); pinned = dict(form, expected_result_tree=f.expected_tree)
    with HTTP(f, 'http') as server:
        ordinary, bundle = server.request('prepare', form, f.patch)
        f.validate(ordinary, bundle)
        assert 'expected_result_tree' not in ordinary
        bound, same = server.request('prepare', pinned, f.patch, chunked=True)
        assert bound.pop('expected_result_tree') == f.expected_tree and bound == ordinary and same == bundle
        record(f.fmt, 'http-independent-tree-pin-preserves-exact-refactoring-bundle')
        for label, bad in [('old-tree', f.old_tree), ('commit-as-tree', f.base), ('blob-as-tree', oid(f.fmt, 'blob', b'before\n'))]:
            error = server.request('prepare', dict(form, expected_result_tree=bad), f.patch, code=409)
            assert b'patch_result_tree_mismatch' in error
            record(f.fmt, 'http-' + label + '-refuses-without-candidate')
        for label, bad in [('empty', ''), ('zero', '0' * len(f.base)), ('uppercase', 'A' * len(f.base)), ('invalid', 'z' * len(f.base)), ('wrong-domain', 'a' * (64 if f.fmt == 'sha1' else 40))]:
            server.request('prepare', dict(form, expected_result_tree=bad), f.patch, code=400)
            record(f.fmt, 'http-' + label + '-pin-refused')
        server.request('prepare', list(pinned.items()) + [('expected_result_tree', f.expected_tree)], f.patch, code=400)
        server.request('prepare', [(k, v) for k, v in pinned.items() if k != 'message'] + [('expected_result_tree', f.expected_tree)], f.patch, code=400)
        record(f.fmt, 'http-duplicate-pin-refused')
        alt, alt_bundle = server.request('prepare', form, f.extra_patch)
        assert alt['root_tree'] == f.alternate_tree
        error = server.request('prepare', pinned, f.extra_patch, code=409)
        assert b'patch_result_tree_mismatch' in error
        allowed, allowed_bundle = server.request('prepare', dict(form, expected_result_tree=f.alternate_tree), f.extra_patch)
        assert allowed.pop('expected_result_tree') == f.alternate_tree and allowed == alt and allowed_bundle == alt_bundle
        record(f.fmt, 'http-valid-unintended-sibling-mode-refused-beside-permitted-twin')
        server.request('prepare', pinned, f.patch, code=401, token='invalid-fixture-token')
        record(f.fmt, 'http-pin-does-not-bypass-authentication')
        assert server.request('prepare', form, f.patch) == (ordinary, bundle)
        inspected = server.request('inspect', dict(object_format=f.fmt, ref='refs/heads/main', expected_commit=f.base, candidate_commit=f.candidate), bundle)
        assert inspected['candidate_commit'] == f.candidate
        record(f.fmt, 'http-reviewed-bundle-inspection-remains-independent')
    assert f.basis() == before
    with HTTP(f, 'http-reopen') as server:
        again, again_bundle = server.request('prepare', pinned, f.patch)
        assert again.pop('expected_result_tree') == f.expected_tree and again == ordinary and again_bundle == bundle
        record(f.fmt, 'http-restart-reproduces-exact-pinned-bundle')
        apply = dict(object_format=f.fmt, ref='refs/heads/main', expected_commit=f.base, candidate_commit=f.candidate)
        server.request('apply', dict(apply, expected_result_tree=f.expected_tree), bundle, code=400, key='unused-tree-pin')
        accepted = server.request('apply', apply, bundle, key='reviewed-result')
        assert accepted['outcome'] == 'committed'
        assert server.request('apply', apply, bundle, key='reviewed-result') == accepted
        record(f.fmt, 'http-pin-cannot-replace-commit-review-and-original-key')
        server.request('prepare', pinned, f.patch, code=409)
        record(f.fmt, 'http-pinned-preparation-still-refuses-stale-source')
    with HTTP(f, 'http-recover') as server:
        assert server.request('apply', apply, bundle, key='reviewed-result') == accepted
        record(f.fmt, 'http-restart-recovers-original-publication-without-repreparing')
    assert f.basis() != before

if __name__ == '__main__':
    fg, root = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    for fmt in ['sha1', 'sha256']: http_campaign(Fixture(fg, root, fmt))
    (root / 'results.json').write_text(json.dumps(RESULTS, indent=2) + '\n')
