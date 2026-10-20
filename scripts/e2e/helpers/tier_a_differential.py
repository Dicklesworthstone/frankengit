"""Tier-A differential: pinned Git against `fg serve` over loopback git://.

Every operation runs twice: once against a pinned-Git reference (file
transport inside the oracle sandbox) and once against `fg serve` through the
oracle's fixed loopback modes. The observable results are compared: the ref
advertisement and capabilities, protocol-v2 ls-refs, HEAD, refs, the object
set, fsck, the checked-out index, and push report-status. A row passes only
when every one of its checks passes. Nothing here is a production path; Git
runs only through scripts/e2e/oracle/oracle.sh.

usage: tier_a_differential.py FG ORACLE PIN RUN_DIRECTORY WORK RESULTS_JSON
"""
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import time

FG, ORACLE, PIN = sys.argv[1], sys.argv[2], sys.argv[3]
RUN = pathlib.Path(sys.argv[4]).resolve()
WORK = pathlib.Path(sys.argv[5]).resolve()
RESULTS = pathlib.Path(sys.argv[6]).resolve()
SANDBOX = RUN / 'work'
TENANT, REPOSITORY, PRINCIPAL = '7a' * 16, '7b' * 16, '7c' * 16
REPOSITORY_PATH = f'/{REPOSITORY}.git'
FORMATS = ('sha1', 'sha256')
CORPORA = ('empty', 'deep', 'wide', 'delta', 'shape', 'trunk', 'many')
# More objects than the ~16.4k at which per-scan lookup charges refused every
# import and push (frankengit-eq4h, NEG-037).
MANY_FILES = 20_000
# A corpus whose default branch is not main: fg is initialized with
# `--initial-branch` to match, as `git init -b` would be.
DEFAULT_BRANCH = {'trunk': 'trunk'}
WORK.mkdir(parents=True, exist_ok=True)
LOG = open(WORK / 'commands.log', 'a', encoding='utf-8')

# Capabilities upstream advertises only under non-default configuration, which
# fg advertises because its visibility proof already bounds them. Each is a
# declared, named divergence; anything else fg advertises that the pinned
# server does not is a defect. `agent` always differs and is never compared.
DIVERGENCES = {
    'allow-reachable-sha1-in-want': 'DIV-TA-001: fg serves reachable-object wants inside its exact-head visible-graph proof; upstream needs uploadpack.allowReachableSHA1InWant',
    'filter': 'DIV-TA-002: fg serves object filters inside its visibility proof; upstream needs uploadpack.allowFilter',
}
# Report-status reasons that differ only in wording, as exact (upstream, fg)
# pairs. The accept/refuse decision must still match; any other wording
# difference is a defect.
REASON_DIVERGENCES = {
    ('deletion of the current branch prohibited', 'protected ref denied'):
        'DIV-TA-003: fg refuses deleting HEAD\'s branch through its ref-protection policy and reports that policy\'s reason',
}
# The capability subset Tier A requires both servers to advertise identically.
TIER_A_V0_CAPABILITIES = ('ofs-delta', 'thin-pack', 'side-band-64k', 'include-tag', 'shallow', 'object-format', 'symref')
TIER_A_V2_COMMANDS = ('ls-refs', 'fetch', 'object-format')
TIER_A_RECEIVE_CAPABILITIES = ('report-status', 'delete-refs', 'ofs-delta', 'atomic', 'object-format')


def log(*parts):
    LOG.write(' '.join(str(part) for part in parts) + '\n')
    LOG.flush()


def run(argv, timeout=600, stdin=None):
    started = time.monotonic()
    result = subprocess.run(argv, capture_output=True, timeout=timeout, stdin=stdin)
    log(f'[{time.monotonic() - started:7.2f}s rc={result.returncode}]', *argv)
    if result.returncode != 0 and result.stderr:
        log('  stderr:', result.stderr[-2000:].decode('utf-8', 'replace').replace('\n', '\n          '))
    return result


def git(cwd, *args, timeout=600):
    """Pinned Git, file transport only, inside the oracle sandbox."""
    return run([ORACLE, 'run', PIN, str(RUN), cwd, '--', *args], timeout=timeout)


def git_ok(cwd, *args):
    result = git(cwd, *args)
    if result.returncode != 0:
        raise RuntimeError(f'oracle git {cwd} {args} failed: {result.stderr[-600:]!r}')
    return result.stdout


def git_shell(repository, name, script):
    """Run a fixed shell bridge to an already-pinned executable via a repo-local alias."""
    git_ok(repository, 'config', f'alias.{name}', '!' + script)
    return git(repository, name)


# ---------------------------------------------------------------- corpora

IDENT = 'Tier A <tier-a@invalid.example>'


class Stream:
    def __init__(self):
        self.parts, self.mark, self.clock = [], 0, 1_700_000_000

    def data(self, body):
        body = body if isinstance(body, bytes) else body.encode()
        self.parts.append(b'data %d\n' % len(body) + body + b'\n')

    def blob(self, body):
        self.mark += 1
        self.parts.append(b'blob\nmark :%d\n' % self.mark)
        self.data(body)
        return self.mark

    def commit(self, ref, message, files=(), parents=(), deleteall=False):
        self.mark += 1
        self.clock += 60
        self.parts.append(f'commit {ref}\nmark :{self.mark}\n'.encode())
        self.parts.append(f'author {IDENT} {self.clock} +0000\ncommitter {IDENT} {self.clock} +0000\n'.encode())
        self.data(message)
        for index, parent in enumerate(parents):
            self.parts.append(f'{"from" if index == 0 else "merge"} {parent}\n'.encode())
        if deleteall:
            self.parts.append(b'deleteall\n')
        for mode, mark_or_body, path in files:
            if mode == 'D':
                self.parts.append(f'D {path}\n'.encode())
            elif mode == '120000':
                self.parts.append(f'M 120000 inline {path}\n'.encode())
                self.data(mark_or_body)
            else:
                self.parts.append(f'M {mode} :{mark_or_body} {path}\n'.encode())
        return f':{self.mark}'

    def tag(self, name, target, message, mark=False):
        self.clock += 60
        if mark:
            self.mark += 1
        self.parts.append(f'tag {name}\n'.encode() + (f'mark :{self.mark}\n'.encode() if mark else b''))
        self.parts.append(f'from {target}\ntagger {IDENT} {self.clock} +0000\n'.encode())
        self.data(message)
        return f':{self.mark}' if mark else None

    def reset(self, ref, target):
        self.parts.append(f'reset {ref}\nfrom {target}\n\n'.encode())

    def bytes(self):
        return b''.join(self.parts) + b'done\n'


def noise(seed, size):
    out, counter = bytearray(), 0
    while len(out) < size:
        out += hashlib.sha256(f'{seed}:{counter}'.encode()).digest()
        counter += 1
    return bytes(out[:size])


def corpus_stream(name):
    s = Stream()
    if name == 'deep':
        tip = None
        for n in range(1200):
            files = [('100644', s.blob(f'entry {n}\n' * (1 + n % 7)), 'log.txt')]
            if n % 100 == 0:
                files.append(('100644', s.blob(f'checkpoint {n}\n'), f'd/{n:04d}.txt'))
            tip = s.commit('refs/heads/main', f'deep {n}\n', files, (tip,) if tip else ())
        s.reset('refs/tags/deep-tip', tip)
    elif name == 'wide':
        files = []
        for directory in range(50):
            for entry in range(50):
                files.append(('100644', s.blob(f'{directory}/{entry}\n'), f'w/d{directory:02d}/f{entry:02d}.txt'))
        files += [
            ('100644', s.blob('deep\n'), '/'.join(f'n{level}' for level in range(12)) + '/leaf.txt'),
            ('100644', s.blob('spaced\n'), 'with space.txt'),
            ('100644', s.blob('unicode\n'), 'ünïcode/ñ.txt'),
            ('100755', s.blob('#!/bin/sh\nexit 0\n'), 'tool.sh'),
            ('100644', s.blob(b''), 'empty'),
            ('120000', 'w/d00/f00.txt', 'link'),
        ]
        root = s.commit('refs/heads/main', 'wide\n', files)
        changed = [('100644', s.blob(f'changed {n}\n'), f'w/d{n * 2:02d}/f{n:02d}.txt') for n in range(25)]
        s.commit('refs/heads/main', 'wide edit\n', changed + [('D', None, 'empty')], (root,))
    elif name == 'delta':
        lines = [f'line {n:05d} {noise(n, 24).hex()}\n' for n in range(2400)]
        binary = bytearray(noise('bin', 65536))
        tip = None
        for n in range(80):
            lines[(n * 37) % len(lines)] = f'edit {n:03d} {noise(("e", n), 24).hex()}\n'
            files = [('100644', s.blob(''.join(lines)), 'big.txt')]
            if n % 8 == 0:
                binary[(n * 997) % len(binary)] ^= 0x5A
                files.append(('100644', s.blob(bytes(binary)), 'blob.bin'))
            tip = s.commit('refs/heads/main', f'delta {n}\n', files, (tip,) if tip else ())
    elif name == 'shape':
        base = s.commit('refs/heads/main', 'root\n', [('100644', s.blob('root\n'), 'README')])
        main = s.commit('refs/heads/main', 'second\n', [('100644', s.blob('two\n'), 'two.txt')], (base,))
        feature = s.commit('refs/heads/feature/a', 'feature one\n', [('100644', s.blob('f1\n'), 'f.txt')], (main,))
        feature = s.commit('refs/heads/feature/a', 'feature two\n', [('100644', s.blob('f2\n'), 'f.txt')], (feature,))
        release = s.commit('refs/heads/release/1.0', 'release\n', [('100644', s.blob('r\n'), 'r.txt')], (main,))
        merged = s.commit('refs/heads/main', 'merge feature/a\n', [('100644', s.blob('f2\n'), 'f.txt')], (main, feature))
        third = s.commit('refs/heads/topic/octopus', 'octo base\n', [('100644', s.blob('o\n'), 'o.txt')], (base,))
        s.commit('refs/heads/topic/octopus', 'octopus\n', [('100644', s.blob('o3\n'), 'o.txt')], (third, release, merged))
        s.commit('refs/heads/orphan', 'independent root\n', [('100644', s.blob('alone\n'), 'alone.txt')], deleteall=True)
        s.commit('refs/heads/empty-tree', 'empty tree\n', [], deleteall=True)
        annotated = s.tag('v1.0', merged, 'release 1.0\n', mark=True)
        s.tag('nested', annotated, 'tag of a tag\n')
        s.reset('refs/tags/light', release)
    elif name == 'many':
        files = [('100644', s.blob(f'file {n}\n'), f'm{n // 200:03d}/f{n % 200:03d}.txt') for n in range(MANY_FILES)]
        s.commit('refs/heads/main', 'many objects\n', files)
    elif name == 'trunk':
        tip = s.commit('refs/heads/trunk', 'trunk root\n', [('100644', s.blob('trunk\n'), 'TRUNK')])
        tip = s.commit('refs/heads/trunk', 'trunk two\n', [('100644', s.blob('two\n'), 'two.txt')], (tip,))
        s.commit('refs/heads/side', 'side\n', [('100644', s.blob('side\n'), 'side.txt')], (tip,))
    return s.bytes()


def build_source(fmt, corpus):
    """A pinned-Git bare repository whose HEAD names the corpus's default branch."""
    repository = f'src/{fmt}-{corpus}.git'
    if (SANDBOX / repository).exists():
        return repository
    git_ok('src', 'init', '-q', '--bare', f'--object-format={fmt}', f'{fmt}-{corpus}.git')
    git_ok(repository, 'symbolic-ref', 'HEAD', f"refs/heads/{DEFAULT_BRANCH.get(corpus, 'main')}")
    if corpus != 'empty':
        stream = SANDBOX / 'streams' / f'{corpus}.fi'
        if not stream.exists():
            stream.write_bytes(corpus_stream(corpus))
        imported = git_shell(repository, 'tierafastimport',
                             f'$GIT_EXEC_PATH/git-fast-import --quiet < /work/streams/{corpus}.fi')
        if imported.returncode != 0:
            raise RuntimeError(f'fast-import {fmt}-{corpus}: {imported.stderr[-600:]!r}')
        if corpus == 'delta':
            git_ok(repository, 'repack', '-adf', '--depth=50', '--window=50', '-q')
    return repository


# ---------------------------------------------------------------- fg

def fg(*args, expect=0, timeout=900):
    result = run([FG, '--timeout-secs', '600', *map(str, args)], timeout=timeout)
    if expect is not None and result.returncode != expect:
        raise RuntimeError(f'fg {args[:1]} exited {result.returncode}: {result.stderr[-800:]!r}')
    return result


def fg_node(label, fmt, source=None, initial_branch=None):
    node = WORK / 'nodes' / label
    node.parent.mkdir(parents=True, exist_ok=True)
    fg('init', node, TENANT, REPOSITORY, fmt, *(['--initial-branch', initial_branch] if initial_branch else []))
    if source is not None:
        fg('import', node, TENANT, REPOSITORY, PRINCIPAL, f'tier-a-{label}', SANDBOX / source)
    return node


class Serve:
    """`fg serve --continuous` on a free loopback port, stopped through its stop file."""

    def __init__(self, node, receive=False):
        self.node, self.receive = node, receive

    def __enter__(self):
        for attempt in range(8):
            probe = socket.socket()
            probe.bind(('127.0.0.1', 0))
            self.port = probe.getsockname()[1]
            probe.close()
            self.stop = WORK / f'stop-{self.node.name}-{self.port}-{attempt}'
            argv = [FG, 'serve', str(self.node), TENANT, REPOSITORY, f'127.0.0.1:{self.port}',
                    '--continuous', '--stop-file', str(self.stop)]
            if self.receive:
                # Operator configuration, as --initial-branch is. A push must
                # fit both the session budget (from accept) and the processing
                # budget (from the pack trailer), 300 s each by default, which
                # admits up to ~15k objects; many-objects pushes more
                # (frankengit-pc9g).
                argv += ['--receive-principal', PRINCIPAL, '--allow-unauthenticated-network-push',
                         '--session-timeout-secs', '1800', '--processing-timeout-secs', '1800']
            self.out = open(WORK / f'serve-{self.node.name}-{self.port}.out', 'wb')
            self.err = open(WORK / f'serve-{self.node.name}-{self.port}.err', 'wb')
            self.process = subprocess.Popen(argv, stdout=self.out, stderr=self.err)
            log('[spawn]', *argv)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and self.process.poll() is None:
                try:
                    socket.create_connection(('127.0.0.1', self.port), timeout=1).close()
                    return self
                except OSError:
                    time.sleep(0.05)
            self.process.kill()
            self.process.wait()
            self.out.close()
            self.err.close()
        raise RuntimeError(f'fg serve never listened for {self.node}')

    def __exit__(self, *exc):
        self.stop.touch()
        try:
            self.process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise RuntimeError(f'fg serve for {self.node} did not drain within 60 s of its stop file')
        finally:
            self.out.close()
            self.err.close()
        return False


# ---------------------------------------------------------------- pkt-line

def pkt(data):
    return b'%04x' % (len(data) + 4) + data


def parse_pkts(raw):
    out, at = [], 0
    while at + 4 <= len(raw):
        size = int(raw[at:at + 4], 16)
        if size < 4:
            out.append(('flush', 'delim', 'end')[size] if size < 3 else 'bad')
            at += 4
            continue
        out.append(raw[at + 4:at + size])
        at += size
    return out


def read_until_flush(sock):
    buffer, packets = b'', []
    while True:
        while len(buffer) < 4:
            chunk = sock.recv(65536)
            if not chunk:
                return packets, False
            buffer += chunk
        size = int(buffer[:4], 16)
        if size < 4:
            buffer = buffer[4:]
            if size == 0:
                return packets, True
            packets.append(('flush', 'delim', 'end')[size])
            continue
        while len(buffer) < size:
            chunk = sock.recv(65536)
            if not chunk:
                return packets, False
            buffer += chunk
        packets.append(buffer[4:size])
        buffer = buffer[size:]


def fg_request(port, service, extra=b'', body=None):
    with socket.create_connection(('127.0.0.1', port), timeout=30) as sock:
        sock.sendall(pkt(service + b' ' + REPOSITORY_PATH.encode() + b'\0host=127.0.0.1\0' + extra))
        advertised, complete = read_until_flush(sock)
        response = None
        if body is not None:
            sock.sendall(body)
            response, _ = read_until_flush(sock)
        sock.sendall(b'0000')
        return advertised, complete, response


def lsrefs_request(fmt):
    # `unborn` as a v2 clone sends it: an empty or dangling HEAD must then be
    # reported byte for byte as upstream reports it.
    return (pkt(b'command=ls-refs\n') + pkt(f'object-format={fmt}\n'.encode()) + b'0001'
            + pkt(b'symrefs\n') + pkt(b'peel\n') + pkt(b'unborn\n') + b'0000')


def parse_v0(packets):
    refs, capabilities = [], {}
    for packet in packets:
        if not isinstance(packet, bytes):
            continue
        line = packet.rstrip(b'\n')
        if b'\0' in line:
            line, caps = line.split(b'\0', 1)
            for token in caps.decode().split():
                key, _, value = token.partition('=')
                capabilities.setdefault(key, []).append(value)
        oid, _, name = line.decode().partition(' ')
        refs.append((name, oid))
    return refs, capabilities


def parse_v2_capabilities(packets):
    commands = {}
    for packet in packets:
        if isinstance(packet, bytes) and packet.rstrip(b'\n') != b'version 2':
            key, _, value = packet.rstrip(b'\n').decode().partition('=')
            commands[key] = value
    return commands


def compare_capabilities(check, ours, theirs, required):
    """fg must advertise every required capability with upstream's value and
    nothing upstream lacks, except the declared divergences."""
    applied = []
    for key in required:
        if key not in theirs:
            check(f'upstream-advertises-{key}', False, f'pinned Git did not advertise {key}; the Tier-A declaration is wrong')
            continue
        check(f'advertises-{key}', key in ours and ours[key] == theirs[key],
              f'fg {key}={ours.get(key)!r} upstream {key}={theirs[key]!r}')
    for key in sorted(set(ours) - set(theirs) - {'agent'}):
        if key in DIVERGENCES:
            applied.append(DIVERGENCES[key])
        else:
            check(f'no-invented-{key}', False, f'fg advertises {key}={ours[key]!r}, which pinned Git does not')
    missing = sorted(set(theirs) - set(ours) - {'agent'} - set(required))
    return applied, missing


# ---------------------------------------------------------------- comparisons

def repository_state(directory):
    refs = git_ok(directory, 'for-each-ref', '--format=%(objectname) %(refname)').decode()
    objects = git_ok(directory, 'cat-file', '--batch-all-objects',
                     '--batch-check=%(objectname) %(objecttype) %(objectsize)').decode()
    head = git(directory, 'symbolic-ref', '-q', 'HEAD').stdout.decode().strip()
    tip = git(directory, 'rev-parse', '-q', '--verify', 'HEAD').stdout.decode().strip()
    origin_head = git(directory, 'symbolic-ref', '-q', 'refs/remotes/origin/HEAD').stdout.decode().strip()
    return {
        'refs': sorted(refs.splitlines()),
        'objects': sorted(objects.splitlines()),
        'head': head, 'tip': tip, 'origin_head': origin_head,
    }


class Row:
    def __init__(self, row_id):
        self.id, self.checks, self.divergences, self.notes = row_id, [], set(), []

    def check(self, scope):
        def record(name, ok, detail=''):
            self.checks.append({'check': f'{scope}:{name}', 'ok': bool(ok), 'detail': '' if ok else detail})
        return record

    def result(self):
        failed = [c for c in self.checks if not c['ok']]
        return {
            'status': 'pass' if self.checks and not failed else 'fail',
            'checks': len(self.checks), 'failed': failed,
            'divergences': sorted(self.divergences), 'notes': self.notes,
        }


def compare_clones(check, reference, candidate, candidate_stderr, reference_stderr):
    ours, theirs = repository_state(candidate), repository_state(reference)
    check('object-set', ours['objects'] == theirs['objects'],
          f"{len(ours['objects'])} objects vs {len(theirs['objects'])}; first difference "
          f"{sorted(set(ours['objects']) ^ set(theirs['objects']))[:3]}")
    check('refs', ours['refs'] == theirs['refs'], f"fg {ours['refs'][:6]} upstream {theirs['refs'][:6]}")
    check('head-symref', ours['head'] == theirs['head'], f"fg HEAD {ours['head']!r} upstream {theirs['head']!r}")
    check('origin-head', ours['origin_head'] == theirs['origin_head'],
          f"fg origin/HEAD {ours['origin_head']!r} upstream {theirs['origin_head']!r}")
    check('checkout', ours['tip'] == theirs['tip'], f"fg HEAD commit {ours['tip']!r} upstream {theirs['tip']!r}")
    fsck = git(candidate, 'fsck', '--strict', '--no-progress', '--no-dangling')
    check('fsck', fsck.returncode == 0, fsck.stderr[-400:].decode('utf-8', 'replace'))
    index_ours = git(candidate, 'ls-files', '-s').stdout
    index_theirs = git(reference, 'ls-files', '-s').stdout
    check('index', index_ours == index_theirs, 'checked-out index differs')
    warnings_ours = {line for line in candidate_stderr.splitlines() if line.startswith(b'warning:')}
    warnings_theirs = {line for line in reference_stderr.splitlines() if line.startswith(b'warning:')}
    check('no-extra-warnings', warnings_ours <= warnings_theirs,
          f'fg-only client warnings {sorted(warnings_ours - warnings_theirs)!r}')


def transcript(label):
    return (RUN / 'transcripts' / label / 'stderr.bin').read_bytes()


# ---------------------------------------------------------------- rows

def upload_rows(fmt, rows, timings):
    upload = [rows[f'TA-{name}-{fmt.upper()}'] for name in ('CLONE', 'ADV-V0', 'ADV-V2', 'FETCH-V0', 'FETCH-V1', 'FETCH-V2')]
    imported = rows[f'TA-IMPORT-{fmt.upper()}']
    for corpus in CORPORA:
        source = build_source(fmt, corpus)
        node = None
        if corpus == 'empty':
            node = fg_node(f'{fmt}-{corpus}', fmt)
        else:
            started = time.monotonic()
            try:
                node = fg_node(f'{fmt}-{corpus}', fmt, source, DEFAULT_BRANCH.get(corpus))
                imported.check(corpus)('import', True)
            except RuntimeError as error:
                imported.check(corpus)('import', False, str(error)[:600])
            timings[f'{fmt}-{corpus}:import'] = round(time.monotonic() - started, 2)
        if node is None:
            for row in upload:
                row.check(corpus)('node-available', False, 'fg import refused the corpus; see the import row')
            continue
        try:
            upload_corpus(fmt, corpus, source, node, rows, timings)
        except Exception as error:  # A harness failure fails this corpus's checks; it never passes them.
            log('[harness-error]', fmt, corpus, repr(error))
            for row in upload:
                row.check(corpus)('harness', False, str(error)[:600])


def upload_corpus(fmt, corpus, source, node, rows, timings):
    clone, adv0, adv2 = rows[f'TA-CLONE-{fmt.upper()}'], rows[f'TA-ADV-V0-{fmt.upper()}'], rows[f'TA-ADV-V2-{fmt.upper()}']
    fetch = {p: rows[f'TA-FETCH-{p.upper()}-{fmt.upper()}'] for p in ('v0', 'v1', 'v2')}
    label = f'{fmt}-{corpus}'
    # Reference advertisements from the same pinned upload-pack, over stdio.
    reference_v0 = parse_pkts(git_shell(source, 'tieraadv0', '$GIT_EXEC_PATH/git-upload-pack --advertise-refs .').stdout)
    reference_v2 = parse_pkts(git_shell(source, 'tieraadv2',
                                        'GIT_PROTOCOL=version=2 $GIT_EXEC_PATH/git-upload-pack --advertise-refs .').stdout)
    request = SANDBOX / 'requests' / f'{label}-ls-refs.bin'
    request.parent.mkdir(exist_ok=True)
    request.write_bytes(lsrefs_request(fmt))
    reference_lsrefs = parse_pkts(git_shell(
        source, 'tieralsrefs',
        f'GIT_PROTOCOL=version=2 $GIT_EXEC_PATH/git-upload-pack --stateless-rpc . < /work/requests/{label}-ls-refs.bin').stdout)
    with Serve(node) as serve:
        ours_v0, complete, _ = fg_request(serve.port, b'git-upload-pack')
        ours_v2, _, ours_lsrefs = fg_request(serve.port, b'git-upload-pack', b'\0version=2\0', lsrefs_request(fmt))
        check = adv0.check(corpus)
        check('advertisement-complete', complete, 'fg closed the connection before the advertisement flush')
        refs_ours, caps_ours = parse_v0(ours_v0)
        refs_theirs, caps_theirs = parse_v0(reference_v0)
        check('head-advertised', [r for r in refs_ours if r[0] == 'HEAD'] == [r for r in refs_theirs if r[0] == 'HEAD'],
              f"fg HEAD line {[r for r in refs_ours if r[0] == 'HEAD']} upstream {[r for r in refs_theirs if r[0] == 'HEAD']}")
        check('ref-lines', [r for r in refs_ours if r[0] != 'HEAD'] == [r for r in refs_theirs if r[0] != 'HEAD'],
              f'fg {refs_ours[:5]} upstream {refs_theirs[:5]}')
        required = [key for key in TIER_A_V0_CAPABILITIES if key != 'symref' or 'symref' in caps_theirs]
        applied, missing = compare_capabilities(check, caps_ours, caps_theirs, required)
        adv0.divergences.update(applied)
        if missing:
            adv0.notes.append(f'{corpus}: upstream-only capabilities (not Tier-A required): {missing}')
        check = adv2.check(corpus)
        commands_ours, commands_theirs = parse_v2_capabilities(ours_v2), parse_v2_capabilities(reference_v2)
        for command in TIER_A_V2_COMMANDS:
            check(f'command-{command}', command in commands_ours and command in commands_theirs,
                  f'fg {sorted(commands_ours)} upstream {sorted(commands_theirs)}')
        check('object-format', commands_ours.get('object-format') == commands_theirs.get('object-format'),
              f"fg {commands_ours.get('object-format')!r} upstream {commands_theirs.get('object-format')!r}")
        for command in sorted(set(commands_ours) - {'agent'}):
            ours_features = set(commands_ours[command].split()) if commands_ours[command] else set()
            theirs_features = set(commands_theirs.get(command, '').split())
            for feature in sorted(ours_features - theirs_features):
                if feature in DIVERGENCES:
                    adv2.divergences.add(DIVERGENCES[feature])
                else:
                    check(f'no-invented-{command}-{feature}', False, f'fg advertises {command}={feature}, pinned Git does not')
            if command not in commands_theirs:
                check(f'no-invented-command-{command}', False, f'fg advertises v2 command {command}, pinned Git does not')
        ls_ours = [p for p in (ours_lsrefs or []) if isinstance(p, bytes)]
        ls_theirs = [p for p in reference_lsrefs if isinstance(p, bytes)]
        check('ls-refs', ls_ours == ls_theirs, f'fg {ls_ours[:4]} upstream {ls_theirs[:4]}')
        missing_v2 = sorted(set(commands_theirs) - set(commands_ours) - {'agent'})
        if missing_v2 or commands_ours.get('ls-refs') != commands_theirs.get('ls-refs'):
            adv2.notes.append(f"{corpus}: upstream-only v2 surface {missing_v2}, ls-refs={commands_theirs.get('ls-refs')!r} vs fg {commands_ours.get('ls-refs')!r}")
        # Clone (protocol v2, the pinned client's default).
        (SANDBOX / 'cand').mkdir(exist_ok=True)
        (SANDBOX / 'ref').mkdir(exist_ok=True)
        started = time.monotonic()
        cloned = run([ORACLE, 'clone-loopback', PIN, str(RUN), f'clone-{label}', f'127.0.0.1:{serve.port}',
                      REPOSITORY_PATH, f'cand/clone-{label}'])
        timings[f'{label}:clone'] = round(time.monotonic() - started, 2)
        reference = git('.', 'clone', '--no-local', source, f'ref/clone-{label}')
        check = clone.check(corpus)
        check('exit', cloned.returncode == reference.returncode == 0,
              f'fg clone exit {cloned.returncode} upstream {reference.returncode}: {transcript(f"clone-{label}")[-300:]!r}')
        if cloned.returncode == 0 and reference.returncode == 0:
            compare_clones(check, f'ref/clone-{label}', f'cand/clone-{label}', transcript(f'clone-{label}'), reference.stderr)
        # Full fetch over each protocol version into an empty repository.
        for protocol, row in fetch.items():
            version = protocol[1]
            cand, ref = f'cand/fetch-{protocol}-{label}', f'ref/fetch-{protocol}-{label}'
            git_ok('.', 'init', '-q', f'--object-format={fmt}', cand)
            git_ok('.', 'init', '-q', f'--object-format={fmt}', ref)
            git_ok(ref, 'config', 'protocol.version', version)
            started = time.monotonic()
            fetched = run([ORACLE, 'fetch-loopback', PIN, str(RUN), f'fetch-{protocol}-{label}', f'127.0.0.1:{serve.port}',
                           REPOSITORY_PATH, cand, protocol, 'refs/heads/*:refs/remotes/origin/*'])
            timings[f'{label}:fetch-{protocol}'] = round(time.monotonic() - started, 2)
            upstream = git(ref, 'fetch', '--no-tags', f'../../{source}', 'refs/heads/*:refs/remotes/origin/*')
            check = row.check(f'{corpus}:full')
            check('exit', fetched.returncode == upstream.returncode == 0,
                  f'fg fetch exit {fetched.returncode} upstream {upstream.returncode}: {transcript(f"fetch-{protocol}-{label}")[-300:]!r}')
            if fetched.returncode == 0 and upstream.returncode == 0:
                ours, theirs = repository_state(cand), repository_state(ref)
                check('object-set', ours['objects'] == theirs['objects'], f"{len(ours['objects'])} vs {len(theirs['objects'])}")
                check('refs', ours['refs'] == theirs['refs'], f"fg {ours['refs'][:4]} upstream {theirs['refs'][:4]}")
                fsck = git(cand, 'fsck', '--strict', '--no-progress', '--no-dangling')
                check('fsck', fsck.returncode == 0, fsck.stderr[-300:].decode('utf-8', 'replace'))
    if corpus == 'shape':
        incremental_fetch(fmt, source, node, fetch, timings)


def incremental_fetch(fmt, source, node, fetch, timings):
    """Advance both servers by the same new branch, then fetch it incrementally."""
    label = f'{fmt}-shape'
    advance = f'src/{fmt}-advance.git'
    git_ok('.', 'clone', '-q', '--bare', '--no-local', source, advance)
    stream = Stream()
    stream.mark = 0
    tip = None
    for n in range(12):
        tip = stream.commit('refs/heads/next', f'next {n}\n',
                            [('100644', stream.blob(f'next {n}\n' * (n + 1)), 'next.txt')],
                            (('refs/heads/main^0',) if tip is None else (tip,)))
    (SANDBOX / 'streams' / f'{fmt}-advance.fi').write_bytes(stream.bytes())
    imported = git_shell(advance, 'tieraadvance', f'$GIT_EXEC_PATH/git-fast-import --quiet < /work/streams/{fmt}-advance.fi')
    if imported.returncode != 0:
        raise RuntimeError(f'advance fast-import: {imported.stderr[-400:]!r}')
    # The advance source publishes only the new branch: fg import creates refs.
    for line in git_ok(advance, 'for-each-ref', '--format=%(refname)').decode().split():
        if line != 'refs/heads/next':
            git_ok(advance, 'update-ref', '-d', line)
    git_ok(advance, 'symbolic-ref', 'HEAD', 'refs/heads/next')
    fg('import', node, TENANT, REPOSITORY, PRINCIPAL, f'tier-a-{label}-advance', SANDBOX / advance)
    git_ok(source, 'fetch', '-q', f'../../{advance}', 'refs/heads/next:refs/heads/next')
    with Serve(node) as serve:
        for protocol, row in fetch.items():
            cand, ref = f'cand/fetch-{protocol}-{label}', f'ref/fetch-{protocol}-{label}'
            before = len(repository_state(cand)['objects'])
            started = time.monotonic()
            fetched = run([ORACLE, 'fetch-loopback', PIN, str(RUN), f'incremental-{protocol}-{label}', f'127.0.0.1:{serve.port}',
                           REPOSITORY_PATH, cand, protocol, 'refs/heads/*:refs/remotes/origin/*'])
            timings[f'{label}:incremental-{protocol}'] = round(time.monotonic() - started, 2)
            upstream = git(ref, 'fetch', '--no-tags', f'../../{source}', 'refs/heads/*:refs/remotes/origin/*')
            check = row.check('shape:incremental')
            check('exit', fetched.returncode == upstream.returncode == 0,
                  f'fg fetch exit {fetched.returncode} upstream {upstream.returncode}')
            if fetched.returncode == 0 and upstream.returncode == 0:
                ours, theirs = repository_state(cand), repository_state(ref)
                check('object-set', ours['objects'] == theirs['objects'], f"{len(ours['objects'])} vs {len(theirs['objects'])}")
                check('refs', ours['refs'] == theirs['refs'], f"fg {ours['refs']} upstream {theirs['refs']}")
                check('new-objects-arrived', len(ours['objects']) > before, f'{before} objects before, {len(ours["objects"])} after')


# Each step pushes the same refspecs to fg and to the pinned reference, then
# compares report-status and the complete resulting ref set. The refname
# conflict runs last so a divergence there cannot cascade into earlier steps.
PUSH_STEPS = (
    ('create', 'plain', ('refs/heads/feature/new:refs/heads/feature/new',)),
    ('fast-forward', 'plain', ('refs/heads/main:refs/heads/main',)),
    ('tag', 'plain', ('refs/tags/v2.0:refs/tags/v2.0',)),
    ('non-fast-forward', 'plain', ('refs/heads/feature/new:refs/heads/feature/new',)),
    ('forced', 'plain', ('+refs/heads/feature/new:refs/heads/feature/new',)),
    ('atomic-create', 'atomic', ('refs/heads/a1:refs/heads/a1', 'refs/heads/a2:refs/heads/a2')),
    ('delta-history', 'plain', ('refs/heads/delta-history:refs/heads/delta-history',)),
    ('many-objects', 'plain', ('refs/heads/many-history:refs/heads/many-history',)),
    ('delete', 'plain', (':refs/heads/feature/new',)),
    ('delete-head-target', 'plain', (':refs/heads/main',)),
    # refs/heads/topic/octopus exists, so refs/heads/topic cannot (directory/file).
    ('refname-conflict', 'plain', ('refs/heads/topic:refs/heads/topic',)),
)


def push_rows(fmt, rows, timings):
    push, receive_adv = rows[f'TA-PUSH-{fmt.upper()}'], rows[f'TA-ADV-RECEIVE-{fmt.upper()}']
    source = build_source(fmt, 'shape')
    build_source(fmt, 'delta')
    build_source(fmt, 'many')
    node = fg_node(f'{fmt}-push', fmt, source)
    target = f'ref/push-target-{fmt}.git'
    git_ok('.', 'clone', '-q', '--bare', '--no-local', source, target)
    pusher = f'cand/pusher-{fmt}'
    git_ok('.', 'clone', '-q', '--no-local', source, pusher)
    git_ok(pusher, 'config', 'user.name', 'Tier A')
    git_ok(pusher, 'config', 'user.email', 'tier-a@invalid.example')
    reference_adv = parse_pkts(git_shell(target, 'tierarecvadv', '$GIT_EXEC_PATH/git-receive-pack --advertise-refs .').stdout)
    with Serve(node, receive=True) as serve:
        ours_adv, complete, _ = fg_request(serve.port, b'git-receive-pack')
        check = receive_adv.check('shape')
        check('advertisement-complete', complete, 'fg closed the receive-pack connection before the advertisement flush')
        refs_ours, caps_ours = parse_v0(ours_adv)
        refs_theirs, caps_theirs = parse_v0(reference_adv)
        check('ref-lines', sorted(refs_ours) == sorted(refs_theirs), f'fg {refs_ours[:5]} upstream {refs_theirs[:5]}')
        applied, missing = compare_capabilities(check, caps_ours, caps_theirs, TIER_A_RECEIVE_CAPABILITIES)
        receive_adv.divergences.update(applied)
        if missing:
            receive_adv.notes.append(f'upstream-only receive capabilities (not Tier-A required): {missing}')
        for step, mode, refspecs in PUSH_STEPS:
            prepare_push(pusher, step, fmt)
            started = time.monotonic()
            pushed = run([ORACLE, 'push-loopback', PIN, str(RUN), f'push-{fmt}-{step}', f'127.0.0.1:{serve.port}',
                          REPOSITORY_PATH, pusher, mode, *refspecs])
            timings[f'{fmt}:push-{step}'] = round(time.monotonic() - started, 2)
            upstream = git(pusher, 'push', '--porcelain', *(['--atomic'] if mode == 'atomic' else []),
                           f'../../{target}', *refspecs)
            ours_lines = porcelain((RUN / 'transcripts' / f'push-{fmt}-{step}' / 'stdout.bin').read_bytes())
            theirs_lines = porcelain(upstream.stdout)
            check = push.check(step)
            check('exit', pushed.returncode == upstream.returncode,
                  f'fg push exit {pushed.returncode} upstream {upstream.returncode}')
            matched, applied = report_status_matches(ours_lines, theirs_lines)
            push.divergences.update(applied)
            check('report-status', matched, f'fg {ours_lines} upstream {theirs_lines}')
            # Per step, compare exactly the refs the step names, so one
            # divergence cannot fail every later step; the final clone below
            # compares the complete state.
            touched = {refspec.rsplit(':', 1)[1] for refspec in refspecs}
            served, _, _ = fg_request(serve.port, b'git-upload-pack')
            refs_after, _ = parse_v0(served)
            ours = sorted(r for r in refs_after if r[0] in touched)
            target_refs = git_ok(target, 'for-each-ref', '--format=%(objectname) %(refname)').decode().split('\n')
            theirs = sorted((name, oid) for oid, _, name in (line.partition(' ') for line in target_refs if line)
                            if name in touched)
            check('resulting-refs', ours == theirs, f'fg {ours} upstream {theirs}')
        (SANDBOX / 'cand').mkdir(exist_ok=True)
        cloned = run([ORACLE, 'clone-loopback', PIN, str(RUN), f'clone-after-push-{fmt}', f'127.0.0.1:{serve.port}',
                      REPOSITORY_PATH, f'cand/after-push-{fmt}'])
        reference = git('.', 'clone', '--no-local', target, f'ref/after-push-{fmt}')
        check = push.check('final-clone')
        check('exit', cloned.returncode == reference.returncode == 0, f'fg {cloned.returncode} upstream {reference.returncode}')
        if cloned.returncode == 0 and reference.returncode == 0:
            ours, theirs = repository_state(f'cand/after-push-{fmt}'), repository_state(f'ref/after-push-{fmt}')
            check('object-set', ours['objects'] == theirs['objects'], f"{len(ours['objects'])} vs {len(theirs['objects'])}")
            check('refs', ours['refs'] == theirs['refs'], f"fg {ours['refs'][:5]} upstream {theirs['refs'][:5]}")


def report_status_matches(ours, theirs):
    """Exact equality, except a rejected line whose reason differs only by a
    declared (upstream, fg) wording pair. Flags, ref names and every other
    reason must match byte for byte."""
    if len(ours) != len(theirs):
        return False, set()
    applied = set()
    for mine, upstream in zip(ours, theirs):
        if mine == upstream:
            continue
        mine_head, _, mine_reason = mine.rpartition('(')
        upstream_head, _, upstream_reason = upstream.rpartition('(')
        key = (upstream_reason.rstrip(')'), mine_reason.rstrip(')'))
        if mine_head != upstream_head or key not in REASON_DIVERGENCES:
            return False, set()
        applied.add(REASON_DIVERGENCES[key])
    return True, applied


def porcelain(raw):
    """Per-ref report lines and the trailer; the 'To <url>' line names the remote."""
    return [line for line in raw.decode('utf-8', 'replace').splitlines() if not line.startswith('To ')]


def prepare_push(pusher, step, fmt):
    stream_file = SANDBOX / 'streams' / f'push-{fmt}-{step}.fi'
    s = Stream()
    s.clock = 1_800_000_000 + 10_000 * PUSH_STEPS.index(next(p for p in PUSH_STEPS if p[0] == step))
    if step == 'create':
        tip = s.commit('refs/heads/feature/new', 'new 1\n', [('100644', s.blob('t1\n' * 400), 'new.txt')], ('refs/heads/main^0',))
        s.commit('refs/heads/feature/new', 'new 2\n', [('100644', s.blob('t1\n' * 400 + 't2\n'), 'new.txt')], (tip,))
    elif step == 'fast-forward':
        s.commit('refs/heads/main', 'main advance\n', [('100644', s.blob('advance\n'), 'advance.txt')], ('refs/heads/main^0',))
    elif step == 'tag':
        s.tag('v2.0', 'refs/heads/main^0', 'release 2.0\n')
    elif step == 'non-fast-forward':
        s.commit('refs/heads/feature/new', 'rewritten\n', [('100644', s.blob('rewritten\n'), 'new.txt')], ('refs/heads/main^0',))
    elif step == 'refname-conflict':
        s.commit('refs/heads/topic', 'topic\n', [('100644', s.blob('topic\n'), 'topic.txt')], ('refs/heads/main^0',))
    elif step == 'delta-history':
        # Ordinary history: 80 revisions of a 120 KB file, packed at Git's default depth.
        git_ok(pusher, 'fetch', '-q', f'../../src/{fmt}-delta.git', 'refs/heads/main:refs/heads/delta-history')
        return
    elif step == 'many-objects':
        # One push of more than 20,000 new objects through the receive validator.
        git_ok(pusher, 'fetch', '-q', f'../../src/{fmt}-many.git', 'refs/heads/main:refs/heads/many-history')
        return
    elif step == 'atomic-create':
        s.commit('refs/heads/a1', 'a1\n', [('100644', s.blob('a1\n'), 'a1.txt')], ('refs/heads/main^0',))
        s.commit('refs/heads/a2', 'a2\n', [('100644', s.blob('a2\n'), 'a2.txt')], ('refs/heads/main^0',))
    else:
        return
    stream_file.write_bytes(s.bytes())
    imported = git_shell(pusher, 'tierapush', f'$GIT_EXEC_PATH/git-fast-import --quiet --force < /work/streams/{stream_file.name}')
    if imported.returncode != 0:
        raise RuntimeError(f'push preparation {step}: {imported.stderr[-400:]!r}')


def main():
    for directory in ('src', 'streams', 'cand', 'ref', 'requests'):
        (SANDBOX / directory).mkdir(exist_ok=True)
    rows, timings, errors = {}, {}, []
    for fmt in FORMATS:
        for row_id in (f'TA-IMPORT-{fmt.upper()}', f'TA-ADV-V0-{fmt.upper()}', f'TA-ADV-V2-{fmt.upper()}', f'TA-CLONE-{fmt.upper()}',
                       f'TA-FETCH-V0-{fmt.upper()}', f'TA-FETCH-V1-{fmt.upper()}', f'TA-FETCH-V2-{fmt.upper()}',
                       f'TA-ADV-RECEIVE-{fmt.upper()}', f'TA-PUSH-{fmt.upper()}'):
            rows[row_id] = Row(row_id)
    for fmt in FORMATS:
        for stage in (upload_rows, push_rows):
            try:
                stage(fmt, rows, timings)
            except Exception as error:  # A harness failure fails the stage's rows; it never passes them.
                errors.append(f'{fmt} {stage.__name__}: {error}')
                log('[harness-error]', fmt, stage.__name__, repr(error))
                for row in rows.values():
                    if row.id.endswith(fmt.upper()) and (stage is push_rows) == ('PUSH' in row.id or 'RECEIVE' in row.id):
                        row.check('harness')('completed', False, str(error)[:600])
    document = {
        'schema': 'frankengit.tier-a.differential.v1',
        'oracle_pin': PIN,
        'fg_sha256': hashlib.sha256(pathlib.Path(FG).read_bytes()).hexdigest(),
        'transport': 'git:// loopback (fg serve) vs pinned Git file transport',
        'rows': {row_id: row.result() for row_id, row in sorted(rows.items())},
        'harness_errors': errors,
        'timings_seconds': timings,
    }
    RESULTS.write_text(json.dumps(document, indent=1, sort_keys=True) + '\n')
    print(json.dumps({row_id: value['status'] for row_id, value in document['rows'].items()}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    finally:
        LOG.close()
