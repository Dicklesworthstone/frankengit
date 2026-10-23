"""Actual Rust rebase inspection/publication above inherited native blob content.
Independent Python hashes and packs; no mock service or external Git engine.
"""
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patch_smoke import oid, loose
from source_result_tree import Fixture, HTTP, tree_bytes, TENANT, REPOSITORY, PRINCIPAL, AUTHOR
from candidate_frontier_bytes import bundle
RESULTS = []

def record(f, case, **details):
    row = dict(format=f.fmt, case=case, **details)
    RESULTS.append(row)
    print(json.dumps(row), flush=True)

def commit(tree, parent, label):
    return (f'tree {tree}\n' + (f'parent {parent}\n' if parent else '') +
            f'author {AUTHOR} 1 -0330\ncommitter {AUTHOR} 2 +0000\n\n{label}\n').encode()

class RebaseFixture(Fixture):
    def __init__(self, fg, root, fmt, count=7):
        self.fg, self.root, self.fmt, self.sequence = fg, root / fmt, fmt, 0
        self.root.mkdir(parents=True, mode=0o700)
        self.source, self.node = self.root / 'source', self.root / 'node'
        self.scope = [self.node, TENANT, REPOSITORY]
        (self.source / 'refs/heads').mkdir(parents=True)
        (self.source / 'HEAD').write_text('ref: refs/heads/main\n')
        (self.source / 'config').write_text('[core]\nbare=true\nrepositoryformatversion=' + ('0\n' if fmt == 'sha1' else '1\n[extensions]\nobjectformat=sha256\n'))
        self.rows, self.shared = [], []
        self.shared_bytes = count * 20 * 1024 * 1024
        for n in range(count):
            identity = loose(self.source, fmt, 'blob', bytes([65 + n]) * (20 * 1024 * 1024))
            self.rows.append((f'asset-{n}'.encode(), b'100644', identity))
            self.shared.append(identity)
        self.old_body, self.source_body, self.source_only, self.transient = b'base\n', b'source\n', b'original source only\n', b'temporary\n'
        self.old_blob = loose(self.source, fmt, 'blob', self.old_body)
        self.source_blob = loose(self.source, fmt, 'blob', self.source_body)
        self.source_only_blob = loose(self.source, fmt, 'blob', self.source_only)
        self.onto_tree_body = tree_bytes([*self.rows, (b'file', b'100644', self.old_blob)])
        self.onto_tree = loose(self.source, fmt, 'tree', self.onto_tree_body)
        self.onto = loose(self.source, fmt, 'commit', commit(self.onto_tree, None, 'onto'))
        self.result_rows = [*self.rows, (b'file', b'100644', self.source_blob), (b'raw\xff', b'100755', self.source_only_blob)]
        self.result_tree_body = tree_bytes(self.result_rows)
        self.result_tree = loose(self.source, fmt, 'tree', self.result_tree_body)
        self.original = loose(self.source, fmt, 'commit', commit(self.result_tree, self.onto, 'source'))
        (self.source / 'refs/heads/main').write_text(self.onto + '\n')
        (self.source / 'refs/heads/topic').write_text(self.original + '\n')
        self.transient_blob = oid(fmt, 'blob', self.transient)
        self.first_tree_body = tree_bytes([*self.result_rows, (b'zz-transient', b'100644', self.transient_blob)])
        self.first_tree = oid(fmt, 'tree', self.first_tree_body)
        self.first_body = commit(self.first_tree, self.onto, 'introduce transient')
        self.first = oid(fmt, 'commit', self.first_body)
        self.last_body = commit(self.result_tree, self.first, 'remove transient')
        self.candidate = oid(fmt, 'commit', self.last_body)
        self.objects = [('blob', self.source_body), ('blob', self.source_only), ('blob', self.transient),
                        ('tree', self.first_tree_body), ('tree', self.result_tree_body),
                        ('commit', self.first_body), ('commit', self.last_body)]
        self.minimal = self.bundle(self.candidate, self.objects)
        self.thick = self.bundle(self.candidate, [*self.objects, ('blob', bytes([65]) * (20 * 1024 * 1024))])
        self.command('init', ['init', *self.scope, fmt])
        imported = json.loads(self.command('import', ['import', *self.scope, PRINCIPAL, 'rebase-frontier-fixture', self.source, '--json']))
        self.incarnation = imported['repository_incarnation_id']
        self.token = secrets.token_hex(32)
        header = self.command('header', ['serve-http', *self.scope, '127.0.0.1:0', '--trusted-local', '--print-credentials-header']).decode().strip()
        self.grants = self.root / 'grants'
        self.grants.write_text(header + '\n' + hashlib.sha256(self.token.encode()).hexdigest() + f' {PRINCIPAL} read,receive,outcomes-read\n')
        self.grants.chmod(0o600)
    def bundle(self, candidate, objects):
        original = bundle(self.fmt, self.onto, candidate, objects)
        header, packed = original.split(b'\n\n', 1)
        return header.replace(b' refs/heads/main', b' refs/heads/topic') + b'\n\n' + packed
    def inspect_form(self, candidate=None):
        return dict(profile='linear-v1', object_format=self.fmt, source_ref='refs/heads/topic', onto_ref='refs/heads/main',
                    expected_source=self.original, expected_onto=self.onto, candidate_commit=candidate or self.candidate)
    def apply_form(self):
        return dict(profile='linear-v1', object_format=self.fmt, ref='refs/heads/topic',
                    expected_source=self.original, onto=self.onto, candidate_commit=self.candidate)
    def validate(self, value):
        assert value['type'] == 'rebase_inspection'
        assert value['commit_count'] == len(value['commits']) == 2
        assert not any(value[key] for key in ['objects_staged', 'transaction_created', 'published', 'approval_created', 'publication_authorized', 'replay_equivalence_verified'])
        assert value['candidate_commit'] == self.candidate
        net = value['net_change']
        assert net['entry_count'] == len(net['entries']) == 0
        assert net['before_tree'] == net['after_tree'] == self.result_tree
        for row, identity, parent, tree, body in zip(value['commits'], [self.first, self.candidate], [self.onto, self.first],
                                                   [self.first_tree, self.result_tree], [self.first_body, self.last_body]):
            assert row['commit'] == identity and row['parent'] == parent and row['tree'] == tree
            assert bytes.fromhex(row['body_hex']) == body and oid(self.fmt, 'commit', body) == identity
        first, last = (row['diff'] for row in value['commits'])
        assert {bytes.fromhex(row['path_hex']) for row in first['entries']} == {b'file', b'raw\xff', b'zz-transient'}
        assert first['entry_count'] == 3 and last['entry_count'] == 1
        assert bytes.fromhex(last['entries'][0]['path_hex']) == b'zz-transient'
        assert first['before_tree'] == self.onto_tree and first['after_tree'] == last['before_tree'] == self.first_tree
        assert last['after_tree'] == self.result_tree

def campaign(f):
    basis = f.basis()
    with HTTP(f, 'inspect') as server:
        start = time.monotonic()
        a = server.request('rebase/inspect', f.inspect_form(), f.minimal)
        f.validate(a)
        record(f, 'complete-large-series-retains-transient-changes-with-an-empty-net-diff', shared_bytes=f.shared_bytes, seconds=time.monotonic()-start)
        b = server.request('rebase/inspect', f.inspect_form(), f.thick, chunked=True)
        f.validate(b)
        assert a['commits'] == b['commits'] and a['net_change'] == b['net_change']
        assert a['bundle']['closure_objects'] == b['bundle']['closure_objects']
        record(f, 'minimal-and-thick-packs-have-identical-whole-series-review')
        server.request('rebase/inspect', dict(f.inspect_form(), max_changes=3), f.minimal, code=413)
        f.validate(server.request('rebase/inspect', dict(f.inspect_form(), max_changes=4), f.minimal))
        record(f, 'all-commit-diffs-share-one-inclusive-change-budget')
        omitted = [obj for obj in f.objects if obj[1] not in [f.source_body, f.source_only]]
        server.request('rebase/inspect', f.inspect_form(), f.bundle(f.candidate, omitted), code=503)
        f.validate(server.request('rebase/inspect', f.inspect_form(), f.minimal))
        record(f, 'uploaded-selected-source-tree-cannot-lend-omitted-source-only-payloads')
        missing = [obj for obj in f.objects if obj[1] != f.first_body]
        server.request('rebase/inspect', f.inspect_form(), f.bundle(f.candidate, missing), code=400)
        record(f, 'missing-intermediate-commit-refuses-without-a-partial-series')
        bad = f.minimal[:-1] + bytes([f.minimal[-1] ^ 1])
        server.request('rebase/inspect', f.inspect_form(), bad, code=503)
        record(f, 'pack-corruption-does-not-produce-review-evidence')
        empty = server.request('rebase/inspect', f.inspect_form(f.onto), f.bundle(f.onto, []))
        assert empty['commit_count'] == 0 and empty['commits'] == []
        assert empty['net_change']['entry_count'] == 2
        record(f, 'empty-series-still-reviews-the-original-source-to-onto-result')
    assert f.basis() == basis
    shutil.rmtree(f.source)
    with HTTP(f, 'reopen') as server:
        assert server.request('rebase/inspect', f.inspect_form(), f.minimal) == a
        record(f, 'source-free-restart-reproduces-the-exact-read-only-inspection')
        accepted = server.request('rebase/apply', f.apply_form(), f.minimal, key='reviewed-large-rebase')
        assert accepted['outcome'] == 'committed'
        assert server.request('rebase/apply', f.apply_form(), f.thick, key='reviewed-large-rebase') == accepted
        record(f, 'reviewed-series-publishes-with-original-source-lease-and-original-key')
    after = f.basis()
    assert after != basis
    with HTTP(f, 'recover') as server:
        assert server.request('rebase/apply', f.apply_form(), f.minimal, key='reviewed-large-rebase') == accepted
    assert f.basis() == after
    record(f, 'native-restart-recovers-the-same-terminal-without-a-second-publication')
    for identity in [f.first, f.candidate, f.result_tree]:
        assert b'verified object sample' in f.command('verify', ['doctor', *f.scope, identity])

if __name__ == '__main__':
    fg, root = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    baseline = '--baseline' in sys.argv[3:]
    for fmt in ['sha1', 'sha256']:
        if baseline:
            for count in [1, 7]:
                f = RebaseFixture(fg, root / str(count), fmt, count)
                before = f.basis()
                with HTTP(f, 'baseline') as server:
                    result = server.request('rebase/inspect', f.inspect_form(), f.minimal, code=200 if count == 1 else 413)
                    if count == 1: f.validate(result)
                    record(f, 'baseline-permitted-small-twin' if count == 1 else 'baseline-large-inspection-refused', shared_bytes=f.shared_bytes)
                assert f.basis() == before
        else:
            campaign(RebaseFixture(fg, root, fmt))
    (root / 'results.json').write_text(json.dumps(RESULTS, indent=2) + '\n')
