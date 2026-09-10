#!/usr/bin/env python3
"""Fresh-process fg outcome campaign. --self-test checks fixtures/checker only."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zlib

TENANT, REPOSITORY, PRINCIPAL = 'd1' * 16, 'd2' * 16, 'd3' * 16
OTHER = 'd4' * 16
TARGET, SOURCE = 'refs/heads/main', 'refs/heads/topic'
STATES = {'key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused'}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def native_id(algorithm, kind, body):
    return hashlib.new(algorithm, f'{kind} {len(body)}\0'.encode() + body).hexdigest()


def fixture(root, algorithm):
    objects = {}
    def put(kind, body):
        identity = native_id(algorithm, kind, body)
        objects[identity] = kind, body
        path = root / 'objects' / identity[:2] / identity[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f'{kind} {len(body)}\0'.encode() + body))
        return identity
    def commit(tree, parents, message):
        return (f'tree {tree}\n' + ''.join(f'parent {parent}\n' for parent in parents) +
                'author Fixture <fixture@example.invalid> 1 +0000\n'
                'committer Fixture <fixture@example.invalid> 1 +0000\n\n' + message + '\n').encode()
    (root / 'refs/heads').mkdir(parents=True)
    (root / 'HEAD').write_text(f'ref: {TARGET}\n')
    (root / 'config').write_text('[core]\nbare = true\nrepositoryformatversion = ' +
        ('1\n[extensions]\nobjectformat = sha256\n' if algorithm == 'sha256' else '0\n'))
    blob = put('blob', b'fixture input can be removed after import\n')
    tree = put('tree', b'100644 file\0' + bytes.fromhex(blob))
    base = put('commit', commit(tree, [], 'base'))
    target = put('commit', commit(tree, [base], 'target'))
    source = put('commit', commit(tree, [base], 'source'))
    (root / TARGET).write_text(target + '\n')
    (root / SOURCE).write_text(source + '\n')
    for identity, (kind, body) in objects.items():
        stored = zlib.decompress((root / 'objects' / identity[:2] / identity[2:]).read_bytes())
        require(stored == f'{kind} {len(body)}\0'.encode() + body, 'exact loose fixture bytes')
        require(hashlib.new(algorithm, stored).hexdigest() == identity, 'independent native identity')
    return dict(source=source, target=target, base=base, objects=objects)


def checked_digest(value):
    require(isinstance(value, dict) and set(value) == {'algorithm', 'hex'}, 'typed digest fields')
    require(type(value['algorithm']) is int and 0 < value['algorithm'] <= 65535, 'digest algorithm')
    text = value['hex']
    require(type(text) is str and 0 < len(text) <= 128 and len(text) % 2 == 0
            and all(c in '0123456789abcdef' for c in text), 'bounded canonical digest')


def validate(report, algorithm, state, original=None, principal=PRINCIPAL):
    require(type(report) is dict and state in STATES, 'known recovery schema')
    values = dict(type='transaction_outcome', schema_version=1, tenant_id=TENANT,
                  repository_id=REPOSITORY, principal_id=principal, object_format=algorithm,
                  state=state, terminal=state in ('committed', 'refused'), read_only=True,
                  request_reexecuted=False, absence_proves_non_commit=False,
                  node_closed=True, cleanup_error=None)
    for key, value in values.items():
        require(report.get(key) == value and type(report.get(key)) is type(value), f'recovery field {key}')
    checked_digest(report['key_digest'])
    tx, decision = report['transaction'], report['decision']
    if state in ('key_not_observed', 'seal_not_observed'):
        require(tx is None and decision is None, 'unverified identity must not be disclosed')
        return
    require(type(tx) is dict and set(tx) == {'tx_id', 'seal_id', 'canonical_request_digest', 'request_schema'}, 'seal identity fields')
    for key in ('tx_id', 'seal_id', 'request_schema'):
        require(type(tx[key]) is str and bool(tx[key]), f'nonempty verified {key}')
    checked_digest(tx['canonical_request_digest'])
    if state == 'undecided':
        require(decision is None, 'undecided is not a refusal')
        return
    require(original is not None and original['outcome'] == state, 'original mutation oracle')
    require(tx['tx_id'] == original['tx_id'], 'recover the same logical transaction, not a resealed one')
    require(type(decision) is dict and decision['kind'] == state, 'terminal shape')
    require(type(decision['decision_sequence']) is int and decision['decision_sequence'] > 0
            and decision['decision_sequence'] == original['decision_sequence'], 'original decision sequence')
    if state == 'committed':
        require(set(decision) == {'kind', 'decision_sequence', 'repository_commit_id'}, 'committed fields')
        require(decision['repository_commit_id'] == original['repository_commit_id'], 'exact committed RCR')
    else:
        require(set(decision) == {'kind', 'decision_sequence', 'code', 'code_point', 'refusal_record_id'}, 'refused fields')
        require(decision['refusal_record_id'] == original['refusal_record_id'], 'exact refusal identity')
        require(decision['code'] == original['refusal_code'], 'original refusal code')
        require(type(decision['code_point']) is int and 0 < decision['code_point'] <= 65535, 'typed refusal code')


def invoke(binary, args, expected=0, stdin=None):
    result = subprocess.run([str(binary), *map(str, args)], input=stdin, capture_output=True, timeout=180)
    require(result.returncode == expected,
            f'fg exited {result.returncode}, expected {expected}; stdout={result.stdout!r}; stderr={result.stderr!r}')
    return result


def run(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix='fg-outcome-') as directory:
        root = Path(directory)
        source, node = root / 'source', root / 'node'
        f = fixture(source, algorithm)
        invoke(binary, ['init', node, TENANT, REPOSITORY, algorithm])
        query = ['outcome', node, TENANT, REPOSITORY, '--trusted-local', '--principal', PRINCIPAL,
                 '--object-format', algorithm]
        unseen = invoke(binary, query + ['--idempotency-key', 'not-issued'], 4)
        validate(json.loads(unseen.stdout), algorithm, 'key_not_observed')
        invoke(binary, ['import', node, TENANT, REPOSITORY, PRINCIPAL, 'source-import', source])
        description = root / 'body.md'
        description.write_text('Original body bytes are not available during recovery.\né\n')
        mutation = ['pr', 'open', node, TENANT, REPOSITORY, '17', '--trusted-local',
                    '--principal', PRINCIPAL, '--expected-version', '0', '--source-ref', SOURCE,
                    '--target-ref', TARGET, '--expected-source', f['source'], '--expected-target', f['target'],
                    '--title', 'Recover an exact decision', '--body-file', description]
        opened = json.loads(invoke(binary, mutation + ['--idempotency-key', 'lost-open']).stdout)
        refused = json.loads(invoke(binary, mutation + ['--idempotency-key', 'lost-refusal'], 3).stdout)
        require(opened['type'] == refused['type'] == 'pull_request_publication', 'real mutation receipt schema')
        require(opened['outcome'] == 'committed' and refused['outcome'] == 'refused', 'fixture created both outcomes')
        state_args = ['at', node, TENANT, REPOSITORY, 'latest']
        before = invoke(binary, state_args).stdout
        shutil.rmtree(source)
        description.unlink()
        # The mutation CLI cannot now reconstruct its body; outcome must not try.
        require(not invoke(binary, mutation + ['--idempotency-key', 'lost-open'], 2).stdout, 'missing body yielded a mutation receipt')
        recovered = {}
        for key, original, exit_code in [('lost-open', opened, 0), ('lost-refusal', refused, 3)]:
            first = invoke(binary, query + ['--idempotency-key', key], exit_code)
            report = json.loads(first.stdout)
            validate(report, algorithm, original['outcome'], original)
            require(key.encode() not in first.stdout, 'raw key disclosed in recovery output')
            for flags, data in [(['--idempotency-key-hex', key.encode().hex()], None), (['--key-stdin'], key.encode())]:
                require(invoke(binary, query + flags, exit_code, data).stdout == first.stdout, 'key transport changed recovery')
            require(invoke(binary, query + ['--idempotency-key', key], exit_code).stdout == first.stdout, 'recovery is not deterministic')
            recovered[key] = report
        require(recovered['lost-open']['key_digest'] != recovered['lost-refusal']['key_digest'], 'distinct client keys collapsed')
        wrong = query.copy(); wrong[wrong.index('--principal') + 1] = OTHER
        validate(json.loads(invoke(binary, wrong + ['--idempotency-key', 'lost-open'], 4).stdout),
                 algorithm, 'key_not_observed', principal=OTHER)
        for key in [b'lost-open\n', b'opaque\0\xff', b'', b'x' * 256]:
            stdin_result = invoke(binary, query + ['--key-stdin'], 4, key)
            validate(json.loads(stdin_result.stdout), algorithm, 'key_not_observed')
            require(invoke(binary, query + ['--idempotency-key-hex', key.hex()], 4).stdout == stdin_result.stdout, 'exact raw-key mismatch')
        require(not invoke(binary, query + ['--key-stdin'], 2, b'x' * 257).stdout, 'oversized key produced success')
        for extra in [['--bundle', 'missing.bundle'], ['--idempotency-key-hex', 'FF'],
                      ['--idempotency-key', 'lost-open', '--key-stdin']]:
            require(not invoke(binary, query + extra, 2, b'').stdout, 'malformed recovery returned success')
        absent = query.copy(); absent[1] = root / 'missing-node'
        require(not invoke(binary, absent + ['--idempotency-key', 'lost-open'], 2).stdout, 'missing repository became key absence')
        require(invoke(binary, state_args).stdout == before, 'outcome queries changed canonical repository state')
        print(json.dumps(dict(type='transaction_outcome_smoke', object_format=algorithm,
                              passed=True, rust_executed=True, original_inputs_removed=True)))


def sample(state, algorithm='sha1'):
    original = dict(tx_id='fixture-tx', outcome=state, decision_sequence=7,
                    repository_commit_id='fixture-rcr', refusal_record_id='fixture-refusal', refusal_code='EvidenceInvalid')
    digest = dict(algorithm=1, hex='ab' * 32)
    tx = None if state in ('key_not_observed', 'seal_not_observed') else dict(
        tx_id=original['tx_id'], seal_id='fixture-seal', canonical_request_digest=copy.deepcopy(digest), request_schema='receive-admission/1.0')
    decision = None
    if state == 'committed':
        decision = dict(kind=state, decision_sequence=7, repository_commit_id=original['repository_commit_id'])
    elif state == 'refused':
        decision = dict(kind=state, decision_sequence=7, code=original['refusal_code'], code_point=1,
                        refusal_record_id=original['refusal_record_id'])
    return dict(type='transaction_outcome', schema_version=1, tenant_id=TENANT, repository_id=REPOSITORY,
                principal_id=PRINCIPAL, object_format=algorithm, state=state, terminal=state in ('committed', 'refused'),
                read_only=True, request_reexecuted=False, absence_proves_non_commit=False, node_closed=True,
                cleanup_error=None, key_digest=digest, transaction=tx, decision=decision), original


def self_test():
    rejected = 0
    for algorithm in ('sha1', 'sha256'):
        with tempfile.TemporaryDirectory() as directory:
            f = fixture(Path(directory), algorithm)
            require(len(f['objects']) == 5 and len(f['source']) == hashlib.new(algorithm).digest_size * 2, 'native fixture shape')
        for state in sorted(STATES):
            report, original = sample(state, algorithm)
            validate(report, algorithm, state, original)
        report, original = sample('committed', algorithm)
        corruptions = [('type', 'pull_request_publication'), ('schema_version', True), ('tenant_id', OTHER),
                       ('repository_id', OTHER), ('principal_id', OTHER), ('object_format', 'unknown'),
                       ('state', 'undecided'), ('terminal', False), ('read_only', False), ('request_reexecuted', True),
                       ('absence_proves_non_commit', True), ('node_closed', False), ('cleanup_error', 'failed'),
                       ('transaction', None), ('decision', None), ('key_digest', dict(algorithm=True, hex='ab' * 32))]
        for key, value in corruptions:
            bad = copy.deepcopy(report); bad[key] = value
            try:
                validate(bad, algorithm, 'committed', original)
            except (AssertionError, KeyError, TypeError):
                rejected += 1
            else:
                raise AssertionError(f'checker accepted corrupted {key}')
        for kind in ['tx', 'rcr', 'sequence', 'extra_decision', 'seal']:
            bad = copy.deepcopy(report)
            if kind == 'tx': bad['transaction']['tx_id'] = 'another-tx'
            elif kind == 'rcr': bad['decision']['repository_commit_id'] = 'another-rcr'
            elif kind == 'sequence': bad['decision']['decision_sequence'] = 8
            elif kind == 'extra_decision': bad['decision']['refusal_record_id'] = 'conflicting-outcome'
            else: bad['transaction']['seal_id'] = ''
            try:
                validate(bad, algorithm, 'committed', original)
            except (AssertionError, KeyError, TypeError):
                rejected += 1
            else:
                raise AssertionError(f'checker accepted {kind}')
        refused, original = sample('refused', algorithm)
        for key in ['code', 'refusal_record_id']:
            bad = copy.deepcopy(refused); bad['decision'][key] = 'different'
            try:
                validate(bad, algorithm, 'refused', original)
            except AssertionError:
                rejected += 1
            else:
                raise AssertionError(f'checker accepted changed refusal {key}')
    print(json.dumps(dict(type='transaction_outcome_checker_self_test', passed=True,
                          corrupted_reports_rejected=rejected, rust_executed=False)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--self-test', action='store_true')
    group.add_argument('--fg', type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    binary = args.fg.resolve(strict=True)
    require(binary.is_file(), 'fg must be an existing executable file')
    fingerprint = hashlib.sha256(binary.read_bytes()).hexdigest()
    print(json.dumps(dict(type='tested_binary', path=str(binary), sha256=fingerprint)), flush=True)
    for algorithm in ('sha1', 'sha256'):
        run(binary, algorithm)
    require(hashlib.sha256(binary.read_bytes()).hexdigest() == fingerprint, 'tested executable changed during campaign')


if __name__ == '__main__':
    main()
