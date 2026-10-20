"""Tier A receipt: one status per registries/compatibility_tiers.tsv row.

usage: tier_a_receipt.py REGISTRY RUN_ALL_RECEIPT FG_BINARY ORACLE_INSTALL_RECEIPT

A row's status is the status its owning suite recorded for the row's
acceptance ID in that suite's own NDJSON log. A row with no such assertion is
`not_run`, never `pass`. Writes the receipt JSON to stdout. Exit 0 when every
row passed, 3 when rows are unsupported (the pinned oracle was unavailable)
and none failed, 1 otherwise.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

registry, run_receipt, fg_binary, oracle_receipt = map(pathlib.Path, sys.argv[1:5])


def digest(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


lines = [line for line in registry.read_text().splitlines() if line and not line.startswith('#')]
header = lines[0].split('\t')
rows = [dict(zip(header, line.split('\t'))) for line in lines[1:]]

logs = {}
for line in run_receipt.read_text().splitlines() if run_receipt.exists() else []:
    record = json.loads(line)
    if record.get('kind') == 'suite_script':
        logs[record['script']] = (record.get('log_path'), record.get('disposition'))

assertions = {}
for script, (log_path, _) in logs.items():
    if not log_path or not pathlib.Path(log_path).exists():
        continue
    for line in pathlib.Path(log_path).read_text().splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get('kind') == 'assert' and record.get('acceptance_id'):
            assertions[(script, record['acceptance_id'])] = (
                record['result']['status'], record['result'].get('detail') or '', record.get('run_id'))

receipt_rows, counts = [], {}
for row in rows:
    status, detail, run_id = assertions.get((row['owning_suite'], row['id']), ('not_run', 'the owning suite recorded no assertion for this row', None))
    counts[status] = counts.get(status, 0) + 1
    receipt_rows.append({**{key: row[key] for key in ('id', 'gcm_surfaces', 'service', 'transport', 'protocol',
                                                      'object_format', 'operation', 'oracle_pin', 'owning_suite')},
                         'status': status, 'detail': detail, 'run_id': run_id})


def git(*args):
    return subprocess.run(['git', *args], capture_output=True, text=True).stdout.strip()


if counts.get('pass', 0) == len(rows) and rows:
    verdict, code = 'pass', 0
elif set(counts) <= {'pass', 'unsupported'} and counts.get('unsupported'):
    verdict, code = 'unsupported', 3
else:
    verdict, code = 'fail', 1
json.dump({
    'schema': 'frankengit.tier-a-receipt.v1',
    'revision': git('rev-parse', 'HEAD'),
    'dirty': bool(git('status', '--porcelain', '--untracked-files=no')),
    'registry_sha256': digest(registry),
    'fg_sha256': digest(fg_binary),
    'oracle_install_receipt_sha256': digest(oracle_receipt),
    'verdict': verdict,
    'counts': counts,
    'rows': receipt_rows,
}, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write('\n')
sys.exit(code)
