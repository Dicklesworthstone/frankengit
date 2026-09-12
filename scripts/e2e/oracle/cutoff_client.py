"""Pure bounded construction of the pinned cutoff campaign's Git arguments."""
from datetime import datetime, timezone
import re

def cutoff_arguments(value):
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError('cutoff profile exceeds its bound')
    parts = value.split(';')
    if len(parts) != 3:
        raise ValueError('cutoff profile needs timestamp;excluded-refs;filter')
    since, excluded, profile = parts
    if profile not in {'full', 'blob:none', 'tree:0'}:
        raise ValueError('unknown cutoff filter profile')
    arguments = []
    if since != '-':
        if not re.fullmatch(r'[1-9][0-9]{0,9}', since) or int(since) > 2147483647:
            raise ValueError('cutoff timestamp is outside the campaign')
        arguments.append('--shallow-since=' + datetime.fromtimestamp(int(since), timezone.utc).isoformat())
    if excluded != '-':
        refs = excluded.split(',')
        allowed = {'cut-old', 'cut-new', 'refs/tags/cut-old', 'refs/heads/cut-new'}
        if not 1 <= len(refs) <= 4 or any(ref not in allowed for ref in refs):
            raise ValueError('exclusion is outside the fixed fixture refs')
        arguments.extend('--shallow-exclude=' + ref for ref in refs)
    if not arguments:
        raise ValueError('at least one cutoff is required')
    if profile != 'full':
        arguments.append('--filter=' + profile)
    return arguments
