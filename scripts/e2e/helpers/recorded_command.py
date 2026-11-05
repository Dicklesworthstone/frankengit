"""Record the native MCP acceptance lane's exact command streams."""
import subprocess
import sys


def run(prefix, argv, data=None, *, timeout=120):
    # Record input before spawning, and let the child write directly to its
    # artifacts. A timeout, failed spawn or interrupted driver must not erase
    # the only evidence of what was requested and how far it got.
    if data is not None:
        prefix.with_suffix('.requests.ndjson').write_bytes(data)
    with prefix.with_suffix('.out').open('wb') as output, prefix.with_suffix('.err').open('wb') as errors:
        try:
            # subprocess.run kills and waits for its direct child on timeout.
            # Do not convert that exception or a spawn failure into success.
            result = subprocess.run(list(map(str, argv)), input=data, stdout=output, stderr=errors, timeout=timeout)
        finally:
            errors.flush()
            diagnostic = prefix.with_suffix('.err').read_bytes()
            if diagnostic:
                sys.stderr.buffer.write(diagnostic)
                sys.stderr.buffer.flush()
    stdout = prefix.with_suffix('.out').read_bytes()
    assert result.returncode == 0, (str(prefix), result.returncode, stdout, diagnostic)
    return stdout
