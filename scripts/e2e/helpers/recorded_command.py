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
        primary = None
        try:
            # subprocess.run kills and waits for its direct child on timeout.
            # check=True enforces exit status even under optimized Python.
            subprocess.run(list(map(str, argv)), input=data, stdout=output, stderr=errors,
                           timeout=timeout, check=True)
        except BaseException as problem:
            primary = problem
            raise
        finally:
            try:
                output.flush()
                errors.flush()
                stdout = prefix.with_suffix('.out').read_bytes()
                diagnostic = prefix.with_suffix('.err').read_bytes()
                if isinstance(primary, (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
                    primary.output = stdout
                    primary.stderr = diagnostic
                if diagnostic:
                    sys.stderr.buffer.write(diagnostic)
                    sys.stderr.buffer.flush()
            except Exception as capture_error:
                if primary is None:
                    raise
                # Diagnostic failures must not replace the execution failure.
                # Retain the secondary cause for callers and tracebacks, too.
                primary.capture_error = capture_error
                if hasattr(primary, 'add_note'):
                    primary.add_note(f'command capture/diagnostic delivery failed: {capture_error!r}')
    return stdout
