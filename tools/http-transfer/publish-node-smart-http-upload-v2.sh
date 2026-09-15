#!/usr/bin/env bash
set -euo pipefail

patched="$RUNNER_TEMP/publish-node-smart-http-upload-fixed.sh"
cp tools/http-transfer/publish-node-smart-http-upload.sh "$patched"
python3 - "$patched" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
s=p.read_text()
replacements={
    'use std::cell::Cell;\nuse std::error::Error;': 'use std::cell::Cell;\nuse std::error::Error;\nuse std::sync::atomic::{AtomicBool, Ordering};',
    'let admission_deadline_expired = Cell::new(false);': 'let admission_deadline_expired = AtomicBool::new(false);',
    'admission_deadline_expired.set(true);': 'admission_deadline_expired.store(true, Ordering::Relaxed);',
    'admission_deadline_expired.get()': 'admission_deadline_expired.load(Ordering::Relaxed)',
}
for old,new in replacements.items():
    if old not in s:
        raise SystemExit(f'missing expected publisher source: {old!r}')
    s=s.replace(old,new,1)
old='''            if write_response_part(writer, framed.prefix.as_bytes(), "write HTTP chunk prefix")
                .and_then(|()| write_response_part(writer, framed.data, "write smart HTTP body"))
                .and_then(|()| write_response_part(writer, framed.suffix, "write HTTP chunk suffix"))
                .is_err()
            {
                response.abort();
                return Err(NodeSmartHttpRefusal::Io {
                    operation: "write smart HTTP response",
                    source: io::Error::new(io::ErrorKind::BrokenPipe, "response writer failed"),
                });
            }
'''
new='''            if let Err(error) = write_response_part(
                writer,
                framed.prefix.as_bytes(),
                "write HTTP chunk prefix",
            )
            .and_then(|()| write_response_part(writer, framed.data, "write smart HTTP body"))
            .and_then(|()| {
                write_response_part(writer, framed.suffix, "write HTTP chunk suffix")
            }) {
                response.abort();
                return Err(error);
            }
'''
if s.count(old)!=1:
    raise SystemExit('response write error block changed')
s=s.replace(old,new)
p.write_text(s)
PY
bash "$patched"
