#!/usr/bin/env bash
set -euo pipefail

patched="$RUNNER_TEMP/publish-node-smart-http-receive-rpc-fixed.sh"
cp tools/http-transfer/publish-node-smart-http-receive-rpc.sh "$patched"
python3 - "$patched" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
s=p.read_text()
old='''        let outcome = self
            .runtime
            .block_on(self.receive_loopback_pack_durable_in('''
new='''        let outcome = self
            .receive_loopback_pack_durable_in('''
if s.count(old)!=1:
    raise SystemExit('durable receive call anchor changed')
s=s.replace(old,new)
old='''                cancellation,
            ))
            .map_err(NodeSmartHttpRefusal::from)?;'''
new='''                cancellation,
            )
            .map_err(NodeSmartHttpRefusal::from)?;'''
if s.count(old)!=1:
    raise SystemExit('durable receive call terminator changed')
s=s.replace(old,new)
p.write_text(s)
PY
bash "$patched"
