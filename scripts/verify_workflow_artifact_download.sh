#!/usr/bin/env bash
# Client contracts only: explicit HTTP schema peers, not native fg admission.
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
node --check scripts/fg_workflow_watch.mjs
node --check scripts/operator/workflow_artifact_download.mjs
node --check tests/operator/workflow_artifact_download.test.mjs
node --check tests/operator/workflow_artifact_streaming.test.mjs
node --test tests/operator/workflow_artifact_download.test.mjs tests/operator/workflow_artifact_streaming.test.mjs
