#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node --check scripts/operator/event_feed.mjs
node --check scripts/operator/event_archive.mjs
node --check scripts/fg_events.mjs
node --test tests/operator/event_feed.test.mjs \
  tests/operator/event_archive.test.mjs \
  tests/operator/event_consumer_cli.test.mjs
