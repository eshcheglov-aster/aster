#!/usr/bin/env bash
# Shared dispatch validation and invocation; inputs arrive only through env.
set -euo pipefail
cd "$(dirname "$0")/../.."
python3 - <<'PY'
import os
import sys
sys.path.insert(0, 'tools/duration-benchmark')
from controller import validate
try:
    rate = 0.0 if os.environ['RATE'] == 'max' else float(os.environ['RATE'])
    overall = float(os.environ['OVERALL'])
    validate(int(os.environ['AGENTS']), float(os.environ['DURATION']), overall,
             rate, int(os.environ['PAYLOAD']), 100000)
    if not 1 <= int(os.environ['WINDOW']) <= 8 or overall > 3600:
        raise ValueError('ci_bounds')
except (KeyError, ValueError, OverflowError):
    sys.exit('Invalid input. Check ranges and units in tools/duration-benchmark/README.md')
PY
if [[ "${1:-}" == validate ]]; then
  exit 0
fi
[[ "${1:-}" == run ]] || exit 2
args=(
  --fixture target/release/aster-agent-acceptance-fixture
  --initializer target/release/aster
  --generator tools/duration-benchmark/target/release/aster-duration-benchmark
  --output "$BENCHMARK_OUTPUT"
  --agents "$AGENTS"
  --duration-seconds "$DURATION"
  --events-per-second "$RATE"
  --payload-bytes "$PAYLOAD"
  --window "$WINDOW"
  --overall-seconds "$OVERALL"
)
# Bound provisioning as well as execution. TERM targets the entire process group.
# The generator's own deadline normally leaves time for reports and child cleanup.
exec timeout --signal=TERM --kill-after=60s 75m \
  python3 -u tools/duration-benchmark/controller.py "${args[@]}"
