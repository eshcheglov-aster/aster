#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo "macOS compatibility lane requires macOS" >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

target_root=${CARGO_TARGET_DIR:-target}
systemd_target="$target_root/systemd-workspace"
compose_target="$target_root/compose-package"

run_systemd_workspace_tests() {
    CARGO_TARGET_DIR="$systemd_target" sh tools/with-test-resources.sh \
        cargo +1.97.1 test --locked --offline --workspace --all-features \
        --exclude aster-compose-credentials "$@"
}

run_compose_tests() {
    CARGO_TARGET_DIR="$compose_target" sh tools/with-test-resources.sh \
        cargo +1.97.1 test --locked --offline \
        -p aster-compose-credentials --all-features "$@"
}

run_systemd_workspace_tests --no-run
run_compose_tests --no-run
run_systemd_workspace_tests platform_compat_
run_compose_tests platform_compat_
