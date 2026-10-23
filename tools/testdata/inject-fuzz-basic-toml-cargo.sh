#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

manifest_path=
previous_argument=
for argument do
  if [ "$previous_argument" = "--manifest-path" ]; then
    manifest_path=$argument
  fi
  previous_argument=$argument
done

case "$manifest_path" in
  */fuzz/Cargo.toml)
    "${ASTER_TEST_REAL_CARGO:?}" "$@"
    printf '%s\n' 'basic-toml v0.1.10'
    exit 0
    ;;
esac

exec "${ASTER_TEST_REAL_CARGO:?}" "$@"
