#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

all_features=false
inverted=false
basic_toml=false
manifest_path=
previous_argument=
for argument do
  if [ "$previous_argument" = "--manifest-path" ]; then
    manifest_path=$argument
  fi
  case "$argument" in
    --all-features)
      all_features=true
      ;;
    --invert|-i)
      inverted=true
      ;;
    basic-toml@0.1.10)
      basic_toml=true
      ;;
  esac
  previous_argument=$argument
done

case "$manifest_path" in
  */fuzz/Cargo.toml)
    ;;
  *)
    if [ "$all_features" = true ] && [ "$inverted" = false ]; then
      "${ASTER_TEST_REAL_CARGO:?}" "$@"
      printf '%s\n' 'basic-toml v0.1.10' 'unexpected-basic-toml-consumer v9.9.9'
      exit 0
    fi
    ;;
esac

if [ "$inverted" = true ] && [ "$basic_toml" = true ]; then
  "${ASTER_TEST_REAL_CARGO:?}" "$@"
  printf '%s\n' 'unexpected-basic-toml-consumer v9.9.9'
  exit 0
fi

exec "${ASTER_TEST_REAL_CARGO:?}" "$@"
