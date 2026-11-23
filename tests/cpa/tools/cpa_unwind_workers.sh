#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance
#
# Run the cpa next to this script's CPA_BIN (default build/bin/cpa) with
# --unwind_workers=$CPA_UNWIND_WORKERS (default 4) added to every monitor
# command that does not set it, so that any test runs with several unwind
# workers:
#   TEST_CPA_PATH=$PWD/tests/cpa/tools/cpa_unwind_workers.sh python3 -m pytest tests/cpa
bin=${CPA_BIN:-$(dirname "$0")/../../../build/bin/cpa}
n=${CPA_UNWIND_WORKERS:-4}
if [ "$1" = monitor ]; then
	for a in "$@"; do
		case "$a" in --unwind_workers*) exec "$bin" "$@" ;; esac
	done
	exec "$bin" "$@" --unwind_workers="$n"
fi
exec "$bin" "$@"
