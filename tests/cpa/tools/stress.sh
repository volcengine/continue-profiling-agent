#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance
#
# Stress --unwind_workers under a sanitizer build (build_sanitized.sh):
#   tests/cpa/tools/stress.sh CPA_BIN WORKERS SECONDS OUTDIR [monitor args...]
# Samples the whole system while short-lived processes are forked in a loop
# and busy ones run; with MIDNIGHT_IN=S (needs libfaketime) the clock crosses
# midnight after S seconds, so the run also pauses and restores every
# worker once.  Prints the sanitizer report count; 0 is a pass.
set -u
bin=$1 n=$2 secs=$3 out=$4
shift 4
mkdir -p "$out/store"
log="$out/monitor.log"
san_log="$out/san"

loads=""
for i in 1 2 3 4; do
	( while :; do :; done ) & loads="$loads $!"
done
( while :; do /bin/true; sh -c 'i=0; while [ $i -lt 200 ]; do i=$((i+1)); done'; done ) & loads="$loads $!"
( while :; do sleep 0.01; done ) & loads="$loads $!"

preload="" faketime=""
if [ -n "${MIDNIGHT_IN:-}" ]; then
	lib=$(ls /usr/lib/*/faketime/libfaketime.so.1 2>/dev/null | head -1)
	[ -n "$lib" ] || { echo "MIDNIGHT_IN needs libfaketime" >&2; kill $loads; exit 2; }
	if ldd "$bin" | grep -q libtsan; then
		# libfaketime breaks TSan's clock interception: no midnight there
		echo "MIDNIGHT_IN does not work with a TSan build" >&2; kill $loads; exit 2
	fi
	midnight=$(date -d "$(date -d tomorrow +%Y-%m-%d) 00:00:00" +%s)
	# a sanitizer runtime must come first in the library list
	san_rt=$(ldd "$bin" | awk '/libasan\.so/{print $3; exit}')
	preload="${san_rt:+$san_rt }$lib"
	faketime="@$(date -d @$((midnight - MIDNIGHT_IN)) '+%Y-%m-%d %H:%M:%S')"
fi

# only the monitor gets the preload; the exit grace period compares BPF
# (real) monotonic times, so the monotonic clock stays real
env ${preload:+LD_PRELOAD="$preload"} ${faketime:+FAKETIME="$faketime"} DONT_FAKE_MONOTONIC=1 \
	TSAN_OPTIONS="log_path=$san_log halt_on_error=0 second_deadlock_stack=1" \
	ASAN_OPTIONS="log_path=$san_log detect_leaks=1" \
	LD_LIBRARY_PATH="$(dirname "$bin")" \
	"$bin" monitor --store_dir "$out/store" --duration "$secs" \
	--unwind_workers="$n" --log_print_cycles=10 "$@" > "$log" 2>&1
rc=$?
kill $loads 2>/dev/null
wait 2>/dev/null
reports=$(cat "$san_log".* 2>/dev/null | grep -cE "^(WARNING: ThreadSanitizer|==[0-9]+==ERROR: )")
dirs=$(ls -d "$out"/store/cpa_* 2>/dev/null | wc -l)
echo "workers=$n rc=$rc sanitizer_reports=$reports store_dirs=$dirs"
