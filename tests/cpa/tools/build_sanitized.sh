#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance
#
# Build cpa and libgunwinder both instrumented, in OUT:
#   tests/cpa/tools/build_sanitized.sh tsan|asan OUT
# libgunwinder builds inside its source tree, and make does not rebuild it
# when only the flags change, so a copy of it is built in OUT and its
# library replaces the one next to OUT/bin/cpa.
set -e
kind=$1
out=$2
case "$kind" in
tsan) opt=-DCPA_BPF_ENABLE_TSAN=ON san=thread ;;
asan) opt=-DCPA_BPF_ENABLE_ASAN=ON san=address ;;
*) echo "usage: $0 tsan|asan OUT" >&2; exit 2 ;;
esac
[ -n "$out" ] || { echo "usage: $0 tsan|asan OUT" >&2; exit 2; }
root=$(cd "$(dirname "$0")/../../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)

cmake -S "$root" -B "$out" "$opt"
cmake --build "$out" -- -j"$(nproc)"

rm -rf "$out/libgunwinder-src"
cp -a "$root/libs/libgunwinder" "$out/libgunwinder-src"
make -C "$out/libgunwinder-src" clean >/dev/null
make -C "$out/libgunwinder-src" -j"$(nproc)" \
	CFLAGS_OPT="-O1 -fno-omit-frame-pointer" DEBUG_FLAGS="-g -fsanitize=$san" \
	lib/libgunwinder.so
cp "$out/libgunwinder-src/lib/libgunwinder.so" "$out/bin/libgunwinder.so"
case "$san" in
thread) sym=__tsan_func_entry ;;
address) sym=__asan_report_load8 ;;
esac
nm -D "$out/bin/libgunwinder.so" | grep -q "$sym" || {
	echo "libgunwinder.so is not instrumented" >&2
	exit 1
}
echo "built $out/bin/cpa with -fsanitize=$san"
