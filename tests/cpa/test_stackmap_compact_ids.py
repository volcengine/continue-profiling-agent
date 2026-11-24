# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""The live stack map: packed delta-varint stacks, arenas, intern indexes.

The harness links the real cli_stackmap.c with a zstd stub that writes
plain files, feeds it stacks from a fixed pseudo-random workload (close and
far string ids, ids past 2^14 and 2^21, repeated stacks, an empty frame, an
over-long frame) and dumps the store.  The strmap and idsmap must be exactly
what the workload implies (ids in first-seen order), and the map read back
through FOR_EACH_STACKMAP_STR and cli_stackmap_ids_copy() must give the
stacks fed in.  The varint codec is checked on its own, and a stack whose
interning or counting fails must not leak its frames into the next one.
"""

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SM = REPO_ROOT / "src/cli_stackmap_helper"
FRAME_MAX = 8192

STUB_HEADERS = {
    "cli_config.h": "",
    "cli_output.h": """
        #ifndef TEST_CLI_OUTPUT_H
        #define TEST_CLI_OUTPUT_H
        #define CLI_ERROR(...) ((void)0)
        #define CLI_OUTPUT(...) ((void)0)
        #define CLI_OUTPUT_NO_END(...) ((void)0)
        #define CLI_VERBOSE(...) ((void)0)
        #define CLI_VERBOSE_NO_END(...) ((void)0)
        #endif
    """,
    "cli_common.h": """
        #ifndef TEST_CLI_COMMON_H
        #define TEST_CLI_COMMON_H
        #include <stdint.h>
        char *path_join(const char *path1, const char *path2);
        uint64_t get_current_ms(void);
        uint64_t get_start_of_today(void);
        #endif
    """,
    "cli_zstd_helper.h": """
        #ifndef TEST_CLI_ZSTD_HELPER_H
        #define TEST_CLI_ZSTD_HELPER_H
        #include <stddef.h>
        #include <stdio.h>
        typedef struct { FILE *fp; } ZSTDStream;
        ZSTDStream *cli_zstd_init(const char *fileName);
        void cli_zstd_destroy(ZSTDStream *stream);
        int cli_zstd_write(ZSTDStream *stream, const char *fmt, ...);
        int cli_zstd_write_bytes(ZSTDStream *stream, const void *data, size_t length);
        int cli_zstd_write_done(ZSTDStream *stream);
        int cli_zstd_flush(ZSTDStream *stream);
        char *cli_zstd_decompress_file(const char *file_name, int use_cache);
        #endif
    """,
}

STUBS = r'''
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli_stackmap.h"

/* zstd: plain files, so the store can be compared byte for byte */
ZSTDStream *cli_zstd_init(const char *name)
{
	ZSTDStream *s = calloc(1, sizeof(*s));

	if (s && !(s->fp = fopen(name, "w"))) {
		free(s);
		return NULL;
	}
	return s;
}
void cli_zstd_destroy(ZSTDStream *s) { if (s) { fclose(s->fp); free(s); } }
int cli_zstd_write(ZSTDStream *s, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vfprintf(s->fp, fmt, ap);
	va_end(ap);
	return n < 0 ? -1 : 0;
}
int cli_zstd_write_bytes(ZSTDStream *s, const void *d, size_t l)
{
	return fwrite(d, 1, l, s->fp) == l ? 0 : -1;
}
int cli_zstd_write_done(ZSTDStream *s) { (void)s; return 0; }
int cli_zstd_flush(ZSTDStream *s) { return fflush(s->fp) ? -1 : 0; }
char *cli_zstd_decompress_file(const char *f, int c) { (void)f; (void)c; return NULL; }
char *path_join(const char *a, const char *b)
{
	char *out = malloc(strlen(a) + strlen(b) + 2);

	sprintf(out, "%s/%s", a, b);
	return out;
}
uint64_t get_current_ms(void) { return 1000; }
uint64_t get_start_of_today(void) { return 0; }
'''

WORKLOAD = r'''
#include <assert.h>

#define NSTRINGS 3000000U	/* string ids past 2^21: 4-byte varint deltas */
#define NSTACKS 20000

static uint64_t rng = 0x9e3779b97f4a7c15ULL;

static uint32_t next_rand(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return (uint32_t)(rng >> 32);
}

static char *frame_name(uint32_t n, char *buf)
{
	if (n == 0)
		return "";	/* an empty frame is a frame */
	sprintf(buf, "fn_%u", n);
	return buf;
}

int main(int argc, char **argv)
{
	struct cli_stackmap *map = cli_stackmap_init();
	static char big[FRAME_MAX + 100];
	char buf[32];
	FILE *log;

	assert(argc == 3 && map);
	log = fopen(argv[2], "w");
	assert(log);
	memset(big, 'A', sizeof(big) - 1);

	/* a far string first, so later stacks mix close and far ids */
	for (uint32_t i = 0; i < NSTRINGS; i += 997) {
		assert(cli_stackmap_append(map, frame_name(i + 1, buf)) == 0);
		fprintf(log, "%s\n", frame_name(i + 1, buf));
	}
	assert(cli_stackmap_done(map, 1) == 0);
	fprintf(log, "--\n");

	for (int s = 0; s < NSTACKS; s++) {
		/* every 7th stack repeats an earlier one */
		uint64_t keep = rng;
		int depth;

		if (s % 7 == 6)
			rng = 0x1234567ULL + (uint64_t)(s / 7);
		depth = 1 + next_rand() % 40;
		for (int d = 0; d < depth; d++) {
			uint32_t r = next_rand();
			uint32_t n = (r & 3) ? (r >> 2) % 200 : ((r >> 2) % NSTRINGS) + 1;

			assert(cli_stackmap_append(map, frame_name(n, buf)) == 0);
			fprintf(log, "%s\n", frame_name(n, buf));
		}
		if (s == 100) {
			/* cut to FRAME_MAX bytes, like any longer frame */
			assert(cli_stackmap_append(map, big) == 0);
			fprintf(log, "%.*s\n", FRAME_MAX, big);
		}
		if (s % 7 == 6)
			rng = keep;
		assert(cli_stackmap_done(map, 1 + s % 3) == 0);
		fprintf(log, "--\n");
	}
	fclose(log);

	/* read back: every stack id gives its frames, both ways */
	FILE *back = fopen(argv[1], "w");
	assert(back);
	for (uint32_t id = 1; id < map->ids_id; id++) {
		const char *str;
		uint32_t n = 0, *ids = cli_stackmap_ids_copy(map, id, &n);
		uint32_t i = 0;

		assert(ids);
		FOR_EACH_STACKMAP_STR(map, id, str) {
			assert(i < n && strcmp(map->str_rec_by_id[ids[i]]->str, str) == 0);
			fprintf(back, "%s\n", str);
			i++;
		}
		assert(i == n);
		fprintf(back, "--\n");
		free(ids);
	}
	fclose(back);
	assert(cli_stackmap_ids_copy(map, map->ids_id, &(uint32_t){ 0 }) == NULL);

	/* a stack record takes ~1-5 bytes per frame, never 4 per frame plus a handle */
	struct cli_stackmap_memory_usage *u = cli_stackmap_get_memory_usage(map);
	printf("ids_id=%u str_id=%u idsmap=%llu strmap=%llu idsindex=%llu strindex=%llu\n",
	       map->ids_id, map->str_id, (unsigned long long)u->memory_usage_idsmap,
	       (unsigned long long)u->memory_usage_strmap, (unsigned long long)u->memory_usage_idsindex,
	       (unsigned long long)u->memory_usage_strindex);
	cli_stackmap_dump_delta_stack(map, getenv("DUMP_DIR"));
	cli_stackmap_destroy(map);
	return 0;
}
'''

CODEC = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "stackmap_ids_codec.h"

static void roundtrip(const uint32_t *ids, uint32_t n)
{
	uint8_t buf[5 + 64 * STACKMAP_IDS_VARINT_MAX], *rec = buf;
	struct stackmap_ids_iter it;
	uint32_t got, i = 0;
	size_t payload = stackmap_ids_encode(buf + 5, ids, n), plen;
	size_t prefix = stackmap_ids_varint_len(payload);

	assert(payload <= n * STACKMAP_IDS_VARINT_MAX);
	memmove(buf + prefix, buf + 5, payload);
	assert(stackmap_ids_put_varint(rec, payload) == prefix);
	assert(stackmap_ids_payload(rec, &plen) == rec + prefix && plen == payload);
	stackmap_ids_iter_init(&it, rec);
	while (stackmap_ids_iter_next(&it, &got))
		assert(i < n && got == ids[i++]);
	assert(i == n);
}

int main(void)
{
	const uint32_t a[] = { 0 }, b[] = { 1, 2, 3, 2, 1 }, c[] = { UINT32_MAX, 0, UINT32_MAX, 1 },
		       d[] = { 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456 };
	uint32_t e[64], f[64];

	roundtrip(a, 0);
	roundtrip(a, 1);
	roundtrip(b, 5);
	roundtrip(c, 4);
	roundtrip(d, 8);
	for (uint32_t i = 0; i < 64; i++)
		e[i] = i * 2654435761U;
	roundtrip(e, 64);
	/* unique: different stacks never encode alike */
	memcpy(f, e, sizeof(f));
	f[63] ^= 1;
	uint8_t x[64 * 5], y[64 * 5];
	size_t lx = stackmap_ids_encode(x, e, 64), ly = stackmap_ids_encode(y, f, 64);
	assert(lx != ly || memcmp(x, y, lx));
	/* close ids take one byte each */
	assert(stackmap_ids_encode(x, b, 5) == 5);
	assert(stackmap_ids_varint_len(UINT64_MAX >> 31) == STACKMAP_IDS_VARINT_MAX);
	printf("codec ok\n");
	return 0;
}
'''

FAIL = r'''
#include <assert.h>

/* the timewheel count and the stack index fail while set (-Wl,--wrap) */
static bool fail_count, fail_intern;

int __real_stackmap_timewheel_add(struct stackmap_timewheel *w, uint64_t ms, uint32_t id, uint64_t count);
int __wrap_stackmap_timewheel_add(struct stackmap_timewheel *w, uint64_t ms, uint32_t id, uint64_t count)
{
	return fail_count ? -1 : __real_stackmap_timewheel_add(w, ms, id, count);
}

int __real_stackmap_intern_index_prepare_insert(struct stackmap_intern_index *index, const void *key, size_t key_len,
						 stackmap_intern_index_eq_fn eq, void *ctx,
						 struct stackmap_intern_index_insert *insert, uint32_t *id, bool *found);
int __wrap_stackmap_intern_index_prepare_insert(struct stackmap_intern_index *index, const void *key, size_t key_len,
						 stackmap_intern_index_eq_fn eq, void *ctx,
						 struct stackmap_intern_index_insert *insert, uint32_t *id, bool *found)
{
	/* only the stack index: the map's ids index has the ids_index_eq callback */
	if (fail_intern && index == ((struct cli_stackmap *)ctx)->ids_index)
		return -1;
	return __real_stackmap_intern_index_prepare_insert(index, key, key_len, eq, ctx, insert, id, found);
}

int main(void)
{
	for (int mode = 0; mode < 3; mode++) {
		struct cli_stackmap *map = cli_stackmap_init();
		uint32_t id = 0, n = 0, *ids;

		assert(map);
		if (mode != 1)
			assert(cli_stackmap_enable_timewheel(map, 10000) == 0);
		assert(cli_stackmap_append(map, "leaf") == 0);
		assert(cli_stackmap_append(map, "root") == 0);
		fail_count = mode == 0;
		fail_intern = mode != 0;
		assert(cli_stackmap_done_at(map, 1, 1000) != 0);
		fail_count = fail_intern = false;
		assert(cli_stackmap_current_length(map) == 0);
		/* the next stack is its own frames only */
		assert(cli_stackmap_append(map, "other") == 0);
		assert(cli_stackmap_done_intern(map, &id) == 0);
		ids = cli_stackmap_ids_copy(map, id, &n);
		assert(ids && n == 1 && strcmp(map->str_rec_by_id[ids[0]]->str, "other") == 0);
		free(ids);
		cli_stackmap_destroy(map);
	}
	assert(cli_stackmap_done(NULL, 1) != 0);
	printf("failures ok\n");
	return 0;
}
'''


def _headers(tmp_path: Path) -> Path:
    inc = tmp_path / "include"
    inc.mkdir()
    for name, text in STUB_HEADERS.items():
        (inc / name).write_text(textwrap.dedent(text))
    return inc


def _build(tmp_path: Path, name: str, body: str, extra=()) -> Path:
    if shutil.which("cc") is None:
        pytest.skip("needs a C compiler")
    inc = _headers(tmp_path) if not (tmp_path / "include").exists() else tmp_path / "include"
    src = tmp_path / f"{name}.c"
    src.write_text(f"#define FRAME_MAX {FRAME_MAX}\n" + STUBS + body)
    out = tmp_path / name
    cmd = ["cc", "-std=gnu11", "-O1", "-g", "-Wall", "-Werror", "-pthread",
           "-I", str(inc), "-I", str(SM), "-I", str(REPO_ROOT / "src"),
           *extra, str(src)]
    cmd += [str(SM / f) for f in ("cli_stackmap.c", "stackmap_count_table.c", "stackmap_timewheel.c",
                                  "stackmap_arena.c", "stackmap_intern_index.c")]
    subprocess.run(cmd + ["-o", str(out)], check=True)
    return out


def test_ids_codec(tmp_path: Path) -> None:
    if shutil.which("cc") is None:
        pytest.skip("needs a C compiler")
    src = tmp_path / "codec.c"
    src.write_text(CODEC)
    out = tmp_path / "codec"
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Werror", "-I", str(SM), str(src), "-o", str(out)], check=True)
    assert "codec ok" in subprocess.run([str(out)], capture_output=True, text=True, check=True).stdout


@pytest.mark.parametrize("sanitize", ["", "address,undefined"])
def test_store_is_what_the_workload_implies(tmp_path: Path, sanitize: str) -> None:
    extra = [f"-fsanitize={sanitize}", "-fno-omit-frame-pointer"] if sanitize else []
    try:
        binary = _build(tmp_path, "workload", WORKLOAD, extra)
    except subprocess.CalledProcessError:
        if sanitize:
            pytest.skip("compiler without this sanitizer")
        raise
    dump = tmp_path / "store"
    dump.mkdir()
    back, log = tmp_path / "back.txt", tmp_path / "log.txt"
    run = subprocess.run([str(binary), str(back), str(log)], capture_output=True, text=True, timeout=600,
                         env={"DUMP_DIR": str(dump), "ASAN_OPTIONS": "detect_leaks=1"})
    assert run.returncode == 0, run.stdout + run.stderr

    # ids in first-seen order, stacks deduplicated: the store the old map wrote
    str_ids, stacks, stack_ids, order = {}, [], {}, []
    cur = []
    for line in log.read_text().split("\n")[:-1]:
        if line == "--":
            key = tuple(cur)
            if key not in stack_ids:
                stack_ids[key] = len(stack_ids) + 1
                stacks.append(key)
            order.append(key)
            cur = []
            continue
        if line not in str_ids:
            str_ids[line] = len(str_ids) + 1
        cur.append(str_ids[line])
    names = {v: k for k, v in str_ids.items()}
    want_str = "".join(f"{k} {v}\n" for k, v in str_ids.items())
    want_ids = "".join("".join(f"{i};" for i in st) + f" {n}\n" for n, st in enumerate(stacks, 1))
    assert (dump / "strmap").read_text() == want_str
    assert (dump / "idsmap").read_text() == want_ids
    want_back = "".join("".join(names[i] + "\n" for i in st) + "--\n" for st in stacks)
    assert back.read_text() == want_back
    assert len(stacks) < len(order)  # the repeats were found
    assert max(len(k) for k in str_ids) == FRAME_MAX and "" in str_ids

    stats = dict(kv.split("=") for kv in run.stdout.split())
    frames = sum(len(st) for st in stacks)
    # the old map: 4 bytes per frame and a 56-byte hash handle and header per stack
    assert int(stats["idsmap"]) < frames * 4 + len(stacks) * 72
    assert int(stats["idsindex"]) > 0 and int(stats["strindex"]) > 0


def test_a_stack_that_fails_ends_anyway(tmp_path: Path) -> None:
    binary = _build(tmp_path, "fail", FAIL, ["-Wl,--wrap=stackmap_timewheel_add",
                                             "-Wl,--wrap=stackmap_intern_index_prepare_insert"])
    run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
    assert run.returncode == 0 and "failures ok" in run.stdout, run.stdout + run.stderr
