from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

HARNESS = r"""
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <zstd.h>

#include <cli_zstd_helper.h>

char *path_join(const char *path1, const char *path2)
{
    size_t len = strlen(path1) + strlen(path2) + 2;
    char *out = malloc(len);
    if (!out)
        return NULL;
    snprintf(out, len, "%s/%s", path1, path2);
    return out;
}

void create_directory_if_notexist(const char *path)
{
    mkdir(path, 0755);
}

void clear_file_cache(FILE *fp)
{
    (void)fp;
}

/* Compress payload with the reference zstd API into the named file. */
static void write_reference_zstd(const char *path, const unsigned char *buf,
                                 size_t len)
{
    FILE *f = fopen(path, "wb");
    assert(f);
    ZSTD_CStream *cs = ZSTD_createCStream();
    assert(cs);
    assert(ZSTD_initCStream(cs, 1) == 0);
    unsigned char out[32 * 1024];
    ZSTD_outBuffer ob = { out, sizeof(out), 0 };
    ZSTD_inBuffer ib = { buf, len, 0 };
    for (;;) {
        size_t r = ZSTD_compressStream(cs, &ob, &ib);
        assert(!ZSTD_isError(r));
        fwrite(out, 1, ob.pos, f);
        ob.pos = 0;
        if (ib.pos == ib.size) {
            unsigned int left;
            do {
                ob.pos = 0;
                left = ZSTD_endStream(cs, &ob);
                assert(!ZSTD_isError(left));
                fwrite(out, 1, ob.pos, f);
            } while (left != 0);
            break;
        }
    }
    ZSTD_freeCStream(cs);
    fclose(f);
}

int main(void)
{
    /* 1) decompress through a store directory longer than the old 256-byte
     *    fixed buffers. */
    const char *deep = getenv("DEEP_DIR");
    assert(deep && strlen(deep) > 300);
    char stack_path[2048];
    snprintf(stack_path, sizeof(stack_path), "%s/stack.bin", deep);

    size_t payload_len = 4096;
    unsigned char *payload = malloc(payload_len);
    assert(payload);
    for (size_t i = 0; i < payload_len; i++)
        payload[i] = (unsigned char)(i * 7 + 3);
    write_reference_zstd(stack_path, payload, payload_len);

    char *decompressed = cli_zstd_decompress_file(stack_path, 0);
    assert(decompressed != NULL);
    FILE *df = fopen(decompressed, "rb");
    assert(df);
    unsigned char *roundtrip = malloc(payload_len);
    assert(roundtrip);
    size_t got = fread(roundtrip, 1, payload_len, df);
    assert(got == payload_len);
    assert(memcmp(payload, roundtrip, payload_len) == 0);
    fclose(df);
    free(decompressed);

    /* cache hit path */
    assert(cli_zstd_decompress_file(stack_path, 1) != NULL);

    /* 2) slashless names must not deref a NULL strrchr. */
    assert(cli_zstd_decompress_file("bare_name_no_slash", 0) == NULL);
    assert(cli_zstd_decompress_file("", 0) == NULL);

    /* 3) endStream must fully drain a large incompressible payload. */
    size_t big_len = 40 * 1024;
    unsigned char *big = malloc(big_len);
    assert(big);
    for (size_t i = 0; i < big_len; i++)
        big[i] = (unsigned char)(i * 31 + (i >> 3) ^ 17);

    char out_path[2048];
    snprintf(out_path, sizeof(out_path), "%s/drain.bin", deep);
    ZSTDStream *zs = cli_zstd_init(out_path);
    assert(zs);
    /* Single calls must stay under the 16 KiB staging buffer (frame
     * strings are capped to 8 KiB upstream); write in small chunks. */
    for (size_t off = 0; off < big_len; off += 4096) {
        size_t chunk = big_len - off;
        if (chunk > 4096)
            chunk = 4096;
        assert(cli_zstd_write_bytes(zs, big + off, chunk) == 0);
    }
    /* Compress the final buffered input, then drain endStream. */
    assert(cli_zstd_write_done(zs) == 0);
    assert(cli_zstd_flush(zs) == 0);
    cli_zstd_destroy(zs);

    write_reference_zstd(stack_path, payload, payload_len); /* restore */
    char *drain_decompressed = cli_zstd_decompress_file(out_path, 0);
    assert(drain_decompressed != NULL);
    FILE *bf = fopen(drain_decompressed, "rb");
    assert(bf);
    unsigned char check[64];
    size_t total = 0;
    size_t n;
    while ((n = fread(check, 1, sizeof(check), bf)) > 0) {
        assert(total + n <= big_len);
        assert(memcmp(big + total, check, n) == 0);
        total += n;
    }
    assert(total == big_len);
    fclose(bf);
    free(drain_decompressed);

    printf("zstd long-path and flush ok\n");
    return 0;
}
"""


def _write_stub_headers(include_dir: Path) -> None:
    include_dir.mkdir()
    (include_dir / "cli.h").write_text(
        textwrap.dedent(
            """
            #ifndef TEST_CLI_H
            #define TEST_CLI_H
            #include <cli_output.h>
            #include <cli_zstd_helper.h>
            char *path_join(const char *, const char *);
            void create_directory_if_notexist(const char *);
            void clear_file_cache(FILE *);
            #endif
            """
        ),
        encoding="utf-8",
    )
    (include_dir / "cli_output.h").write_text(
        textwrap.dedent(
            """
            #ifndef TEST_CLI_OUTPUT_H
            #define TEST_CLI_OUTPUT_H
            #include <stdio.h>
            #define CLI_ERROR(...) fprintf(stderr, __VA_ARGS__)
            #define CLI_OUTPUT(...) ((void)0)
            #define CLI_OUTPUT_NO_END(...) ((void)0)
            #define CLI_VERBOSE(...) ((void)0)
            #define CLI_VERBOSE_NO_END(...) ((void)0)
            #endif
            """
        ),
        encoding="utf-8",
    )


def test_zstd_decompress_long_paths_and_flush_drain(tmp_path: Path) -> None:
    include_dir = tmp_path / "include"
    _write_stub_headers(include_dir)

    # Deep path through many components (>300 chars, each < NAME_MAX).
    deep_dir = tmp_path
    for _ in range(20):
        deep_dir = deep_dir / "abcdefghijklmnop"
    deep_dir.mkdir(parents=True)

    harness = tmp_path / "zstd_harness.c"
    harness.write_text(HARNESS, encoding="utf-8")
    binary = tmp_path / "zstd_harness"
    compile_cmd = [
        "cc",
        "-std=gnu11",
        "-Wall",
        "-Wextra",
        "-I",
        str(include_dir),
        "-I",
        str(REPO_ROOT / "src/cli_zstd_helper"),
        str(harness),
        str(REPO_ROOT / "src/cli_zstd_helper/cli_zstd_helper.c"),
        "-o",
        str(binary),
        "-lzstd",
    ]
    subprocess.run(compile_cmd, check=True, cwd=REPO_ROOT)
    env = dict(os.environ)
    env["DEEP_DIR"] = str(deep_dir)
    subprocess.run([str(binary)], check=True, env=env)
