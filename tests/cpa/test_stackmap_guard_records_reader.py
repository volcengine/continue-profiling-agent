from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

HARNESS_TEMPLATE = """
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CLISTACK_PRIVATE"
#include "CLISTACK_PUBLIC"

static const char *RAW_DUMP = "RAW_DUMP_PATH";

static ZSTDStream stream_storage;
ZSTDStream *cli_zstd_init(const char *f) { (void)f; return &stream_storage; }
void cli_zstd_destroy(ZSTDStream *s) { (void)s; }
int cli_zstd_write(ZSTDStream *s, const char *f, ...) { (void)s; (void)f; return 0; }
int cli_zstd_write_bytes(ZSTDStream *s, const void *d, size_t l)
{ (void)s; (void)d; (void)l; return 0; }
int cli_zstd_write_done(ZSTDStream *s) { (void)s; return 0; }
int cli_zstd_flush(ZSTDStream *s) { (void)s; return 0; }
char *cli_zstd_decompress_file(const char *f, int c)
{ (void)f; (void)c; return strdup(RAW_DUMP); }
char *path_join(const char *a, const char *b)
{ (void)a; (void)b; return NULL; }
uint64_t get_current_ms(void) { return 0; }
uint64_t get_start_of_today(void) { return 0; }

static void write_record(FILE *f, uint64_t start, uint64_t end, uint64_t count)
{
    unsigned char hdr[2] = { 0xFA, 0xFB };
    unsigned char ftr[2] = { 0xFC, 0xFD };
    fwrite(hdr, 1, 2, f);
    fwrite(&start, sizeof(start), 1, f);
    fwrite(&end, sizeof(end), 1, f);
    fwrite(&count, sizeof(count), 1, f);
    for (uint64_t i = 0; i < count; i++) {
        uint32_t id = (uint32_t)(i + 1);
        uint64_t cnt = 100 + i;
        fwrite(&id, sizeof(id), 1, f);
        fwrite(&cnt, sizeof(cnt), 1, f);
    }
    fwrite(ftr, 1, 2, f);
}

int main(void)
{
    FILE *f = fopen(RAW_DUMP, "wb");
    assert(f);
    write_record(f, 100, 100, 0);    /* timewheel/flush guard */
    write_record(f, 1000, 2000, 2);  /* real interval */
    write_record(f, 2000, 3000, 3);  /* real interval */
    write_record(f, 3000, 4000, 5);  /* trailing partial: dropped */
    fclose(f);

    struct stackmap_dump_info info;
    int ret = cli_stackmap_fetch_dump_info("ignored", &info, 0);
    assert(ret == 0);
    /* guard skipped; OSS flushes string/id tables before stack.bin, so the
     * final complete interval is kept rather than dropped. */
    assert(info.record_count == 3);
    assert(info.start == 1000);
    assert(info.end == 4000);
    assert(info.records[0].starttime == 1000);
    assert(info.records[0].endtime == 2000);
    assert(info.records[0].count == 2);
    assert(info.records[1].starttime == 2000);
    assert(info.records[1].endtime == 3000);
    assert(info.records[1].count == 3);
    assert(info.records[2].starttime == 3000);
    assert(info.records[2].endtime == 4000);
    assert(info.records[2].count == 5);
    free(info.records);

    /* A store containing only guard records is valid but empty. */
    f = fopen(RAW_DUMP, "wb");
    assert(f);
    write_record(f, 500, 500, 0);
    write_record(f, 600, 600, 0);
    fclose(f);

    memset(&info, 0, sizeof(info));
    ret = cli_stackmap_fetch_dump_info("ignored", &info, 0);
    assert(ret == 0);
    assert(info.record_count == 0);
    free(info.records);

    printf("reader guards ok\\n");
    return 0;
}
"""


def _write_harness_headers(include_dir: Path) -> None:
    include_dir.mkdir()
    (include_dir / "cli_config.h").write_text("", encoding="utf-8")
    (include_dir / "cli_output.h").write_text(
        textwrap.dedent(
            """
            #ifndef TEST_CLI_OUTPUT_H
            #define TEST_CLI_OUTPUT_H
            #define CLI_ERROR(...) ((void)0)
            #define CLI_OUTPUT(...) ((void)0)
            #define CLI_OUTPUT_NO_END(...) ((void)0)
            #define CLI_VERBOSE(...) ((void)0)
            #define CLI_VERBOSE_NO_END(...) ((void)0)
            #endif
            """
        ),
        encoding="utf-8",
    )
    (include_dir / "cli_common.h").write_text(
        textwrap.dedent(
            """
            #ifndef TEST_CLI_COMMON_H
            #define TEST_CLI_COMMON_H
            #include <stdint.h>
            char *path_join(const char *path1, const char *path2);
            uint64_t get_current_ms(void);
            uint64_t get_start_of_today(void);
            #endif
            """
        ),
        encoding="utf-8",
    )
    (include_dir / "cli_zstd_helper.h").write_text(
        textwrap.dedent(
            """
            #ifndef TEST_CLI_ZSTD_HELPER_H
            #define TEST_CLI_ZSTD_HELPER_H
            #include <stddef.h>
            typedef struct {
                unsigned char data[4096];
                size_t size;
            } ZSTDStream;
            ZSTDStream *cli_zstd_init(const char *fileName);
            void cli_zstd_destroy(ZSTDStream *stream);
            int cli_zstd_write(ZSTDStream *stream, const char *fmt, ...);
            int cli_zstd_write_bytes(ZSTDStream *stream, const void *data, size_t length);
            int cli_zstd_write_done(ZSTDStream *stream);
            int cli_zstd_flush(ZSTDStream *stream);
            char *cli_zstd_decompress_file(const char *file_name, int use_cache);
            #endif
            """
        ),
        encoding="utf-8",
    )


def test_fetch_dump_info_skips_guards_and_drops_trailing(tmp_path: Path) -> None:
    include_dir = tmp_path / "include"
    _write_harness_headers(include_dir)

    raw_dump = tmp_path / "raw_stack.bin"
    harness = tmp_path / "stackmap_reader_guards_harness.c"
    source = (
        HARNESS_TEMPLATE
        .replace("RAW_DUMP_PATH", raw_dump.as_posix())
        .replace(
            "CLISTACK_PRIVATE",
            (REPO_ROOT / "src/cli_stackmap_helper/cli_stackmap_private.h").as_posix(),
        )
        .replace(
            "CLISTACK_PUBLIC",
            (REPO_ROOT / "src/cli_stackmap_helper/cli_stackmap.h").as_posix(),
        )
    )
    harness.write_text(source, encoding="utf-8")

    binary = tmp_path / "stackmap_reader_guards_harness"
    compile_cmd = [
        "cc",
        "-std=gnu11",
        "-Wall",
        "-Wextra",
        "-I",
        str(include_dir),
        "-I",
        str(REPO_ROOT / "src/cli_stackmap_helper"),
        "-I",
        str(REPO_ROOT / "src"),
        "-pthread",
        str(harness),
        str(REPO_ROOT / "src/cli_stackmap_helper/cli_stackmap.c"),
        str(REPO_ROOT / "src/cli_stackmap_helper/stackmap_count_table.c"),
        str(REPO_ROOT / "src/cli_stackmap_helper/stackmap_timewheel.c"),
        "-o",
        str(binary),
    ]
    subprocess.run(compile_cmd, check=True, cwd=REPO_ROOT)
    subprocess.run([str(binary)], check=True)
