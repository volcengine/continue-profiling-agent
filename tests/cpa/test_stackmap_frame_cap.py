from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


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


def test_interned_frame_length_is_capped(tmp_path: Path) -> None:
    include_dir = tmp_path / "include"
    _write_harness_headers(include_dir)

    cli_stackmap_c = (REPO_ROOT / "src/cli_stackmap_helper/cli_stackmap.c").as_posix()
    harness = tmp_path / "stackmap_frame_cap_harness.c"
    harness.write_text(
        textwrap.dedent(
            f"""
            #include <assert.h>
            #include <pthread.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            #include "{(REPO_ROOT / 'src/cli_stackmap_helper/cli_stackmap_private.h').as_posix()}"
            #include "{(REPO_ROOT / 'src/cli_stackmap_helper/cli_stackmap.h').as_posix()}"

            /* Same cap as cli_stackmap.c (not exposed in headers). */
            #define CLI_STACKMAP_FRAME_MAX_LEN 8192

            static ZSTDStream stream_storage;
            static uint64_t fake_now_ms = 1000;

            ZSTDStream *cli_zstd_init(const char *fileName)
            {{
                (void)fileName;
                memset(&stream_storage, 0, sizeof(stream_storage));
                return &stream_storage;
            }}
            void cli_zstd_destroy(ZSTDStream *stream) {{ (void)stream; }}
            int cli_zstd_write(ZSTDStream *s, const char *f, ...) {{ (void)s; (void)f; return 0; }}
            int cli_zstd_write_bytes(ZSTDStream *s, const void *d, size_t l)
            {{ (void)s; (void)d; (void)l; return 0; }}
            int cli_zstd_write_done(ZSTDStream *s) {{ (void)s; return 0; }}
            int cli_zstd_flush(ZSTDStream *s) {{ (void)s; return 0; }}
            char *cli_zstd_decompress_file(const char *f, int c)
            {{ (void)f; (void)c; return NULL; }}
            char *path_join(const char *a, const char *b)
            {{ (void)a; (void)b; return NULL; }}
            uint64_t get_current_ms(void) {{ return fake_now_ms; }}
            uint64_t get_start_of_today(void) {{ return 0; }}

            int main(void)
            {{
                struct cli_stackmap *map = cli_stackmap_init();
                assert(map);

                /* 20 KiB frame: larger than the 16 KiB zstd staging buffer. */
                size_t big_len = 20 * 1024;
                char *big = malloc(big_len + 1);
                assert(big);
                memset(big, 'A', big_len);
                big[big_len] = '\\0';

                assert(cli_stackmap_append(map, big) == 0);
                assert(map->str_id == 2);
                struct str_hash *first = map->str_hash_by_id[1];
                assert(first);
                assert(strlen(first->str) == CLI_STACKMAP_FRAME_MAX_LEN);

                /* A second over-long frame sharing the 8 KiB prefix dedups. */
                char *big2 = malloc(big_len + 1);
                assert(big2);
                memset(big2, 'A', big_len);
                memset(big2 + CLI_STACKMAP_FRAME_MAX_LEN, 'B',
                       big_len - CLI_STACKMAP_FRAME_MAX_LEN);
                big2[big_len] = '\\0';
                assert(cli_stackmap_append(map, big2) == 0);
                assert(map->str_id == 2);

                /* A genuinely different suffix after the cap dedups too. */
                char *short_frame = strdup("normal_short_frame");
                assert(short_frame);
                assert(cli_stackmap_append(map, short_frame) == 0);
                assert(map->str_id == 3);
                assert(strcmp(map->str_hash_by_id[2]->str, "normal_short_frame") == 0);

                free(big);
                free(big2);
                free(short_frame);
                printf("frame cap ok\\n");
                return 0;
            }}
            """
        ),
        encoding="utf-8",
    )

    binary = tmp_path / "stackmap_frame_cap_harness"
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
