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


def test_empty_stackmap_record_does_not_depend_on_malloc_zero(tmp_path: Path) -> None:
    include_dir = tmp_path / "include"
    _write_harness_headers(include_dir)

    cli_stackmap_c = (REPO_ROOT / "src/cli_stackmap_helper/cli_stackmap.c").as_posix()
    harness = tmp_path / "stackmap_empty_record_harness.c"
    harness.write_text(
        textwrap.dedent(
            f"""
            #include <assert.h>
            #include <pthread.h>
            #include <stdarg.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            static int fail_zero_malloc = 1;

            static void *test_malloc(size_t size)
            {{
                if (size == 0 && fail_zero_malloc)
                    return NULL;
                return calloc(1, size ? size : 1);
            }}

            #define malloc test_malloc
            #include "{cli_stackmap_c}"
            #undef malloc

            static ZSTDStream stream_storage;
            static uint64_t fake_now_ms = 1234;

            ZSTDStream *cli_zstd_init(const char *fileName)
            {{
                (void)fileName;
                memset(&stream_storage, 0, sizeof(stream_storage));
                return &stream_storage;
            }}

            void cli_zstd_destroy(ZSTDStream *stream)
            {{
                (void)stream;
            }}

            int cli_zstd_write(ZSTDStream *stream, const char *fmt, ...)
            {{
                (void)stream;
                (void)fmt;
                return 0;
            }}

            int cli_zstd_write_bytes(ZSTDStream *stream, const void *data, size_t length)
            {{
                assert(stream->size + length <= sizeof(stream->data));
                memcpy(stream->data + stream->size, data, length);
                stream->size += length;
                return 0;
            }}

            int cli_zstd_write_done(ZSTDStream *stream)
            {{
                (void)stream;
                return 0;
            }}

            int cli_zstd_flush(ZSTDStream *stream)
            {{
                (void)stream;
                return 0;
            }}

            char *cli_zstd_decompress_file(const char *file_name, int use_cache)
            {{
                (void)file_name;
                (void)use_cache;
                return NULL;
            }}

            char *path_join(const char *path1, const char *path2)
            {{
                (void)path1;
                (void)path2;
                return NULL;
            }}

            uint64_t get_current_ms(void)
            {{
                return fake_now_ms;
            }}

            uint64_t get_start_of_today(void)
            {{
                return 0;
            }}

            static uint64_t load_u64(size_t off)
            {{
                uint64_t value = 0;
                memcpy(&value, stream_storage.data + off, sizeof(value));
                return value;
            }}

            int main(void)
            {{
                struct cli_stackmap map = {{0}};
                pthread_mutex_init(&map.id_count_lock, NULL);

                fail_zero_malloc = 1;
                _cli_stackmap_dump_stackmap(&map, "ignored", 10, 20);
                assert(stream_storage.size == 28);
                assert(load_u64(18) == 0);
                assert(stream_storage.data[26] == 0xFC);
                assert(stream_storage.data[27] == 0xFD);

                memset(&map, 0, sizeof(map));
                pthread_mutex_init(&map.id_count_lock, NULL);
                fail_zero_malloc = 0;
                fake_now_ms = 4321;
                cli_stackmap_dump_stackmap(&map, "ignored");
                assert(stream_storage.size == 28);
                assert(load_u64(2) == 4321);
                assert(load_u64(10) == 4321);

                return 0;
            }}
            """
        ),
        encoding="utf-8",
    )

    binary = tmp_path / "stackmap_empty_record_harness"
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
        str(REPO_ROOT / "src/cli_stackmap_helper/stackmap_count_table.c"),
        str(REPO_ROOT / "src/cli_stackmap_helper/stackmap_timewheel.c"),
        "-o",
        str(binary),
    ]
    subprocess.run(compile_cmd, check=True, cwd=REPO_ROOT)
    subprocess.run([str(binary)], check=True)
