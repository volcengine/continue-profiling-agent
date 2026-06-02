// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CLI_ZSTD_HELPER_H__
#define __CLI_ZSTD_HELPER_H__

#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <zstd.h>

/**
 * @file cli_zstd_helper.h
 * @brief Small wrapper around zstd streaming I/O for CPA artifacts.
 */

/**
 * typedef struct ZSTDStream - buffered zstd stream state.
 * @inputBuffer: staging buffer for formatted writes.
 * @inputSize: bytes currently stored in @inputBuffer.
 * @inputCapacity: allocated size of @inputBuffer.
 * @outFile: destination file handle.
 * @outputBuffer: zstd output scratch buffer.
 */
typedef struct {
	ZSTD_CStream *cstream;
	char *inputBuffer;
	size_t inputSize;
	size_t inputCapacity;
	FILE *outFile;
	char *outputBuffer;
} ZSTDStream;

/**
 * CHUNK_SIZE - maximum chunk size used by internal zstd buffers.
 */
#define CHUNK_SIZE 16384

/**
 * cli_zstd_init - open a compressed output stream.
 * @fileName: target output path.
 *
 * Return: new stream object or %NULL on failure.
 */
ZSTDStream *cli_zstd_init(const char *fileName);

/**
 * cli_zstd_destroy - flush and close a compressed stream.
 * @stream: stream to destroy.
 */
void cli_zstd_destroy(ZSTDStream *stream);

/**
 * cli_zstd_write - append formatted text into stream buffer.
 * @stream: target stream.
 * @fmt: printf-style format.
 *
 * Return: 0 on success, negative on failure.
 */
int cli_zstd_write(ZSTDStream *stream, const char *fmt, ...);

/**
 * cli_zstd_write_bytes - append raw bytes to compressed stream.
 * @stream: target stream.
 * @data: input bytes.
 * @length: number of bytes.
 *
 * Return: 0 on success, -1 on failure.
 */
int cli_zstd_write_bytes(ZSTDStream *stream, const void *data, size_t length);

/**
 * cli_zstd_write_done - flush internal formatted/raw buffer.
 * @stream: target stream.
 *
 * Return: 0 on success, non-zero on compression error.
 */
int cli_zstd_write_done(ZSTDStream *stream);

/**
 * cli_zstd_flush - finish stream frame and flush destination file.
 * @stream: target stream.
 *
 * Return: 0 always currently.
 */
int cli_zstd_flush(ZSTDStream *stream);

/**
 * cli_zstd_decompress_file - decompress one zstd file to a side-file.
 * @file_name: source compressed file.
 * @use_cache: reuse cached decompressed file when available.
 *
 * Return: path to cached decompressed file, caller owns the returned memory.
 */
char *cli_zstd_decompress_file(const char *file_name, int use_cache);

#endif /* __CLI_ZSTD_HELPER_H__ */
