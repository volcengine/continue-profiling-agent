// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <cli_zstd_helper.h>
#include <cli.h>

ZSTDStream *cli_zstd_init(const char *fileName)
{
	ZSTDStream *stream = malloc(sizeof(ZSTDStream));
	if (!stream)
		return NULL;

	stream->inputBuffer = malloc(CHUNK_SIZE);
	if (!stream->inputBuffer) {
		free(stream);
		return NULL;
	}
	stream->inputSize = 0;
	stream->inputCapacity = CHUNK_SIZE;

	stream->outputBuffer = malloc(CHUNK_SIZE);
	if (!stream->outputBuffer) {
		free(stream->inputBuffer);
		free(stream);
		return NULL;
	}

	stream->cstream = ZSTD_createCStream();
	if (ZSTD_initCStream(stream->cstream, 1) != 0) {
		free(stream->inputBuffer);
		free(stream->outputBuffer);
		free(stream);
		return NULL;
	}

	stream->outFile = fopen(fileName, "wb");
	if (stream->outFile == NULL) {
		ZSTD_freeCStream(stream->cstream);
		free(stream->inputBuffer);
		free(stream->outputBuffer);
		free(stream);
		return NULL;
	}

	return stream;
}

void cli_zstd_destroy(ZSTDStream *stream)
{
	if (!stream)
		return;

	ZSTD_outBuffer output = { stream->outputBuffer, CHUNK_SIZE, 0 };
	ZSTD_endStream(stream->cstream, &output);
	fwrite(stream->outputBuffer, 1, output.pos, stream->outFile);

	clear_file_cache(stream->outFile);
	fclose(stream->outFile);
	ZSTD_freeCStream(stream->cstream);
	free(stream->outputBuffer);
	free(stream->inputBuffer);
	free(stream);
}

int cli_zstd_write(ZSTDStream *stream, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	int needed = vsnprintf(NULL, 0, fmt, args);
	va_end(args);

	if (needed < 0)
		return -1;

	if ((size_t)needed >= stream->inputCapacity - stream->inputSize)
		if (cli_zstd_write_done(stream) != 0)
			return -1;

	va_start(args, fmt);
	int result = vsnprintf(stream->inputBuffer + stream->inputSize, stream->inputCapacity - stream->inputSize, fmt, args);
	va_end(args);

	if (result < 0)
		return -1;

	stream->inputSize += result;
	return 0;
}

int cli_zstd_write_bytes(ZSTDStream *stream, const void *data, size_t length)
{
	if (stream->inputSize + length > stream->inputCapacity)
		if (cli_zstd_write_done(stream) != 0)
			return -1;

	memcpy(stream->inputBuffer + stream->inputSize, data, length);
	stream->inputSize += length;

	return 0;
}

int cli_zstd_write_done(ZSTDStream *stream)
{
	ZSTD_inBuffer input = { stream->inputBuffer, stream->inputSize, 0 };

	while (input.pos < input.size) {
		ZSTD_outBuffer output = { stream->outputBuffer, CHUNK_SIZE, 0 };
		size_t remaining = ZSTD_compressStream(stream->cstream, &output, &input);
		if (ZSTD_isError(remaining))
			return 1;
		if (fwrite(stream->outputBuffer, 1, output.pos, stream->outFile) !=
		    output.pos)
			return -1;
	}
	stream->inputSize = 0;
	return 0;
}

int cli_zstd_flush(ZSTDStream *stream)
{
	size_t remaining;

	do {
		ZSTD_outBuffer output = { stream->outputBuffer, CHUNK_SIZE, 0 };

		remaining = ZSTD_endStream(stream->cstream, &output);
		if (ZSTD_isError(remaining))
			return -1;
		if (fwrite(output.dst, 1, output.pos, stream->outFile) !=
		    output.pos)
			return -1;
	} while (remaining != 0);
	if (fflush(stream->outFile) != 0)
		return -1;
	return 0;
}

ZSTDStream *cli_stackmap_change_zstd_file(ZSTDStream *oldStream, const char *newFileName)
{
	if (!oldStream)
		return NULL;

	cli_zstd_destroy(oldStream);

	ZSTDStream *newStream = cli_zstd_init(newFileName);
	if (!newStream) {
		CLI_ERROR("Failed to initialize new ZSTD stream for file: %s", newFileName);
		return NULL;
	}

	return newStream;
}

char *cli_zstd_decompress_file(const char *file_name, int use_cache)
{
	const char *slash = NULL;
	const char *basename = NULL;
	char *parent_path = NULL;
	char *out_folder_path = NULL;
	char *out_file_path = NULL;
	int success = 0;
	FILE *fin = NULL, *fout = NULL;
	void *buffIn = NULL, *buffOut = NULL;
	ZSTD_DStream *dstream = NULL;

	if (!file_name || !file_name[0]) {
		CLI_ERROR("Invalid input file path");
		goto free;
	}

	slash = strrchr(file_name, '/');
	if (!slash || !slash[1]) {
		CLI_ERROR("Input file path must include a basename");
		goto free;
	}
	basename = slash + 1;

	size_t parent_len = slash - file_name;
	if (parent_len == 0) {
		parent_path = strdup("/");
	} else {
		parent_path = malloc(parent_len + 1);
		if (parent_path) {
			memcpy(parent_path, file_name, parent_len);
			parent_path[parent_len] = '\0';
		}
	}
	if (!parent_path) {
		CLI_ERROR("Failed to allocate parent path");
		goto free;
	}

	out_folder_path = path_join(parent_path, "decompressed");
	if (!out_folder_path)
		goto free;

	out_file_path = path_join(out_folder_path, basename);
	if (!out_file_path)
		goto free;

	create_directory_if_notexist(out_folder_path);

	if (access(out_file_path, F_OK) == 0 && use_cache) {
		success = 1;
		goto free;
	}

	fin = fopen(file_name, "rb");
	if (fin == NULL) {
		CLI_ERROR("Failed to open input file");
		goto free;
	}

	fout = fopen(out_file_path, "wb");
	if (fout == NULL) {
		CLI_ERROR("Failed to open output file");
		goto free;
	}

	size_t const buffInSize = ZSTD_DStreamInSize();
	size_t const buffOutSize = ZSTD_DStreamOutSize();
	buffIn = malloc(buffInSize);
	buffOut = malloc(buffOutSize);

	dstream = ZSTD_createDStream();
	if (dstream == NULL) {
		CLI_ERROR("Failed to create decompression stream.\n");
		goto free;
	}

	size_t result = ZSTD_initDStream(dstream);
	if (ZSTD_isError(result)) {
		CLI_ERROR("Failed to initialize decompression stream: %s\n", ZSTD_getErrorName(result));
		goto free;
	}

	size_t read, toRead = buffInSize;
	ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
	ZSTD_inBuffer input = { buffIn, 0, 0 };

	while ((read = fread(buffIn, 1, toRead, fin))) {
		input.size = read;
		input.pos = 0;
		do {
			output.pos = 0;
			result = ZSTD_decompressStream(dstream, &output, &input);
			if (ZSTD_isError(result)) {
				CLI_ERROR("Decompression error: %s", ZSTD_getErrorName(result));
				break;
			}
			fwrite(buffOut, 1, output.pos, fout);
		} while (input.pos < input.size);
	}

	success = 1;

free:
	if (fin)
		fclose(fin);
	if (fout)
		fclose(fout);
	if (buffIn)
		free(buffIn);
	if (buffOut)
		free(buffOut);
	if (dstream)
		ZSTD_freeDStream(dstream);
	free(parent_path);
	free(out_folder_path);
	if (success)
		return out_file_path;
	free(out_file_path);
	return NULL;
}
