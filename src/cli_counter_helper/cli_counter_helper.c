// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli_counter_helper.h"
#include "cli_output.h"

#include <stdlib.h>
#include <string.h>

struct cli_counter {
	char *name;
	enum cli_counter_type type;
	uint64_t *bins; /* counts for [2^i, 2^(i+1)] */
	size_t bins_len; /* number of allocated bins */
	uint64_t min_val;
	uint64_t max_val;
	__uint128_t sum_val; /* for AVG */
	uint64_t sample_cnt;
};

struct unit_group {
	const char **units;
	size_t unit_count;
	double step; /* progression factor between units */
};

static const char *time_units[] = { "ns", "us", "ms", "s" };
static const char *size_units[] = { "B", "KB", "MB", "GB", "TB", "PB" };

static const struct unit_group UNIT_GROUPS[] = {
	[CLI_COUNTER_TYPE_TIME_NS] = { time_units, 4, 1000.0 },
	[CLI_COUNTER_TYPE_SIZE] = { size_units, 6, 1024.0 },
};

static size_t value_to_bin_index(uint64_t v)
{
	/* treat 0 as 1 for first bin */
	if (v == 0)
		v = 1;
	/* floor(log2(v)) */
	int idx = 63 - __builtin_clzll(v);
	if (idx < 0)
		idx = 0;
	return (size_t)idx;
}

static int ensure_bins(struct cli_counter *c, size_t required)
{
	if (!c)
		return -1;
	size_t need = required + 1; /* bins indexed [0..required] inclusive */
	if (need <= c->bins_len)
		return 0;
	size_t new_len = c->bins_len ? c->bins_len : 0;
	while (new_len < need) {
		new_len = new_len ? new_len * 2 : 8;
	}
	uint64_t *new_bins = (uint64_t *)realloc(c->bins, new_len * sizeof(uint64_t));
	if (!new_bins)
		return -1;
	/* zero the new section */
	if (new_len > c->bins_len)
		memset(new_bins + c->bins_len, 0, (new_len - c->bins_len) * sizeof(uint64_t));
	c->bins = new_bins;
	c->bins_len = new_len;
	return 0;
}

static int unit_index_for_value(const struct unit_group *grp, uint64_t val)
{
	int idx = 0;
	double d = (double)val;
	while (idx < (int)grp->unit_count - 1 && d >= grp->step) {
		d /= grp->step;
		idx++;
	}
	return idx;
}

static double convert_to_unit(const struct unit_group *grp, uint64_t val, int unit_idx)
{
	double d = (double)val;
	for (int i = 0; i < unit_idx; i++)
		d /= grp->step;
	return d;
}

static void format_interval(char *buf, size_t buflen, struct cli_counter *c, uint64_t start, uint64_t end, uint64_t cnt)
{
	const struct unit_group *grp = &UNIT_GROUPS[c->type];
	int uidx = unit_index_for_value(grp, start);
	double s_val = convert_to_unit(grp, start, uidx);
	double e_val = convert_to_unit(grp, end, uidx);
	const char *u = grp->units[uidx];
	snprintf(buf, buflen, "[%.1f-%.1f](%s): %llu", s_val, e_val, u, (unsigned long long)cnt);
}

struct cli_counter *cli_counter_init(const char *map_name, enum cli_counter_type type)
{
	struct cli_counter *c = (struct cli_counter *)calloc(1, sizeof(struct cli_counter));
	if (!c)
		return NULL;
	c->type = type;
	c->name = map_name ? strdup(map_name) : NULL;
	c->bins = NULL;
	c->bins_len = 0;
	c->min_val = UINT64_MAX;
	c->max_val = 0;
	c->sum_val = 0;
	c->sample_cnt = 0;
	return c;
}

void cli_counter_destroy(struct cli_counter *counter)
{
	if (!counter)
		return;
	free(counter->name);
	free(counter->bins);
	free(counter);
}

int cli_counter_add(struct cli_counter *counter, uint64_t value)
{
	if (!counter)
		return -1;

	uint64_t v = value ? value : 1;
	size_t idx = value_to_bin_index(v);
	if (ensure_bins(counter, idx))
		return -1;
	counter->bins[idx]++;

	if (v < counter->min_val)
		counter->min_val = v;
	if (v > counter->max_val)
		counter->max_val = v;
	counter->sum_val += (__uint128_t)v;
	counter->sample_cnt++;
	return 0;
}

void cli_counter_print(struct cli_counter *counter)
{
	if (!counter)
		return;

	/* Build single-line output for bins with nonzero counts */
	size_t nonzero = 0;
	for (size_t i = 0; i < counter->bins_len; i++)
		if (counter->bins && counter->bins[i])
			nonzero++;

	if (nonzero == 0) {
		CLI_OUTPUT("%s: no data", counter->name ? counter->name : "counter");
	} else {
		size_t est = nonzero * 48 + 64;
		char *line = (char *)malloc(est);
		if (!line) {
			CLI_OUTPUT("%s: memory error on print", counter->name ? counter->name : "counter");
		} else {
			size_t off = 0;
			for (size_t i = 0; i < counter->bins_len; i++) {
				if (!counter->bins || !counter->bins[i])
					continue;
				uint64_t start = (i == 0) ? 1ULL : (1ULL << i);
				uint64_t end = (i >= 63) ? UINT64_MAX : (1ULL << (i + 1));
				char seg[128];
				format_interval(seg, sizeof(seg), counter, start, end, counter->bins[i]);
				size_t need = strlen(seg) + 2; /* space */
				if (off + need >= est) {
					est = est * 2 + need;
					char *nl = (char *)realloc(line, est);
					if (!nl) {
						free(line);
						line = NULL;
						break;
					}
					line = nl;
				}
				if (off) {
					line[off++] = ' ';
				}
				size_t seglen = strlen(seg);
				memcpy(line + off, seg, seglen);
				off += seglen;
			}
			if (line) {
				line[off] = '\0';
				CLI_OUTPUT("%s: %s", counter->name ? counter->name : "counter", line);
				free(line);
			}
		}
	}

	/* Second line: MIN, MAX, AVG */
	if (counter->sample_cnt == 0) {
		CLI_OUTPUT("MIN: 0 MAX: 0 AVG: 0");
		return;
	}

	double avg = (double)((long double)counter->sum_val) / (double)counter->sample_cnt;
	const struct unit_group *grp = &UNIT_GROUPS[counter->type];
	int uidx = unit_index_for_value(grp, counter->max_val);
	double min_v = convert_to_unit(grp, counter->min_val, uidx);
	double max_v = convert_to_unit(grp, counter->max_val, uidx);
	double avg_v = avg;
	for (int i = 0; i < uidx; i++)
		avg_v /= grp->step;
	const char *unit = grp->units[uidx];
	CLI_OUTPUT("MIN: %.3f %s MAX: %.3f %s AVG: %.3f %s", min_v, unit, max_v, unit, avg_v, unit);
}

void cli_counter_clear(struct cli_counter *counter)
{
	if (!counter)
		return;
	if (counter->bins && counter->bins_len)
		memset(counter->bins, 0, counter->bins_len * sizeof(uint64_t));
	counter->min_val = UINT64_MAX;
	counter->max_val = 0;
	counter->sum_val = 0;
	counter->sample_cnt = 0;
}
