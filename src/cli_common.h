// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CLI_COMMON_H
#define CLI_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <linux/sched.h>

#include <cpa_bpf/bpf_event.h>

/**
 * @file cli_common.h
 * @brief Shared helper interfaces for CLI and runtime process utilities.
 */

/**
 * @def CPA_ENV_LEN
 * Max environment payload length to keep in metadata.
 */
#define CPA_ENV_LEN (512)
/**
 * @def CPA_BASE_INFO_LEN
 * Max combined metadata base info buffer size.
 */
#define CPA_BASE_INFO_LEN (TASK_COMM_LEN * 2 + 16 + 16 + 2 + CPA_ENV_LEN)

/**
 * INIT_MODULE_BPF - helper for BPF module initialization call sites.
 * @name: suffix appended to @BPF_MODULE_ macro constant.
 */
#define INIT_MODULE_BPF(name) init_module_bpf(ctx, BPF_MODULE_##name)

/**
 * DISABLE_MODULE_BPF - disable one BPF module from runtime mask.
 * @name: suffix appended to @BPF_MODULE_ macro constant.
 */
#define DISABLE_MODULE_BPF(name) bpf_module_ctl(get_bpf_mask() & ~(1 << BPF_MODULE_##name))

/**
 * init_module_bpf - initialize one module in global BPF loader context.
 * @ctx: CLI context.
 * @module: runtime module bit index constant.
 * @return: 0 on success, non-zero on failure.
 */
int init_module_bpf(void *ctx, int module);

/**
 * should_stop - check global stop flag consumed by worker loops.
 * @return: non-zero when stop is requested.
 */
int should_stop(void);

/**
 * set_stop - set global stop flag.
 */
void set_stop(void);

/**
 * read_file_content - read whole file content into a heap buffer.
 * @path: input path.
 * @return: zero-terminated heap buffer or %NULL.
 */
char *read_file_content(const char *path);

/**
 * struct mount_info - mount table entry snapshot.
 * @path: mount point.
 * @type: filesystem type string.
 */
struct mount_info {
	char *path;
	char *type;
};

/**
 * free_mount_info - release array returned by @read_mount_info.
 */
void free_mount_info(struct mount_info *mounts, size_t count);

/**
 * read_mount_info - parse mount table for mounted paths.
 * @count: output mount entry count.
 * @return: heap-allocated mount list or %NULL.
 */
struct mount_info *read_mount_info(size_t *count);

/**
 * traverse_proc_smaps - iterate /proc/<pid>/smaps with a callback.
 * @smaps_read: callback receiving smaps text for each task.
 * @ctx: callback context.
 */
void traverse_proc_smaps(void (*smaps_read)(pid_t pid, char *smaps, void *ctx), void *ctx);

/**
 * pid stat request flags.
 */
#define PID_STAT_F_STATE (1U << 0)
/**
 * Include start time in @get_pid_stat result.
 */
#define PID_STAT_F_START_TIME (1U << 1)
/**
 * Include cpu id in @get_pid_stat result.
 */
#define PID_STAT_F_CPU_ID (1U << 2)

/**
 * struct pid_stat - parsed /proc/<pid>/stat metadata.
 * @comm: task comm.
 * @start_time: process start timestamp.
 * @state: task state character.
 * @cpu_id: last executing cpu.
 * @valid_mask: fields provided by caller flags.
 */
struct pid_stat {
	char comm[TASK_COMM_LEN];
	unsigned long long start_time;
	char state;
	unsigned int cpu_id;
	unsigned int valid_mask;
};

/**
 * get_pid_stat - fill @stat from /proc/<pid>/stat.
 * @pid: target pid.
 * @stat: destination entry.
 * @flags: bitmask of @PID_STAT_F_*.
 * @return: 0 on success, negative on failure.
 */
int get_pid_stat(pid_t pid, struct pid_stat *stat, unsigned int flags);

/**
 * struct smaps_desc - parsed /proc/<pid>/smaps entry.
 * @path: mapped region path.
 * @rss/pss: resident/shared and proportional set sizes.
 */
struct smaps_desc {
	uint64_t start;
	uint64_t end;
	char *path;
	uint64_t size;
	uint64_t kernelpagesize;
	uint64_t mmupagesize;
	uint64_t rss;
	uint64_t pss;
	uint64_t shared_clean;
	uint64_t shared_dirty;
	uint64_t private_clean;
	uint64_t private_dirty;
	uint64_t referenced;
	uint64_t anonymous;
	uint64_t lazyfree;
	uint64_t anonhugepages;
	uint64_t shmem_pmdmapped;
	uint64_t file_pmdmapped;
	uint64_t shared_hugetlb;
	uint64_t private_hugetlb;
	uint64_t swap;
	uint64_t swap_pss;
	uint64_t locked;
	uint64_t thpeligible;
	uint64_t protectionkey;
	struct {
		unsigned int rd : 1;
		unsigned int wr : 1;
		unsigned int ex : 1;
		unsigned int sh : 1;
		unsigned int mr : 1;
		unsigned int mw : 1;
		unsigned int me : 1;
		unsigned int ms : 1;
		unsigned int gd : 1;
		unsigned int pf : 1;
		unsigned int dw : 1;
		unsigned int lo : 1;
		unsigned int io : 1;
		unsigned int sr : 1;
		unsigned int rr : 1;
		unsigned int dc : 1;
		unsigned int de : 1;
		unsigned int ac : 1;
		unsigned int nr : 1;
		unsigned int ht : 1;
		unsigned int ar : 1;
		unsigned int dd : 1;
		unsigned int sd : 1;
		unsigned int mm : 1;
		unsigned int hg : 1;
		unsigned int nh : 1;
		unsigned int mg : 1;
	} vmflags;
};

/**
 * get_smaps_desc - parse one smaps text segment.
 * @smaps: source text.
 * @count: output entry count.
 * @return: heap array of descriptors or %NULL on failure.
 */
struct smaps_desc *get_smaps_desc(char *smaps, size_t *count);

/**
 * free_smaps_desc - release array from @get_smaps_desc.
 */
void free_smaps_desc(struct smaps_desc *desc_array, size_t count);

/**
 * get_start_of_today - compute current day start offset.
 * @return: ms offset from process uptime.
 */
uint64_t get_start_of_today(void);
/**
 * convert_time_to_seconds - parse time string into absolute seconds.
 * @time_str: input timestamp string.
 * @return: parsed Unix timestamp in seconds, or UINT64_MAX on parse failure.
 */
uint64_t convert_time_to_seconds(const char *time_str);
/**
 * convert_millisecond_to_time - format millisecond timestamp.
 * @millisecond: unix time in milliseconds.
 * @return: static textual representation.
 */
const char *convert_millisecond_to_time(uint64_t millisecond);

/**
 * path_join - join two path components with slash handling.
 * @path1: first path segment.
 * @path2: second path segment.
 * @return: newly allocated path string.
 */
char *path_join(const char *path1, const char *path2);

/**
 * get_cgroup_id - resolve cgroup id from path.
 * @cgroup_path: path to cgroup directory.
 * @return: resolved cgroup id.
 */
unsigned long get_cgroup_id(const char *cgroup_path);

/**
 * get_directory_size - compute total size of directory subtree.
 * @dir_path: directory path.
 * @return: directory size in bytes.
 */
long get_directory_size(const char *dir_path);

/**
 * create_directory_if_notexist - recursively create missing directories.
 * @path: target directory.
 * @return: 0 on success, non-zero on failure.
 */
int create_directory_if_notexist(const char *path);

/**
 * remove_directory - remove directory recursively.
 * @path: target directory.
 * @return: 0 on success, non-zero on failure.
 */
int remove_directory(const char *path);

/**
 * struct cpu_set - parsed cpu list representation.
 * @max_cpu: highest cpu index covered.
 * @bitmap: bitmap storage.
 */
struct cpu_set {
	int max_cpu;
	unsigned long *bitmap;
};

/**
 * parse_cpu_set - parse cpuset-like list such as "1,2-4".
 * @cpu_str: input list string.
 * @return: parsed cpu set.
 */
struct cpu_set parse_cpu_set(const char *cpu_str);

/**
 * is_cpu_in_set - check whether @cpu_num belongs to @set.
 * @set: cpu set parsed by @parse_cpu_set.
 * @cpu_num: cpu number to test.
 * @return: true if cpu is in @set.
 */
bool is_cpu_in_set(const struct cpu_set *set, int cpu_num);

/**
 * free_cpu_set - release resources from @parse_cpu_set.
 * @set: allocated cpu set.
 */
void free_cpu_set(struct cpu_set *set);

/**
 * struct rss_status - RSS counters snapshot.
 * @rss_anon: anonymous RSS bytes.
 * @rss_file: file RSS bytes.
 * @rss_sum: total RSS bytes.
 */
struct rss_status {
	long rss_anon;
	long rss_file;
	long rss_sum;
};

/**
 * get_self_rss_status - populate process RSS snapshot.
 * @status: output buffer.
 */
void get_self_rss_status(struct rss_status *status);

/**
 * is_cmd_available - check command availability in PATH.
 * @cmd: command name.
 * @return: 0 when command exists, non-zero otherwise.
 */
int is_cmd_available(const char *cmd);

/**
 * set_fd_limit - configure soft/hard fd limits.
 * @new_limit: new file-descriptor limit.
 */
void set_fd_limit(int new_limit);

/**
 * struct file_info - file metadata subset.
 */
struct file_info {
	ino_t inode;
	dev_t dev;
	time_t mtime;
};

/**
 * get_file_stat_info - read inode/device/mtime from path.
 * @filename: source path.
 * @info: destination struct.
 * @return: 0 on success, non-zero on failure.
 */
int get_file_stat_info(const char *filename, struct file_info *info);

extern uint32_t __seed;
static inline uint32_t fast_rand(void)
{
	__seed = __seed * 1103515245 + 12345;
	return (__seed >> 16) & 0x7FFF;
}

/**
 * find_symbol_address - lookup a kernel symbol by name.
 * @symbol_name: symbol text.
 * @return: symbol address or 0.
 */
unsigned long long find_symbol_address(const char *symbol_name);

/**
 * cgroup_callback_t - callback for cgroup traversal helpers.
 */
typedef void (*cgroup_callback_t)(const char *relative_path);

/**
 * traverse_cgroup_dirs - traverse configured cgroup hierarchy.
 * @callback: function invoked for each relative cgroup path.
 */
void traverse_cgroup_dirs(cgroup_callback_t callback);

/**
 * get_env_var_by_pid - read environment values from /proc/<pid>/environ.
 * @pid: target process id.
 * @var_names: array of environment variable names.
 * @var_name_count: number of entries in @var_names.
 * @return: concatenated values or %NULL.
 */
char *get_env_var_by_pid(pid_t pid, char **var_names, int var_name_count);

/**
 * get_current_ms - return current ms from monotonic clock.
 * @return: milliseconds since monotonic start.
 */
uint64_t get_current_ms(void);

/**
 * get_current_uptime_ns - return monotonic uptime in nanoseconds.
 * @return: uptime in nanoseconds.
 */
uint64_t get_current_uptime_ns(void);

/**
 * rm_template_param - strip template payload from demangled symbols in-place.
 * @demangled: symbol string to normalize.
 */
void rm_template_param(char *demangled);

/**
 * copy_file - copy source file to target path.
 * @return: 0 on success, non-zero on failure.
 */
int copy_file(const char *file_path, const char *target_file_path);

/**
 * page permission constants for maps filters.
 */
enum {
	PERMISSION_R = 1 << 0,
	PERMISSION_W = 1 << 1,
	PERMISSION_X = 1 << 2,
};

/**
 * struct maps_info - /proc/<pid>/maps region summary.
 */
struct maps_info {
	char *path;
	uint64_t start;
	uint64_t end;
	char permission;
};

/**
 * get_maps_info - parse /proc/<pid>/maps.
 * @pid: target pid.
 * @count: output number of records.
 * @permission_flag: required permission bits.
 * @debug_maps: optional debug flag string.
 * @return: allocated array of entries.
 */
struct maps_info *get_maps_info(int pid, int *count, char permission_flag, char *debug_maps);

/**
 * free_maps_info - release array from @get_maps_info.
 * @maps: map array from @get_maps_info.
 * @count: number of elements.
 */
void free_maps_info(struct maps_info *maps, int count);

/**
 * record_time - snapshot current wall time into internal global.
 */
void record_time(void);
/**
 * record_time_clear - reset internal time snapshot.
 */
void record_time_clear(void);

/**
 * hex_string_to_binary - decode a hex string to bytes.
 * @hex_string: source string without separators.
 * @binary_length: output byte length.
 * @return: newly allocated binary buffer.
 */
unsigned char *hex_string_to_binary(const char *hex_string, size_t *binary_length);

/**
 * clear_file_cache - clear stdio userland file cache for stream.
 */
void clear_file_cache(FILE *fp);

#endif /* CLI_COMMON_H */
