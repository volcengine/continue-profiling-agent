// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * Userspace side of dynamic process selection.
 *
 * Every capture object shares target_ctl's target_pids map (the session
 * refuses to start otherwise), keyed by process instance.  The map is the
 * only state; each entry has a single updater (see target_filter.h):
 *   - BPF creates entries and moves an instance between TRACKED and
 *     UNSELECTED at its own exec; it never deletes;
 *   - this controller inserts the initial seeds, deletes instances that are
 *     gone and owns the session key; it never updates an entry.
 * Startup windows are deadlines stored in the entries and enforced by the
 * sampling gates.
 *
 * Nothing here runs periodically.  Logs follow the BPF events; a dead
 * instance is removed when the unwinder reaps its exit;
 * what that misses (a group whose leader exited first, lost events, scan
 * fences) is inert and swept only when the map fills up.  A --first_match
 * session watches its winner with a pidfd.
 */

#define _GNU_SOURCE
#include "cpa_target_ctl.h"

#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include <fcntl.h>
#include <limits.h>
#include <sys/vfs.h>

#include <cpa_bpf.h>
#include "bpf_event_poll.h"
#include "cli_common.h"
#include "cpa_unwinder.h"
#include "cpa_exit_env.h"
#include "target_ctl.h"
#include "uthash.h"

static bool exit_env_by_name(void);

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434	/* the same number on every architecture */
#endif

/*
 * In-flight BPF programs finish within milliseconds after production stops;
 * the event poll thread hands what they buffered to the callbacks well
 * within this.
 */
#define TARGET_DRAIN_SETTLE_MS 500
#define TARGET_DRAIN_STEP_MS 50
#define TARGET_DRAIN_MAX_MS 15000
/* Without pidfd (before 5.3) the winner's liveness is checked this often. */
#define TARGET_WINNER_RECHECK_MS 1000
#define TARGET_KTHREAD_FLAG 0x00200000u

enum instance_state {
	INSTANCE_ALIVE,
	INSTANCE_DEAD,		/* every thread has exited; maybe not reaped */
	INSTANCE_GONE,		/* no such pid, or it names another process now */
};

enum session_phase {
	PHASE_RUNNING,
	PHASE_DRAINING,
	PHASE_STOPPED,
};

struct proc_info {
	char comm[CPA_TARGET_COMM_LEN];
	char state;
	uint32_t ppid;
	uint64_t identity;	/* start ticks on the boot-time clock */
	unsigned int flags;
};

/*
 * Instances this controller put in the map or heard about, by tgid.  A hint
 * for finding what to delete, never compared with the map: a live pid names
 * one instance, so a newer instance of a tgid means the older one is gone.
 */
struct target_pid {
	uint32_t tgid;
	uint64_t identity;
	UT_hash_handle hh;
};

static struct {
	bool dynamic;
	struct cpa_target_spec spec;
	/* exit capture's own selection, whose env condition target_ctl serves */
	struct cpa_exit_spec exit;
	struct target_rules rules;

	/* the cgroup hierarchy the rules use, see cg_setup() */
	char cg_mount[PATH_MAX];

	/* userspace copy of the rules for the initial /proc scan */
	char cg_paths[CPA_TARGET_MAX_CGROUPS][PATH_MAX];
	int n_cg_paths;
	dev_t exe_dev[CPA_TARGET_MAX_EXES];
	ino_t exe_ino[CPA_TARGET_MAX_EXES];

	int owner_fd;
	int latch_fd;
	atomic_bool accepting;

	pthread_mutex_t index_lock;
	struct target_pid *index;
	unsigned int sweep_at;		/* index size that triggers a sweep */

	/* --first_match */
	pthread_mutex_t latch_lock;
	bool latched;
	struct target_latch_val latch;
	uint64_t winner_deadline_ns;
	int wake_fd;			/* eventfd: latch adopted, stop */
	int winner_fd;			/* pidfd of the winner, -1 without */
	bool winner_watched;
	enum session_phase phase;
	uint64_t drain_start_ms;
	atomic_bool stopping;
	bool thread_started;
	pthread_t thread;
} tc = {
	.owner_fd = -1,
	.latch_fd = -1,
	.wake_fd = -1,
	.winner_fd = -1,
	.index_lock = PTHREAD_MUTEX_INITIALIZER,
	.latch_lock = PTHREAD_MUTEX_INITIALIZER,
};

/* The CLOCK_MONOTONIC that bpf_ktime_get_ns() reads. */
static uint64_t mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint64_t mono_ms(void)
{
	return mono_ns() / 1000000ULL;
}

static const char *origin_name(uint8_t origin)
{
	switch (origin) {
	case TARGET_ORIGIN_STATIC:
		return "pid";
	case TARGET_ORIGIN_SCAN:
		return "scan";
	case TARGET_ORIGIN_EXEC:
		return "exec";
	case TARGET_ORIGIN_INHERIT:
		return "inherit";
	case TARGET_ORIGIN_CHILD:
		return "child";
	}
	return "unknown";
}

static bool startup_mode(void)
{
	return tc.spec.first_match || tc.spec.new_only;
}

static struct target_key instance_key(uint32_t tgid, uint64_t identity)
{
	return (struct target_key){ .tgid = tgid, .identity = identity };
}

static const struct target_key session_key = { .tgid = TARGET_SESSION_TGID };

static uint64_t window_ns(void)
{
	return (uint64_t)tc.spec.startup_window_sec * 1000000000ULL;
}

/* ------------------------------------------------------ time namespace -- */

/*
 * /proc start times and clock_gettime() include the offsets of the
 * profiler's time namespace, BPF sees the host clocks.  A process'
 * identity is its start time: the BPF one of a sample would never match
 * the one read from /proc, and every live process would look dead.  A
 * profiler in a shifted time namespace is refused rather than translated.
 * @fp holds timens_offsets(5) lines: "<clock> <sec> <nsec>".
 */
static int check_time_offsets(FILE *fp)
{
	char name[32];
	long long sec, nsec;
	int ret = 0;

	while (fscanf(fp, "%31s %lld %lld", name, &sec, &nsec) == 3) {
		if (sec || nsec) {
			CLI_ERROR("the profiler runs in a time "
				  "namespace with a %s offset of %llds %lldns; "
				  "run it in the host time namespace", name, sec,
				  nsec);
			ret = -ENOTSUP;
		}
	}
	return ret;
}

/* include/linux/proc_ns.h: the inode of the initial time namespace */
#define PROC_TIME_INIT_INO 0xEFFFFFFAUL

/*
 * The time namespace the profiler runs in, by the inodes of
 * /proc/self/ns/time (@active) and /proc/self/ns/time_for_children
 * (@children), 0 where missing (before 5.6).  timens_offsets shows the
 * offsets of the children's namespace (proc_timens_show_offsets() reads
 * timens_for_children_get()), which after unshare(CLONE_NEWTIME) is another
 * than the active one.  Such a process cannot start a thread either: clone
 * with CLONE_THREAD or CLONE_VM fails while the two differ (kernel/fork.c,
 * copy_process()), and the profiler needs threads.  So: refused when they
 * differ, whichever is shifted; otherwise @offsets are the active
 * namespace's (none in the host's).
 */
static int check_time_namespace(unsigned long active, unsigned long children,
				FILE *offsets)
{
	if (!active)
		return 0;	/* before 5.6: no time namespaces */
	if (active != children) {
		CLI_ERROR("the profiler's time namespace (time:[%lu]) "
			  "is not the one for its children (time:[%lu]): it "
			  "could start no thread; run it in the host time "
			  "namespace", active, children);
		return -ENOTSUP;
	}
	if (active == PROC_TIME_INIT_INO)
		return 0;	/* the host's: no offsets */
	if (!offsets) {
		CLI_ERROR("cannot read the offsets of the profiler's "
			  "time namespace (time:[%lu]); run it in the host time "
			  "namespace", active);
		return -ENOTSUP;
	}
	return check_time_offsets(offsets);
}

static unsigned long ns_inode(const char *path)
{
	struct stat st;

	return stat(path, &st) ? 0 : (unsigned long)st.st_ino;
}

int cpa_check_time_namespace(void)
{
	unsigned long active = ns_inode("/proc/self/ns/time");
	unsigned long children = ns_inode("/proc/self/ns/time_for_children");
	FILE *fp = NULL;
	int ret;

	if (active && active != PROC_TIME_INIT_INO && active == children)
		fp = fopen("/proc/self/timens_offsets", "r");
	ret = check_time_namespace(active, children, fp);
	if (fp)
		fclose(fp);
	return ret;
}

/* ---------------------------------------------------------------- /proc -- */

/* comm, state, task flags and start time (field 22) of @path ("/proc/N/stat"). */
static int read_stat_file(const char *path, struct proc_info *info)
{
	char buf[1024];
	char *open_paren, *close_paren, *p;
	unsigned long long start = 0;
	size_t len;
	FILE *fp;
	int field;

	fp = fopen(path, "r");
	if (!fp)
		return -errno;
	len = fread(buf, 1, sizeof(buf) - 1, fp);
	fclose(fp);
	buf[len] = '\0';

	open_paren = strchr(buf, '(');
	close_paren = strrchr(buf, ')');
	if (!open_paren || !close_paren || close_paren < open_paren ||
	    close_paren[1] != ' ')
		return -EINVAL;
	memset(info, 0, sizeof(*info));
	len = close_paren - open_paren - 1;
	if (len >= sizeof(info->comm))
		len = sizeof(info->comm) - 1;
	memcpy(info->comm, open_paren + 1, len);

	/* fields after "(comm)": 3=state 4=ppid ... 9=flags ... 22=starttime */
	p = close_paren + 2;
	info->state = *p;
	for (field = 3; field <= 22 && p && *p; field++) {
		if (field == 4)
			info->ppid = (uint32_t)strtoul(p, NULL, 10);
		if (field == 9)
			info->flags = (unsigned int)strtoul(p, NULL, 10);
		if (field == 22)
			start = strtoull(p, NULL, 10);
		p = strchr(p, ' ');
		if (p)
			p++;
	}
	if (field <= 22)
		return -EINVAL;
	info->identity = start;
	return 0;
}

static int read_proc_stat(uint32_t pid, struct proc_info *info)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	return read_stat_file(path, info);
}

static bool thread_state_exited(char state)
{
	return state == 'Z' || state == 'X' || state == 'x';
}

/*
 * A thread group lives while any of its threads does.  The leader may have
 * called pthread_exit() and sit as a zombie while other threads run; and a
 * whole group can be dead but not yet reaped by its parent.
 */
static enum instance_state instance_state(const struct target_key *key)
{
	struct proc_info info;
	struct dirent *de;
	char path[64];
	DIR *dir;
	bool live = false;

	if (read_proc_stat(key->tgid, &info) || info.identity != key->identity)
		return INSTANCE_GONE;
	if (!thread_state_exited(info.state))
		return INSTANCE_ALIVE;

	snprintf(path, sizeof(path), "/proc/%u/task", key->tgid);
	dir = opendir(path);
	if (!dir)
		return INSTANCE_GONE;
	while (!live && (de = readdir(dir)) != NULL) {
		struct proc_info thread;
		char stat_path[64 + sizeof(de->d_name)];

		if (de->d_name[0] == '.')
			continue;
		snprintf(stat_path, sizeof(stat_path), "/proc/%u/task/%s/stat",
			 key->tgid, de->d_name);
		live = read_stat_file(stat_path, &thread) == 0 &&
		       !thread_state_exited(thread.state);
	}
	closedir(dir);
	return live ? INSTANCE_ALIVE : INSTANCE_DEAD;
}

/* The task's path in the hierarchy that pairs with task_cgroup_id(). */
static int read_proc_cgroup(uint32_t pid, char *out, size_t outlen)
{
	bool v2 = tc.rules.cg_hier == TARGET_CG_HIER_V2_DFL;
	char path[64], *line = NULL;
	size_t cap = 0;
	FILE *fp;
	int ret = -ENOENT;

	snprintf(path, sizeof(path), "/proc/%u/cgroup", pid);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;
	while (getline(&line, &cap, fp) > 0) {
		char *ctrl = strchr(line, ':');
		char *cgpath = ctrl ? strchr(ctrl + 1, ':') : NULL;
		bool hit = false;

		if (!cgpath)
			continue;
		*cgpath++ = '\0';
		ctrl++;
		cgpath[strcspn(cgpath, "\n")] = '\0';
		if (v2) {
			hit = strcmp(line, "0") == 0 && ctrl[0] == '\0';
		} else {
			char *save = NULL, *tok;

			for (tok = strtok_r(ctrl, ",", &save); tok;
			     tok = strtok_r(NULL, ",", &save))
				if (strcmp(tok, "cpu") == 0)
					hit = true;
		}
		if (hit) {
			snprintf(out, outlen, "%s", cgpath);
			ret = 0;
			break;
		}
	}
	free(line);
	fclose(fp);
	return ret;
}

static bool cgroup_path_selected(const char *task_path)
{
	for (int i = 0; i < tc.n_cg_paths; i++) {
		const char *want = tc.cg_paths[i];
		size_t wlen = strlen(want);
		int depth = 0;

		if (strcmp(task_path, want) == 0)
			return true;
		if (!tc.rules.cg_recursive)
			continue;
		if (strcmp(want, "/") == 0) {
			wlen = 0;
		} else if (strncmp(task_path, want, wlen) != 0 ||
			   task_path[wlen] != '/') {
			continue;
		}
		/* BPF walks at most TARGET_CGROUP_MAX_DEPTH ancestors. */
		for (const char *c = task_path + wlen; *c; c++)
			depth += *c == '/';
		if (depth <= TARGET_CGROUP_MAX_DEPTH)
			return true;
	}
	return false;
}

static bool proc_matches_rules(uint32_t pid, const struct proc_info *info)
{
	if (!cpa_target_has_rules(&tc.spec))
		return false;
	if (tc.spec.n_comms) {
		bool hit = false;

		for (int i = 0; i < tc.spec.n_comms && !hit; i++)
			hit = strcmp(info->comm, tc.spec.comms[i]) == 0;
		if (!hit)
			return false;
	}
	if (tc.n_cg_paths) {
		char cgpath[PATH_MAX];

		if (read_proc_cgroup(pid, cgpath, sizeof(cgpath)) ||
		    !cgroup_path_selected(cgpath))
			return false;
	}
	if (tc.spec.n_exes) {
		char path[64];
		struct stat st;
		bool hit = false;

		snprintf(path, sizeof(path), "/proc/%u/exe", pid);
		if (stat(path, &st))
			return false;
		for (int i = 0; i < tc.spec.n_exes && !hit; i++)
			hit = st.st_dev == tc.exe_dev[i] && st.st_ino == tc.exe_ino[i];
		if (!hit)
			return false;
	}
	return true;
}

/* ---------------------------------------------------------- target set -- */

/* Delete an instance that is gone.  The instance is the key: nothing else is hit. */
static void remove_instance(const struct target_key *key)
{
	struct target_pid *p = NULL;

	if (bpf_map_delete_elem(tc.owner_fd, key) == 0)
		CLI_OUTPUT("target: untrack pid=%u reason=exited",
			   key->tgid);
	HASH_FIND(hh, tc.index, &key->tgid, sizeof(key->tgid), p);
	if (p && p->identity == key->identity) {
		HASH_DEL(tc.index, p);
		free(p);
	}
}

/*
 * Remove every instance in the map without a live thread.  The walk only
 * collects keys, so the map does not change under GET_NEXT_KEY (BPF never
 * deletes) and the walk cannot restart.
 */
static void sweep_locked(void)
{
	struct target_key *keys, key, next;
	unsigned int n = 0, removed = 0;
	int ret;

	keys = calloc(TARGET_MAX_PIDS, sizeof(*keys));
	if (!keys)
		return;
	ret = bpf_map_get_next_key(tc.owner_fd, NULL, &next);
	while (ret == 0 && n < TARGET_MAX_PIDS) {
		key = next;
		ret = bpf_map_get_next_key(tc.owner_fd, &key, &next);
		if (key.tgid != TARGET_SESSION_TGID)
			keys[n++] = key;
	}
	for (unsigned int i = 0; i < n; i++) {
		if (instance_state(&keys[i]) != INSTANCE_ALIVE) {
			remove_instance(&keys[i]);
			removed++;
		}
	}
	free(keys);
	CLI_OUTPUT("target: swept %u instances, %u removed", n, removed);
}

/* Record an instance in the map; a newer instance of the tgid replaces the older. */
static void index_learn_locked(const struct target_key *key)
{
	struct target_pid *p = NULL;

	HASH_FIND(hh, tc.index, &key->tgid, sizeof(key->tgid), p);
	if (p) {
		if (p->identity != key->identity) {
			struct target_key old = instance_key(p->tgid, p->identity);

			p->identity = key->identity;
			bpf_map_delete_elem(tc.owner_fd, &old);
		}
		return;
	}
	p = calloc(1, sizeof(*p));
	if (!p)
		return;
	p->tgid = key->tgid;
	p->identity = key->identity;
	HASH_ADD(hh, tc.index, tgid, sizeof(p->tgid), p);

	if (HASH_COUNT(tc.index) >= tc.sweep_at) {
		sweep_locked();
		/* all still alive: grow by another quarter before sweeping again */
		tc.sweep_at = HASH_COUNT(tc.index) + TARGET_MAX_PIDS / 4;
		if (tc.sweep_at < TARGET_MAX_PIDS / 2)
			tc.sweep_at = TARGET_MAX_PIDS / 2;
	}
}

/* Insert from userspace: explicit pid or the initial /proc scan. */
static void track_instance(uint32_t pid, const struct proc_info *info,
			   uint8_t origin)
{
	struct target_key key = instance_key(pid, info->identity);
	struct target_val val = {
		.armed_ns = mono_ns(),
		.state = TARGET_STATE_TRACKED,
		.origin = origin,
	};

	if (window_ns())
		val.deadline_ns = val.armed_ns + window_ns();

	if (bpf_map_update_elem(tc.owner_fd, &key, &val, BPF_NOEXIST)) {
		if (errno != EEXIST)
			CLI_ERROR("target: cannot track pid=%u: %s", pid,
				  strerror(errno));
		return;
	}
	pthread_mutex_lock(&tc.index_lock);
	index_learn_locked(&key);
	pthread_mutex_unlock(&tc.index_lock);
	CLI_OUTPUT("target: track pid=%u comm=%s origin=%s", pid,
		   info->comm, origin_name(origin));
}

/*
 * Seed the set with already running processes that match the rules.  Runs
 * while rules.scanning is set: a process that execs a non-matching program
 * after being read here gets a BPF fence entry, and the stale seed insert
 * fails with EEXIST.
 */
static void scan_proc(void)
{
	DIR *dir = opendir("/proc");
	struct dirent *de;
	uint32_t self = (uint32_t)getpid();

	if (!dir)
		return;
	while ((de = readdir(dir)) != NULL) {
		struct proc_info info;
		char *end = NULL;
		unsigned long pid = strtoul(de->d_name, &end, 10);

		if (!end || *end || pid == 0 || pid == self)
			continue;
		if (read_proc_stat((uint32_t)pid, &info) ||
		    (info.flags & TARGET_KTHREAD_FLAG) ||
		    thread_state_exited(info.state))
			continue;
		if (proc_matches_rules((uint32_t)pid, &info))
			track_instance((uint32_t)pid, &info, TARGET_ORIGIN_SCAN);
	}
	closedir(dir);
}

/* Is the instance @pid (as /proc shows it now) selected and in its window? */
static bool instance_tracked(uint32_t pid, const struct proc_info *info)
{
	struct target_key key = instance_key(pid, info->identity);
	struct target_val val;

	if (bpf_map_lookup_elem(tc.owner_fd, &key, &val))
		return false;
	return val.state == TARGET_STATE_TRACKED &&
	       (!val.deadline_ns || mono_ns() < val.deadline_ns);
}

/*
 * --children: the fork hook follows forks of processes already tracked, so
 * the descendants that were running before their ancestor was seeded come
 * from /proc.  Once a parent is seeded the hook sees its later forks, so a
 * child is either found here or by the hook.  A pass adds the children of
 * what the previous one added, until none is new.
 */
static void scan_children(void)
{
	uint32_t self = (uint32_t)getpid();
	bool added = true;

	for (int pass = 0; added && pass < 64; pass++) {
		DIR *dir = opendir("/proc");
		struct dirent *de;

		if (!dir)
			return;
		added = false;
		while ((de = readdir(dir)) != NULL) {
			struct proc_info info, parent;
			char *end = NULL;
			unsigned long pid = strtoul(de->d_name, &end, 10);

			if (!end || *end || pid == 0 || pid == self)
				continue;
			if (read_proc_stat((uint32_t)pid, &info) ||
			    (info.flags & TARGET_KTHREAD_FLAG) ||
			    thread_state_exited(info.state) || info.ppid == 0)
				continue;
			if (instance_tracked((uint32_t)pid, &info) ||
			    read_proc_stat(info.ppid, &parent) ||
			    !instance_tracked(info.ppid, &parent))
				continue;
			track_instance((uint32_t)pid, &info, TARGET_ORIGIN_CHILD);
			added = true;
		}
		closedir(dir);
	}
}

static int open_session(void)
{
	struct target_val val = {};

	if (bpf_map_update_elem(tc.owner_fd, &session_key, &val, BPF_ANY)) {
		CLI_ERROR("target: cannot open the session: %s",
			  strerror(errno));
		return -errno;
	}
	return 0;
}

/* Stops sampling of every target and every new selection at once. */
static void close_session(void)
{
	bpf_map_delete_elem(tc.owner_fd, &session_key);
}

static void wake_first_match(void)
{
	uint64_t one = 1;

	if (tc.wake_fd >= 0 && write(tc.wake_fd, &one, sizeof(one)) < 0) {
		/* the counter only overflows if nobody reads: already awake */
	}
}

/* Adopt the committed --first_match winner, once there is one. */
static void adopt_latch(const char *comm)
{
	struct target_latch_val latch;
	struct target_val val;
	__u32 zero = 0;

	pthread_mutex_lock(&tc.latch_lock);
	if (tc.latched || bpf_map_lookup_elem(tc.latch_fd, &zero, &latch) ||
	    !latch.committed) {
		pthread_mutex_unlock(&tc.latch_lock);
		return;
	}
	tc.latched = true;
	tc.latch = latch;
	if (bpf_map_lookup_elem(tc.owner_fd, &latch.target, &val) == 0)
		tc.winner_deadline_ns = val.deadline_ns;
	pthread_mutex_unlock(&tc.latch_lock);
	CLI_OUTPUT("target: latched pid=%u comm=%s (first_match)",
		   latch.target.tgid, comm);
	wake_first_match();
}

uint32_t cpa_target_latched_pid(void)
{
	uint32_t pid;

	pthread_mutex_lock(&tc.latch_lock);
	pid = tc.latched ? tc.latch.target.tgid : 0;
	pthread_mutex_unlock(&tc.latch_lock);
	return pid;
}

/* Logs and preloading follow the BPF events; the map already holds the state. */
static void target_event_cb(void *data, unsigned int size, void *user_ctx)
{
	const struct target_event *ev = data;
	char comm[TARGET_COMM_LEN + 1] = {};
	struct target_key key;
	struct target_val val;

	(void)user_ctx;
	if (size < sizeof(*ev))
		return;
	if (!atomic_load(&tc.accepting))
		return;
	memcpy(comm, ev->comm, TARGET_COMM_LEN);
	key = instance_key(ev->tgid, ev->identity);

	if (ev->kind == TARGET_EV_EXIT_NAMED) {
		cpa_exit_env_selected(ev->tgid, ev->identity);
		return;
	}

	if (ev->kind == TARGET_EV_UNTRACKED) {
		CLI_OUTPUT("target: untrack pid=%u "
			   "reason=exec-no-longer-matches", ev->tgid);
		return;
	}
	if (ev->kind == TARGET_EV_LATCHED)
		adopt_latch(comm);
	if (bpf_map_lookup_elem(tc.owner_fd, &key, &val))
		return;		/* gone meanwhile */

	pthread_mutex_lock(&tc.index_lock);
	if (atomic_load(&tc.accepting))
		index_learn_locked(&key);
	pthread_mutex_unlock(&tc.index_lock);
	CLI_OUTPUT("target: track pid=%u comm=%s origin=%s", ev->tgid,
		   comm, origin_name(val.origin));
}

/*
 * The unwinder reaps an exit once its grace period has passed, so the
 * process is past its exit path by now.  Its instance is removed unless
 * other threads still run it; that case is left to the sweep.
 */
void cpa_target_on_exit(uint32_t pid)
{
	struct target_pid *p = NULL;

	if (!atomic_load(&tc.accepting))
		return;
	pthread_mutex_lock(&tc.index_lock);
	HASH_FIND(hh, tc.index, &pid, sizeof(pid), p);
	if (p && atomic_load(&tc.accepting)) {
		struct target_key key = instance_key(p->tgid, p->identity);

		if (instance_state(&key) != INSTANCE_ALIVE)
			remove_instance(&key);
	}
	pthread_mutex_unlock(&tc.index_lock);
}

/* ------------------------------------------------------ --first_match -- */

/*
 * End of a --first_match session: close the session so that no target --
 * known here or not -- produces more samples; let programs already past
 * their gate finish (they run non-preemptible and verifier-bounded, far
 * below the settle time) and the poll thread hand what they buffered to the
 * callbacks; wait until the unwinder has finished every accepted sample;
 * stop.
 */
static void begin_drain(const char *why)
{
	CLI_OUTPUT("target: first_match pid=%u %s, draining",
		   tc.latch.target.tgid, why);
	close_session();
	tc.phase = PHASE_DRAINING;
	tc.drain_start_ms = mono_ms();
}

static void watch_winner(void)
{
	int fd = (int)syscall(__NR_pidfd_open, tc.latch.target.tgid, 0);

	/* the pidfd must name the latched instance, not a later reuse */
	if (fd >= 0 && instance_state(&tc.latch.target) == INSTANCE_ALIVE) {
		tc.winner_fd = fd;
		return;
	}
	if (fd >= 0)
		close(fd);
}

/*
 * Advance the --first_match session.  Returns how long the caller may sleep
 * (-1: until woken or the winner's pidfd fires).
 */
static int first_match_step(uint64_t now_ms)
{
	unsigned int pending;
	int sleep_ms = -1;

	if (!tc.latched)
		return -1;
	if (tc.phase == PHASE_RUNNING) {
		uint64_t deadline_ms = tc.winner_deadline_ns / 1000000ULL;

		if (!tc.winner_watched) {
			watch_winner();
			tc.winner_watched = true;
		}
		if (instance_state(&tc.latch.target) != INSTANCE_ALIVE) {
			begin_drain("exited");
		} else if (deadline_ms && now_ms >= deadline_ms) {
			begin_drain("reached its startup window");
		} else {
			if (deadline_ms)
				sleep_ms = (int)(deadline_ms - now_ms);
			if (tc.winner_fd < 0 &&
			    (sleep_ms < 0 || sleep_ms > TARGET_WINNER_RECHECK_MS))
				sleep_ms = TARGET_WINNER_RECHECK_MS;
			return sleep_ms;
		}
		return TARGET_DRAIN_SETTLE_MS;
	}
	if (tc.phase != PHASE_DRAINING)
		return -1;

	if (now_ms - tc.drain_start_ms < TARGET_DRAIN_SETTLE_MS)
		return (int)(tc.drain_start_ms + TARGET_DRAIN_SETTLE_MS - now_ms);
	pending = cpa_unwinder_pending_samples();
	if (pending && now_ms - tc.drain_start_ms < TARGET_DRAIN_MAX_MS)
		return TARGET_DRAIN_STEP_MS;
	if (pending)
		CLI_ERROR("target: INCOMPLETE: stopping with %u samples not "
			  "yet unwound after %dms", pending, TARGET_DRAIN_MAX_MS);
	CLI_OUTPUT("target: first_match finished, stopping session");
	tc.phase = PHASE_STOPPED;
	set_stop();
	return -1;
}

static void *first_match_main(void *arg)
{
	(void)arg;
	while (!atomic_load(&tc.stopping) && tc.phase != PHASE_STOPPED) {
		struct pollfd fds[2] = {
			{ .fd = tc.wake_fd, .events = POLLIN },
			{ .fd = tc.winner_fd, .events = POLLIN },
		};
		int sleep_ms = first_match_step(mono_ms());
		uint64_t drained;

		if (tc.phase == PHASE_STOPPED)
			break;
		/* the winner's pidfd is readable once it is gone: stop polling it */
		fds[1].fd = tc.phase == PHASE_RUNNING ? tc.winner_fd : -1;
		if (poll(fds, 2, sleep_ms) > 0 && (fds[0].revents & POLLIN) &&
		    read(tc.wake_fd, &drained, sizeof(drained)) < 0) {
			/* nothing to drain: woken twice */
		}
	}
	return NULL;
}

/* ---------------------------------------------------------- lifecycle -- */

static bool raw_bool(void *cli_ctx, const char *name)
{
	return atoi(get_arg_by_name(cli_ctx, name)) != 0;
}

int cpa_target_configure(void *cli_ctx)
{
	struct cpa_target_raw raw = {
		.pid = get_arg_by_name(cli_ctx, "pid"),
		.comm = get_arg_by_name(cli_ctx, "comm"),
		.thread_comm = get_arg_by_name(cli_ctx, "thread_comm"),
		.exe = get_arg_by_name(cli_ctx, "exe"),
		.cgroup = get_arg_by_name(cli_ctx, "cgroup"),
		.container_pid = get_arg_by_name(cli_ctx, "container_pid"),
		.startup_window = get_arg_by_name(cli_ctx, "startup_window"),
		.cgroup_recursive = raw_bool(cli_ctx, "cgroup_recursive"),
		.children = raw_bool(cli_ctx, "children"),
		.new_only = raw_bool(cli_ctx, "new_only"),
		.first_match = raw_bool(cli_ctx, "first_match"),
	};
	char err[256];

	if (cpa_target_parse(&raw, &tc.spec, err, sizeof(err))) {
		CLI_ERROR("Invalid process selection: %s", err);
		return -EINVAL;
	}
	tc.dynamic = tc.spec.mode == CPA_TARGET_DYNAMIC;
	CLI_OUTPUT("target: selection %s mode=%s", tc.spec.summary,
		   tc.dynamic ? "target set" : "pid/thread filter");
	return 0;
}

bool cpa_target_is_dynamic(void)
{
	return tc.dynamic;
}

const struct cpa_target_spec *cpa_target_spec(void)
{
	return &tc.spec;
}

/* ------------------------------------------------------------- cgroups -- */

/*
 * The hierarchy the rules use, as task_cgroup_id() and the BPF walk see it:
 * the cgroup v1 cpu controller when it is mounted, otherwise cgroup v2.
 */
static int cg_setup(void)
{
	char line[4096], v2[PATH_MAX] = "";
	FILE *fp = fopen("/proc/self/mountinfo", "r");

	tc.cg_mount[0] = '\0';
	if (!fp)
		return -errno;
	while (fgets(line, sizeof(line), fp)) {
		char *sep = strstr(line, " - ");
		char mnt[PATH_MAX], fstype[64], source[PATH_MAX], opts[1024];

		if (!sep || sscanf(line, "%*s %*s %*s %*s %4095s", mnt) != 1 ||
		    sscanf(sep + 3, "%63s %4095s %1023s", fstype, source, opts) != 3)
			continue;
		if (strcmp(fstype, "cgroup2") == 0 && !v2[0]) {
			snprintf(v2, sizeof(v2), "%s", mnt);
		} else if (strcmp(fstype, "cgroup") == 0) {
			char *save = NULL;

			for (char *tok = strtok_r(opts, ",", &save); tok;
			     tok = strtok_r(NULL, ",", &save)) {
				if (strcmp(tok, "cpu") == 0) {
					snprintf(tc.cg_mount, sizeof(tc.cg_mount), "%s", mnt);
					break;
				}
			}
		}
	}
	fclose(fp);
	if (tc.cg_mount[0]) {
		tc.rules.cg_hier = TARGET_CG_HIER_V1_CPU;
		return 0;
	}
	if (v2[0]) {
		snprintf(tc.cg_mount, sizeof(tc.cg_mount), "%s", v2);
		tc.rules.cg_hier = TARGET_CG_HIER_V2_DFL;
		return 0;
	}
	CLI_ERROR("target: neither a cgroup v1 cpu nor a cgroup v2 hierarchy is mounted");
	return -ENOENT;
}

/*
 * The kernfs id of a cgroup directory, as BPF reads it (kernfs_node::id):
 * the 8-byte file handle of the directory.  A kernel whose cgroupfs exports
 * no handles (upstream before 4.15) gives no ids: selection by cgroup is
 * refused there.
 */
static uint64_t cg_id(const char *path)
{
	union {
		struct file_handle fh;
		char buf[sizeof(struct file_handle) + sizeof(uint64_t)];
	} handle;
	uint64_t id;
	int mount_id;

	handle.fh.handle_bytes = sizeof(uint64_t);
	if (name_to_handle_at(AT_FDCWD, path, &handle.fh, &mount_id, 0) ||
	    handle.fh.handle_bytes != sizeof(uint64_t)) {
		if (errno == EOPNOTSUPP)
			CLI_ERROR("target: this kernel's cgroupfs gives no cgroup "
				  "ids to user space (upstream Linux 4.15 and later "
				  "do); selection by cgroup is not available");
		return 0;
	}
	memcpy(&id, handle.fh.f_handle, sizeof(id));
	return id;
}

/* Accept "a/b", "/a/b" or "<mount>/a/b"; produce "/a/b". */
static int normalize_cgroup(const char *in, char *out, size_t outlen)
{
	size_t mlen = strlen(tc.cg_mount);

	while (mlen > 1 && tc.cg_mount[mlen - 1] == '/')
		mlen--;
	if (mlen && strncmp(in, tc.cg_mount, mlen) == 0 &&
	    (in[mlen] == '/' || in[mlen] == '\0'))
		in += mlen;
	else if (strncmp(in, "/sys/fs/cgroup", strlen("/sys/fs/cgroup")) == 0)
		return -EXDEV;
	snprintf(out, outlen, "%s%s", in[0] == '/' ? "" : "/", in[0] ? in : "/");
	/* strip a trailing slash except for the root */
	for (size_t len = strlen(out); len > 1 && out[len - 1] == '/'; len--)
		out[len - 1] = '\0';
	return 0;
}

static int add_cgroup_rule(const char *path)
{
	char rel[PATH_MAX], abs[PATH_MAX * 2];
	uint64_t id;

	if (tc.n_cg_paths >= CPA_TARGET_MAX_CGROUPS)
		return -E2BIG;
	if (normalize_cgroup(path, rel, sizeof(rel))) {
		CLI_ERROR("--cgroup %s is not under the %s hierarchy mounted at %s; "
			  "pass a path relative to it", path,
			  tc.rules.cg_hier == TARGET_CG_HIER_V2_DFL ? "cgroup v2" : "cpu",
			  tc.cg_mount);
		return -EXDEV;
	}
	snprintf(abs, sizeof(abs), "%s%s", tc.cg_mount, strcmp(rel, "/") ? rel : "");
	id = cg_id(abs);
	if (!id) {
		CLI_ERROR("--cgroup %s: cannot read the id of %s: %s", path, abs,
			  strerror(errno));
		return -ENOENT;
	}
	snprintf(tc.cg_paths[tc.n_cg_paths], PATH_MAX, "%s", rel);
	tc.rules.cgroup_ids[tc.n_cg_paths] = id;
	tc.n_cg_paths++;
	CLI_OUTPUT("target: cgroup %s id=%llu", rel, (unsigned long long)id);
	return 0;
}

int cpa_target_prepare(void)
{
	struct target_rules *r = &tc.rules;

	if (!cpa_target_needs_bpf())
		return 0;

	memset(r, 0, sizeof(*r));
	for (int i = 0; exit_env_by_name() && i < tc.exit.n_comms; i++)
		memcpy(r->exit_comms[i], tc.exit.comms[i], TARGET_COMM_LEN);
	r->n_exit_comms = exit_env_by_name() ? tc.exit.n_comms : 0;
	if (!tc.dynamic) {
		/* only the exec and fork notifications: no target set */
		tc.owner_fd = target_ctl_pids_fd();
		tc.latch_fd = target_ctl_latch_fd();
		return tc.owner_fd < 0 || tc.latch_fd < 0 ? -ENOENT : 0;
	}
	tc.n_cg_paths = 0;
	if (cpa_target_has_rules(&tc.spec) && (tc.spec.n_cgroups || tc.spec.container_pid) &&
	    cg_setup())
		return -ENOENT;
	r->first_match = tc.spec.first_match;
	r->new_only = tc.spec.new_only;
	r->children = tc.spec.children;
	r->cg_recursive = tc.spec.cgroup_recursive;
	r->window_ns = window_ns();

	for (int i = 0; i < tc.spec.n_comms; i++)
		memcpy(r->comms[i], tc.spec.comms[i], TARGET_COMM_LEN);
	r->n_comms = tc.spec.n_comms;

	for (int i = 0; i < tc.spec.n_cgroups; i++)
		if (add_cgroup_rule(tc.spec.cgroups[i]))
			return -EINVAL;
	if (tc.spec.container_pid) {
		char path[PATH_MAX];

		if (read_proc_cgroup((uint32_t)tc.spec.container_pid, path,
				     sizeof(path))) {
			CLI_ERROR("--container_pid %d: cannot read its cgroup",
				  tc.spec.container_pid);
			return -EINVAL;
		}
		if (add_cgroup_rule(path))
			return -EINVAL;
		/* the container's processes live in or below this cgroup */
		r->cg_recursive = 1;
	}
	r->n_cgroups = tc.n_cg_paths;

	for (int i = 0; i < tc.spec.n_exes; i++) {
		struct stat st;

		if (stat(tc.spec.exes[i], &st)) {
			CLI_ERROR("--exe %s: %s", tc.spec.exes[i], strerror(errno));
			return -EINVAL;
		}
		tc.exe_dev[i] = st.st_dev;
		tc.exe_ino[i] = st.st_ino;
		/* kernel internal dev_t: MAJOR << 20 | MINOR */
		r->exe_dev[i] = ((__u64)major(st.st_dev) << 20) | minor(st.st_dev);
		r->exe_ino[i] = st.st_ino;
	}
	r->n_exes = tc.spec.n_exes;

	tc.owner_fd = target_ctl_pids_fd();
	tc.latch_fd = target_ctl_latch_fd();
	if (tc.owner_fd < 0 || tc.latch_fd < 0)
		return -ENOENT;

	stack_capture_set_target(tc.owner_fd, true);
	offcpu_capture_set_target(tc.owner_fd, true);
	return 0;
}

/* Guard 4: both fds must report one kernel map id. */
static int check_sharing(const char *name, int fd)
{
	uint32_t owner = target_ctl_map_id(tc.owner_fd);
	uint32_t id = target_ctl_map_id(fd);

	if (fd < 0)
		return 0;
	if (owner && id == owner) {
		CLI_OUTPUT("target: map sharing %s=shared map_id=%u", name,
			   id);
		return 0;
	}
	CLI_ERROR("target: %s does not share the target map "
		  "(map_id=%u, owner map_id=%u); refusing to start", name, id,
		  owner);
	return -EXDEV;
}

/* The birth hooks this selection cannot do without. */
static int check_hooks(const struct target_ctl_hooks *hooks)
{
	bool inherits = tc.spec.children ||
			(cpa_target_has_rules(&tc.spec) && !tc.spec.first_match);

	if (cpa_target_has_rules(&tc.spec) && !hooks->exec) {
		CLI_ERROR("target: neither sched_process_exec nor "
			  "setup_new_exec can be hooked; rule based selection "
			  "cannot follow new programs");
		return -ENOTSUP;
	}
	if (inherits && !hooks->fork) {
		CLI_ERROR("target: wake_up_new_task cannot be hooked; "
			  "children of selected processes would be missed");
		return -ENOTSUP;
	}
	CLI_OUTPUT("target: exec hook %s, fork hook %s",
		   !hooks->exec ? "unused" :
		   hooks->exec_tracepoint ? "sched_process_exec" :
		   "kretprobe/setup_new_exec (no t0 sample)",
		   hooks->fork ? "attached" : "unused");
	return 0;
}

static void reset_state(void)
{
	struct target_pid *p, *tmp;

	pthread_mutex_lock(&tc.index_lock);
	HASH_ITER(hh, tc.index, p, tmp) {
		HASH_DEL(tc.index, p);
		free(p);
	}
	tc.sweep_at = TARGET_MAX_PIDS / 2;
	pthread_mutex_unlock(&tc.index_lock);
	pthread_mutex_lock(&tc.latch_lock);
	tc.latched = false;
	memset(&tc.latch, 0, sizeof(tc.latch));
	tc.winner_deadline_ns = 0;
	pthread_mutex_unlock(&tc.latch_lock);
	if (tc.winner_fd >= 0)
		close(tc.winner_fd);
	tc.winner_fd = -1;
	tc.winner_watched = false;
	tc.phase = PHASE_RUNNING;
}

void cpa_target_set_exit(const struct cpa_exit_spec *exit)
{
	tc.exit = *exit;
	cpa_exit_env_configure(exit);
}

/* --exit_comm with an env condition: exec and fork must be told. */
static bool exit_env_by_name(void)
{
	return cpa_exit_env_enabled() && tc.exit.n_comms;
}

bool cpa_target_needs_bpf(void)
{
	return tc.dynamic || exit_env_by_name();
}

/*
 * The env condition's processes that run already: --exit_pid, and those
 * with an --exit_comm name.  After the hooks are attached, so that a
 * process is either seen here or by its exec or fork notification.
 */
static void exit_env_seed(void)
{
	DIR *dir;
	struct dirent *de;

	if (!cpa_exit_env_enabled())
		return;
	for (int i = 0; i < tc.exit.n_pids; i++) {
		struct proc_info info;

		if (!read_proc_stat(tc.exit.pids[i], &info))
			cpa_exit_env_read(tc.exit.pids[i], info.identity);
	}
	if (!tc.exit.n_comms || !(dir = opendir("/proc")))
		return;
	while ((de = readdir(dir)) != NULL) {
		struct proc_info info;
		char *end = NULL;
		unsigned long pid = strtoul(de->d_name, &end, 10);

		if (!end || *end || !pid || read_proc_stat((uint32_t)pid, &info) ||
		    (info.flags & TARGET_KTHREAD_FLAG))
			continue;
		for (int i = 0; i < tc.exit.n_comms; i++)
			if (strcmp(info.comm, tc.exit.comms[i]) == 0) {
				cpa_exit_env_read((uint32_t)pid, info.identity);
				break;
			}
	}
	closedir(dir);
}

/*
 * The env reader, and for --exit_comm without a dynamic selection the
 * exec and fork notifications alone (rules disabled: nothing is selected).
 */
static int exit_env_start(void)
{
	struct target_ctl_hooks hooks;
	int ret;

	if (!cpa_exit_env_enabled())
		return 0;
	ret = cpa_exit_env_start();
	if (ret) {
		CLI_ERROR("exit env: cannot start the reader: %s", strerror(-ret));
		return ret;
	}
	if (tc.dynamic)
		return 0;
	if (exit_env_by_name()) {
		tc.rules.enabled = 0;
		atomic_store(&tc.accepting, true);
		atomic_store(&tc.stopping, false);
		ret = target_ctl_start(&tc.rules, target_event_cb, &hooks);
		if (!ret)
			ret = check_hooks(&hooks);
		if (ret)
			return ret;
	}
	exit_env_seed();
	return 0;
}

int cpa_target_start(bool oncpu, bool offcpu)
{
	struct target_ctl_hooks hooks;
	bool scan;
	int ret;

	ret = exit_env_start();
	if (ret || !tc.dynamic)
		return ret;

	reset_state();
	if ((oncpu && (ret = check_sharing("stack_capture",
					   stack_capture_target_pids_fd()))) ||
	    (offcpu && (ret = check_sharing("offcpu_capture",
					    offcpu_capture_target_pids_fd()))))
		return ret;

	if (oncpu && stack_capture_t0_prog_fd() >= 0) {
		ret = target_ctl_set_t0_prog(stack_capture_t0_prog_fd());
		CLI_OUTPUT("target: t0 sampling %s",
			   ret ? "unavailable" : "enabled");
	}

	scan = cpa_target_has_rules(&tc.spec) && !tc.spec.new_only;
	tc.rules.enabled = 1;
	tc.rules.scanning = scan;
	atomic_store(&tc.accepting, true);
	atomic_store(&tc.stopping, false);
	ret = open_session();
	if (ret)
		return ret;
	ret = target_ctl_start(&tc.rules, target_event_cb, &hooks);
	if (ret)
		return ret;
	ret = check_hooks(&hooks);
	if (ret)
		return ret;

	for (int i = 0; i < tc.spec.n_pids; i++) {
		struct proc_info info;

		if (read_proc_stat(tc.spec.pids[i], &info)) {
			CLI_ERROR("target: pid %u does not exist",
				  tc.spec.pids[i]);
			continue;
		}
		track_instance(tc.spec.pids[i], &info, TARGET_ORIGIN_STATIC);
	}
	/* Hooks are live, so no process can slip between scan and exec. */
	if (scan) {
		scan_proc();
		tc.rules.scanning = 0;
		ret = target_ctl_update_rules(&tc.rules);
		if (ret)
			return ret;
	}
	if (tc.spec.children && !tc.spec.new_only)
		scan_children();
	exit_env_seed();
	pthread_mutex_lock(&tc.index_lock);
	if (!HASH_COUNT(tc.index))
		CLI_OUTPUT("target: waiting for a matching process");
	pthread_mutex_unlock(&tc.index_lock);

	if (tc.spec.first_match) {
		tc.wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (tc.wake_fd < 0 ||
		    pthread_create(&tc.thread, NULL, first_match_main, NULL)) {
			CLI_ERROR("target: failed to start the first_match thread");
			return -EAGAIN;
		}
		tc.thread_started = true;
	}
	return 0;
}

void cpa_target_shutdown(void)
{
	unsigned int tracked;

	/* stop accepting notifications before anything they touch goes away */
	atomic_store(&tc.accepting, false);
	atomic_store(&tc.stopping, true);
	cpa_exit_env_stop();
	wake_first_match();

	if (tc.thread_started)
		pthread_join(tc.thread, NULL);
	tc.thread_started = false;
	if (tc.wake_fd >= 0)
		close(tc.wake_fd);
	tc.wake_fd = -1;

	if (tc.owner_fd >= 0)
		close_session();
	pthread_mutex_lock(&tc.index_lock);
	tracked = HASH_COUNT(tc.index);
	pthread_mutex_unlock(&tc.index_lock);
	if (tc.dynamic)
		CLI_OUTPUT("target: stopped tracked=%u", tracked);
	reset_state();
	tc.owner_fd = -1;
	tc.latch_fd = -1;
	stack_capture_set_target(-1, false);
	offcpu_capture_set_target(-1, false);
}
