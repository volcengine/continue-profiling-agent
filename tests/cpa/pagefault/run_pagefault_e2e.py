#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance
"""End-to-end checks for cpa monitor --pagefault (resident anonymous memory).

Runs ``cpa monitor --pagefault --pid=N`` against pf_app -- or,
for a cold start, ``--cgroup=CG --comm=pf_app --first_match`` before pf_app
is started in CG -- and reads the live set of single seconds with
``cpa show``.  Standard library only, so it also runs in minimal VM
guests.

    run_pagefault_e2e.py --cpa BIN --app PF_APP [--work DIR] [--only a,b]
                         [--unwind_workers N]
"""

import argparse
import collections
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback

MIB = 1024 * 1024
# a stack counts for the first of these it contains: callees before callers
FUNCS = ("pf_child_touch", "pf_cow_write",
         "pf_keep_mmap", "pf_free_mmap", "pf_dontneed", "pf_thp",
         "pf_mremap_move", "pf_file_private_write", "pf_shared_anon",
         "pf_heap_trim", "pf_before", "pf_edge_dest", "pf_edge",
         "[resident before profiling]", "[stack dropped]", "PRESSURE",
         "pf_fork_cow", "pf_folio", "pf_refill", "pf_dontunmap")
CLEARED = "exec'ed or exited, live set cleared"


class Result:
    def __init__(self, name):
        self.name = name
        self.ok = True
        self.notes = []
        self.skip = ""

    def skipped(self, reason):
        """What could not be checked here, and why: never a silent pass."""
        self.skip = reason
        self.notes.append("SKIP " + reason)

    def check(self, cond, msg):
        self.notes.append(("PASS " if cond else "FAIL ") + msg)
        self.ok = self.ok and bool(cond)
        return cond


class Cgroup:
    """A scratch cgroup: the cpu controller's hierarchy on v1, else v2."""

    def __init__(self, name):
        with open("/proc/mounts") as fp:
            mounts = [line.split()[:4] for line in fp]
        v1 = [m for _, m, t, o in mounts
              if t == "cgroup" and "cpu" in o.split(",")]
        v2 = [m for _, m, t, _ in mounts if t == "cgroup2"]
        if not v1 and not v2:
            raise RuntimeError("no cgroup mount with the cpu controller")
        self.path = os.path.join((v1 or v2)[0], name)
        self.rel = "/" + name
        os.makedirs(self.path, exist_ok=True)

    def remove(self):
        try:
            os.rmdir(self.path)
        except OSError:
            pass


class Session:
    """pf_app plus a cpa monitor --pagefault following it.

    With @cgroup the monitor starts first and selects pf_app by
    --cgroup/--comm/--first_match; launch_cold() then starts pf_app there.
    """

    def __init__(self, args, name, app_args, extra=None, cgroup=None):
        self.args = args
        self.app_args = app_args
        self.cgroup = cgroup
        self.dir = os.path.join(args.work, name)
        shutil.rmtree(self.dir, ignore_errors=True)
        self.store = os.path.join(self.dir, "store")
        os.makedirs(self.store)
        self.app_log = open(os.path.join(self.dir, "app.log"), "w")
        self.app = None
        if cgroup:
            target = ["--cgroup=" + cgroup.rel, "--comm=" +
                      os.path.basename(args.app)[:15], "--first_match"]
        else:
            self.app = self.start_app()
            self.wait_file(os.path.join(self.dir, "app.log"), "PHASE ready", 10)
            target = ["--pid=%d" % self.app.pid]
        self.log_path = os.path.join(self.dir, "monitor.log")
        self.log = open(self.log_path, "w")
        cmd = [args.cpa, "monitor", "--backend=bpf", "--pagefault",
               "--store_dir=" + self.store,
               "--unwind_workers=%d" % args.unwind_workers] + target + \
              (extra or [])
        self.mon = subprocess.Popen(cmd, stdout=self.log,
                                    stderr=subprocess.STDOUT)

    def start_app(self, procs=None):
        def preexec():
            if procs:	# joins the cgroup before its exec
                with open(procs, "w") as fp:
                    fp.write(str(os.getpid()))

        return subprocess.Popen([self.args.app] + self.app_args,
                                stdout=self.app_log, stderr=subprocess.STDOUT,
                                preexec_fn=preexec, cwd=self.dir)

    def launch_cold(self):
        """Start pf_app in the cgroup once the monitor waits for it."""
        if not self.wait_file(self.log_path, "waiting for a matching process",
                              90):
            return False
        self.app = self.start_app(os.path.join(self.cgroup.path,
                                               "cgroup.procs"))
        return self.wait_file(os.path.join(self.dir, "app.log"),
                              "PHASE ready", 10)

    @staticmethod
    def wait_file(path, needle, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with open(path, errors="replace") as fp:
                if needle in fp.read():
                    return True
            time.sleep(0.1)
        return False

    def text(self):
        with open(self.log_path, errors="replace") as fp:
            return fp.read()

    def ready(self):
        if self.cgroup:
            ok = self.wait_file(self.log_path,
                                "latched pid=%d " % self.app.pid, 30)
        else:
            ok = self.wait_file(self.log_path, "already resident", 90)
        return ok and "hooks attached" in self.text()

    def run(self, at_phase=None):
        """Start the workload and wait for it to end.

        @at_phase: called with the phase name once pf_app printed it.
        """
        self.app.send_signal(signal.SIGUSR1)
        for name, fn in (at_phase or {}).items():
            if not self.wait_file(os.path.join(self.dir, "app.log"),
                                  "PHASE %s " % name, 60):
                raise RuntimeError("pf_app never reached phase " + name)
            fn()
        self.app.wait(timeout=120)
        time.sleep(2.5)		# the last snapshots

    def region(self, name):
        with open(os.path.join(self.dir, "app.log")) as fp:
            m = re.search(r"REGION %s ([0-9a-f]+)" % name, fp.read())
        return int(m.group(1), 16) if m else None

    def huge_bytes(self, addr):
        """AnonHugePages of the mapping starting at @addr, from smaps."""
        found = False
        with open("/proc/%d/smaps" % self.app.pid) as fp:
            for line in fp:
                m = re.match(r"([0-9a-f]+)-[0-9a-f]+ ", line)
                if m:
                    found = int(m.group(1), 16) == addr
                elif found and line.startswith("AnonHugePages:"):
                    return int(line.split()[1]) * 1024
        raise RuntimeError("no mapping at %#x in smaps" % addr)

    def stop(self):
        if self.mon.poll() is None:
            self.mon.send_signal(signal.SIGINT)
            try:
                self.mon.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.mon.kill()
                self.mon.wait()
        if self.app and self.app.poll() is None:
            self.app.kill()
            self.app.wait()
        self.log.close()
        self.app_log.close()
        return self.mon.returncode

    def phases(self):
        out = {}
        with open(os.path.join(self.dir, "app.log")) as fp:
            for line in fp:
                m = re.match(r"PHASE (\S+) (\d+)", line)
                if m:
                    out[m.group(1)] = int(m.group(2)) / 1000.0
        return out

    def live_set(self, at, until=None):
        """{function: bytes}: a snapshot taken after @at.

        Records are [start, end] seconds, both inclusive, so start == end ==
        T selects the one record ending at T, whose snapshot was taken
        during T-1.  T = floor(at) + 2 guarantees a snapshot after @at.
        With @until (the next phase), the last snapshot taken wholly before
        it: the address-space events of the phase reach the live set within
        the monitor's poll latency, which a loaded host stretches.
        """
        t = int(at) + 2
        if until is not None:
            t = max(t, int(until))
        second = time.strftime("%H:%M:%S", time.localtime(t))
        return self.show(second, second)

    def show(self, start, end):
        subdirs = sorted(d for d in os.listdir(self.store)
                         if d.startswith("cpa_"))
        out = os.path.join(self.dir, "window.prof")
        if os.path.exists(out):
            os.unlink(out)
        with open(os.path.join(self.dir, "show.log"), "w") as log:
            rc = subprocess.run(
                [self.args.cpa, "show", "-r",
                 os.path.join(self.store, subdirs[-1]), "-o", out,
                 "--starttime=" + start, "--endtime=" + end],
                stdout=log, stderr=subprocess.STDOUT, timeout=180,
                cwd=self.dir).returncode
        if rc != 0:
            raise RuntimeError("cpa show failed with %d" % rc)
        totals = collections.Counter()
        self.stacks = collections.Counter()
        if os.path.exists(out):
            with open(out, errors="replace") as fp:
                for line in fp:
                    stack, _, n = line.rstrip("\n").rpartition(" ")
                    if not stack:
                        continue
                    key = next((f for f in FUNCS if f in stack), "other")
                    totals[key] += int(n)
                    self.stacks[stack] += int(n)
        return totals

    def record_range(self):
        with open(os.path.join(self.dir, "show.log"), errors="replace") as fp:
            m = re.search(r"Record Time From \[ (\S+) \] to \[ (\S+) \]",
                          fp.read())
        return m.groups() if m else None


def near(got, want, tol):
    return abs(got - want) <= tol * want


def sample_tol(want, sample_pages, floor):
    """Relative tolerance of a 1-in-@sample_pages estimate of @want bytes:
    six standard deviations of the binomial count of sampled 4 KiB pages
    (the sampler hashes addresses), never below @floor.  At 1 in 16, 32 MiB
    gives 26%: a fixed 15% is 3.5 sigma, a false failure every few hundred
    runs on a correct tracker.  The exact cases (1 in 1) keep @floor."""
    pages = want / 4096
    return max(floor, 6 * math.sqrt((sample_pages - 1) / pages))


def reported_lost(text):
    """Bytes of sampled pages the monitor said it could not record (its last
    INCOMPLETE line); they are missing from every bucket, said out loud."""
    found = re.findall(r"INCOMPLETE: .*?unreported sampled pages=(\d+) KiB", text)
    return int(found[-1]) * 1024 if found else 0


def close(got, want, tol, loose=0):
    """@got estimates @want: never more, and less only by @loose bytes the
    monitor accounted for elsewhere (stackless buckets, reported losses)."""
    return got <= want * (1 + tol) and got + loose >= want * (1 - tol)


def stackless(live):
    """Pages counted where a burst left no stack to charge them to."""
    return live["[stack dropped]"] + live["PRESSURE"]


def check_charged(r, live, func, want, what):
    """@func holds @want bytes: no more, and any shortfall is stackless."""
    got, loose = live[func], stackless(live)
    r.check(got <= want <= got + loose and 2 * got >= want,
            "%s: %.2f of %.2f MiB on %s, %.2f MiB without a stack" %
            (what, got / MIB, want / MIB, func, loose / MIB))


def workload_total(live):
    return sum(v for k, v in live.items()
               if k != "[resident before profiling]")


def check_exact_or_reported(r, text, got, want, what):
    """Every page counted, or the shortfall said out loud."""
    short = want - got
    if abs(short) <= 64 * 1024:
        r.check("INCOMPLETE" not in text, "%s exact (%.2f of %.2f MiB), "
                "nothing reported missing" % (what, got / MIB, want / MIB))
    elif short < 0:
        r.check(False, "%s counted %.2f MiB too much" % (what, -short / MIB))
    else:
        # the whole shortfall is what the monitor said it lost
        lost = reported_lost(text)
        r.check("INCOMPLETE" in text and short <= lost + 64 * 1024,
                "%s short by %.2f MiB, reported as INCOMPLETE (%.2f MiB lost)" %
                (what, short / MIB, lost / MIB))


def thp_mode():
    try:
        with open("/sys/kernel/mm/transparent_hugepage/enabled") as fp:
            return re.search(r"\[(\w+)\]", fp.read()).group(1)
    except (OSError, AttributeError):
        return "unsupported"


STATS = re.compile(r"pagefault: resident=(\d+) KiB .*")


def final_stats(r, text):
    """The tracker's counters, logged once when the monitor stops."""
    lines = STATS.findall(text)
    if not r.check(len(lines) == 1, "final tracker stats logged once"):
        return {}
    line = [l for l in text.splitlines() if "pagefault: resident=" in l][0]
    return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", line)}


def check_drained(r, text):
    """The process is gone: its live set is empty, nothing failed."""
    st = final_stats(r, text)
    r.check(st.get("resident") == 0,
            "live set empty after the process ended (%s KiB)" %
            st.get("resident"))
    r.check(st.get("failed") == 0, "no tracker operation failed (%s)" %
            st.get("failed"))
    return st


def fmt(totals):
    return ", ".join("%s=%.1fM" % (k, v / MIB) for k, v in sorted(totals.items()))


def kernel_has(symbol):
    with open("/proc/kallsyms") as fp:
        return any(line.split()[2] == symbol for line in fp
                   if len(line.split()) >= 3)


ENTRY = "pagefault: new anonymous pages from "


def check_entry(r, text):
    """Only folio_add_new_anon_rmap where the kernel has it (6.3 - 6.7
    keep page_add_new_anon_rmap as its wrapper: both would count twice)."""
    want = "folio_add_new_anon_rmap" if kernel_has("folio_add_new_anon_rmap") \
        else "page_add_new_anon_rmap"
    got = [l.split(ENTRY, 1)[1].strip() for l in text.splitlines() if ENTRY in l]
    r.check(got == [want], "new pages seen by %s alone (log: %s)" % (want, got))


def case_live_set(args, r, sample_pages=16, tol=0.15):
    """Allocate through every path, release some, read two seconds."""
    extra = [] if sample_pages == 16 else ["--pf_sample_pages=%d" % sample_pages]
    s = Session(args, r.name, ["-m", "32", "-t", "4000"], extra)
    try:
        r.check(s.ready(), "monitor attached and scanned the target")
        s.run()
    finally:
        rc = s.stop()	# the store is complete once the monitor stopped
    r.check(rc == 0, "monitor exit status 0 (%s)" % rc)
    r.check(CLEARED in s.text(), "exit cleared the live set")
    check_entry(r, s.text())
    ph = s.phases()
    before = s.live_set(ph["allocated"], ph["released"])
    after = s.live_set(ph["released"], ph["exit"])
    r.notes.append("INFO allocated: " + fmt(before))
    r.notes.append("INFO released:  " + fmt(after))
    lost = reported_lost(s.text())
    if sample_pages == 1:
        # every page recorded: the total is exact even where a burst made
        # the monitor skip unwinding (charged to its pressure marker), short
        # only by what the monitor reported lost (full kernel buffers)
        total = sum(v for k, v in before.items()
                    if k not in ("[resident before profiling]",))
        check_exact_or_reported(r, s.text(), total, 224 * MIB, "workload")
    # a region may be short by what went stackless or was reported lost
    loose = stackless(before) + lost
    t64, t32 = (sample_tol(m * MIB, sample_pages, tol) for m in (64, 32))
    r.check(close(before["pf_keep_mmap"], 64 * MIB, t64, loose),
            "kept mmap ~64 MiB (%.1f, +-%d%%)" % (before["pf_keep_mmap"] / MIB, 100 * t64))
    for f in ("pf_free_mmap", "pf_dontneed", "pf_mremap_move",
              "pf_heap_trim"):
        r.check(close(before[f], 32 * MIB, t32, loose),
                "%s ~32 MiB while allocated (%.1f, +-%d%%)" %
                (f, before[f] / MIB, 100 * t32))
    for f in ("pf_file_private_write", "pf_shared_anon"):
        r.check(not before[f] and not after[f],
                "%s never counted (file copy on write / shmem)" % f)
    for f in ("pf_free_mmap", "pf_dontneed"):
        r.check(not after[f], "%s gone after its release" % f)
    # glibc keeps its top pad and the page with the break: still resident
    r.check(after["pf_heap_trim"] < MIB,
            "heap shrunk by brk down to glibc's top pad (%d KiB)" %
            (after["pf_heap_trim"] // 1024))
    loose_after = stackless(after) + lost
    r.check(close(after["pf_keep_mmap"], 64 * MIB, t64, loose_after) and
            close(after["pf_mremap_move"], 32 * MIB, t32, loose_after),
            "kept and moved memory still resident after the releases "
            "(%.1f, %.1f)" % (after["pf_keep_mmap"] / MIB,
                              after["pf_mremap_move"] / MIB))
    # huge pages or not (10_thp checks the 2 MiB units): all of it resident,
    # less the first MiB unmapped at the release
    r.check(close(before["pf_thp"], 32 * MIB, t32, loose) and
            close(after["pf_thp"], 31 * MIB, t32, loose_after),
            "pf_thp ~32 MiB, ~31 MiB after a partial munmap (%.1f, %.1f)" %
            (before["pf_thp"] / MIB, after["pf_thp"] / MIB))
    check_drained(r, s.text())
    s.show("00:00:00", "23:59:59")
    rng = s.record_range()
    # snapshots of the last second can land after it on a loaded host
    exit_s = time.strftime("%H:%M:%S", time.localtime(ph["exit"] + 3))
    r.check(rng and rng[1][:8] <= exit_s,
            "nothing recorded after the process exited (%s)" % (rng,))


def case_exact(args, r):
    """--pf_sample_pages=1 records every page: the total is exact."""
    case_live_set(args, r, sample_pages=1, tol=0.05)


def case_baseline(args, r):
    """Memory resident before the profiler attached."""
    s = Session(args, r.name, ["-m", "4", "-t", "1000", "-b", "48"])
    try:
        r.check(s.ready(), "monitor attached and scanned the target")
        s.run()
    finally:
        s.stop()
    live = s.live_set(s.phases()["allocated"])
    r.notes.append("INFO " + fmt(live))
    r.check(near(live["[resident before profiling]"], 48 * MIB, 0.2),
            "pre-existing memory charged to [resident before profiling] "
            "(%.1f)" % (live["[resident before profiling]"] / MIB))


def case_exec_reset(args, r):
    """exec replaces the address space: the live set starts over."""
    s = Session(args, r.name, ["-m", "8", "-t", "1500", "-x"])
    try:
        r.check(s.ready(), "monitor attached and scanned the target")
        s.app.send_signal(signal.SIGUSR1)
        s.app.wait(timeout=60)
        time.sleep(2)
    finally:
        s.stop()
    ph = s.phases()
    before = s.live_set(ph["allocated"])
    after = s.live_set(ph["exit"])	# "exit" is the exec; sleep 3 runs on
    r.notes.append("INFO before exec: " + fmt(before))
    r.notes.append("INFO after exec: " + fmt(after))
    r.check(close(before["pf_keep_mmap"], 16 * MIB, sample_tol(16 * MIB, 16, 0.15),
                  stackless(before) + reported_lost(s.text())),
            "kept memory resident before the exec (%.1f of 16 MiB)" %
            (before["pf_keep_mmap"] / MIB))
    r.check(CLEARED in s.text(), "exec detected")
    r.check(not after["pf_keep_mmap"], "old address space gone after exec")


def before_main(stack):
    """A stack of the dynamic loader or of libc before main() was called.

    A stripped loader has no symbols: its frames read "0x... [ld-...]".
    """
    frames = stack.split(";")
    return "main" not in frames and any(
        f.startswith("_dl_") or "[ld-" in f or
        f in ("_start", "__libc_start_main") for f in frames)


def case_cold_start(args, r):
    """--cgroup/--comm/--first_match: the process's memory from its exec."""
    cg = Cgroup("cpa_pf_cold")
    s = Session(args, r.name, ["-m", "8", "-t", "1500", "-b", "16"],
                ["--pf_sample_pages=1"], cgroup=cg)
    try:
        r.check(s.launch_cold(), "monitor waited, then pf_app started in "
                "the cgroup")
        r.check(s.ready(), "pf_app latched at its exec")
        time.sleep(2.5)		# a snapshot of the startup alone
        s.run()
        try:		# first_match ends the session with its process
            s.mon.wait(timeout=60)
        except subprocess.TimeoutExpired:
            pass
        r.check(s.mon.poll() is not None, "session ended with the process")
    finally:
        rc = s.stop()
        cg.remove()
    r.check(rc == 0, "monitor exit status 0 (%s)" % rc)
    text = s.text()
    r.check("first_match finished" in text, "first_match drained and stopped")
    r.check(CLEARED in text, "exit cleared the live set")
    ph = s.phases()
    live = s.live_set(ph["ready"])
    r.notes.append("INFO startup: " + fmt(live))
    early = sum(n for st, n in s.stacks.items() if before_main(st))
    with open(os.path.join(s.dir, "startup_stacks.txt"), "w") as fp:
        for st, n in s.stacks.most_common():
            fp.write("%d %s\n" % (n, st))
    r.notes.append("INFO before main(): %d KiB in %d stacks" % (
        early // 1024, sum(1 for st in s.stacks if before_main(st))))
    # every page counts; where the startup burst overflowed the stack
    # buffer, without its stack
    startup = live["pf_before"] + live["[stack dropped]"] + live["PRESSURE"]
    check_exact_or_reported(r, text, startup, 16 * MIB, "startup")
    r.check(live["pf_before"] >= 8 * MIB,
            "startup allocation charged to its stack (%.2f MiB)" %
            (live["pf_before"] / MIB))
    r.check(not live["[resident before profiling]"],
            "nothing resident before profiling: tracked from the exec")
    r.check(early > 0, "pages of the loader and libc before main() captured")
    after = s.live_set(ph["allocated"])
    r.notes.append("INFO allocated: " + fmt(after))
    r.check(close(after["pf_keep_mmap"], 16 * MIB, 0.05,
                  stackless(after) + reported_lost(text)),
            "workload after startup profiled too (%.1f of 16 MiB)" %
            (after["pf_keep_mmap"] / MIB))
    check_drained(r, text)


def case_leader_exit(args, r):
    """The main thread exits first: the process and its memory stay."""
    s = Session(args, r.name, ["-m", "8", "-t", "3000", "-L"],
                ["--pf_sample_pages=1"])
    try:
        r.check(s.ready(), "monitor attached and scanned the target")
        s.run()
    finally:
        s.stop()
    ph = s.phases()
    live = s.live_set(ph["leader_exit"])
    r.notes.append("INFO after the main thread exited: " + fmt(live))
    check_charged(r, live, "pf_keep_mmap", 16 * MIB,
                  "memory kept while other threads run")
    text = s.text()
    r.check(CLEARED in text, "cleared once the last thread exited")
    gone = s.live_set(ph["exit"] + 1)
    r.check(not gone["pf_keep_mmap"], "nothing left after the process exited")
    check_drained(r, text)


def case_edge_syscalls(args, r):
    """Failed calls, byte lengths and MREMAP_FIXED, taken literally."""
    s = Session(args, r.name, ["-m", "8", "-t", "2500", "-E"],
                ["--pf_sample_pages=1"])
    try:
        r.check(s.ready(), "monitor attached and scanned the target")
        s.run()
    finally:
        s.stop()
    live = s.live_set(s.phases()["allocated"])
    r.notes.append("INFO " + fmt(live))
    with open(os.path.join(s.dir, "app.log")) as fp:
        r.check("pf_edge:" not in fp.read(), "the calls behaved as expected")
    # 8 MiB, less the page of a 1-byte munmap, plus the page moved in;
    # nothing else allocates, so the total is exact even without stacks
    r.check(workload_total(live) == 8 * MIB,
            "failed calls released nothing, lengths count whole pages "
            "(%d of %d bytes)" % (workload_total(live), 8 * MIB))
    check_charged(r, live, "pf_edge", 8 * MIB, "pf_edge's own pages")
    r.check(not live["pf_edge_dest"],
            "MREMAP_FIXED replaced the pages at its target (%d bytes left)" %
            live["pf_edge_dest"])


def case_zero_pages(args, r):
    """Pages only read map the zero page: not resident memory."""
    s = Session(args, r.name, ["-m", "4", "-t", "1000", "-z", "32"],
                ["--pf_sample_pages=1"])
    try:
        r.check(s.ready(), "monitor attached and scanned the target")
        s.run()
    finally:
        s.stop()
    live = s.live_set(s.phases()["allocated"])
    r.notes.append("INFO " + fmt(live))
    r.check(live["[resident before profiling]"] < 2 * MIB,
            "32 MiB of zero pages not charged as resident (%.2f MiB before)" %
            (live["[resident before profiling]"] / MIB))


ONE_PROCESS = "--pagefault profiles exactly one process"
TOO_OLD = ("--pagefault needs Linux 5.4 or later: before 5.4 a full perf "
           "buffer drops sampled pages without the BPF program seeing it")


def kernel_before_5_4(release=None):
    """The running kernel is older than 5.4 (from uname -r)."""
    m = re.match(r"(\d+)\.(\d+)", release or os.uname().release)
    return bool(m) and (int(m.group(1)), int(m.group(2))) < (5, 4)


def case_too_old(args, r):
    """Before 5.4 every case is a refusal to start, with its reason: a
    sampled page lost in a full perf buffer would go unreported there."""
    store = os.path.join(args.work, r.name, "store")
    shutil.rmtree(os.path.dirname(store), ignore_errors=True)
    os.makedirs(store)
    cmd = [args.cpa, "monitor", "--pagefault", "--backend=bpf",
           "--pid=%d" % os.getpid(), "--store_dir=" + store]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                       cwd=store)
    out = p.stdout + p.stderr
    r.check(p.returncode != 0 and TOO_OLD in out,
            "kernel %s: --pagefault refused (exit %d) saying %r" %
            (os.uname().release, p.returncode, TOO_OLD))
NOT_COMBINED = "--pagefault cannot be combined with --offcpu, --oneshot"


def case_refuse(args, r):
    """Setups that cannot be honoured refuse to start, for that reason.

    Each run gets a store directory of its own (two starts in one second
    would name the same store), so a refusal cannot come from anything but
    the setup under test.
    """
    work = os.path.join(args.work, r.name)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    dead = subprocess.Popen(["true"])
    dead.wait()
    for label, extra, reason in (
            ("pid gone", ["--pid=%d" % dead.pid],
             "pagefault: cannot read the pages of pid %d" % dead.pid),
            ("no pid", [], ONE_PROCESS),
            ("rules without --first_match", ["--comm=pf_app"], ONE_PROCESS),
            ("--first_match with --children",
             ["--comm=pf_app", "--first_match", "--children"], ONE_PROCESS),
            ("two pids", ["--pid=1,2"], ONE_PROCESS),
            ("--pid with --children", ["--pid=1", "--children"], ONE_PROCESS),
            ("with --offcpu", ["--pid=1", "--offcpu"], NOT_COMBINED),
            ("with --oneshot", ["--pid=1", "--oneshot"], NOT_COMBINED),
            ("with exit capture", ["--pid=1", "--enable_exit_capture"],
             NOT_COMBINED),
            ("with coredump capture", ["--pid=1", "--enable_coredump_capture"],
             NOT_COMBINED),
            ("with --probe", ["--pid=1", "--probe=kprobe:do_nanosleep"],
             NOT_COMBINED),
            ("with --datapath=ringbuf", ["--pid=1", "--datapath=ringbuf"],
             NOT_COMBINED),
            ("with --kernel_stack", ["--pid=1", "--kernel_stack"],
             "--pagefault cannot be combined with --kernel_stack"),
            ("with --record_interval=2", ["--pid=1", "--record_interval=2"],
             "--pagefault needs --record_interval=1"),
            ("--pf_sample_pages=3", ["--pid=1", "--pf_sample_pages=3"],
             "--pf_sample_pages must be a power of two from 1 to 512"),
            ("--pf_sample_pages=1024", ["--pid=1", "--pf_sample_pages=1024"],
             "--pf_sample_pages must be a power of two from 1 to 512"),
            ("with backend=perf", ["--pid=1", "--backend=perf"],
             "--pagefault requires backend=bpf")):
        backend = [] if any(e.startswith("--backend=") for e in extra) else \
            ["--backend=bpf"]
        store = tempfile.mkdtemp(prefix="store_", dir=work)
        cmd = [args.cpa, "monitor", "--pagefault",
               "--store_dir=" + store] + \
            backend + extra
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                           cwd=store)
        out = p.stdout + p.stderr
        r.check(p.returncode != 0 and reason in out,
                "%s: refused (exit %d) saying %r" % (label, p.returncode, reason))


def thp_attempt(args, r, name):
    s = Session(args, name, ["-m", "32", "-t", "2000"])
    huge = {}

    def read_smaps():
        addr = s.region("thp")
        huge["bytes"] = s.huge_bytes(addr) if addr else None

    try:
        r.check(s.ready(), "monitor attached and scanned the target")
        s.run({"allocated": read_smaps})
    finally:
        s.stop()
    ph = s.phases()
    return (s.text(), s.live_set(ph["allocated"]), s.live_set(ph["released"]),
            huge.get("bytes"))


def case_thp(args, r):
    """A huge page is never sampled out and counts its exact bytes.

    Only where the kernel backed the range by huge pages.  When memory is
    too fragmented for 2 MiB pages, it is compacted once and the case run
    again; THP disabled, or still fragmented, is reported as a skip.
    """
    for attempt in (1, 2):
        text, before, after, got = thp_attempt(args, r, "%s_%d" % (r.name, attempt))
        r.notes.append("INFO attempt %d: THP mode %s, %s of 32 MiB in huge "
                       "pages; profile %.2f MiB, %.2f MiB after unmapping "
                       "1 MiB" % (attempt, thp_mode(), got if got is None else
                                  "%.1f MiB" % (got / MIB),
                                  before["pf_thp"] / MIB, after["pf_thp"] / MIB))
        if not r.check(got is not None, "pf_thp range found in smaps"):
            return
        if got:
            # 1 in 16 pages sampled, but a THP always, with its weight
            r.check(before["pf_thp"] >= got,
                    "every huge page counted although 1 in 16 pages is "
                    "sampled (%.2f >= %.2f MiB)" % (before["pf_thp"] / MIB,
                                                    got / MIB))
        if got == 32 * MIB or thp_mode() == "never" or attempt == 2:
            break
        try:
            with open("/proc/sys/vm/compact_memory", "w") as fp:
                fp.write("1")
        except OSError:
            break
        r.notes.append("INFO memory compacted for 2 MiB pages, run again")
    if got == 0:
        r.skipped("the kernel gave pf_thp no huge page (THP mode %s): "
                  "2 MiB accounting not exercised" % thp_mode())
        return
    if got < 32 * MIB:
        r.skipped("only %.1f of 32 MiB got huge pages (fragmented memory): "
                  "exact totals not checked" % (got / MIB))
        return
    r.check(before["pf_thp"] == 32 * MIB,
            "16 THPs counted as exactly 32 MiB (%d bytes)" % before["pf_thp"])
    r.check(after["pf_thp"] == 31 * MIB,
            "unmapping 1 MiB of a THP removed exactly 1 MiB (%d bytes)" %
            after["pf_thp"])
    check_drained(r, text)


def case_fork_cow(args, r):
    """A forked child is another process; copy on write is not more memory."""
    # hold > 2 s: the snapshot after a phase is taken up to 2 s later
    s = Session(args, r.name, ["-m", "16", "-t", "3000", "-F"],
                ["--pf_sample_pages=1"])
    try:
        r.check(s.ready(), "monitor attached and scanned the target")
        s.run()
    finally:
        s.stop()
    text = s.text()
    with open(os.path.join(s.dir, "app.log")) as fp:
        r.check("pf_fork_cow:" not in fp.read(), "fork and pipes worked")
    ph = s.phases()
    cow = s.live_set(ph["cow"])
    live = s.live_set(ph["child_exit"])
    r.notes.append("INFO after the parent's writes: " + fmt(cow))
    r.notes.append("INFO after the child exited: " + fmt(live))
    for snap, when in ((cow, "while the child lives"),
                       (live, "after the child exited")):
        # only pf_keep_mmap allocates in the target: the total is exact
        r.check(workload_total(snap) == 16 * MIB,
                "copied pages counted once %s (%d bytes)" %
                (when, workload_total(snap)))
        check_charged(r, snap, "pf_keep_mmap", 16 * MIB,
                      "copies keep their first stack " + when)
        r.check(not snap["pf_cow_write"] and not snap["pf_child_touch"],
                "no copy charged to the writer, nothing of the child %s" % when)
    r.check(text.count(CLEARED) == 1 and
            "pid %d %s" % (s.app.pid, CLEARED) in text,
            "only the parent's own exit cleared its live set")
    st = check_drained(r, text)
    # the parent's copies did fault: seen and recognised as live addresses
    r.check(st.get("duplicates", 0) >= 16 * MIB // 4096,
            "the parent's %d copy-on-write faults seen as duplicates (%s)" %
            (16 * MIB // 4096, st.get("duplicates")))


MTHP_DIR = "/sys/kernel/mm/transparent_hugepage"
KPF_COMPOUND_HEAD, KPF_COMPOUND_TAIL = 15, 16


def folio_sizes(pid, addr, length):
    """{folio bytes: bytes of [addr, addr + length) in folios that size},
    from /proc/PID/pagemap and /proc/kpageflags (a folio is a compound
    head and its tails); None where a page is not present."""
    pages = length // 4096
    with open("/proc/%d/pagemap" % pid, "rb") as fp:
        fp.seek(addr // 4096 * 8)
        raw = fp.read(pages * 8)
    pfns = []
    for i in range(pages):
        e = int.from_bytes(raw[i * 8:i * 8 + 8], "little")
        pfns.append(e & ((1 << 55) - 1) if e >> 63 else None)
    if None in pfns or not any(pfns):
        return None
    heads = []
    with open("/proc/kpageflags", "rb") as fp:
        for pfn in pfns:
            fp.seek(pfn * 8)
            f = int.from_bytes(fp.read(8), "little")
            heads.append("head" if f >> KPF_COMPOUND_HEAD & 1 else
                         "tail" if f >> KPF_COMPOUND_TAIL & 1 else "single")
    sizes = collections.Counter()
    i = 0
    while i < pages:
        n = 1
        if heads[i] == "head":
            while i + n < pages and heads[i + n] == "tail":
                n += 1
        sizes[n * 4096] += n * 4096
        i += n
    return dict(sizes)


def fmt_sizes(sizes):
    return ", ".join("%d KiB: %.1f MiB" % (k // 1024, v / MIB)
                     for k, v in sorted((sizes or {}).items()))


def folio_run(args, r, name, sample_pages):
    """pf_app -H: 32 MiB, then 1 MiB from 32 KiB in dropped by MADV_DONTNEED."""
    extra = [] if sample_pages == 16 else ["--pf_sample_pages=%d" % sample_pages]
    s = Session(args, name, ["-m", "32", "-t", "2000", "-H"], extra)
    seen = {}

    def read_sizes():
        addr = s.region("folio")
        seen["sizes"] = folio_sizes(s.app.pid, addr, 32 * MIB) if addr else None

    try:
        r.check(s.ready(), "monitor attached and scanned the target")
        s.run({"allocated": read_sizes})
    finally:
        s.stop()
    text = s.text()
    ph = s.phases()
    return (text, s.live_set(ph["allocated"], ph["released"]),
            s.live_set(ph["released"], ph["exit"]), seen.get("sizes"))


def check_folio_totals(r, text, before, after, sample_pages, unit, what):
    """32 MiB less 1 MiB cut out of folios of @unit bytes: exact where a
    folio is at least N pages (always sampled, its own size), within the
    sampling error of folios when smaller.  pf_folio is all pf_app -H
    allocates: pages whose stack was dropped count in the total too."""
    got_b, got_a = workload_total(before), workload_total(after)
    if unit // 4096 >= sample_pages:
        check_exact_or_reported(r, text, got_b, 32 * MIB,
                                "%s at 1 in %d" % (what, sample_pages))
        check_exact_or_reported(r, text, got_a, 31 * MIB,
                                "%s at 1 in %d, after MADV_DONTNEED of 1 MiB "
                                "across folios" % (what, sample_pages))
        return
    units = 32 * MIB / unit
    tol = max(0.05, 6 * math.sqrt((sample_pages * 4096 / unit - 1) / units))
    lost = reported_lost(text)
    r.check(close(got_b, 32 * MIB, tol, lost) and close(got_a, 31 * MIB, tol, lost),
            "%s: ~32 MiB, ~31 MiB after the MADV_DONTNEED at 1 in %d "
            "(%.2f, %.2f, +-%d%%)" % (what, sample_pages, got_b / MIB,
                                       got_a / MIB, 100 * tol))


def case_thp_dontneed(args, r):
    """MADV_DONTNEED of part of 2 MiB pages: their bytes go in proportion."""
    for attempt in (1, 2):
        text, before, after, sizes = folio_run(args, r, "%s_%d" % (r.name, attempt), 16)
        r.notes.append("INFO attempt %d: THP mode %s, folios %s; profile "
                       "%.2f MiB, %.2f MiB after" % (attempt, thp_mode(),
                       fmt_sizes(sizes), before["pf_folio"] / MIB,
                       after["pf_folio"] / MIB))
        if not r.check(sizes is not None, "pf_folio pages found in pagemap"):
            return
        if sizes.get(2 * MIB) == 32 * MIB or thp_mode() == "never" or attempt == 2:
            break
        try:
            with open("/proc/sys/vm/compact_memory", "w") as fp:
                fp.write("1")
        except OSError:
            break
    if sizes.get(2 * MIB) != 32 * MIB:
        r.skipped("the kernel did not back all of pf_folio by 2 MiB pages "
                  "(THP mode %s, %s): partial release of a THP not checked" %
                  (thp_mode(), fmt_sizes(sizes)))
        return
    check_folio_totals(r, text, before, after, 16, 2 * MIB, "2 MiB pages")
    check_drained(r, text)


def mthp_settings():
    try:
        return {d: open(os.path.join(MTHP_DIR, d, "enabled")).read()
                for d in os.listdir(MTHP_DIR) if d.startswith("hugepages-")}
    except OSError:
        return {}


def mthp_set(sizes, mode_of):
    for d, cur in sizes.items():
        want = mode_of(d) if callable(mode_of) else \
            re.search(r"\[(\w+)\]", mode_of[d]).group(1)
        with open(os.path.join(MTHP_DIR, d, "enabled"), "w") as fp:
            fp.write(want)


def case_mthp(args, r):
    """6.8+ multi-size THP: 64 KiB folios, sampled in proportion to size.

    Only 64 KiB is enabled (2 MiB never): every folio is 16 pages, so 1 in
    1 and 1 in 16 are exact, 1 in 64 within the error of 512 folios.  The
    kernel's folio sizes are read from /proc/kpageflags; fewer than all
    64 KiB is a skip of the exact checks, not a pass.
    """
    saved = mthp_settings()
    if "hugepages-64kB" not in saved:
        r.skipped("no multi-size THP on this kernel (6.8+): %s has no "
                  "hugepages-64kB" % MTHP_DIR)
        return
    try:
        mthp_set(saved, lambda d: "always" if d == "hugepages-64kB" else "never")
        for n in (1, 16, 64):
            text, before, after, sizes = folio_run(args, r, "%s_n%d" % (r.name, n), n)
            r.notes.append("INFO 1 in %d: folios %s; profile %s; after %s" %
                           (n, fmt_sizes(sizes), fmt(before), fmt(after)))
            if not r.check(sizes is not None, "pf_folio pages found in pagemap"):
                continue
            if n == 1:
                check_exact_or_reported(r, text, workload_total(before),
                                        32 * MIB, "1 in 1, folios of any size")
                check_exact_or_reported(r, text, workload_total(after),
                                        31 * MIB, "1 in 1, after the MADV_DONTNEED")
            if sizes.get(64 * 1024) != 32 * MIB:
                r.skipped("1 in %d: the kernel did not back all of pf_folio "
                          "by 64 KiB folios (%s)" % (n, fmt_sizes(sizes)))
                continue
            if n > 1:
                check_folio_totals(r, text, before, after, n, 64 * 1024,
                                   "64 KiB folios")
            check_drained(r, text)
    finally:
        mthp_set(saved, saved)


def case_dontunmap(args, r):
    """mremap(MREMAP_DONTUNMAP) moves the pages and leaves the old range
    empty: both the moved pages and the refilled range are resident.  4 MiB:
    a short burst, so that the stacks fit the buffers of a slow guest."""
    s = Session(args, r.name, ["-m", "4", "-t", "2500", "-D"],
                ["--pf_sample_pages=1"])
    try:
        r.check(s.ready(), "monitor attached and scanned the target")
        s.run()
    finally:
        s.stop()
    with open(os.path.join(s.dir, "app.log")) as fp:
        if "pf_dontunmap: unsupported" in fp.read():
            r.skipped("MREMAP_DONTUNMAP not supported (5.7+)")
            return
    ph = s.phases()
    live = s.live_set(ph["allocated"], ph["released"])
    gone = s.live_set(ph["released"], ph["exit"])
    r.notes.append("INFO moved: " + fmt(live))
    r.notes.append("INFO moved range unmapped: " + fmt(gone))
    check_charged(r, live, "pf_dontunmap", 4 * MIB,
                  "moved pages keep their stack")
    check_charged(r, live, "pf_refill", 4 * MIB, "the emptied range refilled")
    check_exact_or_reported(r, s.text(), workload_total(live), 8 * MIB,
                            "moved and refilled, counted once each")
    r.check(not gone["pf_dontunmap"],
            "nothing left of the moved range once unmapped (%d bytes)" %
            gone["pf_dontunmap"])
    check_exact_or_reported(r, s.text(), workload_total(gone), 4 * MIB,
                            "the refill alone after the moved range went")
    check_drained(r, s.text())


CASES = [
    ("01_live_set", case_live_set),
    ("02_exact_n1", case_exact),
    ("03_baseline", case_baseline),
    ("04_exec_reset", case_exec_reset),
    ("05_refuse", case_refuse),
    ("06_cold_start", case_cold_start),
    ("07_leader_exit", case_leader_exit),
    ("08_edge_syscalls", case_edge_syscalls),
    ("09_zero_pages", case_zero_pages),
    ("10_thp", case_thp),
    ("11_fork_cow", case_fork_cow),
    ("12_thp_dontneed", case_thp_dontneed),
    ("13_mthp", case_mthp),
    ("14_dontunmap", case_dontunmap),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cpa", required=True)
    parser.add_argument("--app", required=True)
    parser.add_argument("--work", default=os.path.join(tempfile.gettempdir(),
                                                       "cpa_pf_e2e"))
    parser.add_argument("--unwind_workers", type=int, default=1)
    parser.add_argument("--only", default="")
    parser.add_argument("--json", default="")
    args = parser.parse_args()
    args.cpa = os.path.abspath(args.cpa)
    args.app = os.path.abspath(args.app)
    os.makedirs(args.work, exist_ok=True)

    only = [o for o in args.only.split(",") if o]
    too_old = kernel_before_5_4()
    results = []
    for name, fn in CASES:
        if only and not any(name.startswith(o) for o in only):
            continue
        r = Result(name)
        t0 = time.time()
        try:
            (case_too_old if too_old else fn)(args, r)
        except Exception as exc:  # report and keep going
            r.check(False, "exception: %r at %s" % (
                exc, " <- ".join("%s:%d" % (f.name, f.lineno) for f in
                                 reversed(traceback.extract_tb(exc.__traceback__)))))
        r.notes.append("INFO duration %.1fs" % (time.time() - t0))
        results.append(r)
        print("[%s] %s" % ("FAIL" if not r.ok else "SKIP" if r.skip else "PASS",
                            name), flush=True)
        for note in r.notes:
            print("    " + note, flush=True)
    if args.json:
        with open(args.json, "w") as fp:
            json.dump([{"name": r.name, "ok": r.ok, "skip": r.skip,
                        "notes": r.notes}
                       for r in results], fp, indent=2)
    failed = [r.name for r in results if not r.ok]
    print("SUMMARY: %d/%d passed%s" % (len(results) - len(failed), len(results),
                                       " failed=" + ",".join(failed) if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
