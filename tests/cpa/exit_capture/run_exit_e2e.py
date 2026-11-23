#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance
"""End-to-end checks for cpa monitor --enable_exit_capture.

One monitor session per case set selects copies of exit_app by --comm; each
copy (its own comm) takes one exit path.  The expected samples per comm:

  ex_sysexit  leader raw SYS_exit(7), no group exit       nothing (the
              documented boundary: no do_exit hook)
  ex_worker   worker exit_group(3), leader in pthread_join exit=3
  ex_ldexit   leader pthread_exit(0), worker exit_group(1) exit=1
  ex_ldkill   leader pthread_exit(0), SIGKILL from outside sig=9
  ex_term     SIGTERM from outside                         sig=15
  ex_race     two threads exit_group(5)/(6) at once        one sample,
              code of the first entrant (may differ from the kept one)
  ex_segv     SIGSEGV, exit capture only                   sig=11
  ex_zero     exit_group(0)                                nothing
  nx_worker   ex_worker's path under a comm the session    nothing (target
              does not select                              filtering)
  ex_exec     a worker thread execs a program that exits 0 nothing (the
              (own session) leader is zapped by de_thread(), group code 0)
  exit+core   ex_segv with --enable_coredump_capture       one COREDUMP,
              no EXIT (the dump claims the instance); ex_worker exit=3;
              ex_busy: 2 s on CPU, then exit_group(4)      exit=4;
              ex_nullcall: a call through NULL (PC 0)      one COREDUMP
  conflicts   --offcpu / --oneshot / --probe / --kernel_stack refused at init
              (coredump capture: --offcpu / --oneshot / --probe refused too),
              or no target at all; --exit_comm without --enable_exit_capture,
              --exit_comm with --exit_pid, an --exit_pid that is not running
  exit_comm   --exit_comm=ex_worker,ex_busy and no global selection: one EXIT
              each, nothing for the nx_ copies, which are still sampled on
              CPU; the EXIT record of ex_busy (sampled while it ran) carries
              its own POD_NAME as the env label
  exit_pid    --exit_pid=P of a copy started before the monitor: P's SIGTERM
              is recorded (its POD_NAME, read at start, satisfies
              --exit_target_env_values), a second copy of the same name is not
  target_env  --exit_comm with --exit_target_env_name=MY_POD_NAME,POD_NAME,
              --exit_target_env_values=job-x and
              --exit_target_env_value_prefix=msrv- and no global selection:
              recorded are the processes whose value satisfies it when they
              were selected -- at the start scan (ex_term, started first),
              at exec (ex_worker; ex_exact, an exact value; ex_myfirst,
              MY_POD_NAME first; nx_execin execing ex_execin), at fork
              (ex_fork's child, no exec).  Dropped and counted as mismatches:
              ex_short (other-, 50 ms before its exit), ex_mylast
              (MY_POD_NAME=other- hides POD_NAME=msrv-), ex_unset (none set).
              ex_flash exits at once: each of its 5 exits is recorded or
              counted as unknown.  ex_execout execs nx_execout: not recorded;
              nx_ copies: not recorded.  No record has an EXIT ENV frame
  target_env_dyn  the same beside a global --comm selection (target_ctl
              serves both): ex_worker recorded, ex_other dropped, nx_busy
              still sampled
  target_env_kprobe  the exec hook forced to kretprobe/setup_new_exec (4.14
              when another program owns sched_process_exec): told before the
              loader sets up the environ, ex_worker and ex_execin are still
              read and recorded
  unset       without --exit_target_env_name nothing is dropped
  list_exit   (in target_env) cpa show --list_exit lists the recorded
              exits, each with its code and no Exit Env line

Each EXIT marker must decode its raw wait(2) status consistently and sit on
the do_group_exit hook.  The stack is unwound once the process is gone, with
the view of its mappings read while it lived: ex_busy runs on CPU first, so
its user frames are required; the other modes sleep from their start and are
never sampled before they exit, so their user part may be missing (a known
limit, see docs/en/usage.md).  The monitor's Exit Capture Count must equal
the number of instances recorded: exit_claim lets exactly one event per
instance reach userspace.

Standard library only, so it also runs in minimal VM guests.

    run_exit_e2e.py --cpa BIN --app EXIT_APP [--work DIR] [--json OUT]
                    [--unwind_workers N]
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

# the monitor prints this once every hook is attached (4.14 takes seconds)
MONITOR_READY = "Init SUCCESS workers"
MONITOR_STARTUP_TIMEOUT_SEC = 60
MONITOR_DURATION_SEC = 20
EXIT_RE = re.compile(r"<# EXIT NONZERO raw=(-?\d+) (.*?) #>")
ENV_RE = re.compile(r"<# EXIT ENV (.*?) #>")  # removed; must not appear
CORE_RE = re.compile(r"<# COREDUMP (\S+)")
STAT_RE = re.compile(r"Exit Capture Count: (\d+)"
                     r" Exit Env Mismatch Drop: (\d+) Exit Env Unknown Drop: (\d+)")
# the record was unwound once the process was gone: no user frames, no label
GONE = "<# PROCESS EXIT #>"
# a frame-pointer chain from a libc leaf (syscall) skips the leaf's caller,
# which only the link register holds on arm64: the thread's entry remains
BUSY_FRAMES = ("busy_exit_fn", "start_thread")
EXIT_ONLY = ("sysexit", "worker", "ldexit", "ldkill", "term", "race", "segv",
             "zero")
# functions of exit_app.c a sampled user stack may end in
APP_FUNCS = ("worker_exit_fn", "worker_late_exit_fn", "worker_spin_fn",
             "spin_forever", "race_fn", "segv_fn", "exec_fn", "busy_exit_fn",
             "main+")


def comm(mode):
    return "ex_" + mode


def decode_status(raw):
    """The marker text wait(2) status raw must produce."""
    if raw & 0x7f == 0:
        return "exit=%d" % ((raw >> 8) & 0xff)
    return "sig=%d core=%d" % (raw & 0x7f, 1 if raw & 0x80 else 0)


class Session:
    def __init__(self, args, name, modes, extra, bystanders=(), select=None,
                 env=None, files=(), argv=None, repeat=None,
                 monitor_env=None):
        self.args = args
        self.modes = modes
        # per copy: environment added to its own
        self.env = env or {}
        # per copy: arguments after its mode, from the session
        self.argv = argv or {}
        # per copy: how many to start one after another (default 1)
        self.repeat = repeat or {}
        # names copied but never started directly (exec targets)
        self.files = files
        # copies started before the monitor (by @select)
        self.pre = {}
        # (comm, mode): copies the session does not select
        self.bystanders = dict(bystanders)
        self.dir = os.path.join(args.work, name)
        self.store = os.path.join(self.dir, "store")
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.store)
        self.bins = {}
        for mode in modes:
            dst = os.path.join(self.dir, comm(mode))
            shutil.copy2(args.app, dst)
            self.bins[mode] = dst
        for name_ in tuple(self.bystanders) + tuple(files):
            dst = os.path.join(self.dir, name_)
            shutil.copy2(args.app, dst)
            self.bins[name_] = dst
        # the selection: by default the global one, by the copies' names
        selection = (select(self) if select else
                     ["--comm", ",".join(comm(m) for m in modes)])
        cmd = [args.cpa, "monitor", "--store_dir", self.store,
               "--backend=bpf", "--freq=9",
               "--duration", str(MONITOR_DURATION_SEC)] + selection + [
               "--enable_exit_capture", "--log_print_cycles=300",
               "--stack_size=65536",
               "--unwind_workers=%d" % args.unwind_workers] + extra
        self.log = open(os.path.join(self.dir, "monitor.log"), "w")
        menv = dict(os.environ)
        menv.update(monitor_env or {})
        self.monitor = subprocess.Popen(cmd, stdout=self.log,
                                        stderr=subprocess.STDOUT, env=menv)
        deadline = time.monotonic() + MONITOR_STARTUP_TIMEOUT_SEC
        path = os.path.join(self.dir, "monitor.log")
        while MONITOR_READY not in open(path, errors="replace").read():
            if self.monitor.poll() is not None:
                raise RuntimeError("monitor exited early rc=%d"
                                   % self.monitor.returncode)
            if time.monotonic() > deadline:
                raise RuntimeError("monitor not ready after %d s"
                                   % MONITOR_STARTUP_TIMEOUT_SEC)
            time.sleep(0.1)
        # the exec and fork hooks are attached by then, the scan has run
        time.sleep(0.5)

    def start(self, key, mode):
        env = dict(os.environ)
        for name in ("POD_NAME", "MY_POD_NAME", "APP_ID"):
            env.pop(name, None)  # only what the case gives
        env.update(self.env.get(key, {}))
        extra = self.argv[key](self) if key in self.argv else []
        return subprocess.Popen([self.bins[key], mode] + extra, env=env)

    def run(self):
        procs = dict(self.pre)
        # pid of each copy started once
        self.procs_pid = {k: p.pid for k, p in procs.items()}
        for key, mode in [(m, m) for m in self.modes] + list(
                self.bystanders.items()):
            if key in procs:
                continue
            if key in self.repeat:
                # one after another: each a fresh instance of the name
                rcs = []
                for _ in range(self.repeat[key]):
                    rcs.append(self.start(key, mode).wait(timeout=10))
                    time.sleep(0.05)
                procs[key] = rcs
                continue
            procs[key] = self.start(key, mode)
            self.procs_pid[key] = procs[key].pid
        time.sleep(2)
        for key, p in procs.items():
            mode = self.bystanders.get(key, key)
            if mode == "ldkill":
                p.send_signal(signal.SIGKILL)
            elif mode == "term":
                p.send_signal(signal.SIGTERM)
        return {m: p if isinstance(p, list) else p.wait(timeout=10)
                for m, p in procs.items()}

    def finish(self):
        try:
            self.monitor.wait(timeout=MONITOR_DURATION_SEC + 30)
        except subprocess.TimeoutExpired:
            self.monitor.send_signal(signal.SIGINT)
            self.monitor.wait(timeout=20)
        self.log.close()
        subdirs = sorted(d for d in os.listdir(self.store)
                         if d.startswith("cpa_"))
        out = os.path.join(self.dir, "all.prof")
        with open(os.path.join(self.dir, "show.log"), "w") as log:
            rc = subprocess.run(
                [self.args.cpa, "show", "--read",
                 os.path.join(self.store, subdirs[-1]), "-o", out,
                 "--starttime=00:00:00", "--endtime=23:59:59", "--show_raw"],
                stdout=log, stderr=subprocess.STDOUT, timeout=180,
                cwd=self.dir).returncode
        if rc != 0:
            raise RuntimeError("cpa show failed with %d" % rc)
        samples = {m: {"exit": [], "core": [], "stacks": [], "labels": [],
                       "env": [], "cpu": 0}
                   for m in tuple(self.modes) +
                   tuple(f[3:] if f.startswith("ex_") else f
                         for f in tuple(self.bystanders) + tuple(self.files))}
        # EXIT ENV frames anywhere (none since --exit_record_env_name is gone)
        samples["_env_frames"] = 0
        with open(out, errors="replace") as fp:
            for line in fp:
                stack, _, n = line.rstrip("\n").rpartition(" ")
                if not stack:
                    continue
                if ENV_RE.search(stack):
                    samples["_env_frames"] += int(n)
                # --show_raw: "<thread comm> <process comm> -cg-cpu-pid|ENV;frames"
                owner = stack.split()[0]
                mode = owner[3:] if owner.startswith("ex_") else owner
                if mode not in samples:
                    continue
                m_exit = EXIT_RE.search(stack)
                m_core = CORE_RE.search(stack)
                for _ in range(int(n)):
                    m = EXIT_RE.search(stack)
                    if m:
                        decoded = m.group(2)
                        if decode_status(int(m.group(1))) != decoded:
                            decoded = "MISDECODED(%s)" % m.group(0)
                        samples[mode]["exit"].append(decoded)
                    m = CORE_RE.search(stack)
                    if m:
                        samples[mode]["core"].append(m.group(1))
                    # an EXIT or COREDUMP record; other markers (PRESSURE
                    # DROP, PROCESS EXIT) are on CPU samples
                    if m_exit or m_core:
                        samples[mode]["stacks"].append(stack)
                        # the env label: after "|" in the metadata frame
                        meta = stack.split(";")[0]
                        samples[mode]["labels"].append(
                            meta.split("|", 1)[1] if "|" in meta else None)
                    else:
                        samples[mode]["cpu"] += 1
        # the last statistics line is printed at shutdown
        log = open(os.path.join(self.dir, "monitor.log"),
                   errors="replace").read()
        stats = STAT_RE.findall(log)
        # no coredump counter: the COREDUMP records stored
        cores = sum(len(v["core"]) for k, v in samples.items()
                    if not k.startswith("_"))
        samples["_count"] = ({"core": cores,
                              "exit": int(stats[-1][0])} if stats else None)
        samples["_drop"] = ({"mismatch": int(stats[-1][1]),
                             "unknown": int(stats[-1][2])} if stats else None)
        return samples


def user_part(stack):
    """The frames between a stack's EXIT/COREDUMP marker and its kernel part."""
    frames = stack.split(";")
    for i, frame in enumerate(frames):
        if frame.startswith("<# EXIT") or frame.startswith("<# COREDUMP"):
            user = []
            for f in frames[i + 1:]:
                if "_[k]" in f:
                    break
                if not f.startswith("<# "):  # a marker is no user frame
                    user.append(f)
            return user
    return None


def list_exit(session):
    """cpa show --list_exit of the session's store: {pid: block text}."""
    subdirs = sorted(d for d in os.listdir(session.store)
                     if d.startswith("cpa_"))
    out = os.path.join(session.dir, "exit_list.txt")
    proc = subprocess.run(
        [session.args.cpa, "show", "--read",
         os.path.join(session.store, subdirs[-1]), "--list_exit",
         "--starttime=00:00:00", "--endtime=23:59:59", "--output_prof", out],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True, timeout=180, cwd=session.dir)
    if proc.returncode != 0:
        raise RuntimeError("cpa show --list_exit failed with %d"
                           % proc.returncode)
    blocks = {}
    for block in open(out, errors="replace").read().split(
            "========== Exit Sample ")[1:]:
        m = re.search(r"^  PID        : (\d+)$", block, re.M)
        if m:
            blocks.setdefault(int(m.group(1)), []).append(block)
    return blocks


def busy_user_part_ok(stacks):
    """Each record's user part is empty (a known limit) or busy's own."""
    return all(not user_part(st) or any(f in st for f in BUSY_FRAMES)
               for st in stacks)


def stack_has(stacks, names):
    """Every recorded stack holds one of names."""
    return bool(stacks) and all(any(n in s for n in names) for s in stacks)


def check(results, cond, msg):
    results.append(("PASS " if cond else "FAIL ") + msg)
    return cond


def case_exit_only(args, results):
    s = Session(args, "exit_only", EXIT_ONLY, [],
                bystanders={"nx_worker": "worker"})
    rcs = s.run()
    got = s.finish()
    check(results, rcs == {"sysexit": 7, "worker": 3, "ldexit": 1,
                           "ldkill": -9, "term": -15, "race": rcs["race"],
                           "segv": -11, "zero": 0, "nx_worker": 3}
          and rcs["race"] in (5, 6),
          "workload exit statuses %s" % rcs)
    want = {"worker": "exit=3", "ldexit": "exit=1",
            "ldkill": "sig=9 core=0", "term": "sig=15 core=0",
            "segv": "sig=11 core=0"}
    for mode, decoded in want.items():
        check(results, got[mode]["exit"] == [decoded],
              "%s: exactly one EXIT %s, got %s"
              % (mode, decoded, got[mode]["exit"]))
    # the code is sampled at entry: the first entrant's, not necessarily the
    # one the kernel keeps
    check(results, got["race"]["exit"] in (["exit=5"], ["exit=6"]),
          "race: exactly one EXIT for two racing exit_group calls, got %s"
          % got["race"]["exit"])
    for mode in ("zero", "sysexit", "nx_worker"):
        check(results, got[mode]["exit"] == [] and got[mode]["stacks"] == [],
              "%s: no EXIT sample, got %s" % (mode, got[mode]["exit"]))
    # one event per instance reached userspace: six non-zero exits
    check(results, got["_count"] == {"core": 0, "exit": 6},
          "monitor counted 6 EXIT events and no COREDUMP, got %s"
          % got["_count"])
    # the thread that entered do_group_exit; these sleep from their start,
    # so their user frames may be missing: the kernel part is required
    for mode in ("worker", "ldexit", "race", "ldkill", "term", "segv"):
        check(results, stack_has(got[mode]["stacks"], ("do_group_exit",)),
              "%s: EXIT stack on do_group_exit" % mode)
    # the caller enters from its syscall (x86_64 do_syscall_64, arm64
    # el0_svc); a zapped thread from get_signal
    worker = "".join(got["worker"]["stacks"])
    syscall_entry = any(entry in worker for entry in ("do_syscall_64", "el0_svc"))
    check(results, syscall_entry and "get_signal" not in worker,
          "worker: the exit_group caller's stack, not a zapped thread's")
    check(results, got["_env_frames"] == 0,
          "no EXIT ENV frame, got %d" % got["_env_frames"])
    check(results, got["_drop"] == {"mismatch": 0, "unknown": 0},
          "no --exit_target_env_name: nothing dropped, got %s" % got["_drop"])
    return got


def case_exit_and_core(args, results):
    s = Session(args, "exit_core", ("segv", "worker", "busy", "nullcall"),
                ["--enable_coredump_capture"])
    rcs = s.run()
    got = s.finish()
    check(results, rcs == {"segv": -11, "worker": 3, "busy": 4,
                           "nullcall": -11},
          "workload exit statuses %s" % rcs)
    check(results, got["nullcall"]["core"] == ["SIGSEGV"]
          and stack_has(got["nullcall"]["stacks"], ("do_coredump", "vfs_coredump")),
          "nullcall: one COREDUMP stack on the coredump hook")
    # busy is selected at exec: its view of the mappings may have been read
    # while its loader still ran (no libc yet), and a pid's mappings are
    # re-read at most once per 30-90 s.  Then no leaf in libc resolves, on
    # CPU or at the exit, and the record is unwound after busy is gone: its
    # user part can be empty (docs: a known limit).  When it has one, it must
    # be busy's own.
    stacks = got["busy"]["stacks"]
    check(results, got["busy"]["exit"] == ["exit=4"]
          and stack_has(stacks, ("do_group_exit",))
          and busy_user_part_ok(stacks),
          "busy: one EXIT exit=4 on do_group_exit, its user part busy's own "
          "or empty, got %s %s" % (got["busy"]["exit"], stacks))
    check(results, got["segv"]["core"] == ["SIGSEGV"],
          "segv: exactly one COREDUMP, got %s" % got["segv"]["core"])
    check(results, got["segv"]["exit"] == [],
          "segv: the dump suppresses EXIT, got %s" % got["segv"]["exit"])
    check(results, got["worker"]["exit"] == ["exit=3"],
          "worker: EXIT still recorded beside coredump capture, got %s"
          % got["worker"]["exit"])
    # the dump is taken on the faulting thread
    check(results, stack_has(got["segv"]["stacks"], ("do_coredump", "vfs_coredump")),
          "segv: COREDUMP stack on the coredump hook")
    check(results, got["_count"] == {"core": 2, "exit": 2},
          "monitor counted 2 COREDUMP and 2 EXIT, got %s" % got["_count"])
    return got


def case_exec_no_sample(args, results):
    # ex_worker is the positive control: the session does record exits
    s = Session(args, "exec", ("exec", "worker"), [])
    rcs = s.run()
    got = s.finish()
    check(results, rcs == {"exec": 0, "worker": 3},
          "workload exit statuses %s" % rcs)
    check(results, got["worker"]["exit"] == ["exit=3"],
          "worker: the control is recorded, got %s" % got["worker"]["exit"])
    check(results, got["exec"]["exit"] == [],
          "exec: the threads de_thread() kills record nothing, got %s"
          % got["exec"]["exit"])
    check(results, got["_count"] == {"core": 0, "exit": 1},
          "monitor counted only the control's EXIT, got %s" % got["_count"])


def fresh_store(args):
    """A store of its own: two runs started within one second in one store
    would ask for the same directory name, and the second fails before
    capture init, with nothing about the refusal under test."""
    path = tempfile.mkdtemp(prefix="refused_", dir=args.work)
    return path


def case_conflicts_rejected(args, results):
    """Combinations exit capture cannot honour fail at init, before loading."""
    only = "--enable_exit_capture only supports"
    for extra, msg in ((["--pid=1", "--offcpu"], only),
                       (["--pid=1", "--oneshot"], only),
                       (["--pid=1", "--probe=kprobe:do_nanosleep"], only),
                       (["--pid=1", "--kernel_stack"], "needs user stacks"),
                       ([], "--enable_exit_capture requires an explicit "
                            "target")):
        # --oneshot writes its output in the working directory
        store = fresh_store(args)
        proc = subprocess.run(
            [args.cpa, "monitor", "--store_dir", store,
             "--backend=bpf", "--duration=3",
             "--enable_exit_capture"] + extra,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=60, cwd=store)
        msgs = msg if isinstance(msg, tuple) else (msg,)
        check(results, proc.returncode != 0
              and any(m in proc.stdout for m in msgs)
              and "loaded skeleton" not in proc.stdout,
              "%s with --enable_exit_capture is refused (rc=%d)"
              % (extra[-1] if extra else "no target", proc.returncode))
    # exit capture's own selection: refused combinations
    for extra, msg in ((["--exit_comm=ex_x"],
                        "--exit_comm/--exit_pid require --enable_exit_capture"),
                       (["--exit_comm=ex_x", "--exit_target_env_name=POD_NAME",
                         "--exit_target_env_values=x"],
                        "require --enable_exit_capture"),
                       (["--enable_exit_capture", "--exit_comm=ex_x",
                         "--exit_pid=1"],
                        "--exit_pid selects processes directly"),
                       (["--enable_exit_capture", "--exit_pid=2147483646"],
                        "is not a running process"),
                       (["--enable_exit_capture", "--exit_comm=ex_x",
                         "--offcpu"],
                        "--enable_exit_capture only supports"),
                       (["--enable_exit_capture", "--comm=ex_x",
                         "--exit_target_env_name=POD_NAME",
                         "--exit_target_env_values=x"],
                        "--exit_target_env_name requires --exit_comm or "
                        "--exit_pid"),
                       (["--enable_exit_capture", "--exit_comm=ex_x",
                         "--exit_target_env_name=POD_NAME"],
                        "--exit_target_env_name needs"),
                       (["--enable_exit_capture", "--exit_comm=ex_x",
                         "--exit_target_env_value_prefix=msrv-"],
                        "need --exit_target_env_name"),
                       (["--enable_exit_capture", "--exit_comm=ex_x",
                         "--exit_target_env_name=A,,B",
                         "--exit_target_env_values=x"],
                        "--exit_target_env_name")):
        # --oneshot writes its output in the working directory
        store = fresh_store(args)
        proc = subprocess.run(
            [args.cpa, "monitor", "--store_dir", store,
             "--backend=bpf", "--duration=3"] + extra,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=60, cwd=store)
        check(results, proc.returncode != 0 and msg in proc.stdout
              and "loaded skeleton" not in proc.stdout,
              "%s is refused (rc=%d)" % (" ".join(extra), proc.returncode))
    # coredump capture is refused the same way, never silently dropped
    only = "--enable_coredump_capture only supports"
    for extra in (["--offcpu"], ["--oneshot"], ["--probe=kprobe:do_nanosleep"]):
        # --oneshot writes its output in the working directory
        store = fresh_store(args)
        proc = subprocess.run(
            [args.cpa, "monitor", "--store_dir", store,
             "--backend=bpf", "--duration=3", "--pid=1",
             "--enable_coredump_capture"] + extra,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=60, cwd=store)
        check(results, proc.returncode != 0 and only in proc.stdout
              and "loaded skeleton" not in proc.stdout,
              "%s with --enable_coredump_capture is refused (rc=%d)"
              % (extra[-1], proc.returncode))


def case_exit_comm_own_selection(args, results):
    """--exit_comm picks exit capture's processes; sampling stays global."""
    pod = {"POD_NAME": "msrv-e2e"}
    s = Session(args, "exit_comm", ("worker", "busy"),
                ["--record_env_name=POD_NAME"],
                bystanders={"nx_worker": "worker", "nx_busy": "busy"},
                select=lambda s: ["--exit_comm", "ex_worker,ex_busy"],
                env={"worker": pod, "nx_worker": pod, "nx_busy": pod,
                     "busy": {"POD_NAME": "msrv-busy"}})
    rcs = s.run()
    got = s.finish()
    check(results, rcs == {"worker": 3, "busy": 4, "nx_worker": 3,
                           "nx_busy": 4},
          "workload exit statuses %s" % rcs)
    check(results, got["worker"]["exit"] == ["exit=3"]
          and got["busy"]["exit"] == ["exit=4"],
          "the --exit_comm processes: one EXIT each, got %s %s"
          % (got["worker"]["exit"], got["busy"]["exit"]))
    for mode in ("nx_worker", "nx_busy"):
        check(results, got[mode]["exit"] == [] and got[mode]["stacks"] == [],
              "%s: not an exit target, no EXIT, got %s"
              % (mode, got[mode]["exit"]))
    # the global selection is not narrowed by --exit_comm
    check(results, got["nx_busy"]["cpu"] > 0,
          "nx_busy: still sampled on CPU, got %d samples"
          % got["nx_busy"]["cpu"])
    check(results, got["_count"] == {"core": 0, "exit": 2},
          "monitor counted 2 EXIT events, got %s" % got["_count"])
    # environ is gone at the exit: the label was read while it ran
    # unless it was unwound after busy was gone (a loaded host, several
    # workers): then no frame or label could be read (docs: a known limit)
    gone = stack_has(got["busy"]["stacks"], (GONE,))
    check(results, gone or got["busy"]["labels"] == ["msrv-busy"],
          "busy: the EXIT record carries its POD_NAME, got %s"
          % got["busy"]["labels"])
    check(results, gone or busy_user_part_ok(got["busy"]["stacks"]),
          "busy: EXIT stack's user part is busy's own (busy_exit_fn, or "
          "start_thread from a libc leaf by FP) or empty, got %s"
          % got["busy"]["stacks"])
    check(results, got["_env_frames"] == 0,
          "no EXIT ENV frame, got %d" % got["_env_frames"])
    check(results, got["_drop"] == {"mismatch": 0, "unknown": 0},
          "no --exit_target_env_name: nothing dropped, got %s" % got["_drop"])


def case_exit_pid(args, results):
    """--exit_pid records that process, not another of the same name."""
    def select(s):
        for key in ("term", "nx_term"):
            s.pre[key] = s.start(key, "term")
        return ["--exit_pid", str(s.pre["term"].pid)]

    s = Session(args, "exit_pid", ("term",),
                ["--exit_target_env_name=POD_NAME",
                 "--exit_target_env_values=msrv-pid"],
                bystanders={"nx_term": "term"}, select=select,
                env={"term": {"POD_NAME": "msrv-pid"},
                     "nx_term": {"POD_NAME": "msrv-pid"}})
    rcs = s.run()
    got = s.finish()
    check(results, rcs == {"term": -15, "nx_term": -15},
          "workload exit statuses %s" % rcs)
    # read when the monitor started: the process was already running
    check(results, got["term"]["exit"] == ["sig=15 core=0"],
          "the --exit_pid process, its POD_NAME read at start: one EXIT "
          "sig=15, got %s" % got["term"]["exit"])
    check(results, got["nx_term"]["exit"] == [],
          "another process of the same name: no EXIT, got %s"
          % got["nx_term"]["exit"])
    check(results, got["_count"] == {"core": 0, "exit": 1} and
          got["_drop"] == {"mismatch": 0, "unknown": 0},
          "monitor counted 1 EXIT event, none dropped, got %s %s"
          % (got["_count"], got["_drop"]))


TARGET_ENV = ["--exit_target_env_name=MY_POD_NAME,POD_NAME",
              "--exit_target_env_values=job-x",
              "--exit_target_env_value_prefix=msrv-"]


def case_target_env(args, results):
    """--exit_target_env_*: only exits whose environment satisfied it."""
    def select(s):
        # running before the monitor: found by the start scan
        s.pre["term"] = s.start("term", "term")
        return ["--exit_comm",
                "ex_worker,ex_term,ex_short,ex_flash,ex_fork,ex_execin,"
                "ex_execout,ex_exact"]

    pod = lambda pod: {"POD_NAME": pod}
    s = Session(args, "target_env",
                ("worker", "term", "short", "flash", "fork"),
                TARGET_ENV,
                bystanders={"nx_worker": "worker", "nx_execin": "execto",
                            "ex_execout": "execto", "ex_exact": "worker"},
                files=("ex_execin", "nx_execout"),
                argv={"nx_execin": lambda s: [s.bins["ex_execin"], "worker"],
                      "ex_execout": lambda s: [s.bins["nx_execout"],
                                               "worker"]},
                repeat={"flash": 5},
                select=select,
                env={"worker": {"POD_NAME": "msrv-a-1", "APP_ID": "7"},
                     "term": pod("msrv-scan"),
                     "short": pod("other-b-1"),
                     "flash": pod("msrv-flash"),
                     "fork": pod("msrv-fork"),
                     "ex_exact": pod("job-x"),
                     "nx_execin": pod("msrv-execin"),
                     "ex_execout": pod("msrv-execout"),
                     "nx_worker": pod("msrv-nx")})
    rcs = s.run()
    got = s.finish()
    check(results, rcs == {"worker": 3, "term": -15, "short": 1,
                           "flash": [1] * 5, "fork": 0, "ex_execout": 3,
                           "ex_exact": 3, "nx_worker": 3, "nx_execin": 3},
          "workload exit statuses %s" % rcs)
    want = {"worker": (["exit=3"], "exec, prefix msrv-"),
            "term": (["sig=15 core=0"], "start scan"),
            # the forked child's record; the parent exits 0
            "fork": (["exit=2"], "fork"),
            "execin": (["exit=3"], "exec into the name"),
            "exact": (["exit=3"], "exec, exact value job-x")}
    for mode, (codes, when) in want.items():
        check(results, got[mode]["exit"] == codes,
              "%s: recorded %s (read at %s), got %s"
              % (mode, codes, when, got[mode]["exit"]))
    check(results, got["short"]["exit"] == [],
          "short: POD_NAME=other-b-1 does not satisfy it, not recorded, "
          "got %s" % got["short"]["exit"])
    # at once: each exit is recorded, or dropped as unknown
    flash = len(got["flash"]["exit"])
    check(results, got["flash"]["exit"] == ["exit=1"] * flash and
          got["_drop"] is not None and
          flash + got["_drop"]["unknown"] == 5,
          "flash: 5 exits, %d recorded, the rest counted unknown, got %s"
          % (flash, got["_drop"]))
    # ex_execout exits as nx_execout, which is not an exit target
    for mode in ("nx_execout", "nx_worker", "nx_execin"):
        check(results, got[mode]["exit"] == [],
              "%s: not an exit target, no EXIT, got %s"
              % (mode, got[mode]["exit"]))
    check(results, got["_count"] == {"core": 0, "exit": 11} and
          got["_drop"]["mismatch"] == 1,
          "monitor received 11 EXIT events, 1 a mismatch, got %s %s"
          % (got["_count"], got["_drop"]))
    check(results, got["_env_frames"] == 0,
          "no EXIT ENV frame, got %d" % got["_env_frames"])
    # cpa show --list_exit lists the recorded ones, with their code
    blocks = list_exit(s)
    listed = [b for bs in blocks.values() for b in bs]
    check(results, len(listed) == 5 + flash and
          all("Exit       : raw=" in b and "do_group_exit" in b and
              "Exit Env" not in b for b in listed),
          "--list_exit: %d exit samples on do_group_exit, no Exit Env, got %d"
          % (5 + flash, len(listed)))
    worker = blocks.get(s.procs_pid.get("worker"), [])
    check(results, len(worker) == 1 and
          "Exit       : raw=768 exit=3" in worker[0],
          "--list_exit: ex_worker's block has its code")


def case_target_env_names(args, results):
    """The value is the first listed name set; none set does not satisfy."""
    s = Session(args, "target_env_names", ("worker",), TARGET_ENV,
                bystanders={"ex_myfirst": "worker", "ex_mylast": "worker",
                            "ex_unset": "worker"},
                select=lambda s: ["--exit_comm",
                                  "ex_worker,ex_myfirst,ex_mylast,ex_unset"],
                env={"worker": {"MY_POD_NAME": "", "POD_NAME": "msrv-w"},
                     "ex_myfirst": {"POD_NAME": "other-1",
                                    "MY_POD_NAME": "msrv-my"},
                     "ex_mylast": {"MY_POD_NAME": "other-my",
                                   "POD_NAME": "msrv-x"}})
    rcs = s.run()
    got = s.finish()
    check(results, rcs == {"worker": 3, "ex_myfirst": 3, "ex_mylast": 3,
                           "ex_unset": 3},
          "workload exit statuses %s" % rcs)
    for mode, rec, why in (("worker", True, "MY_POD_NAME= is unset"),
                           ("myfirst", True, "MY_POD_NAME is listed first"),
                           ("mylast", False, "MY_POD_NAME=other- wins"),
                           ("unset", False, "none set")):
        check(results, got[mode]["exit"] == (["exit=3"] if rec else []),
              "%s: %s (%s), got %s" % (mode, "recorded" if rec else
                                       "not recorded", why, got[mode]["exit"]))
    check(results, got["_count"] == {"core": 0, "exit": 4} and
          got["_drop"] == {"mismatch": 2, "unknown": 0},
          "monitor received 4 EXIT events, 2 mismatches, got %s %s"
          % (got["_count"], got["_drop"]))


def case_target_env_dynamic(args, results):
    """The same with a global selection: target_ctl serves both."""
    s = Session(args, "target_env_dyn", ("worker",),
                ["--exit_target_env_name=POD_NAME",
                 "--exit_target_env_values=msrv-dyn"],
                bystanders={"nx_busy": "busy", "ex_other": "worker"},
                select=lambda s: ["--comm", "nx_busy",
                                  "--exit_comm", "ex_worker,ex_other"],
                env={"worker": {"POD_NAME": "msrv-dyn"},
                     "ex_other": {"POD_NAME": "msrv-dyn2"}})
    rcs = s.run()
    got = s.finish()
    check(results, rcs == {"worker": 3, "nx_busy": 4, "ex_other": 3},
          "workload exit statuses %s" % rcs)
    check(results, got["worker"]["exit"] == ["exit=3"],
          "worker: POD_NAME=msrv-dyn, one EXIT, got %s"
          % got["worker"]["exit"])
    check(results, got["other"]["exit"] == [],
          "other: POD_NAME=msrv-dyn2 is no exact match, no EXIT, got %s"
          % got["other"]["exit"])
    check(results, got["nx_busy"]["exit"] == [] and got["nx_busy"]["cpu"] > 0,
          "nx_busy: sampled by the global selection, no EXIT, got %d samples"
          " %s" % (got["nx_busy"]["cpu"], got["nx_busy"]["exit"]))
    check(results, got["_count"] == {"core": 0, "exit": 2} and
          got["_drop"] == {"mismatch": 1, "unknown": 0},
          "monitor received 2 EXIT events, 1 mismatch, got %s %s"
          % (got["_count"], got["_drop"]))


def case_target_env_exec_kprobe(args, results):
    """The exec fallback tells before the environ exists: read again."""
    s = Session(args, "target_env_kprobe", ("worker",),
                ["--exit_target_env_name=POD_NAME",
                 "--exit_target_env_value_prefix=msrv-kp"],
                bystanders={"nx_execin": "execto"},
                files=("ex_execin",),
                argv={"nx_execin": lambda s: [s.bins["ex_execin"], "worker"]},
                select=lambda s: ["--exit_comm", "ex_worker,ex_execin"],
                env={"worker": {"POD_NAME": "msrv-kp"},
                     "nx_execin": {"POD_NAME": "msrv-kp-execin"}},
                monitor_env={"CPA_TARGET_FORCE_EXEC_KPROBE": "1"})
    rcs = s.run()
    got = s.finish()
    log = open(os.path.join(s.dir, "monitor.log"), errors="replace").read()
    check(results, "target: exec hook kretprobe/setup_new_exec" in log,
          "the exec hook is the setup_new_exec kretprobe")
    check(results, rcs == {"worker": 3, "nx_execin": 3},
          "workload exit statuses %s" % rcs)
    for mode in ("worker", "execin"):
        check(results, got[mode]["exit"] == ["exit=3"],
              "%s: read after the loader, one EXIT, got %s"
              % (mode, got[mode]["exit"]))
    check(results, got["_count"] == {"core": 0, "exit": 2} and
          got["_drop"] == {"mismatch": 0, "unknown": 0},
          "monitor received 2 EXIT events, none dropped, got %s %s"
          % (got["_count"], got["_drop"]))


CASES = (("01_exit_only", case_exit_only),
         ("02_exit_and_core", case_exit_and_core),
         ("03_conflicts_rejected", case_conflicts_rejected),
         ("04_exec_no_sample", case_exec_no_sample),
         ("05_exit_comm_own_selection", case_exit_comm_own_selection),
         ("06_exit_pid", case_exit_pid),
         ("07_target_env", case_target_env),
         ("08_target_env_names", case_target_env_names),
         ("09_target_env_dynamic", case_target_env_dynamic),
         ("10_target_env_exec_kprobe", case_target_env_exec_kprobe))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cpa", required=True)
    ap.add_argument("--app", required=True)
    ap.add_argument("--work", default="/tmp/exit_e2e")
    ap.add_argument("--json")
    # the last stack must not depend on how soon a worker unwinds a target
    # first seen at exec (its loader still running): run it with several too
    ap.add_argument("--unwind_workers", type=int, default=1)
    args = ap.parse_args()
    args.cpa = os.path.abspath(args.cpa)
    args.app = os.path.abspath(args.app)
    # cpa show runs in each case's directory
    args.work = os.path.abspath(args.work)
    os.makedirs(args.work, exist_ok=True)
    report, failed = {}, []
    for name, fn in CASES:
        results = []
        try:
            fn(args, results)
        except Exception as exc:  # report and keep going
            results.append("FAIL exception: %r" % exc)
        ok = all(r.startswith("PASS") for r in results)
        print("[%s] %s" % ("PASS" if ok else "FAIL", name))
        for r in results:
            print("    " + r)
        report[name] = results
        if not ok:
            failed.append(name)
    print("SUMMARY: %d/%d passed%s" % (len(CASES) - len(failed), len(CASES),
          " failed=" + ",".join(failed) if failed else ""))
    if args.json:
        with open(args.json, "w") as fp:
            json.dump(report, fp, indent=1)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
