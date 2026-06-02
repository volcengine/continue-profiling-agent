# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance


from __future__ import annotations

import argparse
import os
import re
import selectors
import subprocess
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--show-regex", default=r"(^|\\b)(warning:|error:)")
    parser.add_argument("--tail-lines", type=int, default=80)
    parser.add_argument("cmd", nargs=argparse.REMAINDER)
    ns = parser.parse_args(argv)

    cmd = list(ns.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise SystemExit("missing command after --")

    log_path = Path(ns.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    show_re = re.compile(ns.show_regex, re.IGNORECASE)

    with log_path.open("w", encoding="utf-8", errors="replace") as log_fp:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=os.environ.copy(),
        )
        assert proc.stdout is not None
        assert proc.stderr is not None

        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ, ("stdout", proc.stdout))
        sel.register(proc.stderr, selectors.EVENT_READ, ("stderr", proc.stderr))

        while sel.get_map():
            for key, _ in sel.select():
                stream_name, fp = key.data
                line = fp.readline()
                if line == "":
                    try:
                        sel.unregister(fp)
                    except Exception:
                        pass
                    continue

                log_fp.write(line)
                log_fp.flush()

                if stream_name == "stderr" or show_re.search(line):
                    sys.stderr.write(line)
                    sys.stderr.flush()

        rc = proc.wait()

    if rc != 0 and ns.tail_lines > 0:
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines(True)
        except OSError:
            lines = []
        tail = lines[-ns.tail_lines :]
        if tail:
            sys.stderr.write("---- quiet-build log tail ----\n")
            sys.stderr.writelines(tail)
            if not tail[-1].endswith("\n"):
                sys.stderr.write("\n")
            sys.stderr.write("---- end log tail ----\n")
            sys.stderr.flush()

    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
