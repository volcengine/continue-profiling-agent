#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass, field


KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
}

CALLBACK_HINTS = (
    ".init_fn = ",
    ".destroy_fn = ",
    ".pause_fn = ",
    ".restore_fn = ",
    ".timer_fn = ",
    ".main_worker_fn = ",
    "pthread_create(",
    "setup_process_exit_event(",
)


@dataclass
class FunctionDef:
    name: str
    path: pathlib.Path
    line: int
    storage: str
    body: str
    calls: set[str] = field(default_factory=set)


SIG_RE = re.compile(
    r"^\s*(?P<storage>static\s+)?"
    r"(?P<prefix>.+?)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*$"
)
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def strip_comments_and_strings(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
    return text


def find_function_defs(path: pathlib.Path) -> list[FunctionDef]:
    raw = path.read_text(encoding="utf-8")
    text = strip_comments_and_strings(raw)
    lines = text.splitlines()
    defs: list[FunctionDef] = []
    i = 0

    while i < len(lines):
        line = lines[i]
        sig_lines = [line]
        if "(" not in line:
            i += 1
            continue

        j = i
        while j + 1 < len(lines) and "{" not in lines[j]:
            j += 1
            sig_lines.append(lines[j])
            if ";" in lines[j]:
                break

        sig = " ".join(part.strip() for part in sig_lines)
        if ";" in sig and "{" not in sig:
            i += 1
            continue

        if "{" not in sig:
            i += 1
            continue

        sig_prefix = sig.split("{", 1)[0].strip()
        match = SIG_RE.match(sig_prefix)
        if not match:
            i += 1
            continue

        name = match.group("name")
        if name in KEYWORDS:
            i += 1
            continue

        brace_depth = sig.count("{") - sig.count("}")
        body_lines = [sig.split("{", 1)[1]]
        k = j
        while brace_depth > 0 and k + 1 < len(lines):
            k += 1
            body_lines.append(lines[k])
            brace_depth += lines[k].count("{") - lines[k].count("}")

        defs.append(
            FunctionDef(
                name=name,
                path=path,
                line=i + 1,
                storage=(match.group("storage") or "").strip(),
                body="\n".join(body_lines),
            )
        )
        i = k + 1

    return defs


def collect_calls(body: str, known_names: set[str]) -> set[str]:
    calls = set()
    for callee in CALL_RE.findall(body):
        if callee in KEYWORDS or callee not in known_names:
            continue
        calls.add(callee)
    return calls


def repo_rg_hits(repo_root: pathlib.Path, name: str) -> list[str]:
    result = subprocess.run(
        ["rg", "-n", rf"\b{name}\b", "src", "bpf", "tests"],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return [line for line in result.stdout.splitlines() if line]


def looks_like_callback(defn: FunctionDef, hits: list[str]) -> bool:
    for hit in hits[1:]:
        if any(hint + defn.name in hit or hint + "&" + defn.name in hit for hint in CALLBACK_HINTS):
            return True
        if f", {defn.name}," in hit or f"({defn.name}," in hit:
            return True
        if f", {defn.name})" in hit or f"({defn.name}," in hit:
            return True
    return False


def scan(repo_root: pathlib.Path, paths: list[pathlib.Path]) -> list[FunctionDef]:
    defs: list[FunctionDef] = []
    for path in paths:
        if path.is_dir():
            defs.extend(find_function_defs(p) for p in sorted(path.rglob("*.c")))
        else:
            defs.extend(find_function_defs(path))

    flat_defs: list[FunctionDef] = []
    for item in defs:
        if isinstance(item, list):
            flat_defs.extend(item)
        else:
            flat_defs.append(item)

    known_names = {defn.name for defn in flat_defs}
    for defn in flat_defs:
        defn.calls = collect_calls(defn.body, known_names)
    return flat_defs


def emit_dot(defs: list[FunctionDef]) -> str:
    lines = ["digraph cpa_calls {"]
    for defn in defs:
        lines.append(f'  "{defn.name}" [label="{defn.name}\\n{defn.path.name}:{defn.line}"];')
    for defn in defs:
        for callee in sorted(defn.calls):
            lines.append(f'  "{defn.name}" -> "{callee}";')
    lines.append("}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Find dead-function candidates in CPA C sources.")
    parser.add_argument("paths", nargs="*", default=["src/cli_common.c"], help="files or dirs to scan")
    parser.add_argument("--repo-root", default=".", help="repository root")
    parser.add_argument("--dot", help="write a DOT callgraph to this path")
    args = parser.parse_args()

    repo_root = pathlib.Path(args.repo_root).resolve()
    paths = [(repo_root / p).resolve() for p in args.paths]
    defs = scan(repo_root, paths)

    inbound: dict[str, int] = {defn.name: 0 for defn in defs}
    for defn in defs:
        for callee in defn.calls:
            if callee in inbound:
                inbound[callee] += 1

    if args.dot:
        pathlib.Path(args.dot).write_text(emit_dot(defs), encoding="utf-8")

    for defn in sorted(defs, key=lambda d: (inbound[d.name], str(d.path), d.line, d.name)):
        hits = repo_rg_hits(repo_root, defn.name)
        if inbound[defn.name] != 0:
            continue
        if looks_like_callback(defn, hits):
            continue
        if len(hits) > 2:
            continue
        rel = defn.path.relative_to(repo_root)
        print(f"{rel}:{defn.line}: {defn.name} [hits={len(hits)}]")
        for hit in hits:
            print(f"  {hit}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
