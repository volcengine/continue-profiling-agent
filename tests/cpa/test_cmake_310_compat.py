from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CMAKE_FILES = [
    REPO_ROOT / "CMakeLists.txt",
    *(REPO_ROOT / "cmake").glob("*.cmake"),
    *(REPO_ROOT / "bpf" / "cmake").glob("*.cmake"),
]


def _without_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _iter_cmake_commands(text: str, command: str) -> list[str]:
    clean_text = _without_comments(text)
    pattern = re.compile(rf"(?i)(?<![A-Za-z0-9_]){re.escape(command)}\s*\(")
    commands: list[str] = []
    for match in pattern.finditer(clean_text):
        depth = 1
        pos = match.end()
        while pos < len(clean_text) and depth:
            if clean_text[pos] == "(":
                depth += 1
            elif clean_text[pos] == ")":
                depth -= 1
            pos += 1
        commands.append(clean_text[match.start():pos])
    return commands


def _tokens(command: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_+-]+", command.upper())


def test_project_keeps_cmake_minimum_at_3_10() -> None:
    top_level = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

    assert re.search(
        r"(?im)^\s*cmake_minimum_required\s*\(\s*VERSION\s+3\.10\s*\)",
        top_level,
    )


def test_project_cmake_files_do_not_use_post_3_10_features() -> None:
    violations: list[str] = []

    for path in CMAKE_FILES:
        text = path.read_text(encoding="utf-8")
        rel_path = path.relative_to(REPO_ROOT)

        for command in _iter_cmake_commands(text, "find_program"):
            if "REQUIRED" in _tokens(command):
                violations.append(
                    f"{rel_path}: find_program(... REQUIRED) requires CMake "
                    "newer than 3.10"
                )

        for command in _iter_cmake_commands(text, "file"):
            tokens = _tokens(command)
            if (
                len(tokens) >= 2
                and tokens[1] in {"GLOB", "GLOB_RECURSE"}
                and "CONFIGURE_DEPENDS" in tokens
            ):
                violations.append(
                    f"{rel_path}: file({tokens[1]} ... CONFIGURE_DEPENDS) "
                    "requires CMake newer than 3.10"
                )

    assert violations == []
