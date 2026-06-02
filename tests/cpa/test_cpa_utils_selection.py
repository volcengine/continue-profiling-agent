# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

from pathlib import Path

import pytest

from . import cpa_utils


def test_parse_cpa_prof_file_tolerates_non_utf8_stack_bytes(tmp_path: Path) -> None:
    prof = tmp_path / "non_utf8.prof"
    metadata = f"{'thread':<15}{'proc':<15}-1-2-3|ENV;"
    prof.write_bytes(metadata.encode("utf-8") + b"bad\xa0symbol; 1\n")

    records = cpa_utils.parse_cpa_prof_file(str(prof), no_delete=True)

    assert len(records) == 1
    assert records[0].pid == 3
    assert records[0].stack[0].startswith("bad")


def test_parse_cpa_prof_file_allows_root_marker_frames(tmp_path: Path) -> None:
    prof = tmp_path / "root_marker.prof"
    metadata = f"{'thread':<15}{'proc':<15}-1-2-3|ENV;"
    prof.write_text(
        metadata + "<# IRQOFF SAMPLE ON CPU 2 #>;main;leaf; 1\n",
        encoding="utf-8",
    )

    records = cpa_utils.parse_cpa_prof_file(str(prof), no_delete=True)

    assert len(records) == 1
    assert records[0].stack[0] == "<# IRQOFF SAMPLE ON CPU 2 #>"


def test_parse_cpa_prof_file_rejects_marker_after_normal_frame(
    tmp_path: Path,
) -> None:
    prof = tmp_path / "bad_marker.prof"
    metadata = f"{'thread':<15}{'proc':<15}-1-2-3|ENV;"
    prof.write_text(
        metadata + "main;<# IRQOFF SAMPLE ON CPU 2 #>;leaf; 1\n",
        encoding="utf-8",
    )

    with pytest.raises(AssertionError, match="marker frame must be in the root"):
        cpa_utils.parse_cpa_prof_file(str(prof), no_delete=True)
