from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CPA_SHOW_SOURCE = REPO_ROOT / "src/cpa_show/cpa_show.c"


def test_cpa_show_rejects_empty_selected_range_before_last_record_index() -> None:
    source = CPA_SHOW_SOURCE.read_text(encoding="utf-8")
    range_assignment = "if (endtime != 0)\n\t\toutput_num = record_count;"
    last_record_index = "endtime = dump_info.records[record_index + output_num - 1].endtime;"

    assignment_offset = source.index(range_assignment)
    index_offset = source.index(last_record_index)
    assert assignment_offset < index_offset

    selection_window = source[assignment_offset:index_offset]
    assert "if (output_num <= 0)" in selection_window
    assert "No records selected in requested range" in selection_window


def test_cpa_show_does_not_count_records_after_requested_endtime() -> None:
    source = CPA_SHOW_SOURCE.read_text(encoding="utf-8")
    loop_start = source.index("for (int i = 0; i < dump_info.record_count; i++)")
    count_start = source.index("\t\tif (record_index != -1) {", loop_start)

    before_counting_selected_records = source[loop_start:count_start]
    assert "dump_info.records[i].starttime > endtime" in before_counting_selected_records
    assert "break;" in before_counting_selected_records
