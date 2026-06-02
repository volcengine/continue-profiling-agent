# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]


class CPAUnwinderRegRestoreTest(unittest.TestCase):
    def _unwind_block(self) -> str:
        source = (REPO_ROOT / "src" / "cpa_monitor" / "cpa_unwinder.c").read_text(
            encoding="utf-8"
        )

        block_start = source.index("static void cpa_unwind")
        block_end = source.index("int cpa_add_pid_exit_event", block_start)
        return source[block_start:block_end]

    def test_probe_unwind_restores_registers_before_final_unwind(self) -> None:
        block = self._unwind_block()

        unwind_call = "gu_unwind(gu_ctx, sample->info, process_single_frame_p"
        first_unwind = block.index(unwind_call)
        restore = block.index("cpa_unwind_state_restore", first_unwind)
        final_unwind = block.index(unwind_call, restore)

        self.assertLess(first_unwind, restore)
        self.assertLess(restore, final_unwind)

    def test_bench_records_final_dwarf_path_once_per_sample(self) -> None:
        block = self._unwind_block()

        first_unwind = block.index(
            "gu_unwind(gu_ctx, sample->info, process_single_frame_p"
        )
        restore = block.index("cpa_unwind_state_restore", first_unwind)
        first_record = block.index("cpa_unwind_bench_record(bench_start_ns)")

        self.assertGreater(first_record, restore)
        self.assertIn(
            "if (!run_final_unwind)\n"
            "\t\t\t\tcpa_unwind_bench_record(bench_start_ns);",
            block,
        )
        self.assertNotIn("!run_final_unwind || use_fp", block)
        self.assertEqual(block.count("cpa_unwind_bench_record(bench_start_ns)"), 2)
