# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

import pytest

from .conftest import print_test_name, run_command


@pytest.mark.usefixtures("print_test_name")
def test_cli_help_flag():
    """Test the global --help flag output."""
    stdout, stderr, return_code = run_command(["--help"])
    assert return_code == 0, f"cpa --help failed with stderr: {stderr}\nStdout: {stdout}"
    assert "Usage:" in stdout
    assert "Available COMMAND" in stdout
    assert "output_format" not in stdout
    assert "output_path" not in stdout
    assert "--count" not in stdout
    assert "--interval" not in stdout
    for command in ("monitor", "show", "help", "version"):
        assert command in stdout


@pytest.mark.usefixtures("print_test_name")
def test_help_subcommand_matches_global_help_surface():
    """The dedicated `help` subcommand should expose the same public commands."""
    stdout, stderr, return_code = run_command(["help"])
    assert return_code == 0, f"cpa help failed with stderr: {stderr}\nStdout: {stdout}"
    assert "Usage:" in stdout
    for command in ("monitor", "show", "help", "version"):
        assert command in stdout
    assert "output_format" not in stdout
    assert "output_path" not in stdout


@pytest.mark.usefixtures("print_test_name")
def test_subcommand_help_flag():
    """Test {sub_cmd} --help prints help only for that subcommand."""
    stdout, stderr, return_code = run_command(["monitor", "--help"])
    assert return_code == 0, f"CLI monitor --help failed with stderr: {stderr}\nStdout: {stdout}"
    assert "Usage:" in stdout
    assert "monitor" in stdout
    assert "Available COMMAND" not in stdout
    assert "--persistent_day" in stdout
    assert "--output_prof" in stdout
    assert "--bench" in stdout
    assert "--debug_cache_path" not in stdout
    assert "--background" not in stdout
    assert "--force_fp" not in stdout
    assert "--no_backtrace_lang" not in stdout
    assert "one-shot" in stdout.lower()
    assert "flamegraph file path" in stdout.lower()
    assert "bpf or perf" in stdout.lower()


@pytest.mark.usefixtures("print_test_name")
def test_show_help_has_clearer_option_descriptions():
    """`show --help` should explain cache and range/export semantics clearly."""
    stdout, stderr, return_code = run_command(["show", "--help"])
    assert return_code == 0, f"CLI show --help failed with stderr: {stderr}\nStdout: {stdout}"
    assert "--output_num" in stdout
    assert "positive integer" in stdout.lower()
    assert "--use_cache" in stdout
    assert "reuse decompressed files" in stdout.lower()
    assert "--show_range" in stdout
    assert "print available record time range" in stdout.lower()
    assert "--metrics" not in stdout


@pytest.mark.usefixtures("print_test_name")
def test_show_metrics_option_is_rejected():
    """Removed show options should not stay silently accepted."""
    stdout, stderr, return_code = run_command(["show", "--metrics", "/tmp/metrics"])
    assert return_code != 0
    assert (
        "invalid option" in stderr.lower()
        or "unknown" in stderr.lower()
        or "unrecognized option" in stderr.lower()
    )


@pytest.mark.usefixtures("print_test_name")
def test_unknown_monitor_options_are_rejected():
    """Monitor should reject options that are not part of the public CPA surface."""
    for opt in (
        "--this-option-does-not-exist",
        "--invalid-runtime-flag=/tmp/cpa-cache",
        "--bogus-filter=java",
    ):
        stdout, stderr, return_code = run_command(["monitor", opt])
        assert return_code != 0
        assert (
            "invalid option" in stderr.lower()
            or "unknown" in stderr.lower()
            or "unrecognized option" in stderr.lower()
        )


@pytest.mark.usefixtures("print_test_name")
def test_invalid_command():
    """Test the CLI with an invalid command."""
    stdout, stderr, return_code = run_command(["invalidcommand"])
    assert return_code != 0, "CLI did not exit with non-zero for invalid command."
    assert (
        "Error: Unknown command" in stderr
        or "Unknown command" in stderr
        or "invalid" in stderr.lower()
    ), f"Expected error message for invalid command not found in stderr: {stderr}"


@pytest.mark.usefixtures("print_test_name")
def test_cli_version_command():
    """Test the public product name shown by `cpa version`."""
    stdout, stderr, return_code = run_command(["version"])
    assert return_code == 0, f"cpa version failed with stderr: {stderr}\nStdout: {stdout}"
    assert stderr == ""
    assert stdout.strip() == "continue-profiling-agent 1.0.0"


@pytest.mark.usefixtures("print_test_name")
def test_show_requires_read_argument():
    """`cpa show` should reject invocations without the required store path."""
    stdout, stderr, return_code = run_command(["show"])
    assert return_code != 0
    assert "arg \"read\" required" in (stdout + stderr).lower()
