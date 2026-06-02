from __future__ import annotations

import stat
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_release_workflow_builds_sopacker_package_on_tags() -> None:
    workflow = REPO_ROOT / ".github" / "workflows" / "release.yml"
    text = workflow.read_text(encoding="utf-8")

    assert "runs-on: ubuntu-24.04" in text
    assert "tags:" in text and "v*" in text
    assert "submodules: recursive" in text
    assert "LIBGUNWINDER_DEPLOY_KEY" not in text
    assert "Configure private libgunwinder deploy key" not in text
    assert "cmake --build build -j --target cpa_portable" in text
    assert "dist/cpa_portable-linux-x86_64 version" in text
    assert "gh release create" in text
    assert "gh release upload" in text


def test_pipe_to_bash_installer_is_documented_and_executable() -> None:
    installer = REPO_ROOT / "tools" / "install_cpa.sh"
    text = installer.read_text(encoding="utf-8")
    mode = installer.stat().st_mode

    assert mode & stat.S_IXUSR
    assert "releases/latest/download" in text
    assert "tools/deploy_cpa.sh" in text
    assert "--version TAG" in text
    assert "GITHUB_TOKEN" not in text and "GH_TOKEN" not in text
    assert "gh release download" not in text

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "tools/install_cpa.sh | sudo bash" in readme


def test_deploy_script_documents_env_and_creates_link_parent() -> None:
    text = (REPO_ROOT / "tools" / "deploy_cpa.sh").read_text(encoding="utf-8")

    assert "Environment:" in text
    assert "CPA_INSTALL_DIR" in text
    assert "CPA_BIN_LINK" in text
    assert "mkdir -p" in text and "dirname" in text and "bin_link" in text


def test_release_installer_has_uninstall_path_and_quick_start_docs() -> None:
    deploy = (REPO_ROOT / "tools" / "deploy_cpa.sh").read_text(encoding="utf-8")
    installer = (REPO_ROOT / "tools" / "install_cpa.sh").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    deploy_doc = (REPO_ROOT / "docs" / "en" / "deploy.md").read_text(encoding="utf-8")

    assert "--uninstall" in deploy
    assert "--purge-store" in deploy
    assert "remove_profile_store" in deploy
    assert "systemctl disable" in deploy
    assert "systemctl stop" in deploy

    assert "--uninstall" in installer
    assert "--purge-store" in installer
    assert "refs/heads/main/tools/deploy_cpa.sh" in installer
    assert "deploy_cpa.sh --uninstall" in deploy_doc

    assert "## Quick Start" in readme
    assert "## Manual Build" in readme
    assert "## Manual Deployment" in readme
    assert "Install CPA from the latest release" in readme
    assert "tools/install_cpa.sh | sudo bash" in readme
    assert "sudo systemctl status cpa.service" in readme
    assert "--uninstall" in readme


def test_kernel_warning_and_llvm_install_docs_are_linked() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    readme_zh = (REPO_ROOT / "README.zh-CN.md").read_text(encoding="utf-8")
    kernel_doc = (
        REPO_ROOT / "docs" / "en" / "kernel-compatibility.md"
    ).read_text(encoding="utf-8")
    build_doc = (REPO_ROOT / "docs" / "en" / "build.md").read_text(encoding="utf-8")

    assert "Kernel Compatibility Warning" in readme
    assert "5.19 through 6.3" in readme
    assert "docs/en/kernel-compatibility.md" in readme
    assert "docs/zh-CN/kernel-compatibility.md" in readme_zh

    assert "Upstream 6.1.x LTS" in kernel_doc
    assert "Do not use" in kernel_doc
    assert "bugzilla.redhat.com" not in kernel_doc
    assert "copy_from_user_nofault" in kernel_doc
    assert "sockmap/sockhash" not in kernel_doc
    assert "d319f344561de23e810515d109c7278919bff7b0" in kernel_doc

    assert "https://apt.llvm.org/llvm.sh" in build_doc
    assert "sudo ./llvm.sh 15" in build_doc
    assert "export PATH=/usr/lib/llvm-15/bin:$PATH" in build_doc
    assert "-DCPA_BPF_LLVM_VERSION=15" in build_doc

    deploy_doc = (REPO_ROOT / "docs" / "en" / "deploy.md").read_text(encoding="utf-8")
    deep_dive = (
        REPO_ROOT / "docs" / "en" / "technical-deep-dive.md"
    ).read_text(encoding="utf-8")

    assert "Distribution Environment Setup" in deploy_doc
    assert "sudo apt-get install" in deploy_doc
    assert "sudo dnf install" in deploy_doc
    assert "cmake3" in deploy_doc
    assert "CentOS Stream or Fedora" in deploy_doc
    assert "openSUSE" not in deploy_doc
    assert "Arch Linux" not in deploy_doc

    assert "CONFIG_HARDENED_USERCOPY" in kernel_doc
    assert "nmi_uaccess_okay" in kernel_doc
    assert "find_vmap_area" in kernel_doc
    assert "Continuous Profiling at CLK" in deep_dive
    assert "CLK2025" in deep_dive
