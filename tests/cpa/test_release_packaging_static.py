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
