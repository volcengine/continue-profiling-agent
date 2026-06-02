#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

set -euo pipefail

repo="${CPA_RELEASE_REPO:-volcengine/continue-profiling-agent}"
version="${CPA_RELEASE_VERSION:-latest}"
asset="${CPA_RELEASE_ASSET:-}"
deploy_args=()

usage()
{
	cat <<'EOF'
Usage: curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/main/tools/install_cpa.sh | sudo bash -s -- [options]

Downloads the CPA portable release artifact and installs it through
tools/deploy_cpa.sh. Run as root because the deploy helper writes systemd,
/etc/cpa, /usr/local, and /var/log/cpa by default.

Options:
  --version TAG          release tag to install, for example v1.0.0
                         (default: latest release)
  --repo OWNER/REPO      GitHub repository (default: volcengine/continue-profiling-agent)
  --asset NAME           release asset name (default: cpa_portable-linux-x86_64)
  --btf PATH             custom BTF file passed to deploy_cpa.sh
  --store-dir DIR        profile store root passed to deploy_cpa.sh
  --freq HZ              sampling frequency passed to deploy_cpa.sh
  --record-interval SEC  store/query interval passed to deploy_cpa.sh
  --persistent-day DAYS  retention window passed to deploy_cpa.sh
  --no-start             install files without starting cpa.service
  -h, --help             show this help

Environment:
  CPA_RELEASE_REPO       default repository override
  CPA_RELEASE_VERSION    default release tag override
  CPA_RELEASE_ASSET      default release asset override
  CPA_INSTALL_DIR        install directory consumed by deploy_cpa.sh
  CPA_BIN_LINK           cpa symlink path consumed by deploy_cpa.sh
  CPA_CONFIG_DIR         config directory consumed by deploy_cpa.sh
  CPA_CONFIG_PATH        config file path consumed by deploy_cpa.sh
  CPA_STORE_DIR          profile store root consumed by deploy_cpa.sh
  CPA_SERVICE_PATH       systemd unit path consumed by deploy_cpa.sh
EOF
}

require_value()
{
	if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
		echo "$1 requires a value" >&2
		exit 2
	fi
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--version)
		require_value "$@"
		version="$2"
		shift 2
		;;
	--repo)
		require_value "$@"
		repo="$2"
		shift 2
		;;
	--asset)
		require_value "$@"
		asset="$2"
		shift 2
		;;
	--btf|--store-dir|--freq|--record-interval|--persistent-day)
		require_value "$@"
		deploy_args+=("$1" "$2")
		shift 2
		;;
	--no-start)
		deploy_args+=("$1")
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		echo "unknown option: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

if [[ "$(id -u)" != "0" ]]; then
	echo "install_cpa.sh must run as root. Use: curl ... | sudo bash" >&2
	exit 1
fi

case "$(uname -m)" in
	x86_64|amd64) default_asset="cpa_portable-linux-x86_64" ;;
	*)
		echo "unsupported architecture for prebuilt CPA release: $(uname -m)" >&2
		exit 1
		;;
esac

if [[ -z "$asset" ]]; then
	asset="$default_asset"
fi

if ! command -v curl >/dev/null 2>&1; then
	echo "curl is required" >&2
	exit 1
fi

workdir="$(mktemp -d)"
cleanup()
{
	rm -rf "$workdir"
}
trap cleanup EXIT

if [[ "$version" == "latest" ]]; then
	asset_url="https://github.com/${repo}/releases/latest/download/${asset}"
	deploy_ref="main"
else
	asset_url="https://github.com/${repo}/releases/download/${version}/${asset}"
	deploy_ref="$version"
fi

binary="$workdir/cpa"
deploy="$workdir/deploy_cpa.sh"

echo "Downloading ${asset_url}"
curl -fL --retry 3 --retry-delay 2 -o "$binary" "$asset_url"
chmod 0755 "$binary"

deploy_url="https://raw.githubusercontent.com/${repo}/${deploy_ref}/tools/deploy_cpa.sh"
if ! curl -fL --retry 3 --retry-delay 2 -o "$deploy" "$deploy_url"; then
	deploy_url="https://raw.githubusercontent.com/${repo}/main/tools/deploy_cpa.sh"
	curl -fL --retry 3 --retry-delay 2 -o "$deploy" "$deploy_url"
fi
chmod 0755 "$deploy"

"$binary" version
"$deploy" --binary "$binary" "${deploy_args[@]}"

echo "CPA install finished."
