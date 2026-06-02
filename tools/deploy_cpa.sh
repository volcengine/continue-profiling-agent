#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

set -euo pipefail

binary="${CPA_BINARY:-build/bin/cpa}"
libgunwinder="${CPA_LIBGUNWINDER:-}"
install_dir="${CPA_INSTALL_DIR:-/usr/local/lib/cpa}"
bin_link="${CPA_BIN_LINK:-/usr/local/bin/cpa}"
config_dir="${CPA_CONFIG_DIR:-/etc/cpa}"
config_path="${CPA_CONFIG_PATH:-/etc/cpa/cpa.conf}"
store_dir="${CPA_STORE_DIR:-/var/log/cpa}"
service_path="${CPA_SERVICE_PATH:-/etc/systemd/system/cpa.service}"
backend="${CPA_BACKEND:-bpf}"
freq="${CPA_FREQ:-49}"
record_interval="${CPA_RECORD_INTERVAL:-1}"
persistent_day="${CPA_PERSISTENT_DAY:-7}"
log_print_cycles="${CPA_LOG_PRINT_CYCLES:-10}"
btf_path="${CPA_BTF_PATH:-}"
start_service=1

usage()
{
	cat <<'EOF'
Usage: sudo tools/deploy_cpa.sh [options]

Installs CPA, writes /etc/cpa/cpa.conf, and writes a cpa.service systemd unit.
The --binary input may be either build/bin/cpa or a SOPacker cpa_portable
release artifact.

Options:
  --binary PATH          CPA binary to install (default: build/bin/cpa)
  --lib PATH             libgunwinder.so to install; defaults to binary dir
  --btf PATH             custom BTF file written as btf_path in cpa.conf
  --store-dir DIR        profile store root (default: /var/log/cpa)
  --freq HZ              sampling frequency (default: 49)
  --record-interval SEC  store/query interval (default: 1)
  --persistent-day DAYS  retention window (default: 7)
  --no-start             install files without starting the service
  -h, --help             show this help

Environment:
  CPA_BINARY             default --binary path
  CPA_LIBGUNWINDER       default --lib path
  CPA_INSTALL_DIR        install directory (default: /usr/local/lib/cpa)
  CPA_BIN_LINK           cpa symlink path (default: /usr/local/bin/cpa)
  CPA_CONFIG_DIR         config directory (default: /etc/cpa)
  CPA_CONFIG_PATH        config file path (default: /etc/cpa/cpa.conf)
  CPA_STORE_DIR          profile store root (default: /var/log/cpa)
  CPA_SERVICE_PATH       systemd unit path (default: /etc/systemd/system/cpa.service)
  CPA_BACKEND            generated config backend (default: bpf)
  CPA_FREQ               generated config frequency (default: 49)
  CPA_RECORD_INTERVAL    generated config record interval (default: 1)
  CPA_PERSISTENT_DAY     generated config retention days (default: 7)
  CPA_LOG_PRINT_CYCLES   generated config log interval (default: 10)
  CPA_BTF_PATH           default --btf path
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
	--binary)
		require_value "$@"
		binary="$2"
		shift 2
		;;
	--lib)
		require_value "$@"
		libgunwinder="$2"
		shift 2
		;;
	--btf)
		require_value "$@"
		btf_path="$2"
		shift 2
		;;
	--store-dir)
		require_value "$@"
		store_dir="$2"
		shift 2
		;;
	--freq)
		require_value "$@"
		freq="$2"
		shift 2
		;;
	--record-interval)
		require_value "$@"
		record_interval="$2"
		shift 2
		;;
	--persistent-day)
		require_value "$@"
		persistent_day="$2"
		shift 2
		;;
	--no-start)
		start_service=0
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
	echo "deploy_cpa.sh must run as root." >&2
	exit 1
fi

if [[ ! -x "$binary" ]]; then
	echo "CPA binary is not executable: $binary" >&2
	exit 1
fi

if [[ -z "$libgunwinder" ]]; then
	candidate="$(dirname "$binary")/libgunwinder.so"
	if [[ -f "$candidate" ]]; then
		libgunwinder="$candidate"
	fi
fi

if [[ -n "$btf_path" && ! -r "$btf_path" ]]; then
	echo "custom BTF is not readable: $btf_path" >&2
	exit 1
fi

mkdir -p \
	"$install_dir" \
	"$config_dir" \
	"$store_dir" \
	"$(dirname "$bin_link")" \
	"$(dirname "$config_path")" \
	"$(dirname "$service_path")"
install -m 0755 "$binary" "$install_dir/cpa"

if [[ -n "$libgunwinder" ]]; then
	if [[ ! -r "$libgunwinder" ]]; then
		echo "libgunwinder.so is not readable: $libgunwinder" >&2
		exit 1
	fi
	install -m 0644 "$libgunwinder" "$install_dir/libgunwinder.so"
fi

ln -sfn "$install_dir/cpa" "$bin_link"

tmp_conf="$(mktemp)"
cat >"$tmp_conf" <<EOF
store_dir: $store_dir
backend: $backend
freq: $freq
record_interval: $record_interval
persistent_day: $persistent_day
log_print_cycles: $log_print_cycles
record_env_name: POD_NAME,MY_POD_NAME
EOF

if [[ -n "$btf_path" ]]; then
	echo "btf_path: $btf_path" >>"$tmp_conf"
fi

install -m 0644 "$tmp_conf" "$config_path"
rm -f "$tmp_conf"

tmp_unit="$(mktemp)"
cat >"$tmp_unit" <<EOF
[Unit]
Description=Continue Profiling Agent
Documentation=file://$config_path
After=local-fs.target
ConditionPathExists=$config_path

[Service]
Type=simple
WorkingDirectory=$install_dir
Environment=LD_LIBRARY_PATH=$install_dir
ExecStart=$install_dir/cpa monitor --config $config_path
Restart=always
RestartSec=5s
KillSignal=SIGINT
TimeoutStopSec=30s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

install -m 0644 "$tmp_unit" "$service_path"
rm -f "$tmp_unit"

if ! command -v systemctl >/dev/null 2>&1; then
	echo "systemctl not found; installed files but did not start service." >&2
	exit 0
fi

systemctl daemon-reload
systemctl enable cpa.service

if [[ "$start_service" == "1" ]]; then
	systemctl restart cpa.service
	systemctl --no-pager --full status cpa.service || true
else
	echo "Installed cpa.service. Start it with: systemctl start cpa.service"
fi
