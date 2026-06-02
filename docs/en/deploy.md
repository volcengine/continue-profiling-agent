# CPA Deployment Guide

[Back to README](../../README.md)

This guide describes a minimal systemd deployment for continuous profiling.
The default deployment records on-CPU profiles at 49 Hz and writes data under
`/var/log/cpa`.


## Distribution Environment Setup

For the release installer, the target host only needs a normal Linux userspace
with `systemd`, `curl`, and enough privilege to install under `/usr/local`,
`/etc/cpa`, `/etc/systemd/system`, and `/var/log/cpa`. The portable release
artifact carries CPA and its bundled shared-library runtime.

Use these commands when you want to build CPA locally before deployment.

Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  autoconf automake binutils-dev build-essential clang cmake curl git \
  libdw-dev libelf-dev libiberty-dev libssl-dev libtool libzstd-dev \
  llvm make pkg-config python3 zlib1g-dev zstd cargo
```

Debian:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  autoconf automake binutils-dev build-essential clang cmake curl git \
  libdw-dev libelf-dev libiberty-dev libssl-dev libtool libzstd-dev \
  llvm make pkg-config python3 zlib1g-dev zstd cargo
```

CentOS Stream or Fedora:

```bash
sudo dnf install -y \
  autoconf automake binutils-devel clang cmake curl elfutils-devel \
  elfutils-libelf-devel gcc gcc-c++ git libiberty-devel libtool llvm \
  make openssl-devel pkgconf-pkg-config python3 rust cargo zlib-devel \
  zstd zstd-devel
```

CPA requires `cmake >= 3.10`. Check the selected CMake before configuring:

```bash
cmake --version
```

On older CentOS systems where `/usr/bin/cmake` is too old, install `cmake3`
and use it for configure and build:

```bash
sudo yum install -y epel-release
sudo yum install -y cmake3
cmake3 -S . -B build
cmake3 --build build -j
```

If the default LLVM is too old for your environment, install LLVM 15 from
apt.llvm.org and put it first in your shell `PATH`:

```bash
wget https://apt.llvm.org/llvm.sh
chmod +x ./llvm.sh
sudo ./llvm.sh 15

# Add this line to your shell startup file, for example ~/.bashrc or ~/.zshrc.
export PATH=/usr/lib/llvm-15/bin:$PATH
```

Then configure with `-DCPA_BPF_LLVM_VERSION=15`.

Before deploying, also check the kernel warning in
[docs/en/kernel-compatibility.md](kernel-compatibility.md).

## Build the Agent

Build CPA on the target host or on a compatible build host:

```bash
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j
```

The deploy script expects `build/bin/cpa` and, for the normal dynamic build,
`build/bin/libgunwinder.so`.

## BTF Preparation

The BPF backend prefers `/sys/kernel/btf/vmlinux` when the running kernel
provides it:

```bash
test -r /sys/kernel/btf/vmlinux && echo "system BTF is available"
```

If the host does not provide system BTF, generate a detached BTF file from the
debug-info `vmlinux` that exactly matches the running kernel, then pass it
explicitly:

```bash
sudo mkdir -p /etc/cpa
sudo pahole --btf_encode_detached=/etc/cpa/vmlinux.btf \
  /usr/lib/debug/boot/vmlinux-$(uname -r)
```

Common distributions may place the debug-info kernel image in a different
path. The important requirement is that the `vmlinux` input must match the
running kernel. When running CPA directly, pass the detached BTF with
`cpa monitor --btf_path /etc/cpa/vmlinux.btf`. When using the deployment
helper, pass the same file to
`tools/deploy_cpa.sh --btf /etc/cpa/vmlinux.btf`; the helper writes it to the
`btf_path` field in `/etc/cpa/cpa.conf`.

## Release Installer

After a GitHub release is published, install the portable Linux x86_64 package
with:

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/refs/heads/main/tools/install_cpa.sh | sudo bash
```

To pin a version:

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/refs/heads/main/tools/install_cpa.sh | sudo bash -s -- --version v1.0.0
```

The installer downloads `cpa_portable-linux-x86_64` from GitHub Releases and
then calls `tools/deploy_cpa.sh`. Pass deployment options after `--`, for
example `--no-start`, `--freq`, `--store-dir`, or `--btf`.

## One-command Deployment

Run the helper as root for a locally built binary:

```bash
sudo tools/deploy_cpa.sh \
  --binary build/bin/cpa \
  --btf /etc/cpa/vmlinux.btf
```

When system BTF exists, omit `--btf`:

```bash
sudo tools/deploy_cpa.sh --binary build/bin/cpa
```

For a dry install that writes files but does not start the service, pass
`--no-start`.

The script performs these actions:

- installs CPA to `/usr/local/lib/cpa/cpa`
- installs `libgunwinder.so` next to the binary when it is present
- creates `/usr/local/bin/cpa` as a convenience symlink
- creates `/var/log/cpa`
- writes `/etc/cpa/cpa.conf`
- writes `/etc/systemd/system/cpa.service`
- runs `systemctl daemon-reload`
- enables and starts `cpa.service`

Default generated config:

```text
store_dir: /var/log/cpa
backend: bpf
freq: 49
record_interval: 1
persistent_day: 7
log_print_cycles: 10
record_env_name: POD_NAME,MY_POD_NAME
```

If `--btf` is provided, the script also writes:

```text
btf_path: /etc/cpa/vmlinux.btf
```

## Uninstall

Remove the installed binary, symlink, config file, and systemd unit while
preserving profiling data under `/var/log/cpa`:

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/refs/heads/main/tools/install_cpa.sh | sudo bash -s -- --uninstall
```

For a local checkout, run:

```bash
sudo tools/deploy_cpa.sh --uninstall
```

To also remove the profile store root, add `--purge-store`:

```bash
sudo tools/deploy_cpa.sh --uninstall --purge-store
```

## Manual systemd Service

If you prefer to manage files yourself, install the binary and shared library
under one directory, create `/etc/cpa/cpa.conf`, then use this unit:

```ini
[Unit]
Description=Continue Profiling Agent
After=local-fs.target
ConditionPathExists=/etc/cpa/cpa.conf

[Service]
Type=simple
WorkingDirectory=/usr/local/lib/cpa
Environment=LD_LIBRARY_PATH=/usr/local/lib/cpa
ExecStart=/usr/local/lib/cpa/cpa monitor --config /etc/cpa/cpa.conf
Restart=always
RestartSec=5s
KillSignal=SIGINT
TimeoutStopSec=30s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

Then enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cpa.service
```

## Operations

Check status and logs:

```bash
sudo systemctl status cpa.service
sudo journalctl -u cpa.service -f
```

Inspect stored data:

```bash
cpa show --read /var/log/cpa/cpa_YYMMDD --show_range 1
cpa show --read /var/log/cpa/cpa_YYMMDD --output_prof cpa.prof
```

The second command exports from the first matching record unless `--starttime`
and `--endtime` select a specific record timeline range.

Stop or restart:

```bash
sudo systemctl stop cpa.service
sudo systemctl restart cpa.service
```
