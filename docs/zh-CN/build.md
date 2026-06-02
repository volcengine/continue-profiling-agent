# CPA 构建指南

[返回 README](../../README.zh-CN.md)

## 主机要求

CPA 面向支持 eBPF CO-RE 的 Linux 环境。

所需工具：

- `cmake >= 3.10`
- `clang`
- `llvm-strip`
- `llvm-objdump`
- `python3`
- `cargo`
- `make`

所需库：

- `libelf`
- `libdw`
- `libzstd`
- `libcrypto`
- `libiberty`

Ubuntu 24.04 可用以下命令安装构建依赖：

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  autoconf automake binutils-dev build-essential clang-18 cmake curl git \
  libdw-dev libelf-dev libiberty-dev libssl-dev libtool libzstd-dev \
  llvm-18 make pkg-config python3 zlib1g-dev zstd
```

然后配置时传入 `-DCPA_BPF_LLVM_VERSION=18`。

实际还需要：

- 能正常使用 BTF/CO-RE 的内核环境
- 能运行 BPF 和 perf 采集的权限
- 用于构建内嵌 `cpa_show` 静态库的 Rust 工具链
- 已从 GitHub 初始化的 `libs/libgunwinder` submodule

第三方 BPF 依赖来源和 checkpoint 详见
[docs/zh-CN/bpf-dependencies.md](bpf-dependencies.md)。

## 配置与构建

首次 clone 后先初始化 BPF 相关 submodule：

```bash
git submodule update --init --recursive
```

标准构建：

```bash
cmake -S . -B build
cmake --build build -j
```

主产物：

- `build/bin/cpa`

标准构建过程中，CMake 会在 `libs/libgunwinder` 下调用
`lib/libgunwinder.so` Makefile 目标，把生成的 shared object 复制到
`build/bin/cpa` 旁边，并通过 `$ORIGIN` 运行时搜索路径动态链接。
source-tree 构建不需要额外安装 `libgunwinder`。

ASan 构建：

```bash
cmake -S . -B build-asan -DCPA_BPF_ENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-asan -j
```

ASan 主产物：

- `build-asan/bin/cpa`

Portable 打包产物：

```bash
cmake --build build -j --target cpa_portable
```

- `build/bin/cpa_portable`

`cpa_portable` 通过
[SOPacker](https://github.com/XinShuichen/sopacker)
生成。默认会在首次构建该目标时把上游仓库拉取到 build 目录；如果你已经有
本地 checkout，可以在配置阶段传入：

```bash
cmake -S . -B build -DCPA_BPF_SOPACKER_DIR=/path/to/sopacker
```

该目标把动态链接的可执行文件及其依赖 shared libraries 打成单文件脚本，
不会把 `libgunwinder` 静态链接进主程序。

构建过程中还会生成：

- `build/generated/` 下的 BPF 生成文件
- `src/cpa_show/rust/target/release/` 下的 Rust 静态库

如果需要在构建阶段生成嵌入式 `min_core_btf`：

```bash
git clone --depth 1 https://github.com/aquasecurity/btfhub-archive bpf/btfhub-archive
cmake -S . -B build
cmake --build build -j
```

构建系统会在 `bpf/btfhub-archive` 存在时自动把 archive 编进产物。也可以通过
`-DCPA_BPF_BTFHUB_ARCHIVE=/path/to/btfhub-archive` 指向其他 checkout。

## 从零重建

如果修改了构建系统、BPF 或 Rust 集成，直接 clean rebuild 往往更省时间：

```bash
rm -rf build
cmake -S . -B build
cmake --build build -j
```

如果要强制重建 Rust 产物：

```bash
rm -rf src/cpa_show/rust/target
cmake --build build -j
```

## 运行测试

主 Python 测试集：

```bash
pytest -q tests/cpa
```

ASan 全流程 smoke：

```bash
TEST_CPA_PATH=$PWD/build-asan/bin/cpa \
TEST_CPA_ASAN=1 \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
pytest -q tests/cpa/test_asan_e2e.py
```

说明：

- `tests/cpa/test_asan_e2e.py` 覆盖 `monitor -> show` 主链
- `libfaketime` 相关跨天测试默认不会在 ASan 下执行
- CPU 预算/性能类断言不作为 ASan 质量门槛

内嵌 viewer 的 Rust 测试：

```bash
cargo test --manifest-path src/cpa_show/rust/Cargo.toml
```

很多集成测试依赖：

- root 权限
- 能加载仓库内测试模块的内核和工具链环境
- 已成功构建出的 `build/bin/cpa`

## 常见构建问题

找不到 Cargo：

- 本仓库强依赖 `cpa_show`
- `cmake/cpa.cmake` 在找不到 `cargo` 时会直接失败

找不到系统库：

- 当前构建依赖 `elf`、`dw`、`zstd`、`crypto`、`iberty`
- 如果 CMake 找不到这些库，需要检查系统库路径，或设置 `CMAKE_LIBRARY_PATH`

BTF 或内核不匹配：

- BPF 后端依赖目标内核和 BTF 可用性
- 默认优先使用 `/sys/kernel/btf/vmlinux`
- 如果需要，也可以在运行时通过 `--btf_path` 指定自定义 BTF

权限不足：

- `cpa monitor` 和大多数集成测试都需要足够权限来打开 perf event、加载 BPF 程序并访问目标进程信息
