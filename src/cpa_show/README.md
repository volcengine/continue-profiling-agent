本目录为 `cpa_show` 工程。

定位
- `cpa_show` 是 `continue-profiling-agent` 的 Rust 版 TUI 查看器。
- 它只作为 `cpa show --use_cui` 的内嵌 Rust 组件编译和调用。
- 目标是高效打开 `cpa monitor` 生成的 profile 目录，并提供 conf 展示、筛选、趋势图与火焰图查看能力。

架构
- UI 依赖稳定的数据面：`UiProfile` + `ProfileData`。
- 通过 `ProfileLoader`/`LoaderRegistry` 从路径选择加载器；当前默认 loader 为 `binary-dir`。

使用方式
- 通过 `cpa show --read /var/log/cpa/<store> --use_cui` 打开。
- Rust crate 本身不再作为独立可执行文件发布。

常用参数
- `--read, -r <DIR>`：profile 目录（必填）
- `--starttime, -B <HH:MM:SS>`：起始偏移时间（默认 `00:00:00`）
- `--endtime, -E <HH:MM:SS>`：结束偏移时间（默认 `00:00:00`；表示只取最小窗口）
- `--show_range, -p <0|1>`：打印时间范围（默认 0，非 0 则打印后退出）
- `--use_cache, -u <0|1>`：是否复用 `decompressed/`（默认 0；0=每次重新解压覆盖，1=存在则复用）
- `--no-tui`：只加载并打印摘要，不进入 TUI
- `--timing`：打印启动阶段各步骤耗时（stderr）

编译说明
- 需要 Rust 工具链（Cargo）与 `libiberty-dev`（用于 C++ demangle）。
- CMake 会在构建 `cpa` 时直接编译 `libcpa_show.a`。

使用手册
- 中文：`doc/cpa_show.md`
- English: `doc/cpa_show.en.md`

项目级文档
- English overview: [../../README.md](../../README.md)
- 中文总览：[../../README.zh-CN.md](../../README.zh-CN.md)
- English architecture: [../../docs/en/architecture.md](../../docs/en/architecture.md)
- 中文架构：[../../docs/zh-CN/architecture.md](../../docs/zh-CN/architecture.md)
