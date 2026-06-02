
# cpa_show 用户手册

> `cpa_show`：`continue-profiling-agent` 的 TUI flamegraph viewer。

---

### 1. 目标与整体逻辑

`cpa_show` 用于打开 profile 路径（当前支持 `cpa monitor` 生成的采样目录：`conf/strmap/idsmap/stack.bin`），在终端内提供：

- **趋势图（CPU Trend）**：展示选中时间窗口附近的 CPU 总利用率（CPU）与内核态利用率（Sys）。
- **火焰图（Flamegraph）**：对当前窗口内的调用栈进行聚合，支持 zoom 与不同聚合方向。
- **筛选（Filters）**：按 `pid/comm/cpu/pod` 过滤样本。
- **筛选（Filters）**：支持 `cgid`（cgroup_id）过滤。
- **配置/帮助/状态**：快速查看 `conf`，以及键位提示。

核心思想：

1) `idsmap/stack.bin` 大文件按需读取（避免一次性全量加载造成卡顿）。
2) 曲线计算为增量/后台补齐；当“当前屏幕可见曲线”未完成时会忙刷以确保即时出现曲线。
3) 字符串帧（`strmap`）在加载阶段做 C++ demangle（基于 `libiberty`），并缓存已 demangle 的结果；同时可去除模板参数以提升可读性。

架构说明：

- UI 只依赖稳定数据面：`UiProfile` + `ProfileData`（records/entries/ids/strings/metadata）。
- 当前实现使用 `binary-dir` loader 加载存储目录。

---

### 2. 运行与参数

运行（TUI）：

```bash
cpa show --read /var/log/cpa/cpa_260129 --use_cui
```

常用参数（与 `cpa show --use_cui` 对齐）：

- `--read, -r <DIR>`：profile 数据目录（必填）。
- `--starttime, -B <HH:MM:SS>`：record 时间线里的起始绝对时间。
- `--endtime, -E <HH:MM:SS>`：record 时间线里的结束绝对时间。
- `--show_range, -p <0|1>`：打印日志时间范围（默认 0；非 0 则打印后退出）。
- `--use_cache, -u <0|1>`：是否复用 `decompressed/`（默认 0；0=每次重新解压覆盖，1=存在则复用）。

额外参数：

- `--no-tui`：只加载并打印摘要，不进入 TUI（便于排障/脚本）。
- `--timing`：打印启动阶段耗时（输出到 stderr；注意不要在进入 TUI 后额外输出）。

> 说明：`cpa_show` 在仓库中作为 `cpa show --use_cui` 的内嵌 Rust 组件构建，不再单独发布可执行文件。
> `starttime/endtime` 会和落盘 record 的时间戳直接匹配，是绝对时间，
> 不是相对首个 record 的偏移。选择范围前可用 `--show_range` 或 TUI
> 状态栏确认可用时间线。

---

### 3. 界面分区与字段含义

界面自上而下通常为三块（可用 `g` 切换趋势图高度）：

#### 3.1 CPU Trend（趋势图）

- **横轴（X）**：时间范围。
  - `Sel:` 表示当前窗口对应的时间段。
  - `0` 切换为全量历史视图；`9` 回到默认窗口（默认 600s）。
- **纵轴（Y）**：单位为 **C**（可理解为“核数占用”，例如 12C≈12 个 CPU 核满载）。
  - 左侧会显示 `0C / maxC`，以及在范围内时显示 `NC`、`(N/2)C`（`N` 来自 `conf.cpu_num`）。
- **曲线颜色**：
  - **CPU（青色）**：总 CPU 利用率。
  - **Sys（黄色）**：内核态 CPU 利用率（根据栈帧是否包含 `_[k]` 近似判断）。
- **绿色竖线**：当前窗口（Sel）的起止位置标记。

> 注意：纵轴上限只取“当前屏幕可见区间内”的最大值向上取整（不会强行拉到整机核数）。

#### 3.2 Flamegraph（火焰图）

- **矩形块**：聚合后的调用栈节点。
  - 宽度≈样本占比（samples）。
  - 颜色为稳定 hash（用于区分函数名）。
- **选中节点（高亮）**：用方向键/hjkl/ad 移动，`Enter` zoom，`Esc` 返回。
- **底部详情行**（示例）：
  - `samples`：该节点样本数。
  - `x.xxC/s (y.yyC)`：秒均核数占用 + 总计核秒（`totalC = samples/freq`；`C/s = totalC / window_seconds`）。
  - `View:xx.x%`：该节点相对当前视图 root 的占比。
  - `All:xx.xx%`：该节点相对整机（`cpu_num` 核）的百分比（基于 `C/s` 计算）。
  - `D:d/max Y:y`：当前选中节点深度/最大深度 + 火焰图纵向滚动偏移（便于超高火焰图定位）。

#### 3.3 Status（状态区）

- `Render: xx.xms`：上一帧渲染耗时。
- `Window: ... (Total: ...)`：当前窗口时长与总时长（`ms` 或 `s`，避免 <1s 显示为 0）。
- `Total range: ... .. ...`：整个数据集的时间范围（便于对照当前窗口）。
- `Nodes`：火焰图节点数。
- `Filters`：当前启用的过滤器数量。
- `Toggles: ...`：开关状态（字符表示 ON，`-` 表示 OFF）。
- 第二行显示最近的状态提示（例如 rebuild 用时、输入错误等）。

---

### 4. 键位说明（快捷键）

#### 4.1 通用

- `[q]`：退出。
- `[h]` / `?`：显示/隐藏帮助；再次按同一按键关闭帮助面板。
- `[c]`：显示/隐藏 conf。
- `[o]`：显示/隐藏 filters 列表。

#### 4.2 时间窗口（影响 Flamegraph 与 Sel）

- `[t]` / `[T]`：窗口向后/向前平移一个 span。
- `[s]` / `[S]`：增大/减小 span。
- `[J]`：跳转到 record 时间线里的绝对时间（`HH:MM:SS[.mmm]`）。
- `[R]`：输入 record 时间线里的绝对时间范围（`A..B` 或 `A B`）。

#### 4.3 趋势图视图

- `[g]`：切换趋势图高度（Small/Half/Full）。
- `[0]`：趋势图显示全量历史。
- `[9]`：趋势图回到默认窗口（默认 600s）。

#### 4.4 火焰图导航

- `↑/↓/←/→` 或 `hjkl` 或 `ad`：移动选中节点（同层可环绕）。
- `[Enter]`：zoom 进入选中节点。
- `[Esc]`：退出 zoom（回到 root）。

#### 4.5 聚合方向与显示开关

- `[I]`：聚合方向切换（Caller/Callee）。
- `[N]`：显示/隐藏 Env。
- `[P]`：显示/隐藏 Pid。
- `[M]`：显示/隐藏 Comm。
- `[D]`：显示/隐藏 CgroupId（cgid）。
- `[C]`：显示/隐藏 CPU 列（元数据层）。
- `[H]`：显示/隐藏 Thread。
- `[O]`：仅保留 kernel 栈（KernelOnly）。

#### 4.6 栈帧“显示聚合”

- `[X]`：地址+模块聚合：`0x... [xxx]` 显示为 `<...> [xxx]`。
- `[U]`：IRQOFF CPU 聚合：`<# IRQOFF SAMPLE ON CPU 47 #>` 显示为 `... CPU <...> ...`。

---

### 5. Filters（命令行输入）

按 `:` 进入命令输入（回车生效，`Esc` 取消）。支持（`*v` 表示排除/反选）：

- `pid <n>`：仅保留 pid。
- `pidv <n>`：排除 pid。
- `cpu <set>`：仅保留 cpu 集合（示例：`0-3,7`）。
- `cpuv <set>`：排除 cpu 集合。
- `pod <s>`：仅保留 env/pod。
- `podv <s>`：排除 env/pod。
- `comm <s>`：仅保留 group_comm。
- `commv <s>`：排除 group_comm。
- `cgid <n>`：仅保留 cgroup_id。
- `cgidv <n>`：排除 cgroup_id。
- `unset <cmd>`：移除某类 filter（例如 `unset pid`、`unset cpuv`）。

说明：按 `[o]` 打开 filters 列表时，会以“命令风格”展示当前生效的过滤器（例如 `cpu 0-3,7`）。

---

### 6. 常见问题

1) 趋势图一开始“全黑”：正常，曲线是增量补齐；当当前屏幕曲线未完成时会忙刷直到出现。
2) 字符串太长/乱码：`cpa_show` 渲染时按终端列宽安全裁剪（避免 UTF-8 边界 panic）。

---

英文文档见：`doc/cpa_show.en.md`
