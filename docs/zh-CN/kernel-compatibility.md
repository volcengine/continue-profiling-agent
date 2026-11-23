# 内核兼容性说明

[返回 README](../../README.zh-CN.md)

## BPF copy_from_user_nofault 死锁风险

不要在 upstream Linux 5.19 到 6.3 的内核上运行 CPA。
这个范围包含 6.1 LTS。

这些内核处于 `copy_from_user_nofault()` 内核 BPF 问题的影响范围内。CPA 的
BPF 后端会从 tracing context 使用 `bpf_probe_read_user()` 等 BPF helper；在
受影响内核上，这些路径可能进入不适合当前上下文的
`copy_from_user_nofault()` 实现。失败模式可能是主机 lockup，因此即使只是
测试，也不要在这些内核上部署 CPA。

根因是内核侧 nofault user-copy 实现问题，不是 CPA userspace 逻辑问题。受影响
实现主要有三个问题：

- 使用了面向 user context 的 `access_ok()`，从 IRQ context 调用时可能触发
  warning；
- 缺少架构相关的 `nmi_uaccess_okay()` 检查；x86 在 NMI-like context 做用户
  访问前需要这个检查；
- 在 `CONFIG_HARDENED_USERCOPY` 下，`__copy_from_user_inatomic()` 可能调用
  `check_object_size()`，进一步进入 `find_vmap_area()` 并获取 spinlock。这个
  路径不能安全地从 BPF、kprobe/eprobe 或 perf 路径调用，可能导致死锁。

upstream fix 让 `copy_from_user_nofault()` 改用更底层的 `__access_ok()`，补上
`nmi_uaccess_okay()`，并避免在 page fault disabled 时进入 hardened-usercopy
的 vmalloc-area 锁路径。

参考链接：

- Original report thread: https://lore.kernel.org/bpf/20230118213202.3859786-1-hsinweih@uci.edu/T/
- Follow-up fix thread: https://lore.kernel.org/bpf/20230118051443.78988-1-alexei.starovoitov@gmail.com/
- Upstream fix: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d319f344561de23e810515d109c7278919bff7b0

## 版本建议

| 内核版本线 | CPA 建议 | 说明 |
| --- | --- | --- |
| Upstream 5.19.x | 不要使用 | 受 nofault user-copy bug 影响。 |
| Upstream 6.0.x | 不要使用 | 受 nofault user-copy bug 影响。 |
| Upstream 6.1.x LTS | 不要使用 | 该 LTS 线在受影响 upstream 范围内。 |
| Upstream 6.2.x | 不要使用 | 受 nofault user-copy bug 影响。 |
| Upstream 6.3.x | 不要使用 | 6.4 之前最后一个受影响 upstream 版本线。 |
| Upstream 6.4+ | 支持基线 | upstream fix 进入 6.4 开发周期。 |
| 5.15 LTS 与 vendor kernel | 仅在 vendor 已回合修复时使用 | 原始报告涉及 5.15；需确认发行版已回合修复。 |
| 5.10 LTS 或更老版本 | 未验证不建议使用 | 不在 CPA 当前 upstream 支持说明范围内；需先确认 vendor BPF backport 和 BTF/CO-RE 支持。 |

## 5.3 以前的内核（例如 4.14）

5.3 以前的内核不允许 BPF 程序里有循环，每个程序最多 4096 条指令；4.18 以前的内核
没有 `bpf_get_stack`。在这些内核上，BPF 后端会加载 on-CPU 和 off-CPU 采集对象的
lite 版本：

- 内核栈用 `bpf_get_stackid` 存进一个 16 MiB 的 stack-trace map，再在用户态取出；
  相同的栈共用一项，哈希到已占用槽位的新栈会覆盖旧栈，所以那一刻还在队列里的
  样本可能显示成新的栈；
- 每个样本最多拷贝 16 KiB 用户栈（DWARF 回溯到拷贝末尾为止）；
- 不采集帧指针用户栈。

缺少 `bpf_get_stack`，或完整对象加载失败时，会自动改用 lite 对象；这时不使用
ring buffer 数据通路。已在 4.14.81（x86_64）上验证 on-CPU、off-CPU 和
只采内核栈三种模式。

`--pagefault` 在 5.4 以前不可用：那里 perf 输出到满的缓冲区时失败不会告诉
BPF 程序，采样页的计数无法精确。这些内核上它会拒绝启动并说明原因。

对于发行版内核，不要只看 `uname -r`。vendor 经常在不改变 upstream
major/minor 版本的情况下回合 BPF 和 mm 修复。启用 CPA 前，请检查 vendor 内核
changelog，确认 upstream fix commit 已包含。
`cpa capabilities` 可以查看当前内核实际提供了哪些 BPF 能力（见使用手册）。
