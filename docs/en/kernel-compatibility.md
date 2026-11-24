# Kernel Compatibility Notes

[Back to README](../../README.md)

## BPF copy_from_user_nofault Deadlock Warning

Do not run CPA on upstream Linux kernels from 5.19 through 6.3.
That range includes the 6.1 LTS line.

Those kernels are in the affected range of a kernel BPF issue in
`copy_from_user_nofault()`. CPA's BPF backend can use BPF helpers such as
`bpf_probe_read_user()` from tracing contexts; on affected kernels those paths
can reach `copy_from_user_nofault()` in contexts where the implementation is
not safe. The failure mode can be a host lockup, so CPA should not be deployed
on those kernels even for testing.

The root cause is a kernel-side nofault user-copy bug, not a userspace CPA bug.
The affected implementation had three problems:

- it used `access_ok()`, which is intended for user context and can warn when
  called from IRQ contexts;
- it missed the architecture `nmi_uaccess_okay()` check that x86 needs before
  user access from NMI-like contexts;
- under `CONFIG_HARDENED_USERCOPY`, `__copy_from_user_inatomic()` could call
  `check_object_size()`, which can reach `find_vmap_area()` and take a spinlock.
  That is not safe from BPF, kprobe/eprobe, or perf paths and can deadlock.

The upstream fix makes `copy_from_user_nofault()` use the lower-level
`__access_ok()` check, adds the missing `nmi_uaccess_okay()` gate, and avoids
the hardened-usercopy vmalloc-area lock path while page faults are disabled.

References:

- Original report thread: https://lore.kernel.org/bpf/20230118213202.3859786-1-hsinweih@uci.edu/T/
- Follow-up fix thread: https://lore.kernel.org/bpf/20230118051443.78988-1-alexei.starovoitov@gmail.com/
- Upstream fix: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d319f344561de23e810515d109c7278919bff7b0

## Version Guidance

| Kernel line | CPA guidance | Notes |
| --- | --- | --- |
| Upstream 5.19.x | Do not use | Affected by the nofault user-copy bug. |
| Upstream 6.0.x | Do not use | Affected by the nofault user-copy bug. |
| Upstream 6.1.x LTS | Do not use | This LTS line is inside the affected upstream range. |
| Upstream 6.2.x | Do not use | Affected by the nofault user-copy bug. |
| Upstream 6.3.x | Do not use | Last affected upstream line before 6.4. |
| Upstream 6.4+ | Supported baseline | The upstream fix is in the 6.4 development cycle. |
| 5.15 LTS and vendor kernels | Vendor-patched only | The original report involved 5.15; use only when your vendor confirms the fix is backported. |
| 5.10 LTS or older | Validate first | Check vendor BPF backports and BTF/CO-RE support; 4.14 runs with the lite objects described below. |

Tested for this release: 4.14.81, 5.15 (x86_64 and arm64), 6.6.95, 6.8.0 and
6.17.0, with on-CPU, off-CPU, process selection, exit capture and
`--pagefault` (refused before 5.4).

## User Stack Copy

On-CPU samples copy the user stack from SP into the event. Where the kernel
offers `bpf_find_vma` (5.17, and vendor kernels that backported it; see
`cpa capabilities`, `find_vma`), the ring-buffer object copies up to the end
of the VMA holding SP only: a page inside it that cannot be read is
zero-filled and the copy goes on, and a stack in an I/O or PFN mapping is not
read at all. Elsewhere, and for off-CPU samples, the copy stops at the first
page that cannot be read, so a large frame whose middle pages were never
touched can lose its callers. The start line says which copy runs
(`user_stack_copy=vma_bound|unbounded`).

## Linux 6.15 to 6.17

Followed by the BPF backend: `kernfs_node::parent` became `__parent` (6.15),
`do_coredump()` became `vfs_coredump()` (6.17; `--enable_coredump_capture`
attaches whichever the kernel has), `CONFIG_X86_FRED` kernels keep 16 bytes
free at the top of the task stack (the user registers are read 16 bytes
lower), and `.cold` parts of functions are never chosen as kprobe targets.

## Kernels Before 5.3 (for example 4.14)

Kernels before 5.3 accept no loops and at most 4096 instructions per BPF
program, and kernels before 4.18 have no `bpf_get_stack`. On such kernels the
BPF backend loads a lite variant of the on-CPU and off-CPU capture objects:

- kernel stacks are taken with `bpf_get_stackid` into a 16 MiB stack-trace
  map and resolved in user space; identical stacks share one entry, and a
  stack that hashes to an occupied bucket replaces it, so a sample still
  queued at that moment can show the newer stack;
- at most 16 KiB of the user stack is copied per sample (DWARF unwinding
  stops where the copy ends);
- no frame-pointer user stack is captured.

The lite objects are chosen automatically when `bpf_get_stack` is missing, or
when the full object fails to load. The ring-buffer datapath is not used
there. Validated on 4.14.81 (x86_64) with on-CPU, off-CPU and kernel-only
sampling.

`--pagefault` is not available before 5.4: a perf output into a full buffer
fails there without telling the BPF program, so its accounting of sampled
pages could not be exact. It refuses to start on those kernels, saying so.

For distribution kernels, do not rely only on `uname -r`. Vendors often
backport BPF and mm fixes without changing the upstream major/minor version.
Check the vendor kernel changelog for the upstream fix commit before enabling
CPA.
`cpa capabilities` shows which BPF features the running kernel actually
offers (see the usage guide).
