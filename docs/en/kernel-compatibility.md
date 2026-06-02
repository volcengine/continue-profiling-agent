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
| 5.10 LTS or older | Not recommended without validation | Outside CPA's documented upstream support window; check vendor BPF backports and BTF/CO-RE support first. |

For distribution kernels, do not rely only on `uname -r`. Vendors often
backport BPF and mm fixes without changing the upstream major/minor version.
Check the vendor kernel changelog for the upstream fix commit before enabling
CPA.
