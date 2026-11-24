// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_USER_STACK_VMA_BPF_H
#define CPA_USER_STACK_VMA_BPF_H

/*
 * The VMA that holds a user SP, from bpf_find_vma (5.17, and vendor kernels
 * that backported it).  Only objects built with CPA_STACK_VMA_BOUND include this:
 * the helper and its bpf2bpf callback cannot even be loaded on older kernels,
 * so those objects are opened only where the helper was probed.
 *
 * Copying the user stack page by page past the end of its VMA can read
 * whatever is mapped next, a device mapping included, whose reads go to the
 * hardware and are slow.  Bounded by the VMA, the copy never leaves the stack.
 */

/* include/linux/mm.h; unchanged since the bits were introduced */
#define USER_STACK_VM_PFNMAP	0x00000400UL
#define USER_STACK_VM_IO	0x00004000UL

enum user_stack_vma {
	USER_STACK_VMA_UNKNOWN,	/* no VMA: copy page by page as before */
	USER_STACK_VMA_FOUND,	/* copy up to its end */
	USER_STACK_VMA_DEVICE,	/* SP sits in an I/O or PFN mapping: copy nothing */
};

struct user_stack_vma_info {
	u64 end;
	u64 flags;
};

static long user_stack_vma_found(struct task_struct *task,
				 struct vm_area_struct *vma,
				 struct user_stack_vma_info *info)
{
	info->end = vma->vm_end;
	info->flags = vma->vm_flags;
	return 0;
}

/*
 * Where the VMA of the current task holding sp ends.  The helper only
 * try-locks mmap_lock, so a busy lock (or no VMA at sp) gives UNKNOWN; the
 * caller then takes the unbounded path for this sample and never retries.
 */
static __always_inline enum user_stack_vma user_stack_vma_end(u64 sp, u64 *end)
{
	struct user_stack_vma_info info = {};

	if (bpf_find_vma(bpf_get_current_task_btf(), sp, user_stack_vma_found,
			 &info, 0))
		return USER_STACK_VMA_UNKNOWN;
	if (info.flags & (USER_STACK_VM_IO | USER_STACK_VM_PFNMAP))
		return USER_STACK_VMA_DEVICE;
	*end = info.end;
	return USER_STACK_VMA_FOUND;
}

#endif /* CPA_USER_STACK_VMA_BPF_H */
