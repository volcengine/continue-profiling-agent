// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched/clock.h>

static unsigned int time_secs = 1;
module_param(time_secs, uint, 0600);
MODULE_PARM_DESC(time_secs, "irq-disable time in seconds");

static int __init test_irq_disable_init(void)
{
	u64 start_ns;
	u64 duration_ns;

	if (!time_secs)
		return -EINVAL;

	duration_ns = (u64)time_secs * NSEC_PER_SEC;

	local_irq_disable();
	start_ns = local_clock();
	while (local_clock() - start_ns < duration_ns)
		cpu_relax();
	local_irq_enable();

	return -EAGAIN;
}
module_init(test_irq_disable_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test module to disable interrupts for a fixed duration");
