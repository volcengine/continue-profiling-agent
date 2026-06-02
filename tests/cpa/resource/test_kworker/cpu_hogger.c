// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h> // For msleep_interruptible, mdelay
#include <linux/timekeeping.h> // For ktime_get
#include <linux/sched/signal.h> // For allow_signal

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test User via AI Assistant");
MODULE_DESCRIPTION("A kernel module to hog CPU with a kworker, alternating two hot paths.");

static struct task_struct *cpu_hog_kworker_thread;

// --- Path A: Simulating a complex data processing pipeline ---
// Level 5 (Innermost function for Path A)
static void path_a_core_computation(volatile unsigned long long *counter)
{
	ktime_t deadline;
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_A: Core computation - Starting 500ms CPU hog\n");
	deadline = ktime_add_ms(ktime_get(), 500);
	while (ktime_before(ktime_get(), deadline)) {
		(*counter)++; // Simple busy work to consume CPU cycles
		// DO NOT call cond_resched() or msleep() or anything that yields here
	}
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_A: Core computation - Finished 500ms CPU hog\n");
}
// Level 4
static void path_a_analyze_dataset(volatile unsigned long long *counter)
{
	path_a_core_computation(counter);
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_A: Analyzing dataset\n");
}
// Level 3
static void path_a_transform_data(volatile unsigned long long *counter)
{
	path_a_analyze_dataset(counter);
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_A: Transforming data\n");
}
// Level 2
static void path_a_load_and_validate_data(volatile unsigned long long *counter)
{
	path_a_transform_data(counter);
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_A: Loading and validating data\n");
}
// Level 1 (Entry to Path A stack from perform_cpu_intensive_work)
static void path_a_data_processing_pipeline(volatile unsigned long long *counter)
{
	path_a_load_and_validate_data(counter);
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_A: Data processing pipeline entry\n");
}

// --- Path B: Simulating a network request handling pipeline ---
// Level 5 (Innermost function for Path B)
static void path_b_generate_response_data(volatile unsigned long long *counter)
{
	ktime_t deadline;
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_B: Generating response data - Starting 500ms CPU hog\n");
	deadline = ktime_add_ms(ktime_get(), 500);
	while (ktime_before(ktime_get(), deadline)) {
		(*counter)++; // Simple busy work to consume CPU cycles
		// DO NOT call cond_resched() or msleep() or anything that yields here
	}
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_B: Generating response data - Finished 500ms CPU hog\n");
}
// Level 4
static void path_b_execute_query(volatile unsigned long long *counter)
{
	path_b_generate_response_data(counter);
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_B: Executing query\n");
}
// Level 3
static void path_b_authorize_request(volatile unsigned long long *counter)
{
	path_b_execute_query(counter);
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_B: Authorizing request\n");
}
// Level 2
static void path_b_parse_and_validate_request(volatile unsigned long long *counter)
{
	path_b_authorize_request(counter);
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_B: Parsing and validating request\n");
}
// Level 1 (Entry to Path B stack from perform_cpu_intensive_work)
static void path_b_network_request_handler(volatile unsigned long long *counter)
{
	path_b_parse_and_validate_request(counter);
	// printk(KERN_DEBUG "CPU_HOGGER_PATH_B: Network request handler entry\n");
}

// This function now only calls one of the L1 functions
static void perform_cpu_intensive_work(int path_type, volatile unsigned long long *counter)
{
	// Call the entry function for the selected path (Level 1 of the 5-deep stack)
	// The actual CPU hogging is now done within the L5 functions:
	// path_a_core_computation or path_b_generate_response_data
	if (path_type == 0) {
		// printk(KERN_DEBUG "CPU_HOGGER: Calling Path A pipeline\n");
		path_a_data_processing_pipeline(counter);
	} else {
		// printk(KERN_DEBUG "CPU_HOGGER: Calling Path B pipeline\n");
		path_b_network_request_handler(counter);
	}
	// The CPU hogging loop has been moved to the L5 functions.
}

static int cpu_hog_kworker_main(void *data)
{
	int path_selector = 0;
	volatile unsigned long long work_counter = 0; // Counter to ensure work is done

	allow_signal(SIGKILL);

	printk(KERN_INFO "CPU_HOGGER: kworker started. Will hog CPU for 500ms, then sleep 500ms, alternating paths.\n");

	while (!kthread_should_stop()) {
		perform_cpu_intensive_work(path_selector, &work_counter);

		path_selector = 1 - path_selector;

		if (msleep_interruptible(500)) {
			printk(KERN_INFO "CPU_HOGGER: kworker sleep interrupted, preparing to stop.\n");
			break;
		}
	}

	printk(KERN_INFO "CPU_HOGGER: kworker stopping. Final work_counter: %llu\n", work_counter);
	return 0;
}

static int __init cpu_hogger_module_init(void)
{
	printk(KERN_INFO "CPU_HOGGER: Initializing module.\n");

	cpu_hog_kworker_thread = kthread_run(cpu_hog_kworker_main, NULL, "cpu_hog_kworker");
	if (IS_ERR(cpu_hog_kworker_thread)) {
		printk(KERN_ERR "CPU_HOGGER: Failed to create kworker thread (error %ld).\n", PTR_ERR(cpu_hog_kworker_thread));
		return PTR_ERR(cpu_hog_kworker_thread);
	}
	printk(KERN_INFO "CPU_HOGGER: kworker thread created and started successfully.\n");
	return 0;
}

static void __exit cpu_hogger_module_exit(void)
{
	printk(KERN_INFO "CPU_HOGGER: Exiting module.\n");
	if (cpu_hog_kworker_thread) {
		printk(KERN_INFO "CPU_HOGGER: Sending stop signal to kworker thread.\n");
		kthread_stop(cpu_hog_kworker_thread);
		printk(KERN_INFO "CPU_HOGGER: kworker thread stopped.\n");
	}
}

module_init(cpu_hogger_module_init);
module_exit(cpu_hogger_module_exit);
