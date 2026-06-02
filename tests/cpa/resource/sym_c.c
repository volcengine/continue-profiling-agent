// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

// Functions to create deep call stack
long c_path_a_calc_final_stage(long i)
{
	return i + rand();
}
long c_path_a_calc_stage_9(long i)
{
	return c_path_a_calc_final_stage(i + rand());
}
long c_path_a_calc_stage_8(long i)
{
	return c_path_a_calc_stage_9(i + rand());
}
long c_path_a_calc_stage_7(long i)
{
	return c_path_a_calc_stage_8(i + rand());
}
long c_path_a_calc_stage_6(long i)
{
	return c_path_a_calc_stage_7(i + rand());
}
long c_path_a_calc_stage_5(long i)
{
	return c_path_a_calc_stage_6(i + rand());
}
long c_path_a_calc_stage_4(long i)
{
	return c_path_a_calc_stage_5(i + rand());
}
long c_path_a_calc_stage_3(long i)
{
	return c_path_a_calc_stage_4(i + rand());
}
long c_path_a_calc_stage_2(long i)
{
	return c_path_a_calc_stage_3(i + rand());
}
long c_path_a_calc_entry(long i)
{
	return c_path_a_calc_stage_2(i + rand());
}

// Another set of functions for a different hot path
long c_path_b_transform_final_stage(long i)
{
	return i * rand();
}
long c_path_b_transform_stage_4(long i)
{
	return c_path_b_transform_final_stage(i * rand());
}
long c_path_b_transform_stage_3(long i)
{
	return c_path_b_transform_stage_4(i * rand());
}
long c_path_b_transform_stage_2(long i)
{
	return c_path_b_transform_stage_3(i * rand());
}
long c_path_b_transform_entry(long i)
{
	return c_path_b_transform_stage_2(i * rand());
}

// Function with a large stack allocation
void c_allocate_large_stack_buffer()
{
	char large_array[32 * 1024]; // 32KB array
	for (int i = 0; i < sizeof(large_array); ++i) {
		large_array[i] = (char)(i % 256); // Ensure this line is indented correctly
	}
	// Ensure the array is used to prevent optimization
	long sum = 0;
	for (int i = 0; i < sizeof(large_array); ++i) {
		sum += large_array[i];
	}
	if (sum == 0)
		printf("sum is zero\n"); // Should not happen
}

int main(int argc, char *argv[])
{
	srand(time(NULL));
	long result = 0;
	int use_large_stack = 0;

	if (argc > 1 && strcmp(argv[1], "large_stack") == 0) {
		use_large_stack = 1;
	}

	printf("C Workload (sym_c) PID: %d\n", getpid());
	if (use_large_stack) {
		printf("Using large stack allocation.\n");
	}

	while (1) {
		for (long i = 0; i < 1000000; ++i) {
			// Make c_path_a_calc_entry the dominant hot path
			if (i % 10 < 8) { // Call path A 80% of the time
				result += c_path_a_calc_entry(i);
			} else if (i % 10 == 8) { // Call path B 10% of the time
				result += c_path_b_transform_entry(i);
			} else { // Other operations 10% of the time
				if (use_large_stack) {
					c_allocate_large_stack_buffer();
				}
				result -= i;
			}
		}
		// usleep(10000); // Optional: sleep to reduce CPU usage if needed for testing specific scenarios
		if (result > 100000000000L) { // Prevent overflow and ensure computation
			result = result / 2;
		}
	}
	return 0;
}
