// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance Inc.

package main

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

__attribute__((noinline, noclone))
int actual_hot_c_function(int val1) {
    int tempRes = 0;
    int val2 = 10;
    for (int k = 0; k < 5000; k++) {
        tempRes += (val1 * val2 * k) / (k + 1);
        // tempRes -= rand() % 10; // Removed rand() call to simplify
        tempRes -= (k % 10); // Replaced with a simple deterministic calculation
        if (k % 1000 == 0) {
            // sched_yield(); // Equivalent to runtime.Gosched(), requires <sched.h>
        }
    }
    return tempRes;
}

__attribute__((noinline, noclone))
void actual_hot_c_function_end() {
    asm volatile(""); // Ensure it's not optimized away and has a distinct address.
}

typedef int (*executable_func_ptr)(int);

executable_func_ptr mmap_func_ptr = NULL;

// Setup function to mmap and copy the function code
int setup_mmap_executable_function() {
    if (mmap_func_ptr != NULL) {
        // Already initialized
        return 0;
    }

    void *start_addr = (void*)actual_hot_c_function;
    const size_t FIXED_FUNC_SIZE = 4096; // Using a page size as a safer fixed size
    size_t func_size = FIXED_FUNC_SIZE;

    fprintf(stderr, "Debug: actual_hot_c_function address: %p\n", start_addr);
    fprintf(stderr, "Debug: Using fixed func_size: %zu\n", func_size);

    if (func_size == 0) {
        fprintf(stderr, "Error: Fixed function size is 0. This is invalid.\n");
        return -3; // New error code for invalid fixed size
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (func_size > page_size) { 
        fprintf(stderr, "Error: Fixed function size for mmap (%zu bytes) is larger than page size (%ld bytes).\n", func_size, page_size);
        return -1; // Indicate failure due to size
    }

    void* mmap_region = mmap(NULL, func_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mmap_region == MAP_FAILED) {
        perror("mmap failed");
        return -1;
    }

    memcpy(mmap_region, start_addr, func_size);

    mmap_func_ptr = (executable_func_ptr)mmap_region;
    return 0; // Success
}

int call_mmap_function(int val) {
    if (mmap_func_ptr == NULL) {
        fprintf(stderr, "Mmap function not initialized\n");
        return -1; // Or handle error appropriately
    }
    return mmap_func_ptr(val);
}

void cleanup_mmap_region() {
    if (mmap_func_ptr != NULL) {
        const size_t FIXED_FUNC_SIZE = 4096; // Must match the size used in setup
        size_t func_size = FIXED_FUNC_SIZE;
        
        if (func_size > 0) { // Only munmap if size is valid
            munmap((void*)mmap_func_ptr, func_size);
        }
        mmap_func_ptr = NULL;
        fprintf(stderr, "Debug: mmap region cleaned up using fixed size: %zu\n", func_size);
    }
}

*/
import "C"

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"time"
)

func go_path_a_process_data_final(n int) int {
	// Call the C function that executes from the mmap-ed region
	// The parameter 'n' is passed to the C function.
	// The C function `call_mmap_function` will internally call the mmap_func_ptr.
	return int(C.call_mmap_function(C.int(n)))
}

func go_path_a_process_data_stage_4(n int) int {
	runtime.Gosched()
	return go_path_a_process_data_final(n + rand.Intn(100))
}

func go_path_a_process_data_stage_3(n int) int {
	runtime.Gosched()
	return go_path_a_process_data_stage_4(n + rand.Intn(100))
}

func go_path_a_process_data_stage_2(n int) int {
	runtime.Gosched()
	return go_path_a_process_data_stage_3(n + rand.Intn(100))
}

func go_path_a_process_data_entry(n int) int {
	runtime.Gosched()
	return go_path_a_process_data_stage_2(n + rand.Intn(100))
}

func go_path_b_transform_input_final(n int) int {
	runtime.Gosched()
	return n * rand.Intn(5)
}

func go_path_b_transform_input_stage_2(n int) int {
	runtime.Gosched()
	return go_path_b_transform_input_final(n * rand.Intn(5))
}

func go_path_b_transform_input_entry(n int) int {
	runtime.Gosched()
	return go_path_b_transform_input_stage_2(n * rand.Intn(5))
}

func worker(id int, jobs <-chan int, results chan<- int) {

	for j := range jobs {
		// Simulate work with deep call stack
		fmt.Printf("Worker %d started job %d\n", id, j)
		var res int
		for i := 0; i < 1000; i++ {
			// anonHotFunction is now called deep inside go_path_a_process_data_final
			// So, to make it the hot path, we call go_path_a_process_data_entry more often.
			if i%10 < 9 { // Call path A (which leads to anonHotFunction) 90% of the time
				res += go_path_a_process_data_entry(j + i)
			} else { // Call path B 10% of the time
				res += go_path_b_transform_input_entry(j + i)
			}
		}
		results <- res
		fmt.Printf("Worker %d finished job %d\n", id, j)
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	C.srand(C.uint(time.Now().UnixNano())) // Seed C's rand as well

	// Setup the mmap-ed executable function
	if C.setup_mmap_executable_function() != 0 {
		fmt.Println("Failed to setup mmap executable function")
		os.Exit(1)
	}
	defer C.cleanup_mmap_region() // Ensure cleanup on exit

	fmt.Printf("Go Workload (sym_go_anon with mmap) PID: %d\n", os.Getpid())

	numJobs := 10000000 // Large number of jobs to keep CPU busy
	numWorkers := runtime.NumCPU() * 2 // More workers than CPUs to ensure contention

	jobs := make(chan int, numJobs)
	results := make(chan int, numJobs)

	for w := 1; w <= numWorkers; w++ {
		go worker(w, jobs, results)
	}

	for j := 1; j <= numJobs; j++ {
		jobs <- j
	}
	close(jobs)

	var mainLoopCounter int64
	for {
		mainLoopCounter++
		if mainLoopCounter%100000000 == 0 {
			fmt.Println("Main loop still running...")
		}
		if mainLoopCounter < 0 { // Prevent overflow
		    mainLoopCounter = 0
		}
	}
}
