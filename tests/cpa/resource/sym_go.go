// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance Inc.

package main

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"time"
)

func go_path_a_process_data_final(n int) int {
	runtime.Gosched()
	return n + rand.Intn(100)
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
			// Make go_path_a_process_data_entry the dominant hot path
			if i % 10 < 8 { // Call path A 80% of the time
								res += go_path_a_process_data_entry(j * i)
			} else { // Call path B 20% of the time (implicitly, as there are only two paths here)
								res += go_path_b_transform_input_entry(j + i)
			}
		}
		results <- res
		fmt.Printf("Worker %d finished job %d\n", id, j)
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	fmt.Printf("Go Workload (sym_go) PID: %d\n", os.Getpid())

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
