// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance


use rand::Rng;
use std::thread;
use std::time::Duration;

fn rust_path_a_compute_final(i: i64) -> i64 { i + rand::thread_rng().gen_range(0..100) }
fn rust_path_a_compute_stage_9(i: i64) -> i64 { rust_path_a_compute_final(i + rand::thread_rng().gen_range(0..100)) }
fn rust_path_a_compute_stage_8(i: i64) -> i64 { rust_path_a_compute_stage_9(i + rand::thread_rng().gen_range(0..100)) }
fn rust_path_a_compute_stage_7(i: i64) -> i64 { rust_path_a_compute_stage_8(i + rand::thread_rng().gen_range(0..100)) }
fn rust_path_a_compute_stage_6(i: i64) -> i64 { rust_path_a_compute_stage_7(i + rand::thread_rng().gen_range(0..100)) }
fn rust_path_a_compute_stage_5(i: i64) -> i64 { rust_path_a_compute_stage_6(i + rand::thread_rng().gen_range(0..100)) }
fn rust_path_a_compute_stage_4(i: i64) -> i64 { rust_path_a_compute_stage_5(i + rand::thread_rng().gen_range(0..100)) }
fn rust_path_a_compute_stage_3(i: i64) -> i64 { rust_path_a_compute_stage_4(i + rand::thread_rng().gen_range(0..100)) }
fn rust_path_a_compute_stage_2(i: i64) -> i64 { rust_path_a_compute_stage_3(i + rand::thread_rng().gen_range(0..100)) }
fn rust_path_a_compute_entry(i: i64) -> i64 { rust_path_a_compute_stage_2(i + rand::thread_rng().gen_range(0..100)) }

fn rust_path_b_process_data_final(i: i64) -> i64 { i * rand::thread_rng().gen_range(0..5) }
fn rust_path_b_process_data_stage_4(i: i64) -> i64 { rust_path_b_process_data_final(i * rand::thread_rng().gen_range(0..5)) }
fn rust_path_b_process_data_stage_3(i: i64) -> i64 { rust_path_b_process_data_stage_4(i * rand::thread_rng().gen_range(0..5)) }
fn rust_path_b_process_data_stage_2(i: i64) -> i64 { rust_path_b_process_data_stage_3(i * rand::thread_rng().gen_range(0..5)) }
fn rust_path_b_process_data_entry(i: i64) -> i64 { rust_path_b_process_data_stage_2(i * rand::thread_rng().gen_range(0..5)) }

fn main() {
    println!("Rust Workload PID: {}", std::process::id());

    let num_threads = num_cpus::get_physical(); // Use physical cores

    for i in 0..num_threads {
        thread::spawn(move || {
            println!("Thread {} started", i);
            let mut result: i64 = 0;
            loop {
                for j in 0..1_000_000 {
                    if j % 2 == 0 {
                                            result = result.wrapping_add(rust_path_a_compute_entry(j as i64));
                    } else {
                                            result = result.wrapping_add(rust_path_b_process_data_entry(j as i64));
                    }
                }
                // Optional: sleep to reduce CPU usage if needed for testing specific scenarios
                // thread::sleep(Duration::from_millis(10)); 
                if result > 1_000_000_000_000 {
                    result /= 2;
                }
            }
        });
    }

    // Keep main thread alive
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
