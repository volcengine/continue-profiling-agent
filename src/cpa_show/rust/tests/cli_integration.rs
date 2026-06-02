// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use clap::Parser;
use cpa_show::cli::{run, Args};
use std::fs;

fn zstd_level1(data: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(data, 1).expect("zstd encode")
}

fn write_minimal_store(root: &std::path::Path) {
    fs::write(
        root.join("conf"),
        "cpu_num: 4\nfreq: 100\nrecord_interval: 1\n",
    )
    .unwrap();

    let merged = format!("{:<15}{:<15}", "comm", "group");
    let meta = format!("{}-0-0-42|pod-x", merged);
    let strmap_txt = format!("{} 1\nfoo_[k] 2\nbar 3\n", meta);
    fs::write(root.join("strmap"), zstd_level1(strmap_txt.as_bytes())).unwrap();

    let idsmap_txt = "1;2;3 10\n";
    fs::write(root.join("idsmap"), zstd_level1(idsmap_txt.as_bytes())).unwrap();

    let mut raw = Vec::new();
    raw.extend_from_slice(&[0xFA, 0xFB]);
    raw.extend_from_slice(&1u64.to_le_bytes());
    raw.extend_from_slice(&2u64.to_le_bytes());
    raw.extend_from_slice(&1u64.to_le_bytes());
    raw.extend_from_slice(&10u32.to_le_bytes());
    raw.extend_from_slice(&100u64.to_le_bytes());
    raw.extend_from_slice(&[0xFC, 0xFD]);
    raw.extend_from_slice(&[0xFA, 0xFB]);
    raw.extend_from_slice(&3u64.to_le_bytes());
    raw.extend_from_slice(&4u64.to_le_bytes());
    raw.extend_from_slice(&0u64.to_le_bytes());
    raw.extend_from_slice(&[0xFC, 0xFD]);

    fs::write(root.join("stack.bin"), zstd_level1(&raw)).unwrap();
}

#[test]
fn cpa_show_cli_runs_with_embedded_cpa_store() {
    let dir = tempfile::tempdir().unwrap();
    write_minimal_store(dir.path());

    let args = Args::parse_from([
        "cpa_show",
        "--read",
        dir.path().to_str().unwrap(),
        "--no-tui",
    ]);

    run(args).expect("embedded cpa_show CLI should load CPA store");
}
