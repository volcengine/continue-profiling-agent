// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use cpa_show::cpa::Store;
use std::fs;

fn zstd_level1(data: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(data, 1).expect("zstd encode")
}

#[test]
fn open_store_from_minimal_dir() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // conf
    fs::write(
        root.join("conf"),
        "cpu_num: 4\nfreq: 100\nrecord_interval: 1\n",
    )
    .unwrap();

    // strmap
    let merged = format!("{:<15}{:<15}", "comm", "group");
    let meta = format!("{}-0-0-42|pod-x", merged);
    let strmap_txt = format!("{} 1\nfoo_[k] 2\nbar 3\n", meta);
    fs::write(root.join("strmap"), zstd_level1(strmap_txt.as_bytes())).unwrap();

    // idsmap: ids_id=10 => [1,2,3]
    let idsmap_txt = "1;2;3 10\n";
    fs::write(root.join("idsmap"), zstd_level1(idsmap_txt.as_bytes())).unwrap();

    // stack.bin: two records; parsing drops the last one
    let mut raw = Vec::new();
    // record 0
    raw.extend_from_slice(&[0xFA, 0xFB]);
    raw.extend_from_slice(&1u64.to_le_bytes());
    raw.extend_from_slice(&2u64.to_le_bytes());
    raw.extend_from_slice(&1u64.to_le_bytes());
    raw.extend_from_slice(&10u32.to_le_bytes());
    raw.extend_from_slice(&100u64.to_le_bytes());
    raw.extend_from_slice(&[0xFC, 0xFD]);
    // record 1 (will be dropped)
    raw.extend_from_slice(&[0xFA, 0xFB]);
    raw.extend_from_slice(&3u64.to_le_bytes());
    raw.extend_from_slice(&4u64.to_le_bytes());
    raw.extend_from_slice(&0u64.to_le_bytes());
    raw.extend_from_slice(&[0xFC, 0xFD]);

    fs::write(root.join("stack.bin"), zstd_level1(&raw)).unwrap();

    let store = Store::open(root).unwrap();
    assert_eq!(store.record_count(), 1);

    let agg = store.aggregate_ids_id(0, 1);
    assert_eq!(agg.get(&10).copied(), Some(100));

    let ids = store.ids_for(10).unwrap();
    let meta = store.metadata_for_ids(ids.as_slice()).unwrap();
    assert_eq!(meta.pid, 42);
    assert_eq!(meta.cgroup_id, 0);
    assert_eq!(meta.env, "pod-x");
}
