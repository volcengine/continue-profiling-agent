// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

mod config;
mod filters;
mod maps;
mod metadata;
mod stackbin;
mod utils;

pub use config::Config;
pub use filters::{parse_cpu_set, Filter, FilterSet, FilterTarget, FilterValue};
pub use maps::{IdsMap, StrMap};
pub use metadata::{Metadata, MetadataParseError};
pub use stackbin::{RecordMeta, StackBin, StackBinError};
pub use utils::ensure_decompressed_zstd_maybe;

use anyhow::Context;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs::File, io::Seek};

/// Represents a single cpa store directory.
///
/// Key files:
/// - conf: text config (name: value)
/// - strmap/idsmap: zstd-compressed text maps
/// - stack.bin: zstd-compressed binary record stream
#[derive(Debug)]
pub struct Store {
    pub dir: PathBuf,
    pub config: Config,
    pub strmap: StrMap,
    pub idsmap: IdsMap,
    pub stack: StackBin,
    stack_file: Mutex<File>,
    pub filters: Mutex<FilterSet>,
    metadata_cache: Mutex<HashMap<u32, Metadata>>,
}

impl Store {
    pub fn open(dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::open_with_timing(dir, false, true)
    }

    pub fn open_with_timing(
        dir: impl AsRef<Path>,
        timing: bool,
        use_cache: bool,
    ) -> anyhow::Result<Self> {
        let dir = dir.as_ref().to_path_buf();

        let t0 = std::time::Instant::now();

        let conf_path = dir.join("conf");
        let (config, dt_conf) = timed(timing, "load conf", || {
            Config::load(&conf_path)
                .with_context(|| format!("读取 conf 失败: {}", conf_path.display()))
        })?;

        let (strmap, idsmap, stack) = std::thread::scope(|s| {
            let dir_clone1 = dir.clone();
            let dir_clone2 = dir.clone();
            let dir_clone3 = dir.clone();

            let h_strmap = s.spawn(move || {
                timed(timing, "load strmap", || {
                    StrMap::load_zstd_maybe(&dir_clone1.join("strmap"), timing, use_cache)
                        .with_context(|| format!("读取 strmap 失败: {}", dir_clone1.display()))
                })
            });
            let h_idsmap = s.spawn(move || {
                timed(timing, "load idsmap", || {
                    IdsMap::load_zstd_maybe(&dir_clone2.join("idsmap"), timing, use_cache)
                        .with_context(|| format!("读取 idsmap 失败: {}", dir_clone2.display()))
                })
            });
            let h_stack = s.spawn(move || {
                timed(timing, "open stack.bin", || {
                    stackbin::StackBin::load(&dir_clone3, timing, use_cache)
                        .with_context(|| format!("读取 stack.bin 失败: {}", dir_clone3.display()))
                })
            });

            (
                h_strmap.join().unwrap(),
                h_idsmap.join().unwrap(),
                h_stack.join().unwrap(),
            )
        });

        let (strmap, _dt_strmap) = strmap?;
        let (idsmap, _dt_idsmap) = idsmap?;
        let (stack, _dt_stack) = stack?;

        let mut stack_file = File::open(&stack.path).with_context(|| {
            format!("打开 decompressed stack.bin 失败: {}", stack.path.display())
        })?;
        let _ = stack_file.rewind();

        if timing {
            let total = t0.elapsed();
            eprintln!(
                "[cpa_show][timing] open store total: {:.2}ms (records={})",
                total.as_secs_f64() * 1000.0,
                stack.records.len()
            );
            // silence unused warning if future edits remove prints
            let _ = dt_conf;
        }

        Ok(Self {
            dir,
            config,
            strmap,
            idsmap,
            stack,
            stack_file: Mutex::new(stack_file),
            filters: Mutex::new(FilterSet::default()),
            metadata_cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn summary(&self) -> String {
        format!(
            "dir={} record_count={} cpu_num={} freq={} interval={}",
            self.dir.display(),
            self.stack.records.len(),
            self.config.cpu_num.unwrap_or(0),
            self.config.freq.unwrap_or(0),
            self.config.record_interval.unwrap_or(0)
        )
    }

    pub fn record_count(&self) -> usize {
        self.stack.record_count()
    }

    pub fn cpu_samples_per_cpu_per_record(&self) -> Option<f64> {
        let freq = self.config.freq? as f64;
        let interval = self.config.record_interval? as f64;
        Some(freq * interval)
    }

    /// Aggregate entries within a record range (sum by ids_id).
    pub fn aggregate_ids_id(&self, start: usize, span: usize) -> HashMap<u32, u64> {
        let mut out: HashMap<u32, u64> = HashMap::new();
        if self.stack.records.is_empty() || span == 0 {
            return out;
        }

        let end = (start + span).min(self.stack.records.len());
        let start = start.min(end);

        let mut f = self.stack_file.lock();
        for i in start..end {
            let _ = self
                .stack
                .for_each_entry_in_record(&mut f, i, |ids_id, count| {
                    *out.entry(ids_id).or_insert(0) += count;
                    Ok(())
                });
        }
        out
    }

    /// Iterate entries in a single record (ids_id, count).
    ///
    /// This is a low-level building block for UI/backends.
    pub fn for_each_entry_in_record(
        &self,
        record_idx: usize,
        mut cb: impl FnMut(u32, u64) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let mut f = self.stack_file.lock();
        self.stack
            .for_each_entry_in_record(&mut f, record_idx, |ids_id, count| cb(ids_id, count))
    }

    /// Iterate entries in a record range [start, end) with a single file lock.
    pub fn for_each_entry_in_records(
        &self,
        start: usize,
        end: usize,
        mut cb: impl FnMut(u32, u64) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let end = end.min(self.record_count());
        let start = start.min(end);
        let mut f = self.stack_file.lock();
        for i in start..end {
            let _ = self
                .stack
                .for_each_entry_in_record(&mut f, i, |ids_id, count| cb(ids_id, count));
        }
        Ok(())
    }

    /// Fill CPU/Sys curves for a record range into out_cpu/out_sys.
    ///
    /// - `out_cpu[i]` / `out_sys[i]` are in "C" (samples / (freq*interval)).
    /// - Affected by UI filters (curves reflect filtered CPU usage).
    pub fn fill_cpu_sys_curves(
        &self,
        start: usize,
        end: usize,
        ids_has_kernel: &mut HashMap<u32, bool>,
        out_cpu: &mut [f64],
        out_sys: &mut [Option<f64>],
    ) {
        let Some(den) = self.cpu_samples_per_cpu_per_record() else {
            return;
        };
        if den <= 0.0 {
            return;
        }
        if self.stack.records.is_empty() {
            return;
        }

        let end = end.min(self.stack.records.len());
        let start = start.min(end);

        let filters = self.filters.lock();
        let mut f = self.stack_file.lock();
        for i in start..end {
            let mut total: u64 = 0;
            let mut sys: u64 = 0;
            let _ = self
                .stack
                .for_each_entry_in_record(&mut f, i, |ids_id, count| {
                    // Apply filters
                    if !filters.items.is_empty() {
                        if let Some(ids) = self.ids_for(ids_id) {
                            if self.filtered_out_with_lock(ids.as_slice(), &filters) {
                                return Ok(());
                            }
                        }
                    }

                    total += count;
                    if self.ids_id_has_kernel_cached(ids_id, ids_has_kernel) {
                        sys += count;
                    }
                    Ok(())
                });
            out_cpu[i] = total as f64 / den;
            out_sys[i] = Some(sys as f64 / den);
        }
    }

    // Helper to check filter without re-locking
    fn filtered_out_with_lock(&self, ids: &[u32], filters: &FilterSet) -> bool {
        let Some(meta) = self.metadata_for_ids(ids) else {
            return false;
        };
        filters.filtered_out(&meta)
    }

    pub fn ids_id_has_kernel_cached(&self, ids_id: u32, cache: &mut HashMap<u32, bool>) -> bool {
        if let Some(v) = cache.get(&ids_id) {
            return *v;
        }
        let Some(ids) = self.ids_for(ids_id) else {
            cache.insert(ids_id, false);
            return false;
        };
        let mut has = false;
        for &sid in ids.iter().skip(1) {
            let Some(s) = self.str_for(sid) else {
                continue;
            };
            if s.contains("_[k]") {
                has = true;
                break;
            }
        }
        cache.insert(ids_id, has);
        has
    }

    /// ids_id -> frame id list (from idsmap)
    pub fn ids_for(&self, ids_id: u32) -> Option<Arc<Vec<u32>>> {
        self.idsmap.get(ids_id)
    }

    pub fn str_for(&self, id: u32) -> Option<&str> {
        self.strmap.get(id)
    }

    /// Parse metadata from ids[0]'s strmap entry.
    pub fn metadata_for_ids(&self, ids: &[u32]) -> Option<Metadata> {
        let meta_id = *ids.first()?;

        if let Some(m) = self.metadata_cache.lock().get(&meta_id).cloned() {
            return Some(m);
        }

        let raw = self.str_for(meta_id)?;
        let parsed = Metadata::parse(raw).ok()?;
        self.metadata_cache.lock().insert(meta_id, parsed.clone());
        Some(parsed)
    }

    pub fn filtered_out(&self, ids: &[u32]) -> bool {
        let Some(meta) = self.metadata_for_ids(ids) else {
            return false;
        };
        self.filters.lock().filtered_out(&meta)
    }
}

fn timed<T>(
    enabled: bool,
    name: &str,
    f: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<(T, std::time::Duration)> {
    let t0 = std::time::Instant::now();
    let v = f()?;
    let dt = t0.elapsed();
    if enabled {
        eprintln!(
            "[cpa_show][timing] {name}: {:.2}ms",
            dt.as_secs_f64() * 1000.0
        );
    }
    Ok((v, dt))
}
