// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

//! UI-facing profile abstraction.
//!
//! Goal: decouple UI/analytics from the on-disk storage format.
//!
//! - UI consumes `UiProfile` (stable) + `ProfileData` (trait object).
//! - Different loaders can build `UiProfile` from different backends
//!   (current binary-dir, future LevelDB, ...), while UI code stays unchanged.

use crate::cpa::{Config, Metadata, RecordMeta};
use anyhow::Context;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod loaders;

#[derive(Debug, Clone, Copy, Default)]
pub struct LoadOptions {
    pub timing: bool,
    pub use_cache: bool,
}

/// UI layer entrance.
#[derive(Clone)]
pub struct UiProfile {
    pub source_path: PathBuf,
    pub data: Arc<dyn ProfileData>,
}

impl UiProfile {
    pub fn summary(&self) -> String {
        self.data.summary()
    }
}

/// Minimum data access surface required by UI.
///
/// Notes for future backends (e.g. LevelDB):
/// - `str_for()` returns `&str` tied to `&self`, so the backend should implement
///   a stable string-intern/cache (e.g. LRU) to keep returned references valid.
pub trait ProfileData: Send + Sync {
    fn source_path(&self) -> &Path;
    fn config(&self) -> &Config;
    fn records(&self) -> &[RecordMeta];

    fn record_count(&self) -> usize {
        self.records().len()
    }

    fn time_range_ms(&self) -> Option<(u64, u64)> {
        let rs = self.records();
        let s = rs.first().map(|r| r.start_ms)?;
        let e = rs.last().map(|r| r.end_ms).unwrap_or(s);
        Some((s, e))
    }

    /// Iterate entries in a single record.
    fn for_each_entry_in_record(
        &self,
        record_idx: usize,
        cb: &mut dyn FnMut(u32, u64) -> anyhow::Result<()>,
    ) -> anyhow::Result<()>;

    /// Iterate entries in a record range (inclusive start, exclusive end).
    ///
    /// Default implementation loops `for_each_entry_in_record`.
    /// Binary-dir backend should override to keep a single file lock for the whole range.
    fn for_each_entry_in_records(
        &self,
        start: usize,
        end: usize,
        cb: &mut dyn FnMut(u32, u64) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let end = end.min(self.record_count());
        let start = start.min(end);
        for i in start..end {
            self.for_each_entry_in_record(i, cb)?;
        }
        Ok(())
    }

    fn ids_for(&self, ids_id: u32) -> Option<Arc<Vec<u32>>>;
    fn str_for(&self, sid: u32) -> Option<&str>;

    fn metadata_for_ids(&self, ids: &[u32]) -> Option<Metadata>;
    fn ids_id_has_kernel(&self, ids_id: u32) -> bool;

    fn summary(&self) -> String {
        let c = self.config();
        format!(
            "dir={} record_count={} cpu_num={} freq={} interval={}",
            self.source_path().display(),
            self.record_count(),
            c.cpu_num.unwrap_or(0),
            c.freq.unwrap_or(0),
            c.record_interval.unwrap_or(0)
        )
    }
}

pub trait ProfileLoader: Send + Sync {
    fn name(&self) -> &'static str;
    fn can_load(&self, path: &Path) -> bool;
    fn load(&self, path: &Path, opts: LoadOptions) -> anyhow::Result<UiProfile>;
}

#[derive(Default)]
pub struct LoaderRegistry {
    loaders: Vec<Box<dyn ProfileLoader>>,
}

impl LoaderRegistry {
    pub fn new() -> Self {
        let mut r = Self {
            loaders: Vec::new(),
        };
        // current format
        r.register(Box::new(loaders::binary_dir::BinaryDirLoader));
        r
    }

    pub fn register(&mut self, l: Box<dyn ProfileLoader>) {
        self.loaders.push(l);
    }

    pub fn load(&self, path: impl AsRef<Path>, opts: LoadOptions) -> anyhow::Result<UiProfile> {
        let path = path.as_ref();
        let loader = self
            .loaders
            .iter()
            .find(|l| l.can_load(path))
            .with_context(|| format!("No suitable loader for {}", path.display()))?;
        loader.load(path, opts)
    }
}
