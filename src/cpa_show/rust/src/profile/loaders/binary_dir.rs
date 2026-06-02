// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use crate::cpa::{Metadata, RecordMeta, Store};
use crate::profile::{LoadOptions, ProfileData, ProfileLoader, UiProfile};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Loader for current on-disk format (directory with conf/strmap/idsmap/stack.bin).
pub struct BinaryDirLoader;

impl ProfileLoader for BinaryDirLoader {
    fn name(&self) -> &'static str {
        "binary-dir"
    }

    fn can_load(&self, path: &Path) -> bool {
        if !path.is_dir() {
            return false;
        }
        // Minimal signature for current format.
        path.join("conf").is_file()
            && path.join("strmap").is_file()
            && path.join("idsmap").is_file()
            && path.join("stack.bin").is_file()
    }

    fn load(&self, path: &Path, opts: LoadOptions) -> anyhow::Result<UiProfile> {
        let store = Store::open_with_timing(path, opts.timing, opts.use_cache)?;
        let data = Arc::new(BinaryProfileData::new(store));
        Ok(UiProfile {
            source_path: path.to_path_buf(),
            data,
        })
    }
}

/// `ProfileData` implementation backed by current `cpa::Store`.
///
/// It keeps its own caches to provide stable read access for UI rendering.
pub struct BinaryProfileData {
    store: Store,
    source: PathBuf,

    // stable caches (important for future backends too)
    meta_cache: Mutex<HashMap<u32, Metadata>>,
    has_kernel_cache: Mutex<HashMap<u32, bool>>,
}

impl BinaryProfileData {
    pub fn new(store: Store) -> Self {
        let source = store.dir.clone();
        Self {
            store,
            source,
            meta_cache: Mutex::new(HashMap::new()),
            has_kernel_cache: Mutex::new(HashMap::new()),
        }
    }
}

impl ProfileData for BinaryProfileData {
    fn source_path(&self) -> &Path {
        &self.source
    }

    fn config(&self) -> &crate::cpa::Config {
        &self.store.config
    }

    fn records(&self) -> &[RecordMeta] {
        &self.store.stack.records
    }

    fn for_each_entry_in_record(
        &self,
        record_idx: usize,
        cb: &mut dyn FnMut(u32, u64) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.store
            .for_each_entry_in_record(record_idx, |ids_id, count| cb(ids_id, count))
    }

    fn for_each_entry_in_records(
        &self,
        start: usize,
        end: usize,
        cb: &mut dyn FnMut(u32, u64) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.store
            .for_each_entry_in_records(start, end, |ids_id, count| cb(ids_id, count))
    }

    fn ids_for(&self, ids_id: u32) -> Option<Arc<Vec<u32>>> {
        self.store.ids_for(ids_id)
    }

    fn str_for(&self, sid: u32) -> Option<&str> {
        self.store.str_for(sid)
    }

    fn metadata_for_ids(&self, ids: &[u32]) -> Option<Metadata> {
        let meta_id = *ids.first()?;
        if let Some(v) = self.meta_cache.lock().get(&meta_id).cloned() {
            return Some(v);
        }
        let raw = self.str_for(meta_id)?;
        let parsed = crate::cpa::Metadata::parse(raw).ok()?;
        self.meta_cache.lock().insert(meta_id, parsed.clone());
        Some(parsed)
    }

    fn ids_id_has_kernel(&self, ids_id: u32) -> bool {
        if let Some(v) = self.has_kernel_cache.lock().get(&ids_id).copied() {
            return v;
        }
        let mut has = false;
        if let Some(ids) = self.ids_for(ids_id) {
            for &sid in ids.iter().skip(1) {
                if let Some(s) = self.str_for(sid) {
                    if s.contains("_[k]") {
                        has = true;
                        break;
                    }
                }
            }
        }
        self.has_kernel_cache.lock().insert(ids_id, has);
        has
    }

    fn summary(&self) -> String {
        self.store.summary()
    }
}
