// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::utils::ensure_decompressed_zstd_maybe;

#[derive(Debug, Clone)]
pub struct RecordMeta {
    /// Milliseconds since 00:00 of the day; may exceed 86400*1000 when spanning days.
    pub start_ms: u64,
    pub end_ms: u64,
    /// Offset of the record header in the decompressed file.
    pub file_off: u64,
    /// Number of entries.
    pub entry_len: u64,
}

#[derive(Debug, Clone)]
pub struct StackBin {
    pub path: PathBuf,
    pub records: Vec<RecordMeta>,
}

#[derive(Debug, thiserror::Error)]
pub enum StackBinError {
    #[error("stack.bin 解析失败: {0}")]
    Parse(String),
}

impl StackBin {
    pub fn load(dir: &Path, timing: bool, use_cache: bool) -> anyhow::Result<Self> {
        let compressed = dir.join("stack.bin");
        let decompressed =
            ensure_decompressed_zstd_maybe(&compressed, timing, "stack.bin", use_cache)?;

        let t0 = std::time::Instant::now();
        let records = index_decompressed_stack_bin(&decompressed)?;
        if timing {
            eprintln!(
                "[cpa_show][timing] index stack.bin (decompressed): {:.2}ms (records={})",
                t0.elapsed().as_secs_f64() * 1000.0,
                records.len()
            );
        }

        Ok(Self {
            path: decompressed,
            records,
        })
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn for_each_entry_in_record(
        &self,
        file: &mut fs::File,
        index: usize,
        mut cb: impl FnMut(u32, u64) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let meta = &self.records[index];
        // entries offset = header(2) + start(u64) + end(u64) + entry_len(u64)
        let entries_off = meta.file_off + 2 + 8 + 8 + 8;
        file.seek(SeekFrom::Start(entries_off))?;
        for _ in 0..meta.entry_len {
            let ids_id = read_u32_from(file)?;
            let count = read_u64_from(file)?;
            cb(ids_id, count)?;
        }
        Ok(())
    }
}

fn index_decompressed_stack_bin(path: &Path) -> anyhow::Result<Vec<RecordMeta>> {
    let mut f = fs::File::open(path)?;
    let mut records = Vec::new();
    let mut off: u64 = 0;
    let mut dump_start: Option<u64> = None;
    let mut last_record_was_guard = false;
    const DAY_MS: u64 = 86_400_000;

    loop {
        let mut header = [0u8; 2];
        match f.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        if header != [0xFA, 0xFB] {
            break;
        }

        let rec_off = off;
        off += 2;

        let start_ms = read_u64_from(&mut f)?;
        let mut end_ms = read_u64_from(&mut f)?;
        let entry_len = read_u64_from(&mut f)?;
        off += 8 + 8 + 8;

        let is_guard_record = entry_len == 0 && start_ms == end_ms;

        if dump_start.is_none() {
            dump_start = Some(start_ms);
        }
        // Align with C-side behavior: if end_ms < dump_start due to crossing days, add one day.
        if let Some(ds) = dump_start {
            if end_ms < ds {
                end_ms += DAY_MS;
            }
        }

        // skip entries + footer
        let skip = entry_len
            .checked_mul(4 + 8)
            .ok_or_else(|| StackBinError::Parse("entry_len overflow".into()))?;
        f.seek(SeekFrom::Current(skip as i64))?;
        off += skip;

        // footer
        let mut footer = [0u8; 2];
        f.read_exact(&mut footer)
            .map_err(|_| StackBinError::Parse("缺少 footer".into()))?;
        off += 2;
        if footer != [0xFC, 0xFD] {
            return Err(StackBinError::Parse("footer 不匹配".into()).into());
        }

        // Align with the C dump parser: timewheel can write zero-entry,
        // zero-duration guard records between flushed buckets.
        if !is_guard_record {
            records.push(RecordMeta {
                start_ms,
                end_ms,
                file_off: rec_off,
                entry_len,
            });
            last_record_was_guard = false;
        } else {
            last_record_was_guard = true;
        }
    }

    // Drop the last non-guard tail record. If the dump ended on a guard record,
    // the last real bucket is complete and should remain visible.
    if !last_record_was_guard && !records.is_empty() {
        records.pop();
    }
    Ok(records)
}

fn read_u32_from(r: &mut impl Read) -> anyhow::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64_from(r: &mut impl Read) -> anyhow::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_and_iter_ok() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("decompressed")).unwrap();
        let p = root.join("decompressed/stack.bin");

        // Two records; indexing drops the last one.
        let mut buf = Vec::new();
        // record 1
        buf.extend_from_slice(&[0xFA, 0xFB]);
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&100u64.to_le_bytes());
        buf.extend_from_slice(&11u32.to_le_bytes());
        buf.extend_from_slice(&200u64.to_le_bytes());
        buf.extend_from_slice(&[0xFC, 0xFD]);
        // record 2 (dropped)
        buf.extend_from_slice(&[0xFA, 0xFB]);
        buf.extend_from_slice(&3u64.to_le_bytes());
        buf.extend_from_slice(&4u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&[0xFC, 0xFD]);

        fs::write(&p, &buf).unwrap();

        let rs = index_decompressed_stack_bin(&p).unwrap();
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].entry_len, 2);

        let sb = StackBin {
            path: p,
            records: rs,
        };
        let mut f = fs::File::open(&sb.path).unwrap();
        let mut got = Vec::new();
        sb.for_each_entry_in_record(&mut f, 0, |id, c| {
            got.push((id, c));
            Ok(())
        })
        .unwrap();
        assert_eq!(got, vec![(10, 100), (11, 200)]);
    }

    #[test]
    fn index_skips_zero_duration_timewheel_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("decompressed")).unwrap();
        let p = root.join("decompressed/stack.bin");

        let mut buf = Vec::new();
        // record 1
        buf.extend_from_slice(&[0xFA, 0xFB]);
        buf.extend_from_slice(&1_000u64.to_le_bytes());
        buf.extend_from_slice(&2_000u64.to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&100u64.to_le_bytes());
        buf.extend_from_slice(&[0xFC, 0xFD]);
        // zero-duration sentinel written between timewheel buckets
        buf.extend_from_slice(&[0xFA, 0xFB]);
        buf.extend_from_slice(&2_000u64.to_le_bytes());
        buf.extend_from_slice(&2_000u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&[0xFC, 0xFD]);
        // record 2
        buf.extend_from_slice(&[0xFA, 0xFB]);
        buf.extend_from_slice(&2_000u64.to_le_bytes());
        buf.extend_from_slice(&3_000u64.to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.extend_from_slice(&11u32.to_le_bytes());
        buf.extend_from_slice(&200u64.to_le_bytes());
        buf.extend_from_slice(&[0xFC, 0xFD]);
        // trailing tail record still gets dropped by the existing partial-record rule
        buf.extend_from_slice(&[0xFA, 0xFB]);
        buf.extend_from_slice(&3_000u64.to_le_bytes());
        buf.extend_from_slice(&4_000u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&[0xFC, 0xFD]);

        fs::write(&p, &buf).unwrap();

        let rs = index_decompressed_stack_bin(&p).unwrap();
        assert_eq!(rs.len(), 2);
        assert_eq!((rs[0].start_ms, rs[0].end_ms), (1_000, 2_000));
        assert_eq!((rs[1].start_ms, rs[1].end_ms), (2_000, 3_000));
    }
}
