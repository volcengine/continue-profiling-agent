// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use std::fs;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

/// Decompress a zstd-compressed file into `decompressed/` under the same directory and return the path.
///
/// - If `use_cache=true` and `decompressed/<filename>` exists, reuse it.
/// - If `use_cache=false`, always overwrite by re-decompressing (align with `cpa show --use_cache=0`).
/// - If input is not zstd (magic mismatch), return the original path.
pub fn ensure_decompressed_zstd_maybe(
    path: &Path,
    timing: bool,
    label: &str,
    use_cache: bool,
) -> anyhow::Result<PathBuf> {
    // quick sniff: zstd frame magic = 0xFD2FB528 (little endian: 28 B5 2F FD)
    let mut fin = fs::File::open(path)?;
    let mut magic = [0u8; 4];
    let n = fin.read(&mut magic)?;
    fin.rewind()?;
    if n < 4 || magic != [0x28, 0xB5, 0x2F, 0xFD] {
        return Ok(path.to_path_buf());
    }

    let Some(parent) = path.parent() else {
        anyhow::bail!("invalid path");
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("invalid path"))?;
    let out_dir = parent.join("decompressed");
    let out_path = out_dir.join(file_name);

    if use_cache && out_path.exists() {
        return Ok(out_path);
    }

    fs::create_dir_all(&out_dir)?;

    let t0 = std::time::Instant::now();
    let mut decoder = zstd::stream::Decoder::new(fin)?;
    // overwrite when use_cache == false
    let mut fout = fs::File::create(&out_path)?;
    std::io::copy(&mut decoder, &mut fout)?;
    fout.flush()?;

    if timing {
        eprintln!(
            "[cpa_show][timing] decompress {label} -> {}: {:.2}ms",
            out_path.display(),
            t0.elapsed().as_secs_f64() * 1000.0
        );
    }

    Ok(out_path)
}
