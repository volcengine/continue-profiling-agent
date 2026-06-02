// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use std::{
    ffi::CString,
    os::raw::{c_char, c_int, c_void},
};

use super::utils::ensure_decompressed_zstd_maybe;

#[derive(Debug, Clone, Default)]
pub struct StrMap {
    inner: HashMap<u32, String>,
}

impl StrMap {
    pub fn load_zstd_maybe(path: &Path, timing: bool, use_cache: bool) -> anyhow::Result<Self> {
        let mut inner = HashMap::new();
        // cache demangled result by mangled base symbol
        let mut demangle_cache: HashMap<String, String> = HashMap::new();

        let real = ensure_decompressed_zstd_maybe(path, timing, "strmap", use_cache)?;
        let f = fs::File::open(real)?;
        let mut r = BufReader::new(f);

        let mut line = Vec::with_capacity(256);
        while r.read_until(b'\n', &mut line)? != 0 {
            if line.ends_with(b"\n") {
                line.pop();
            }
            if line.ends_with(b"\r") {
                line.pop();
            }

            if let Some(sp) = line.iter().rposition(|&b| b == b' ') {
                let (left, right) = line.split_at(sp);
                let id = std::str::from_utf8(right)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok());
                if let Some(id) = id {
                    if let Ok(text) = std::str::from_utf8(left) {
                        let raw = text.to_string();
                        let cooked =
                            maybe_demangle_symbol_line(&raw, &mut demangle_cache).unwrap_or(raw);
                        inner.insert(id, cooked);
                    } else {
                        // fallback
                        let raw = String::from_utf8_lossy(left).to_string();
                        let cooked =
                            maybe_demangle_symbol_line(&raw, &mut demangle_cache).unwrap_or(raw);
                        inner.insert(id, cooked);
                    }
                }
            }

            line.clear();
        }

        Ok(Self { inner })
    }

    pub fn get(&self, id: u32) -> Option<&str> {
        self.inner.get(&id).map(|s| s.as_str())
    }
}

extern "C" {
    fn free(ptr: *mut c_void);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[link(name = "iberty", kind = "static")]
extern "C" {
    // libiberty: https://sourceware.org/binutils/docs-2.31/libiberty/
    fn cplus_demangle(mangled: *const c_char, options: c_int) -> *mut c_char;
}

fn looks_like_itanium_mangled(sym: &str) -> bool {
    // Itanium ABI mangled names usually start with "_Z".
    sym.starts_with("_Z") && sym.len() > 2
}

fn is_mangled_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '$')
}

fn maybe_demangle_symbol_line(s: &str, cache: &mut HashMap<String, String>) -> Option<String> {
    // Only demangle the leading token, keep suffix like "+0" or " [lib.so]".
    if s.is_empty() {
        return None;
    }

    let base_end = s
        .char_indices()
        .find(|&(_i, ch)| !is_mangled_ident_char(ch))
        .map(|(i, _)| i)
        .unwrap_or_else(|| s.len());

    if base_end == 0 {
        return None;
    }
    let base = &s[..base_end];
    if !looks_like_itanium_mangled(base) {
        return None;
    }

    if let Some(v) = cache.get(base) {
        let mut out = String::with_capacity(v.len() + (s.len() - base_end));
        out.push_str(v);
        out.push_str(&s[base_end..]);
        return Some(out);
    }

    let demangled = demangle_with_libiberty(base)?;
    let demangled = strip_template_params_safe(&demangled);
    cache.insert(base.to_string(), demangled.clone());
    let mut out = String::with_capacity(demangled.len() + (s.len() - base_end));
    out.push_str(&demangled);
    out.push_str(&s[base_end..]);
    Some(out)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn demangle_with_libiberty(mangled: &str) -> Option<String> {
    let cstr = CString::new(mangled).ok()?;

    // options=0: let libiberty choose a reasonable default; we post-process templates.
    let p = unsafe { cplus_demangle(cstr.as_ptr(), 0) };
    if p.is_null() {
        return None;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(p) }
        .to_string_lossy()
        .to_string();
    unsafe {
        free(p as *mut c_void);
    }
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn demangle_with_libiberty(_mangled: &str) -> Option<String> {
    None
}

fn strip_template_params_safe(input: &str) -> String {
    // Remove template params like: "foo<int, std::vector<T>>" -> "foo".
    // Safety: if '<'/'>' are unbalanced (e.g. operator<<), do not change.
    let mut depth: i32 = 0;
    let mut saw_angle = false;
    for ch in input.chars() {
        if ch == '<' {
            depth += 1;
            saw_angle = true;
        } else if ch == '>' {
            if depth == 0 {
                // unmatched '>'
                return input.to_string();
            }
            depth -= 1;
        }
    }
    if !saw_angle || depth != 0 {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    depth = 0;
    for ch in input.chars() {
        if ch == '<' {
            depth += 1;
            continue;
        }
        if ch == '>' {
            depth -= 1;
            continue;
        }
        if depth == 0 {
            out.push(ch);
        }
    }
    out
}

#[derive(Debug)]
pub struct IdsMap {
    // lazy index: ids_id -> (start, end) range in file bytes, covering the left part (ids list)
    // Use Vec instead of HashMap: ids_id is roughly contiguous in real data and Vec is faster.
    index: Vec<(u32, u32)>,
    mmap: Arc<memmap2::Mmap>,
    cache: Mutex<HashMap<u32, Arc<Vec<u32>>>>,
}

impl IdsMap {
    pub fn load_zstd_maybe(path: &Path, timing: bool, use_cache: bool) -> anyhow::Result<Self> {
        let real = ensure_decompressed_zstd_maybe(path, timing, "idsmap", use_cache)?;
        let f = fs::File::open(&real)?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&f)? };
        let bytes: &[u8] = &mmap;

        // index[ids_id] = (start,end). (0,0) means missing.
        let mut index: Vec<(u32, u32)> = vec![(0, 0); 1];

        let mut line_start: usize = 0;
        for (i, &b) in bytes.iter().enumerate() {
            if b != b'\n' {
                continue;
            }
            let mut line_end = i;
            if line_end > line_start && bytes[line_end - 1] == b'\r' {
                line_end -= 1;
            }
            if line_end <= line_start {
                line_start = i + 1;
                continue;
            }

            // find last space in [line_start, line_end)
            let mut sp = None;
            for j in (line_start..line_end).rev() {
                if bytes[j] == b' ' {
                    sp = Some(j);
                    break;
                }
            }
            let Some(sp) = sp else {
                line_start = i + 1;
                continue;
            };

            // parse ids_id from (sp..line_end)
            let mut v: u32 = 0;
            let mut mul: u32 = 1;
            let mut ok = false;
            for j in (sp + 1..line_end).rev() {
                let c = bytes[j];
                if (b'0'..=b'9').contains(&c) {
                    ok = true;
                    v = v.saturating_add(((c - b'0') as u32).saturating_mul(mul));
                    mul = mul.saturating_mul(10);
                } else if c == b' ' || c == b'\t' {
                    // ignore
                } else {
                    ok = false;
                    break;
                }
            }
            if ok {
                let id = v as usize;
                if id >= index.len() {
                    let mut new_len = index.len().max(1);
                    while new_len <= id {
                        new_len = new_len.saturating_mul(2);
                    }
                    index.resize(new_len, (0, 0));
                }
                index[id] = (line_start as u32, sp as u32);
            }

            line_start = i + 1;
        }

        Ok(Self {
            index,
            mmap: Arc::new(mmap),
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn get(&self, ids_id: u32) -> Option<Arc<Vec<u32>>> {
        if let Some(v) = self.cache.lock().get(&ids_id).cloned() {
            return Some(v);
        }
        let id = ids_id as usize;
        if id >= self.index.len() {
            return None;
        }
        let (s, e) = self.index[id];
        if s == 0 && e == 0 {
            return None;
        }
        let left = &self.mmap[s as usize..e as usize];

        let mut ids: Vec<u32> = Vec::with_capacity(32);
        let mut cur: u32 = 0;
        let mut in_num = false;
        for &b in left {
            match b {
                b'0'..=b'9' => {
                    in_num = true;
                    cur = cur.saturating_mul(10).saturating_add((b - b'0') as u32);
                }
                b';' => {
                    if in_num {
                        ids.push(cur);
                        cur = 0;
                        in_num = false;
                    }
                }
                _ => {}
            }
        }
        if in_num {
            ids.push(cur);
        }
        if ids.is_empty() {
            return None;
        }

        let v = Arc::new(ids);
        self.cache.lock().insert(ids_id, v.clone());
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn split_last_space_ok() {
        // basic sanity: build index and lookup
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("idsmap");
        fs::write(
            &p,
            zstd::stream::encode_all("1;2;3 10\n".as_bytes(), 1).unwrap(),
        )
        .unwrap();
        let m = IdsMap::load_zstd_maybe(&p, false, true).unwrap();
        let got = m.get(10).unwrap();
        assert_eq!(got.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn strip_template_params_safe_ok() {
        assert_eq!(
            strip_template_params_safe("foo<int>(double)"),
            "foo(double)"
        );
        assert_eq!(
            strip_template_params_safe("std::vector<int, std::allocator<int> >"),
            "std::vector"
        );
        // do not break operators like operator<<
        assert_eq!(strip_template_params_safe("operator<<"), "operator<<");
        assert_eq!(strip_template_params_safe("operator>"), "operator>");
    }
}
