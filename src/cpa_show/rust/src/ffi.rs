// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStringExt;
use std::panic::AssertUnwindSafe;

use clap::Parser;

use crate::cli::Args;

#[no_mangle]
pub extern "C" fn cpa_show_main(argc: c_int, argv: *const *const c_char) -> c_int {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| unsafe {
        let args = argv_to_os_strings(argc, argv)?;
        let parsed = Args::parse_from(args);
        crate::cli::run(parsed)
    }));

    match result {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            eprintln!("{e:?}");
            1
        }
        Err(_) => {
            eprintln!("cpa_show_main panicked");
            2
        }
    }
}

unsafe fn argv_to_os_strings(
    argc: c_int,
    argv: *const *const c_char,
) -> anyhow::Result<Vec<std::ffi::OsString>> {
    if argc < 0 {
        anyhow::bail!("invalid argc: {argc}");
    }
    if argv.is_null() {
        anyhow::bail!("argv is null");
    }
    let mut out = Vec::with_capacity(argc as usize);
    for i in 0..(argc as isize) {
        let p = *argv.offset(i);
        if p.is_null() {
            anyhow::bail!("argv[{i}] is null");
        }
        let bytes = CStr::from_ptr(p).to_bytes();
        out.push(std::ffi::OsString::from_vec(bytes.to_vec()));
    }
    Ok(out)
}
