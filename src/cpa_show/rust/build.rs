// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use std::path::Path;

fn main() {
    // libiberty is commonly shipped as a static archive (libiberty.a).
    // Help rustc find it on typical Debian/Ubuntu paths.
    let candidates = [
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/usr/lib64",
        "/usr/lib",
    ];

    for dir in candidates {
        let p = Path::new(dir).join("libiberty.a");
        if p.exists() {
            println!("cargo:rustc-link-search=native={dir}");
            break;
        }
    }
}
