// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub raw: BTreeMap<String, String>,
    pub cpu_num: Option<u32>,
    pub freq: Option<u32>,
    pub record_interval: Option<u32>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut raw = BTreeMap::new();

        for line in content.lines() {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                if !key.is_empty() {
                    raw.insert(key, val);
                }
            }
        }

        let cpu_num = raw.get("cpu_num").and_then(|v| v.parse().ok());
        let freq = raw.get("freq").and_then(|v| v.parse().ok());
        let record_interval = raw.get("record_interval").and_then(|v| v.parse().ok());

        Ok(Self {
            raw,
            cpu_num,
            freq,
            record_interval,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_conf_basic() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("conf");
        fs::write(
            &p,
            "cpu_num: 8\nfreq: 99\nrecord_interval: 5\nfoo: bar baz\n",
        )
        .unwrap();

        let c = Config::load(&p).unwrap();
        assert_eq!(c.cpu_num, Some(8));
        assert_eq!(c.freq, Some(99));
        assert_eq!(c.record_interval, Some(5));
        assert_eq!(c.raw.get("foo").unwrap(), "bar baz");
    }
}
