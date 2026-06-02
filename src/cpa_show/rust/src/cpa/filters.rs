// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use super::Metadata;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterTarget {
    Pod,
    Cpu,
    Pid,
    Comm,
    CgroupId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterValue {
    Str(String),
    CpuSet(BTreeSet<u32>),
    U32(u32),
    U64(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// Similar to CUI `xxx`: drop non-matching samples (keep matching only)
    IncludeOnly {
        target: FilterTarget,
        value: FilterValue,
    },
    /// Similar to CUI `xxxv`: drop matching samples
    Exclude {
        target: FilterTarget,
        value: FilterValue,
    },
}

#[derive(Debug, Default, Clone)]
pub struct FilterSet {
    pub items: Vec<Filter>,
}

impl FilterSet {
    pub fn filtered_out(&self, meta: &Metadata) -> bool {
        for f in &self.items {
            let matched = match_filter(f, meta);
            let out = match f {
                Filter::IncludeOnly { .. } => !matched,
                Filter::Exclude { .. } => matched,
            };
            if out {
                return true;
            }
        }
        false
    }

    pub fn remove_by_command(&mut self, cmd: &str) -> bool {
        let before = self.items.len();
        self.items.retain(|f| !matches_cmd(f, cmd));
        before != self.items.len()
    }
}

fn matches_cmd(f: &Filter, cmd: &str) -> bool {
    match (f, cmd) {
        (
            Filter::IncludeOnly {
                target: FilterTarget::Pid,
                ..
            },
            "pid",
        ) => true,
        (
            Filter::Exclude {
                target: FilterTarget::Pid,
                ..
            },
            "pidv",
        ) => true,
        (
            Filter::IncludeOnly {
                target: FilterTarget::Cpu,
                ..
            },
            "cpu",
        ) => true,
        (
            Filter::Exclude {
                target: FilterTarget::Cpu,
                ..
            },
            "cpuv",
        ) => true,
        (
            Filter::IncludeOnly {
                target: FilterTarget::Pod,
                ..
            },
            "pod",
        ) => true,
        (
            Filter::Exclude {
                target: FilterTarget::Pod,
                ..
            },
            "podv",
        ) => true,
        (
            Filter::IncludeOnly {
                target: FilterTarget::Comm,
                ..
            },
            "comm",
        ) => true,
        (
            Filter::Exclude {
                target: FilterTarget::Comm,
                ..
            },
            "commv",
        ) => true,
        (
            Filter::IncludeOnly {
                target: FilterTarget::CgroupId,
                ..
            },
            "cgid",
        ) => true,
        (
            Filter::Exclude {
                target: FilterTarget::CgroupId,
                ..
            },
            "cgidv",
        ) => true,
        _ => false,
    }
}

fn match_filter(f: &Filter, meta: &Metadata) -> bool {
    match f {
        Filter::IncludeOnly { target, value } | Filter::Exclude { target, value } => {
            match (target, value) {
                (FilterTarget::Pid, FilterValue::U32(v)) => meta.pid == *v,
                (FilterTarget::Cpu, FilterValue::CpuSet(set)) => set.contains(&meta.cpu),
                (FilterTarget::Pod, FilterValue::Str(s)) => meta.env == *s,
                (FilterTarget::Comm, FilterValue::Str(s)) => meta.group_comm == *s,
                (FilterTarget::CgroupId, FilterValue::U64(v)) => meta.cgroup_id == *v,
                _ => false,
            }
        }
    }
}

pub fn parse_cpu_set(input: &str) -> BTreeSet<u32> {
    // Common formats: "1,2,3" or "0-3,7" (inclusive range)
    let mut out = BTreeSet::new();
    for part in input.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                for v in lo..=hi {
                    out.insert(v);
                }
            }
        } else if let Ok(v) = part.parse::<u32>() {
            out.insert(v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_set_ok() {
        let s = parse_cpu_set("0-2, 7,9-8");
        let v: Vec<u32> = s.into_iter().collect();
        assert_eq!(v, vec![0, 1, 2, 7, 8, 9]);
    }
}
