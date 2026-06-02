// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub env: String,
    pub cpu: u32,
    pub pid: u32,
    pub cgroup_id: u64,
    pub comm: String,
    pub group_comm: String,
    pub raw: String,
}

#[derive(Debug, Clone)]
pub struct MetadataParseError(String);

impl fmt::Display for MetadataParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "metadata 解析失败: {}", self.0)
    }
}

impl std::error::Error for MetadataParseError {}

impl Metadata {
    /// Align with C-side `parse_metadata`:
    /// `<comm(15)+group_comm(15)>-<cgid>-<cpu>-<pid>|<env>`
    pub fn parse(input: &str) -> Result<Self, MetadataParseError> {
        let s = input.to_string();
        let (base, env) = s
            .split_once('|')
            .ok_or_else(|| MetadataParseError(input.to_string()))?;

        // Find 3 '-' from the tail, corresponding to cgid/cpu/pid.
        let mut dash_pos = Vec::with_capacity(3);
        for (i, ch) in base.char_indices().rev() {
            if ch == '-' {
                dash_pos.push(i);
                if dash_pos.len() == 3 {
                    break;
                }
            }
        }
        if dash_pos.len() != 3 {
            return Err(MetadataParseError(input.to_string()));
        }
        dash_pos.sort_unstable();
        let pid = base[dash_pos[2] + 1..]
            .parse::<u32>()
            .map_err(|_| MetadataParseError(input.to_string()))?;
        let cpu = base[dash_pos[1] + 1..dash_pos[2]]
            .parse::<u32>()
            .map_err(|_| MetadataParseError(input.to_string()))?;
        let cgroup_id = base[dash_pos[0] + 1..dash_pos[1]]
            .parse::<u64>()
            .map_err(|_| MetadataParseError(input.to_string()))?;

        // The first 30 bytes are merged comm fields (fixed-width, space-padded).
        let merged = base
            .get(0..30)
            .ok_or_else(|| MetadataParseError(input.to_string()))?;
        let comm_raw = merged.get(0..15).unwrap_or("");
        let group_comm_raw = merged.get(15..30).unwrap_or("");

        Ok(Self {
            env: env.to_string(),
            cpu,
            pid,
            cgroup_id,
            comm: comm_raw.trim_end().to_string(),
            group_comm: group_comm_raw.trim_end().to_string(),
            raw: input.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metadata_ok() {
        // comm="abc" group_comm="xyz" padded to 15 each
        let merged = format!("{:<15}{:<15}", "abc", "xyz");
        let s = format!("{}-1-2-3|pod-A", merged);
        let m = Metadata::parse(&s).unwrap();
        assert_eq!(m.comm, "abc");
        assert_eq!(m.group_comm, "xyz");
        assert_eq!(m.cpu, 2);
        assert_eq!(m.pid, 3);
        assert_eq!(m.cgroup_id, 1);
        assert_eq!(m.env, "pod-A");
    }
}
