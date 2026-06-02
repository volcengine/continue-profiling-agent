// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use anyhow::Context;
use clap::Parser;

use crate::profile::{LoadOptions, LoaderRegistry};

#[derive(Debug, Parser)]
#[command(
    name = "cpa_show",
    version,
    about = "Render CPA profile data from --read in the Rust TUI."
)]
pub struct Args {
    #[arg(long = "read", short = 'r')]
    pub read: String,

    #[arg(long = "starttime", short = 'B', default_value = "00:00:00")]
    pub starttime: String,

    #[arg(long = "use_cui", short = 'G', default_value_t = false)]
    pub use_cui: bool,

    #[arg(long = "endtime", short = 'E', default_value = "00:00:00")]
    pub endtime: String,

    #[arg(long = "show_range", short = 'p', default_value_t = 0)]
    pub show_range: u32,

    #[arg(long = "use_cache", short = 'u', default_value_t = 0)]
    pub use_cache: u32,

    #[arg(long, default_value_t = false)]
    pub no_tui: bool,

    #[arg(long, default_value_t = false)]
    pub timing: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let use_cache = args.use_cache != 0;
    let opts = LoadOptions {
        timing: args.timing,
        use_cache,
    };
    let profile = LoaderRegistry::new()
        .load(&args.read, opts)
        .with_context(|| format!("打开 profile 失败: {}", args.read))?;

    if args.show_range != 0 {
        let (s, e) = profile.data.time_range_ms().unwrap_or((0, 0));
        let dur = e.saturating_sub(s);
        println!(
            "range: {} .. {} ({}s)  record_count={}  cpu_num={}",
            fmt_ms_hms(s),
            fmt_ms_hms(e),
            dur / 1000,
            profile.data.record_count(),
            profile.data.config().cpu_num.unwrap_or(0)
        );
        return Ok(());
    }

    if args.no_tui {
        println!("{}", profile.summary());
        return Ok(());
    }

    let (start, span) =
        compute_start_span_by_offset_time(profile.data.records(), &args.starttime, &args.endtime)
            .context("解析 starttime/endtime 失败")?;

    crate::tui::run(profile, start, span, args.timing).context("运行 TUI 失败")?;
    Ok(())
}

fn parse_hms_to_ms(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty time");
    }
    let parts: Vec<&str> = s.split(':').collect();
    let (hh, mm, ss) = match parts.as_slice() {
        [h, m, sec] => (*h, *m, *sec),
        [m, sec] => ("0", *m, *sec),
        _ => anyhow::bail!("invalid time format, expect HH:MM:SS"),
    };
    let hh: u64 = hh.parse()?;
    let mm: u64 = mm.parse()?;
    let ss: u64 = ss.parse()?;
    Ok((hh * 3600 + mm * 60 + ss) * 1000)
}

fn fmt_ms_hms(ms: u64) -> String {
    let day_ms = 86_400_000u64;
    let days = ms / day_ms;
    let mut rem = ms % day_ms;
    let hh = rem / 3_600_000;
    rem %= 3_600_000;
    let mm = rem / 60_000;
    rem %= 60_000;
    let ss = rem / 1000;
    if days > 0 {
        format!("+{days}d {:02}:{:02}:{:02}", hh, mm, ss)
    } else {
        format!("{:02}:{:02}:{:02}", hh, mm, ss)
    }
}

fn find_record_by_time(records: &[crate::cpa::RecordMeta], t_ms: u64) -> usize {
    if records.is_empty() {
        return 0;
    }
    let idx = records.partition_point(|r| r.end_ms < t_ms);
    idx.min(records.len().saturating_sub(1))
}

fn find_record_end_exclusive(records: &[crate::cpa::RecordMeta], t_ms: u64) -> usize {
    if records.is_empty() {
        return 0;
    }
    let idx = records.partition_point(|r| r.start_ms < t_ms);
    idx.min(records.len())
}

fn compute_start_span_by_offset_time(
    records: &[crate::cpa::RecordMeta],
    starttime: &str,
    endtime: &str,
) -> anyhow::Result<(usize, usize)> {
    let Some(first) = records.first() else {
        return Ok((0, 1));
    };

    let base = first.start_ms;
    let start_off = parse_hms_to_ms(starttime)?;
    let end_off = parse_hms_to_ms(endtime)?;

    let start_ms = base.saturating_add(start_off);
    let mut start_idx = find_record_by_time(records, start_ms);
    start_idx = start_idx.min(records.len().saturating_sub(1));

    if end_off == 0 {
        return Ok((start_idx, 1));
    }

    let end_ms = base.saturating_add(end_off);
    let mut end_excl = find_record_end_exclusive(records, end_ms);
    if end_excl <= start_idx {
        end_excl = (start_idx + 1).min(records.len().max(1));
    }
    Ok((start_idx, end_excl - start_idx))
}
