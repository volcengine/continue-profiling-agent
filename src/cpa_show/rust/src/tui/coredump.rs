// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use crate::cpa::Metadata;
use crate::profile::ProfileData;
use std::{
    env,
    ffi::CString,
    fs,
    os::{raw::c_char, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
    process::Command,
};

pub(crate) const COREDUMP_MARKER_PREFIX: &str = "<# COREDUMP ";
/* a non-zero exit (--enable_exit_capture), stored like a coredump sample */
pub(crate) const EXIT_MARKER_PREFIX: &str = "<# EXIT NONZERO ";
/* the environment recorded when the exiting process was selected */
pub(crate) const CPA_ADDR2LINE_ENV: &str = "CPA_ADDR2LINE";
const CPA_CORE_CGROUP_ROOT_HINT_ENV: &str = "CPA_CORE_CGROUP_ROOT_HINT";
const AT_FDCWD: i32 = -100;
const AT_SYMLINK_FOLLOW: i32 = 0x400;

#[repr(C)]
struct CgroupFileHandle {
    handle_bytes: u32,
    handle_type: i32,
    cgroup_id: u64,
}

extern "C" {
    fn name_to_handle_at(
        dirfd: i32,
        pathname: *const c_char,
        handle: *mut CgroupFileHandle,
        mount_id: *mut i32,
        flags: i32,
    ) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SampleKind {
    CoreDump,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoreDumpMarker {
    pub raw: String,
    pub kind: SampleKind,
    pub signal: Option<String>,
    pub code: Option<i32>,
    /* Exit: "raw=768 exit=3" or "raw=15 sig=15 core=0" */
    pub exit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeFrame {
    pub pc: Option<u64>,
    pub path: String,
    pub build_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoreDumpFrame {
    pub index: usize,
    pub raw: String,
    pub native: Option<NativeFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoreDumpSample {
    pub record_index: usize,
    pub start_ms: u64,
    pub end_ms: u64,
    pub count: u64,
    pub metadata_raw: String,
    pub metadata: Option<Metadata>,
    pub marker: CoreDumpMarker,
    pub frames: Vec<CoreDumpFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LineResolutionStatus {
    Resolved,
    Skipped,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LineResolution {
    pub status: LineResolutionStatus,
    pub tool: String,
    pub path: String,
    pub path_note: Option<String>,
    pub function: Option<String>,
    pub source: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContainerRootSource {
    ExplicitPid {
        pid: u32,
    },
    Cgroup {
        cgroup_id: u64,
        cgroup_path: String,
        pid: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerRoot {
    pub root: String,
    pub source: ContainerRootSource,
}

impl ContainerRoot {
    pub(crate) fn from_pid(pid: u32) -> Self {
        Self {
            root: format!("/proc/{pid}/root"),
            source: ContainerRootSource::ExplicitPid { pid },
        }
    }

    pub(crate) fn from_cgroup(root: String, cgroup_id: u64, cgroup_path: String, pid: u32) -> Self {
        Self {
            root,
            source: ContainerRootSource::Cgroup {
                cgroup_id,
                cgroup_path,
                pid,
            },
        }
    }

    pub(crate) fn note(&self) -> String {
        match &self.source {
            ContainerRootSource::ExplicitPid { pid } => {
                format!("explicit pid {pid} -> {}", self.root)
            }
            ContainerRootSource::Cgroup {
                cgroup_id,
                cgroup_path,
                pid,
            } => format!("cgroup id {cgroup_id} -> {cgroup_path} pid {pid}"),
        }
    }
}

pub(crate) fn scan_coredump_samples(data: &dyn ProfileData) -> Vec<CoreDumpSample> {
    let mut out = Vec::new();

    for (record_index, record) in data.records().iter().enumerate() {
        let _ = data.for_each_entry_in_record(record_index, &mut |ids_id, count| {
            let Some(ids) = data.ids_for(ids_id) else {
                return Ok(());
            };
            if ids.is_empty() {
                return Ok(());
            }

            let marker = ids
                .iter()
                .skip(1)
                .filter_map(|sid| data.str_for(*sid))
                .find_map(parse_coredump_marker);
            let Some(marker) = marker else {
                return Ok(());
            };

            let metadata_raw = data.str_for(ids[0]).unwrap_or("").to_string();
            let metadata = Metadata::parse(&metadata_raw).ok();
            let mut frames = Vec::new();

            for (frame_index, sid) in ids.iter().skip(1).enumerate() {
                let raw = data.str_for(*sid).unwrap_or("").to_string();
                frames.push(CoreDumpFrame {
                    index: frame_index,
                    /* a marker frame is never a native one */
                    native: if raw.starts_with("<# ") {
                        None
                    } else {
                        parse_native_frame(&raw)
                    },
                    raw,
                });
            }

            out.push(CoreDumpSample {
                record_index,
                start_ms: record.start_ms,
                end_ms: record.end_ms,
                count,
                metadata_raw,
                metadata,
                marker,
                frames,
            });

            Ok(())
        });
    }

    out
}

/* "<# EXIT NONZERO raw=768 exit=3 #>" with @prefix "<# EXIT NONZERO ": "raw=768 exit=3" */
fn marker_body(frame: &str, prefix: &str) -> Option<String> {
    let body = frame.trim().strip_prefix(prefix)?;
    Some(body.strip_suffix("#>").unwrap_or(body).trim().to_string())
}

/* The COREDUMP marker of a coredump sample, or the EXIT marker of an exit. */
pub(crate) fn parse_coredump_marker(frame: &str) -> Option<CoreDumpMarker> {
    let trimmed = frame.trim();
    if let Some(exit) = marker_body(trimmed, EXIT_MARKER_PREFIX) {
        return Some(CoreDumpMarker {
            raw: trimmed.to_string(),
            kind: SampleKind::Exit,
            signal: None,
            code: None,
            exit: Some(exit),
        });
    }
    if !trimmed.starts_with(COREDUMP_MARKER_PREFIX) {
        return None;
    }

    let body = trimmed
        .trim_start_matches(COREDUMP_MARKER_PREFIX)
        .trim_end_matches('>')
        .trim_end_matches('#')
        .trim();
    let mut signal = None;
    let mut code = None;

    for token in body.split_whitespace() {
        if let Some(v) = token.strip_prefix("code=") {
            code = v.parse::<i32>().ok();
        } else if signal.is_none() {
            signal = Some(token.to_string());
        }
    }

    Some(CoreDumpMarker {
        raw: trimmed.to_string(),
        kind: SampleKind::CoreDump,
        signal,
        code,
        exit: None,
    })
}

pub(crate) fn parse_native_frame(frame: &str) -> Option<NativeFrame> {
    let path_end = frame.rfind(']')?;
    let path_start = frame[..path_end].rfind('[')? + 1;
    let path = &frame[path_start..path_end];

    if path == "anon exec segment" || !path.starts_with('/') {
        return None;
    }

    let build_id = extract_build_id(frame);
    let pc = extract_pc(frame);

    Some(NativeFrame {
        pc,
        path: path.to_string(),
        build_id,
    })
}

pub(crate) fn addr2line_tool() -> String {
    env::var(CPA_ADDR2LINE_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "addr2line".to_string())
}

pub(crate) fn resolve_native_frame_with_tool(
    tool: &str,
    frame: &NativeFrame,
    root_hint: Option<&ContainerRoot>,
) -> LineResolution {
    let Some(pc) = frame.pc else {
        return LineResolution {
            status: LineResolutionStatus::Skipped,
            tool: tool.to_string(),
            path: frame.path.clone(),
            path_note: None,
            function: None,
            source: None,
            message: Some("native frame has no pc".to_string()),
        };
    };

    let Some((native_path, path_note)) = resolve_existing_native_path(&frame.path, root_hint)
    else {
        return LineResolution {
            status: LineResolutionStatus::Skipped,
            tool: tool.to_string(),
            path: frame.path.clone(),
            path_note: root_hint.map(ContainerRoot::note),
            function: None,
            source: None,
            message: Some("native path does not exist".to_string()),
        };
    };

    let pc_arg = format!("0x{pc:x}");
    let output = Command::new(tool)
        .args(["-C", "-f", "-e", &native_path, &pc_arg])
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            let (function, source) = parse_addr2line_output(&text);
            LineResolution {
                status: LineResolutionStatus::Resolved,
                tool: tool.to_string(),
                path: native_path,
                path_note,
                function,
                source,
                message: None,
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            LineResolution {
                status: LineResolutionStatus::Error,
                tool: tool.to_string(),
                path: native_path,
                path_note,
                function: None,
                source: None,
                message: Some(if stderr.is_empty() {
                    format!("addr2line exited with {}", output.status)
                } else {
                    stderr
                }),
            }
        }
        Err(err) => LineResolution {
            status: LineResolutionStatus::Error,
            tool: tool.to_string(),
            path: native_path,
            path_note,
            function: None,
            source: None,
            message: Some(format!(
                "addr2line not found or failed to run. Set {CPA_ADDR2LINE_ENV}: {err}"
            )),
        },
    }
}

fn resolve_existing_native_path(
    recorded_path: &str,
    root_hint: Option<&ContainerRoot>,
) -> Option<(String, Option<String>)> {
    /*
     * Keep this no-container path recovery order aligned with list-core in
     * cli_general_show.c:
     * 1. Use the recorded path when it still exists.
     * 2. If the recorded path was captured as /proc/<crashed-pid>/root/...
     *    and that pid is gone, strip the stale proc-root prefix and retry the
     *    container/host absolute path.
     *
     * The Rust TUI currently has no core-container-pid option, so it mirrors
     * the list-core branch used when no live replacement container pid is
     * supplied.
     */
    let container_path =
        strip_stale_proc_root(recorded_path).unwrap_or_else(|| recorded_path.to_string());

    if let Some(root_hint) = root_hint {
        let candidate = join_root_path(&root_hint.root, &container_path);
        if Path::new(&candidate).exists() {
            return Some((candidate, Some(root_hint.note())));
        }
    }

    if Path::new(recorded_path).exists() {
        return Some((recorded_path.to_string(), None));
    }

    let stripped = strip_stale_proc_root(recorded_path)?;
    if Path::new(&stripped).exists() {
        return Some((stripped, None));
    }

    None
}

fn join_root_path(root: &str, path: &str) -> String {
    if path.starts_with('/') {
        format!("{root}{path}")
    } else {
        format!("{root}/{path}")
    }
}

fn strip_stale_proc_root(path: &str) -> Option<String> {
    /*
     * Core dump frames are captured while the crashing task is alive, so native
     * paths may include /proc/<pid>/root. Offline viewing usually happens
     * after that task has exited; the stale proc-root prefix then has to be
     * removed before addr2line can see a locally available ELF.
     */
    let rest = path.strip_prefix("/proc/")?;
    let digits = rest
        .char_indices()
        .find_map(|(idx, ch)| (!ch.is_ascii_digit()).then_some(idx))
        .unwrap_or(rest.len());
    if digits == 0 {
        return None;
    }

    let after_pid = &rest[digits..];
    let after_root = after_pid.strip_prefix("/root")?;
    if !(after_root.is_empty() || after_root.starts_with('/')) {
        return None;
    }
    if after_root.is_empty() {
        Some("/".to_string())
    } else {
        Some(after_root.to_string())
    }
}

pub(crate) fn find_cgroup_root_by_id(cgroup_id: u64) -> Option<ContainerRoot> {
    if cgroup_id == 0 {
        return None;
    }

    if let Some(root) = parse_cgroup_root_hint(cgroup_id) {
        return Some(root);
    }

    let mount = find_cgroup_mount()?;
    find_cgroup_root_in_dir(&mount, Path::new(""), cgroup_id, 0)
}

fn parse_cgroup_root_hint(cgroup_id: u64) -> Option<ContainerRoot> {
    /*
     * Test-only escape hatch used by offline resolver tests. Production
     * lookup follows the same model as the C list-core path:
     * cgroup id -> cgroup directory -> live peer pid -> /proc/<pid>/root.
     */
    let hint = env::var(CPA_CORE_CGROUP_ROOT_HINT_ENV).ok()?;
    let (id_s, rest) = hint.split_once('=')?;
    if id_s.parse::<u64>().ok()? != cgroup_id {
        return None;
    }
    let mut parts = rest.splitn(3, ':');
    let pid = parts.next()?.parse::<u32>().ok()?;
    let root = parts.next()?.to_string();
    let cgroup_path = parts.next()?.to_string();
    Some(ContainerRoot::from_cgroup(
        root,
        cgroup_id,
        cgroup_path,
        pid,
    ))
}

fn find_cgroup_mount() -> Option<PathBuf> {
    let text = fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut v2 = None;

    for line in text.lines() {
        let (left, right) = line.split_once(" - ")?;
        let fs_type = right.split_whitespace().next().unwrap_or("");
        let mount_point = left.split_whitespace().nth(4)?;
        let mount_point = unescape_mountinfo_path(mount_point);
        if fs_type == "cgroup" && mount_point.contains("cpu") {
            return Some(PathBuf::from(mount_point));
        }
        if fs_type == "cgroup2" {
            v2 = Some(PathBuf::from(mount_point));
        }
    }

    v2
}

fn unescape_mountinfo_path(path: &str) -> String {
    path.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn find_cgroup_root_in_dir(
    mount: &Path,
    relative: &Path,
    cgroup_id: u64,
    depth: usize,
) -> Option<ContainerRoot> {
    if depth > 128 {
        return None;
    }

    let full = if relative.as_os_str().is_empty() {
        mount.to_path_buf()
    } else {
        mount.join(relative)
    };

    if cgroup_id_for_path(&full) == Some(cgroup_id) {
        let (pid, root) = root_from_cgroup_procs(&full)?;
        let cgroup_path = if relative.as_os_str().is_empty() {
            "/".to_string()
        } else {
            format!("/{}", relative.display())
        };
        return Some(ContainerRoot::from_cgroup(
            root,
            cgroup_id,
            cgroup_path,
            pid,
        ));
    }

    let entries = fs::read_dir(&full).ok()?;
    for entry in entries.flatten() {
        let file_type = entry.file_type().ok()?;
        if !file_type.is_dir() {
            continue;
        }
        let child_relative = if relative.as_os_str().is_empty() {
            PathBuf::from(entry.file_name())
        } else {
            relative.join(entry.file_name())
        };
        if let Some(root) = find_cgroup_root_in_dir(mount, &child_relative, cgroup_id, depth + 1) {
            return Some(root);
        }
    }

    None
}

fn cgroup_id_for_path(path: &Path) -> Option<u64> {
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut handle = CgroupFileHandle {
        handle_bytes: std::mem::size_of::<u64>() as u32,
        handle_type: 0,
        cgroup_id: 0,
    };
    let mut mount_id = 0;
    let ret = unsafe {
        name_to_handle_at(
            AT_FDCWD,
            c_path.as_ptr(),
            &mut handle,
            &mut mount_id,
            AT_SYMLINK_FOLLOW,
        )
    };
    if ret == 0 && handle.handle_bytes == std::mem::size_of::<u64>() as u32 {
        Some(handle.cgroup_id)
    } else {
        None
    }
}

fn root_from_cgroup_procs(cgroup_dir: &Path) -> Option<(u32, String)> {
    /*
     * The crashing task is normally gone by the time CoreDump details are
     * opened. A still-running peer in the same cgroup can provide the same
     * container root for resolving recorded container-local ELF paths.
     */
    let text = fs::read_to_string(cgroup_dir.join("cgroup.procs")).ok()?;
    for line in text.lines() {
        let pid = line.trim().parse::<u32>().ok()?;
        let root = format!("/proc/{pid}/root");
        if Path::new(&root).exists() {
            return Some((pid, root));
        }
    }
    None
}

fn extract_build_id(frame: &str) -> Option<String> {
    let start = frame.find("[build-id=")? + "[build-id=".len();
    let end = frame[start..].find(']')? + start;
    let build_id = &frame[start..end];

    if build_id.len() == 40 && build_id.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(build_id.to_string())
    } else {
        None
    }
}

fn extract_pc(frame: &str) -> Option<u64> {
    if let Some(start) = frame.find("[pc=0x") {
        return parse_hex_prefix(&frame[start + "[pc=0x".len()..]);
    }
    if let Some(start) = frame.find(" @0x") {
        return parse_hex_prefix(&frame[start + " @0x".len()..]);
    }
    if let Some(rest) = frame.strip_prefix("0x") {
        return parse_hex_prefix(rest);
    }
    None
}

fn parse_hex_prefix(input: &str) -> Option<u64> {
    let end = input
        .char_indices()
        .find_map(|(i, c)| (!c.is_ascii_hexdigit()).then_some(i))
        .unwrap_or(input.len());
    if end == 0 {
        return None;
    }
    u64::from_str_radix(&input[..end], 16).ok()
}

fn parse_addr2line_output(text: &str) -> (Option<String>, Option<String>) {
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let function = lines.next().map(|line| line.trim().to_string());
    let source = lines.next().map(|line| line.trim().to_string());
    (function, source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpa::{Config, RecordMeta};
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct FakeData {
        cfg: Config,
        source: PathBuf,
        records: Vec<RecordMeta>,
        ids_map: HashMap<u32, Arc<Vec<u32>>>,
        strings: HashMap<u32, String>,
        entries: Vec<Vec<(u32, u64)>>,
    }

    impl ProfileData for FakeData {
        fn source_path(&self) -> &Path {
            &self.source
        }

        fn config(&self) -> &Config {
            &self.cfg
        }

        fn records(&self) -> &[RecordMeta] {
            &self.records
        }

        fn for_each_entry_in_record(
            &self,
            record_idx: usize,
            cb: &mut dyn FnMut(u32, u64) -> anyhow::Result<()>,
        ) -> anyhow::Result<()> {
            for (ids_id, count) in self.entries.get(record_idx).into_iter().flatten() {
                cb(*ids_id, *count)?;
            }
            Ok(())
        }

        fn ids_for(&self, ids_id: u32) -> Option<Arc<Vec<u32>>> {
            self.ids_map.get(&ids_id).cloned()
        }

        fn str_for(&self, sid: u32) -> Option<&str> {
            self.strings.get(&sid).map(|s| s.as_str())
        }

        fn metadata_for_ids(&self, ids: &[u32]) -> Option<Metadata> {
            ids.first()
                .and_then(|sid| self.str_for(*sid))
                .and_then(|s| Metadata::parse(s).ok())
        }

        fn ids_id_has_kernel(&self, _ids_id: u32) -> bool {
            false
        }
    }

    fn padded_meta(
        comm: &str,
        group_comm: &str,
        cgid: u64,
        cpu: u32,
        pid: u32,
        env: &str,
    ) -> String {
        format!(
            "{:<15}{:<15}-{}-{}-{}|{}",
            comm, group_comm, cgid, cpu, pid, env
        )
    }

    #[test]
    fn marker_parser_extracts_signal_and_code() {
        let marker = parse_coredump_marker("<# COREDUMP SIGSEGV code=1 #>").unwrap();

        assert_eq!(marker.signal.as_deref(), Some("SIGSEGV"));
        assert_eq!(marker.code, Some(1));
    }

    #[test]
    fn marker_parser_reads_exit_marker() {
        let marker = parse_coredump_marker("<# EXIT NONZERO raw=768 exit=3 #>").unwrap();

        assert_eq!(marker.kind, SampleKind::Exit);
        assert_eq!(marker.exit.as_deref(), Some("raw=768 exit=3"));
        assert_eq!(marker.signal, None);
        assert_eq!(marker.code, None);
        let core = parse_coredump_marker("<# COREDUMP SIGSEGV code=1 #>").unwrap();
        assert_eq!(core.kind, SampleKind::CoreDump);
        assert_eq!(core.exit, None);
    }

    #[test]
    fn scanner_collects_exit_samples() {
        let mut ids_map = HashMap::new();
        let mut strings = HashMap::new();

        strings.insert(
            1,
            padded_meta("exworker", "exhost", 42, 2, 5151, "msrv-a-1"),
        );
        strings.insert(2, "<# EXIT NONZERO raw=768 exit=3 #>".to_string());
        strings.insert(3, "<# EXIT ENV POD_NAME=msrv-a-1 APP_ID=7 #>".to_string());
        strings.insert(
            4,
            "exit_leaf @0x400abc [pc=0x400abc] [/tmp/libexit.so]".to_string(),
        );
        strings.insert(5, padded_meta("exworker", "exhost", 42, 2, 5252, "SYSTEM"));
        strings.insert(6, "<# EXIT NONZERO raw=15 sig=15 core=0 #>".to_string());
        strings.insert(7, "<# COREDUMP SIGSEGV code=1 #>".to_string());
        strings.insert(8, padded_meta("regular", "regular", 0, 1, 6, "SYSTEM"));
        strings.insert(9, "regular_leaf".to_string());
        // a frame of older data (EXIT ENV) that looks like a native path is
        // still no native frame
        strings.insert(10, "<# EXIT ENV P=[/tmp/x] #>".to_string());
        ids_map.insert(11, Arc::new(vec![1, 2, 3, 4]));
        ids_map.insert(12, Arc::new(vec![5, 6, 10, 4]));
        ids_map.insert(13, Arc::new(vec![5, 7, 4]));
        ids_map.insert(14, Arc::new(vec![8, 9]));

        let data = FakeData {
            cfg: Config::default(),
            source: PathBuf::from("/tmp/profile"),
            records: vec![RecordMeta {
                start_ms: 1_000,
                end_ms: 2_000,
                file_off: 0,
                entry_len: 0,
            }],
            ids_map,
            strings,
            entries: vec![vec![(11, 2), (12, 1), (13, 4), (14, 9)]],
        };

        let samples = scan_coredump_samples(&data);

        assert_eq!(samples.len(), 3);
        let exits: Vec<_> = samples
            .iter()
            .filter(|s| s.marker.kind == SampleKind::Exit)
            .collect();
        assert_eq!(exits.len(), 2);
        assert_eq!(exits[0].metadata.as_ref().unwrap().pid, 5151);
        assert_eq!(exits[0].marker.exit.as_deref(), Some("raw=768 exit=3"));
        assert!(exits[0].frames[1].native.is_none());
        assert!(exits[0].frames[2].native.is_some());
        assert!(exits[1].frames[1].native.is_none());
        let core: Vec<_> = samples
            .iter()
            .filter(|s| s.marker.kind == SampleKind::CoreDump)
            .collect();
        assert_eq!(core.len(), 1);
    }

    #[test]
    fn native_parser_extracts_pc_path_and_build_id() {
        let raw = concat!(
            "native_leaf+0x23 @0x7f0012345678 [pc=0x1234] ",
            "[build-id=1234567890abcdef1234567890abcdef12345678] ",
            "[/tmp/libmixed_stack.so]"
        );

        let frame = parse_native_frame(raw).unwrap();

        assert_eq!(frame.pc, Some(0x1234));
        assert_eq!(frame.path, "/tmp/libmixed_stack.so");
        assert_eq!(
            frame.build_id.as_deref(),
            Some("1234567890abcdef1234567890abcdef12345678")
        );
    }

    #[test]
    fn native_parser_ignores_non_native_paths() {
        assert!(parse_native_frame("python_frame [anon exec segment]").is_none());
        assert!(parse_native_frame("python_frame [relative/path]").is_none());
    }

    #[test]
    fn scanner_collects_coredump_samples_with_frames() {
        let mut ids_map = HashMap::new();
        let mut strings = HashMap::new();

        strings.insert(
            1,
            padded_meta("pyworker", "pythonhost", 42, 3, 4242, "SYSTEM"),
        );
        strings.insert(2, "<# COREDUMP SIGBUS code=2 #>".to_string());
        strings.insert(3, "python_leaf".to_string());
        strings.insert(
            4,
            "native_leaf @0x400abc [pc=0x400abc] [/tmp/libmixed_stack.so]".to_string(),
        );
        ids_map.insert(7, Arc::new(vec![1, 2, 3, 4]));

        let data = FakeData {
            cfg: Config::default(),
            source: PathBuf::from("/tmp/profile"),
            records: vec![RecordMeta {
                start_ms: 1_000,
                end_ms: 2_000,
                file_off: 0,
                entry_len: 0,
            }],
            ids_map,
            strings,
            entries: vec![vec![(7, 9)]],
        };

        let samples = scan_coredump_samples(&data);

        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].count, 9);
        assert_eq!(samples[0].metadata.as_ref().unwrap().pid, 4242);
        assert_eq!(samples[0].marker.signal.as_deref(), Some("SIGBUS"));
        assert_eq!(samples[0].frames.len(), 3);
        assert!(samples[0].frames[2].native.is_some());
    }

    #[test]
    fn resolver_strips_stale_proc_root_before_giving_up() {
        let dir = tempfile::tempdir().unwrap();
        let native = dir.path().join("libcrash.so");
        std::fs::write(&native, "not an elf").unwrap();

        let frame = NativeFrame {
            pc: Some(0x1234),
            path: format!("/proc/999999/root{}", native.display()),
            build_id: None,
        };

        let resolved = resolve_native_frame_with_tool("addr2line", &frame, None);

        assert_eq!(resolved.path, native.display().to_string());
        assert_ne!(resolved.status, LineResolutionStatus::Skipped);
        assert_ne!(
            resolved.message.as_deref(),
            Some("native path does not exist")
        );
    }

    #[test]
    fn resolver_prefers_cgroup_root_hint_before_recorded_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let native = root.join("srv/app/libcrash.so");
        std::fs::create_dir_all(native.parent().unwrap()).unwrap();
        std::fs::write(&native, "not an elf").unwrap();

        let frame = NativeFrame {
            pc: Some(0x1234),
            path: "/srv/app/libcrash.so".to_string(),
            build_id: None,
        };
        let root_hint = ContainerRoot::from_cgroup(
            root.display().to_string(),
            123,
            "/kubepods/test.slice".to_string(),
            4242,
        );

        let resolved = resolve_native_frame_with_tool("addr2line", &frame, Some(&root_hint));

        assert_eq!(resolved.path, native.display().to_string());
        assert_eq!(
            resolved.path_note.as_deref(),
            Some("cgroup id 123 -> /kubepods/test.slice pid 4242")
        );
        assert_ne!(resolved.status, LineResolutionStatus::Skipped);
    }

    #[test]
    fn cgroup_root_lookup_uses_cgroup_id_hint() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = env::var(CPA_CORE_CGROUP_ROOT_HINT_ENV).ok();

        env::set_var(
            CPA_CORE_CGROUP_ROOT_HINT_ENV,
            "987=4242:/tmp/container-root:/kubepods/test.slice",
        );

        let root = find_cgroup_root_by_id(987).unwrap();
        assert_eq!(root.root, "/tmp/container-root");
        assert_eq!(
            root.note(),
            "cgroup id 987 -> /kubepods/test.slice pid 4242"
        );

        match old {
            Some(value) => env::set_var(CPA_CORE_CGROUP_ROOT_HINT_ENV, value),
            None => env::remove_var(CPA_CORE_CGROUP_ROOT_HINT_ENV),
        }
    }
}
