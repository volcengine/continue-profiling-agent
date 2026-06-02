# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance


from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import os
import sys


AT_FDCWD = -100
AT_SYMLINK_FOLLOW = 0x400


class FileHandle8(ctypes.Structure):
    _fields_ = [
        ("handle_bytes", ctypes.c_uint),
        ("handle_type", ctypes.c_int),
        ("f_handle", ctypes.c_ubyte * 8),
    ]


def _load_libc() -> ctypes.CDLL:
    path = ctypes.util.find_library("c")
    if not path:
        raise RuntimeError("failed to find libc")
    return ctypes.CDLL(path, use_errno=True)


def cgroup_id_from_full_path(path: str, *, libc: ctypes.CDLL | None = None) -> int:
    os.stat(path)
    if not os.path.isdir(path):
        raise ValueError(f"not a directory: {path}")

    if libc is None:
        libc = _load_libc()

    name_to_handle_at = libc.name_to_handle_at
    if hasattr(name_to_handle_at, "argtypes"):
        name_to_handle_at.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.POINTER(FileHandle8),
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_int,
        ]
        name_to_handle_at.restype = ctypes.c_int

    handle = FileHandle8()
    handle.handle_bytes = 8
    mount_id = ctypes.c_int()

    rc = name_to_handle_at(
        AT_FDCWD,
        os.fsencode(path),
        ctypes.byref(handle),
        ctypes.byref(mount_id),
        AT_SYMLINK_FOLLOW,
    )
    if rc != 0 or handle.handle_bytes != 8:
        err = ctypes.get_errno()
        raise OSError(err, f"name_to_handle_at failed: rc={rc} handle_bytes={handle.handle_bytes}", path)

    return int.from_bytes(bytes(handle.f_handle), byteorder=sys.byteorder, signed=False)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("cgroup_path", help="full cgroup path (including mountpoint), e.g. /sys/fs/cgroup/...")
    args = p.parse_args(argv)

    try:
        cid = cgroup_id_from_full_path(args.cgroup_path)
    except Exception as e:
        print(str(e), file=sys.stderr)
        return 1

    print(f"{cid} 0x{cid:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
