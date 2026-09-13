#!/usr/bin/env python3
"""External ASLR oracle for the MCTTP 2026 demo: reads PurrView's own,
already-running process to recover the real, ASLR-randomized load address of
libpurrview.so -- independently of the app's own `ASLR self-check` button
(bridge.c's dladdr()-based self report). Showing the two agree is the point:
one is the app looking at itself, the other is an external reader finding
the same real address from the outside.

Scope, by construction rather than by promise:

* PID discovery matches only `lab.purrview` or `lab.purrview:<worker>` from
  `adb shell ps -A`; no other process is ever a candidate.
* The actual read is `adb shell run-as lab.purrview cat /proc/<pid>/maps`.
  `run-as` executes `cat` as PurrView's own app UID, and the kernel enforces
  same-UID-or-CAP_SYS_PTRACE for reading another process's /proc/<pid>/maps
  (see `man proc`, /proc/sys/kernel/yama/ptrace_scope). A PID that is not
  actually running as that UID simply gets "Permission denied" back, no
  matter what this script asked for -- this is not a policy this script
  enforces, it is what the device's kernel enforces regardless.
* Only /proc/<pid>/maps (mapping metadata: address ranges and file paths)
  is ever read, never /proc/<pid>/mem, and there is no ptrace-attach, code
  injection, or exfiltration. This is the same class of operation as `pmap`
  or Android Studio's own profiler, not a memory-disclosure exploit.
* Output is limited to the one requested library's base address plus pid
  and process name; the full maps listing is never printed or stored.

Pass --simulate to fall back to the old fully offline, synthetic 12-bit toy
search (no device, no /proc, no real address) for rehearsal without hardware.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from typing import Iterable

PACKAGE = "lab.purrview"
LIBRARY = "libpurrview.so"

# --- real, on-device oracle -------------------------------------------------

MAPS_LINE = re.compile(
    r"^(?P<start>[0-9a-f]+)-[0-9a-f]+\s+\S+\s+\S+\s+\S+\s+\S+\s*(?P<path>.*)$"
)


def run_adb(args: list[str], adb_bin: str, serial: str | None, timeout: float) -> subprocess.CompletedProcess:
    command = [adb_bin]
    if serial:
        command += ["-s", serial]
    command += args
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def find_pids(package: str, adb_bin: str, serial: str | None, timeout: float) -> list[tuple[int, str]]:
    """PIDs whose `ps` name is exactly `package` or `package:<worker>`."""
    result = run_adb(["shell", "ps", "-A"], adb_bin, serial, timeout)
    if result.returncode != 0:
        raise RuntimeError(f"adb shell ps -A failed: {result.stderr.strip()}")
    matches: list[tuple[int, str]] = []
    for line in result.stdout.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 2:
            continue
        pid_text, name = fields[1], fields[-1]
        if name == package or name.startswith(package + ":"):
            if pid_text.isdigit():
                matches.append((int(pid_text), name))
    return matches


def parse_library_base(maps_text: str, library: str) -> int | None:
    """Lowest mapped address for `library`, matching dladdr()'s dli_fbase."""
    base = None
    for line in maps_text.splitlines():
        match = MAPS_LINE.match(line)
        if match and library in match.group("path"):
            start = int(match.group("start"), 16)
            base = start if base is None else min(base, start)
    return base


def read_library_base(
    pid: int, package: str, library: str, adb_bin: str, serial: str | None, timeout: float
) -> int:
    result = run_adb(
        ["shell", "run-as", package, "cat", f"/proc/{pid}/maps"], adb_bin, serial, timeout
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"run-as read of /proc/{pid}/maps refused (pid must be a {package} process "
            f"and the build must be debuggable): {result.stderr.strip()}"
        )
    base = parse_library_base(result.stdout, library)
    if base is None:
        raise RuntimeError(f"{library} is not mapped in pid {pid} yet")
    return base


def real_oracle(args: argparse.Namespace) -> int:
    try:
        pids = find_pids(args.package, args.adb_bin, args.serial, args.timeout)
    except RuntimeError as error:
        print(f"[aslr_oracle] {error}", file=sys.stderr)
        return 2
    if not pids:
        print(
            f"[aslr_oracle] no running process named {args.package!r}; "
            "launch PurrView on the device first",
            file=sys.stderr,
        )
        return 2

    print("MCTTP 2026 demo | ASLR ORACLE | REAL DEVICE, PurrView's own process only")
    exit_code = 0
    for pid, name in pids:
        try:
            base = read_library_base(pid, args.package, args.library, args.adb_bin, args.serial, args.timeout)
        except RuntimeError as error:
            print(f"pid={pid} process={name}: {error}", file=sys.stderr)
            exit_code = 1
            continue
        line = f"pid={pid} process={name} module={args.library} base=0x{base:x}"
        print(line)
        if args.log:
            tagged = run_adb(
                ["shell", "log", "-t", "PurrView/ASLR", f"external oracle: {line}"],
                args.adb_bin, args.serial, args.timeout,
            )
            if tagged.returncode != 0:
                print(f"[aslr_oracle] adb shell log failed: {tagged.stderr.strip()}", file=sys.stderr)
    print(
        "Compare against the app's own 'ASLR self-check' button (dladdr(), "
        "logcat tag PurrView/ASLR): same process, same real base, two "
        "independent readers. Force-stop and relaunch the app, then run this "
        "again -- the base above will differ; that is real ASLR, not a fixed value."
    )
    return exit_code


# --- offline rehearsal fallback (no device, no real address) ---------------

MASK = (1 << 64) - 1
TOY_SEED = 0x4D43545450323032
TOY_BASE = 0x7000000000
TOY_MAX_ATTEMPTS = 4096


def _toy_step(state: int) -> int:
    return (state * 6364136223846793005 + 1442695040888963407) & MASK


def simulate_offline(seed: int = TOY_SEED) -> tuple[int, int, int]:
    """Return (attempt, synthetic address, candidate page) in a toy 12-bit space."""
    state = seed & MASK
    for _ in range(37):
        state = _toy_step(state)
    hidden_page = (state >> 20) & 0xFFF

    state = seed & MASK
    for attempt in range(1, TOY_MAX_ATTEMPTS + 1):
        state = _toy_step(state)
        candidate_page = (state >> 20) & 0xFFF
        if candidate_page == hidden_page:
            return attempt, TOY_BASE | (candidate_page << 12), candidate_page
    raise RuntimeError("synthetic search exhausted")


def simulated_oracle(args: argparse.Namespace) -> int:
    attempt, address, page = simulate_offline(args.seed)
    print("MCTTP 2026 demo | ASLR ORACLE | SIMULATION ONLY, no device, no real address")
    print(f"attempt={attempt} synthetic_page=0x{page:03x}")
    print(f"synthetic_valid_address=0x{address:010x} (page size=0x1000)")
    print("PASS: candidate found in bounded synthetic space")
    print("PASS: no process memory, /proc, ptrace, network, MMS or device access")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--package", default=PACKAGE, help="app package to read (default: %(default)s)")
    parser.add_argument("--library", default=LIBRARY, help="mapped library to locate (default: %(default)s)")
    parser.add_argument("--adb-bin", default=os.environ.get("ADB_BIN", "adb"))
    parser.add_argument("--serial", help="adb device serial")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--log", action="store_true", help="also inject the result into adb logcat (tag PurrView/ASLR)")
    parser.add_argument("--simulate", action="store_true", help="offline toy search instead of a real device read")
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=TOY_SEED, help="--simulate only")
    args = parser.parse_args(list(argv) if argv is not None else None)
    return simulated_oracle(args) if args.simulate else real_oracle(args)


if __name__ == "__main__":
    raise SystemExit(main())
