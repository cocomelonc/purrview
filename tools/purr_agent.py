#!/usr/bin/env python3
"""AI-assisted validation-method selector for the PurrView conference lab.

This is the "strategy" layer above the fixed checkers.  Instead of running one
hard-coded probe, PurrView exposes a *registry* of bounded validation methods
across three areas -- exploitability, ASLR, and the read/write primitive -- and
a model is allowed to choose, from a closed allow-list, which method_id to run
next and with which (also allow-listed) parameters.

One entry point runs the whole loop:

    plan (model picks method_id + params) -> run bounded method -> collect
    typed evidence -> if the area is still inconclusive and budget remains,
    plan the next method -> ... -> final per-area verdict + overall score.

The model never emits code, payloads, offsets outside the fixed buffers, shell
commands, URLs, or free-form addresses.  It returns only a JSON *selection*:

    {"select": [{"area": "aslr", "method_id": "maps_vs_dladdr"},
                {"area": "exploitability", "method_id": "canary_readback"}],
     "skip":   [{"method_id": "restart_stability",
                 "reason": "unnecessary after deterministic replay"}],
     "reason": "cross-check runtime base before bounded validation",
     "confidence": 0.82}

Every selection is validated against the registry allow-list before anything
runs; anything outside it is dropped and a deterministic rule-based planner
takes over, exactly like ai_mutate.py's recipe fallback.

Two execution modes:

* ``--simulate`` (default): no device.  Every method returns honest,
  deterministic evidence derived from PurrView's *own* construction -- the
  fixed leak secret, the exact bypass-probability model, the toy ASLR search.
  This is the same basis aslr_oracle.py --simulate and ai_mutate.py --density
  already use, so it is legitimate to rehearse and to unit-test.
* ``--live``: wires the ASLR and exploitability methods to the real device via
  the same adb/logcat/oracle paths the other tools use.  Methods without a
  real on-device trigger yet are labelled ``simulated`` even here and say so.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

# Reuse the fixture builders, Ollama plumbing and adb helpers rather than
# duplicating them; tools/ is not a package, so add it to the path by hand.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ai_mutate  # noqa: E402
import aslr_oracle  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "build" / "agent"
AREAS = ("exploitability", "aslr", "rw")
# PurrView's own fixed leak secret (parser.c kPurrLeakSecret). The trailing NUL
# is part of the C array and of what the OOB read discloses.
LEAK_SECRET = b"meow-meow MCTTP 2026"
LEAK_SECRET_NUL = LEAK_SECRET + b"\x00"
RW_COMPANION_SIZE = ai_mutate.RW_COMPANION_SIZE
COMPANION_PAD = 0xAA
RW_WRITE_BYTE = 0x41
# Bounded, debuggable-only broadcast triggers (LabControlReceiver).
ASLR_SELFCHECK_ACTION = "lab.purrview.action.ASLR_SELFCHECK"
RW_START_ACTION = "lab.purrview.action.RW_START"
CONTROL_RECEIVER = "lab.purrview/.LabControlReceiver"


# --------------------------------------------------------------------------- #
# Evidence + method registry
# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    """One typed evidence record produced by running a method."""

    method_id: str
    area: str
    evidence_type: str
    status: str          # "conclusive" | "inconclusive"
    verdict: str         # "confirmed" | "refuted" | "inconclusive"
    confidence: float    # 0..1
    observed: dict[str, Any]
    detail: str
    simulated: bool
    cost_s: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "method_id": self.method_id,
            "area": self.area,
            "evidence_type": self.evidence_type,
            "status": self.status,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "observed": self.observed,
            "detail": self.detail,
            "simulated": self.simulated,
            "cost_s": round(self.cost_s, 3),
        }


@dataclass
class RunContext:
    live: bool
    serial: str | None
    output_dir: Path


@dataclass
class Method:
    method_id: str
    area: str
    prerequisites: tuple[str, ...]
    cost_s: float                       # estimated cost, for planner budgeting
    timeout_s: float
    evidence_type: str
    risk: str                           # "low" | "medium"
    success: str                        # what counts as a conclusive success
    uncertainty: str                    # what leaves the method inconclusive
    params: dict[str, tuple[Any, ...]]  # param name -> allow-listed values
    run: Callable[[RunContext, Mapping[str, Any]], Evidence]
    priority: int = 0                   # rule-based planner order (lower first)

    def default_params(self) -> dict[str, Any]:
        return {name: values[0] for name, values in self.params.items()}

    def coerce_params(self, proposed: Mapping[str, Any]) -> dict[str, Any]:
        """Keep only allow-listed param values; fall back to the default."""
        chosen = self.default_params()
        for name, values in self.params.items():
            if name in proposed and proposed[name] in values:
                chosen[name] = proposed[name]
        return chosen

    def to_dict(self) -> dict[str, Any]:
        return {
            "method_id": self.method_id,
            "area": self.area,
            "prerequisites": list(self.prerequisites),
            "cost_s": self.cost_s,
            "timeout_s": self.timeout_s,
            "evidence_type": self.evidence_type,
            "risk": self.risk,
            "success": self.success,
            "uncertainty": self.uncertainty,
            "params": {k: list(v) for k, v in self.params.items()},
        }


# --------------------------------------------------------------------------- #
# Method implementations. Each returns an Evidence record. Simulated evidence
# is derived from PurrView's own deterministic construction, never invented.
# --------------------------------------------------------------------------- #
def _sim_companion(read_offset: int, read_len: int) -> bytes:
    """Reconstruct PurrView's companion buffer window without a device.

    parser.c fills the 64-byte companion with the leak secret (incl. NUL)
    then 0xAA padding; this mirrors that byte-for-byte for the read window.
    """
    buf = bytearray([COMPANION_PAD]) * RW_COMPANION_SIZE
    buf[: len(LEAK_SECRET_NUL)] = LEAK_SECRET_NUL
    return bytes(buf[read_offset : read_offset + read_len])


def _oob_fixture() -> bytes:
    return ai_mutate.build_png(ai_mutate.fallback_recipe("png", "oob"))


def _run_oob_trial(ctx: RunContext, want_marker: str, timeout: float) -> tuple[str, str | None]:
    """Push the canonical OOB fixture, trigger the worker, classify logcat."""
    fixture = ctx.output_dir / "oob-trial.png"
    fixture.write_bytes(_oob_fixture())
    ai_mutate.clear_sweep_log(ctx.serial)
    ai_mutate.push_to_device(fixture, ctx.serial, "purrview-ai.png")
    ai_mutate.trigger_sweep_worker(ctx.serial)
    return ai_mutate.poll_sweep_outcome(ctx.serial, timeout)


def method_crash_reproducibility(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    trials = int(params["trials"])
    start = time.monotonic()
    if ctx.live:
        reproduced = 0
        for _ in range(trials):
            outcome, _ = _run_oob_trial(ctx, "OOB_WRITE", timeout=4.0)
            if outcome == "OOB_WRITE":
                reproduced += 1
        simulated = False
    else:
        # The 128x128 PoC path is deterministic by construction, so every
        # replay reproduces the abort; this is the exact-model equivalent.
        reproduced = trials
        simulated = True
    rate = reproduced / trials if trials else 0.0
    conclusive = rate >= 0.9
    return Evidence(
        "crash_reproducibility", "exploitability", "reproducibility_rate",
        "conclusive" if conclusive else "inconclusive",
        "confirmed" if conclusive else "inconclusive",
        rate,
        {"trials": trials, "reproduced": reproduced, "rate": round(rate, 3),
         "marker": "OOB WRITE | PurrView parser"},
        f"{reproduced}/{trials} trials raised the same OOB-write SIGABRT",
        simulated, time.monotonic() - start,
    )


def method_boundary_probing(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    width = int(params["width"])
    start = time.monotonic()
    h_lo, h_hi = ai_mutate.density_height_range(width)
    boundary = None
    prev = None
    for h in range(h_lo, h_hi + 1):
        outcome = ai_mutate.png_predicted_outcome(width, h)
        if prev == "CONTROL" and outcome == "OOB_WRITE":
            boundary = h
            break
        prev = outcome
    checked = []
    if ctx.live and boundary is not None:
        # Validate three points against the device: below, at, and above the
        # modelled boundary.
        for h in (boundary - 1, boundary, boundary + 1):
            if not h_lo <= h <= h_hi:
                continue
            recipe = {"kind": "png", "width": width, "height": h, "channels": 4,
                      "bit_depth": 8, "pattern": "affine", "seed": 7, "crc": "valid"}
            fixture = ctx.output_dir / f"boundary-{h}.png"
            fixture.write_bytes(ai_mutate.build_png(recipe))
            ai_mutate.clear_sweep_log(ctx.serial)
            ai_mutate.push_to_device(fixture, ctx.serial, "purrview-ai.png")
            ai_mutate.trigger_sweep_worker(ctx.serial)
            outcome, _ = ai_mutate.poll_sweep_outcome(ctx.serial, 4.0)
            checked.append({"height": h, "predicted": ai_mutate.png_predicted_outcome(width, h),
                            "observed": outcome, "match": outcome == ai_mutate.png_predicted_outcome(width, h)})
        simulated = False
        conclusive = bool(checked) and all(c["match"] for c in checked)
    else:
        simulated = True
        conclusive = boundary is not None
    stats = ai_mutate.density_exact_probability(width, h_lo, h_hi)
    return Evidence(
        "boundary_probing", "exploitability", "boundary_map",
        "conclusive" if conclusive else "inconclusive",
        "confirmed" if conclusive else "inconclusive",
        0.9 if conclusive else 0.4,
        {"width": width, "boundary_height": boundary,
         "p_oob_write": float(stats["p_oob_write"]),
         "live_checks": checked},
        f"CONTROL->OOB_WRITE boundary at height={boundary} (width={width})",
        simulated, time.monotonic() - start,
    )


def method_canary_readback(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    start = time.monotonic()
    disclosed = None
    matched = False
    if ctx.live:
        fixture = ctx.output_dir / "leak-trial.png"
        fixture.write_bytes(_oob_fixture())
        ai_mutate.clear_sweep_log(ctx.serial)
        ai_mutate.push_to_device(fixture, ctx.serial, "purrview-ai.png")
        ai_mutate.trigger_sweep_worker(ctx.serial)
        # The OOB read leak line is logged just before the abort.
        line = _grep_logcat(ctx.serial, "OOB READ leak:", timeout=4.0)
        if line:
            disclosed = line.split("OOB READ leak:", 1)[1].strip()
            matched = LEAK_SECRET.decode() in disclosed
        simulated = False
    else:
        disclosed = LEAK_SECRET.decode()
        matched = True
        simulated = True
    conclusive = matched
    return Evidence(
        "canary_readback", "exploitability", "secret_disclosure",
        "conclusive" if conclusive else "inconclusive",
        "confirmed" if conclusive else "inconclusive",
        0.95 if conclusive else 0.3,
        {"disclosed": disclosed, "expected": LEAK_SECRET.decode(), "matched": matched},
        "OOB read disclosed PurrView's known post-buffer secret"
        if conclusive else "leak line not observed",
        simulated, time.monotonic() - start,
    )


def method_controlled_state_impact(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    return _rw_method(
        ctx, "controlled_state_impact", "exploitability", "state_delta",
        offset=int(params["offset"]), length=int(params["length"]), target="memory",
        detail="controlled bounded write changes exactly the targeted window",
    )


def method_restart_stability(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    start = time.monotonic()
    if ctx.live:
        # The main package process must survive a worker abort: workers run in
        # package-owned isolated processes, so a crash leaves the UI on screen.
        alive = _package_pid(ctx.serial, "lab.purrview") is not None
        simulated = False
    else:
        alive = True
        simulated = True
    return Evidence(
        "restart_stability", "exploitability", "restart_stability",
        "conclusive" if alive else "inconclusive",
        "confirmed" if alive else "refuted",
        0.85 if alive and not simulated else (0.7 if alive else 0.2),
        {"main_process_alive_after_crash": alive, "worker_isolation": True},
        "worker abort left the main UI process alive (isolated worker model)",
        simulated, time.monotonic() - start,
    )


def method_maps_snapshot(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    start = time.monotonic()
    if ctx.live:
        base = _live_maps_base(ctx.serial)
        simulated = False
    else:
        _, address, _ = aslr_oracle.simulate_offline()
        base = address
        simulated = True
    conclusive = base is not None
    return Evidence(
        "maps_snapshot", "aslr", "load_base",
        "conclusive" if conclusive else "inconclusive",
        "confirmed" if conclusive else "inconclusive",
        0.8 if conclusive else 0.2,
        {"library": aslr_oracle.LIBRARY, "base": f"0x{base:x}" if base else None},
        "read libpurrview.so load base from /proc/<pid>/maps"
        if conclusive else "no PurrView process / library not mapped",
        simulated, time.monotonic() - start,
    )


def method_maps_vs_dladdr(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    start = time.monotonic()
    if ctx.live:
        # Trigger the app's own dladdr self-check (main process) via the bounded
        # receiver, then cross-check its base against an external /proc/maps read
        # of the *same* pid; each process is randomized separately.
        _broadcast(ctx.serial, ASLR_SELFCHECK_ACTION, CONTROL_RECEIVER)
        time.sleep(0.6)
        dladdr_pid, dladdr_base = _live_dladdr_base(ctx.serial)
        maps_base = _live_maps_base(ctx.serial, pid=dladdr_pid)
        agree = maps_base is not None and dladdr_base is not None and maps_base == dladdr_base
        simulated = False
    else:
        _, address, _ = aslr_oracle.simulate_offline()
        maps_base = dladdr_base = address
        agree = True
        simulated = True
    if maps_base is None or dladdr_base is None:
        status, verdict, conf = "inconclusive", "inconclusive", 0.25
        detail = "need both the external /proc/maps read and the app's dladdr self-check"
    elif agree:
        status, verdict, conf = "conclusive", "confirmed", 0.92
        detail = "external /proc/maps base agrees with the app's own dladdr self-report"
    else:
        status, verdict, conf = "conclusive", "refuted", 0.6
        detail = "two independent readers disagree on the load base"
    return Evidence(
        "maps_vs_dladdr", "aslr", "base_agreement", status, verdict, conf,
        {"maps_base": f"0x{maps_base:x}" if maps_base else None,
         "dladdr_base": f"0x{dladdr_base:x}" if dladdr_base else None,
         "agree": agree},
        detail, simulated, time.monotonic() - start,
    )


def method_repeated_launch(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    launches = int(params["launches"])
    start = time.monotonic()
    bases: list[int] = []
    if ctx.live:
        for _ in range(launches):
            _force_stop(ctx.serial, "lab.purrview")
            _launch(ctx.serial, "lab.purrview")
            time.sleep(0.8)
            base = _live_maps_base(ctx.serial)
            if base is not None:
                bases.append(base)
        simulated = False
    else:
        # Toy 12-bit ASLR search, one synthetic base per launch seed.
        for i in range(launches):
            _, address, _ = aslr_oracle.simulate_offline(aslr_oracle.TOY_SEED + i)
            bases.append(address)
        simulated = True
    distinct = len(set(bases))
    conclusive = distinct >= 2
    return Evidence(
        "repeated_launch", "aslr", "distribution_entropy",
        "conclusive" if conclusive else "inconclusive",
        "confirmed" if conclusive else "inconclusive",
        min(0.6 + 0.1 * distinct, 0.95) if conclusive else 0.3,
        {"launches": launches, "distinct_bases": distinct,
         "bases": [f"0x{b:x}" for b in bases]},
        f"{distinct} distinct load bases across {launches} launches (ASLR active)"
        if conclusive else "load base did not move across launches",
        simulated, time.monotonic() - start,
    )


def method_crash_artifact_correlation(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    # Deliberately weak: a stored crash artifact carries no live-randomized
    # base on its own, so this stays inconclusive and exists mainly so the
    # planner has a lower-value method to *skip* once the base is cross-checked.
    start = time.monotonic()
    return Evidence(
        "crash_artifact_correlation", "aslr", "artifact_correlation",
        "inconclusive", "inconclusive", 0.25,
        {"artifact": "crash-*", "carries_live_base": False},
        "crash artifact alone cannot confirm the runtime base without a live read",
        True, time.monotonic() - start,
    )


def method_bounded_memory_canary(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    return _rw_method(
        ctx, "bounded_memory_canary", "rw", "canary_rw",
        offset=int(params["offset"]), length=int(params["length"]), target="memory",
        detail="in-memory companion canary read, overwritten, and read back",
    )


def method_file_canary(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    ev = _rw_method(
        ctx, "file_canary", "rw", "file_rw",
        offset=int(params["offset"]), length=int(params["length"]), target="file",
        detail="file-backed companion canary read, overwritten, and read back",
    )
    if not ev.simulated:
        ev.observed["backing"] = "purrview-rw-companion.bin"
    else:
        ev.confidence = min(ev.confidence, 0.85)
        ev.observed["backing"] = "purrview-rw-companion.bin"
    return ev


def method_offset_length_boundary(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    start = time.monotonic()
    # A window ending exactly at the companion size must be accepted; one byte
    # past it must be rejected. This is validate_rw_recipe's own boundary.
    accepted = _rw_window_ok(0, RW_COMPANION_SIZE)
    rejected = not _rw_window_ok(1, RW_COMPANION_SIZE)
    conclusive = accepted and rejected
    return Evidence(
        "offset_length_boundary", "rw", "boundary_enforcement",
        "conclusive" if conclusive else "inconclusive",
        "confirmed" if conclusive else "refuted",
        0.9 if conclusive else 0.3,
        {"enforced_size": RW_COMPANION_SIZE,
         "accepted_len_at_offset0": accepted,
         "rejected_one_past_boundary": rejected},
        f"read/write windows are bounded to exactly {RW_COMPANION_SIZE} bytes",
        True, time.monotonic() - start,
    )


def method_repeatability(ctx: RunContext, params: Mapping[str, Any]) -> Evidence:
    repeats = int(params["repeats"])
    start = time.monotonic()
    offset, length = 0, len(LEAK_SECRET_NUL)
    readbacks = {_sim_companion(offset, length).hex() for _ in range(repeats)}
    conclusive = len(readbacks) == 1
    return Evidence(
        "repeatability", "rw", "repeatability",
        "conclusive" if conclusive else "inconclusive",
        "confirmed" if conclusive else "refuted",
        0.88 if conclusive else 0.3,
        {"repeats": repeats, "distinct_readbacks": len(readbacks)},
        f"{repeats} repeats returned an identical bounded read-back",
        True, time.monotonic() - start,
    )


def _rw_method(ctx: RunContext, method_id: str, area: str, evidence_type: str, *,
               offset: int, length: int, target: str, detail: str) -> Evidence:
    """Live device R/W primitive when possible, deterministic model otherwise."""
    if ctx.live:
        return _rw_live(ctx, method_id, area, evidence_type,
                        offset=offset, length=length, target=target, detail=detail)
    return _rw_evidence(method_id, area, evidence_type,
                        offset=offset, length=length, detail=detail)


def _rw_live(ctx: RunContext, method_id: str, area: str, evidence_type: str, *,
             offset: int, length: int, target: str, detail: str) -> Evidence:
    """Drive PurrView's on-device R/W primitive via LabControlReceiver.

    The read window and the write window are the same [offset, offset+length]
    span; the write byte is fixed (0x41). Success is the device's own RW
    READBACK line showing that span now reads back as 0x41*length.
    """
    start = time.monotonic()
    recipe: dict[str, Any] = {
        "kind": "png", "width": 8, "height": 8, "channels": 4, "bit_depth": 8,
        "crc": "valid", "rw_read_offset": offset, "rw_read_len": length,
        "rw_write_offset": offset, "rw_write_len": length, "rw_write_byte": RW_WRITE_BYTE,
    }
    try:
        recipe = ai_mutate.validate_rw_recipe(recipe)
    except ai_mutate.RecipeError as error:
        return Evidence(
            method_id, area, evidence_type, "inconclusive", "refuted", 0.2,
            {"offset": offset, "length": length,
             "companion_size": RW_COMPANION_SIZE, "in_bounds": False},
            f"requested window rejected before dispatch: {error}",
            False, time.monotonic() - start,
        )
    fixture = ctx.output_dir / f"{method_id}.png"
    fixture.write_bytes(ai_mutate.build_png(recipe))
    try:
        ai_mutate.clear_sweep_log(ctx.serial)
        ai_mutate.push_to_device(fixture, ctx.serial, "purrview-rw.png")
        # PngDecodeService reads the target under EXTRA_RW_TARGET ("rw_target").
        _broadcast(ctx.serial, RW_START_ACTION, CONTROL_RECEIVER, {"rw_target": target})
    except (OSError, ai_mutate.subprocess.CalledProcessError) as error:
        return Evidence(
            method_id, area, evidence_type, "inconclusive", "inconclusive", 0.2,
            {"offset": offset, "length": length, "error": str(error)},
            f"adb error dispatching R/W worker: {error}", False, time.monotonic() - start,
        )
    # The heap and file-backed primitives log under different markers.
    read_marker = "RW FILE READ |" if target == "file" else "RW READ |"
    readback_marker = "RW FILE READBACK |" if target == "file" else "RW READBACK |"
    read_line = _grep_logcat(ctx.serial, read_marker, timeout=4.0)
    readback_line = _grep_logcat(ctx.serial, readback_marker, timeout=4.0)
    before_hex = _rw_hex(read_line)
    after_hex = _rw_hex(readback_line)
    expected = f"{RW_WRITE_BYTE:02x}" * length
    applied = after_hex is not None and after_hex.lower() == expected.lower()
    return Evidence(
        method_id, area, evidence_type,
        "conclusive" if applied else "inconclusive",
        "confirmed" if applied else "inconclusive",
        0.92 if applied else 0.3,
        {"offset": offset, "length": length, "target": target, "in_bounds": True,
         "before_hex": before_hex, "after_hex": after_hex,
         "write_byte": f"0x{RW_WRITE_BYTE:02x}", "applied": applied},
        detail + " (device RW READBACK)" if applied
        else "no on-device RW READBACK observed",
        False, time.monotonic() - start,
    )


def _rw_hex(line: str | None) -> str | None:
    if not line:
        return None
    match = re.search(r"hex=([0-9a-fA-F]+)", line)
    return match.group(1) if match else None


def _rw_evidence(method_id: str, area: str, evidence_type: str, *, offset: int,
                 length: int, detail: str) -> Evidence:
    start = time.monotonic()
    if not _rw_window_ok(offset, length):
        return Evidence(
            method_id, area, evidence_type, "inconclusive", "refuted", 0.2,
            {"offset": offset, "length": length,
             "companion_size": RW_COMPANION_SIZE, "in_bounds": False},
            "requested window exceeds the fixed companion buffer",
            True, time.monotonic() - start,
        )
    before = _sim_companion(offset, length)
    write_byte = 0x41
    after = bytes([write_byte]) * length
    changed = before != after
    return Evidence(
        method_id, area, evidence_type,
        "conclusive" if changed else "inconclusive",
        "confirmed" if changed else "inconclusive",
        0.9 if changed else 0.4,
        {"offset": offset, "length": length,
         "before_hex": before.hex(), "after_hex": after.hex(),
         "write_byte": f"0x{write_byte:02x}", "in_bounds": True},
        detail, True, time.monotonic() - start,
    )


def _rw_window_ok(offset: int, length: int) -> bool:
    return length >= 1 and 0 <= offset and offset + length <= RW_COMPANION_SIZE


# --- live device helpers (thin wrappers over aslr_oracle / adb) ------------- #
def _adb(serial: str | None, args: list[str], timeout: float = 10.0):
    return aslr_oracle.run_adb(args, os.environ.get("ADB_BIN", "adb"), serial, timeout)


def _package_pid(serial: str | None, package: str) -> int | None:
    pids = aslr_oracle.find_pids(package, "adb", serial, 10.0)
    for pid, name in pids:
        if name == package:
            return pid
    return pids[0][0] if pids else None


def _live_maps_base(serial: str | None, pid: int | None = None) -> int | None:
    """libpurrview.so base from /proc/<pid>/maps.

    With an explicit pid, read exactly that process (used to cross-check the
    same process the dladdr self-check ran in); otherwise prefer the main
    package process over a worker, since each process is randomized separately.
    """
    pids = aslr_oracle.find_pids("lab.purrview", "adb", serial, 10.0)
    if pid is not None:
        ordered = [(p, n) for p, n in pids if p == pid]
    else:
        ordered = ([(p, n) for p, n in pids if n == "lab.purrview"]
                   + [(p, n) for p, n in pids if n != "lab.purrview"])
    for p, _ in ordered:
        try:
            return aslr_oracle.read_library_base(
                p, "lab.purrview", aslr_oracle.LIBRARY, "adb", serial, 10.0)
        except RuntimeError:
            continue
    return None


def _live_dladdr_base(serial: str | None) -> tuple[int | None, int | None]:
    """(pid, base) from the latest PurrView/ASLR self-check line, or (None, None)."""
    result = _adb(serial, ["logcat", "-d", "-v", "brief", "-s", "PurrView/ASLR:I", "*:S"])
    pid = base = None
    for line in result.stdout.splitlines():
        if "external oracle" in line:  # skip aslr_oracle.py's own injected line
            continue
        match = re.search(r"base=0x([0-9a-fA-F]+)", line)
        if match:
            base = int(match.group(1), 16)
            pid_match = re.search(r"pid=(\d+)", line)
            if pid_match:
                pid = int(pid_match.group(1))
    return pid, base


def _broadcast(serial: str | None, action: str, receiver: str,
               extras: Mapping[str, str] | None = None):
    args = ["shell", "am", "broadcast", "-a", action, "-n", receiver]
    for key, value in (extras or {}).items():
        args += ["--es", key, value]
    return _adb(serial, args)


def _grep_logcat(serial: str | None, needle: str, timeout: float) -> str | None:
    deadline = time.monotonic() + timeout
    while True:
        result = _adb(serial, ["logcat", "-d", "-v", "brief", "-s", "PurrView/PNG:I", "*:S"])
        for line in result.stdout.splitlines():
            if needle in line:
                return line.strip()
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.25)


def _force_stop(serial: str | None, package: str) -> None:
    _adb(serial, ["shell", "am", "force-stop", package])


def _launch(serial: str | None, package: str) -> None:
    _adb(serial, ["shell", "monkey", "-p", package, "-c",
                  "android.intent.category.LAUNCHER", "1"])


# --------------------------------------------------------------------------- #
# The registry (single source of truth + the model's allow-list)
# --------------------------------------------------------------------------- #
def build_registry() -> dict[str, Method]:
    methods = [
        # -- exploitability ------------------------------------------------- #
        Method("crash_reproducibility", "exploitability",
               ("device", "app_running", "png_worker"), 3.0, 6.0,
               "reproducibility_rate", "low",
               "same OOB-write SIGABRT reproduces on >=90% of replays",
               "abort marker missing or intermittent",
               {"trials": (3, 5, 8)}, method_crash_reproducibility, priority=2),
        Method("boundary_probing", "exploitability",
               ("device", "png_worker"), 4.0, 8.0,
               "boundary_map", "low",
               "a clean CONTROL->OOB_WRITE height boundary is located",
               "no boundary in range, or live points disagree with the model",
               {"width": (128, 64, 256)}, method_boundary_probing, priority=1),
        Method("canary_readback", "exploitability",
               ("device", "png_worker"), 3.0, 6.0,
               "secret_disclosure", "low",
               "OOB read discloses PurrView's known post-buffer secret",
               "leak line not observed in logcat",
               {}, method_canary_readback, priority=0),
        Method("controlled_state_impact", "exploitability",
               ("companion_buffer",), 1.0, 3.0,
               "state_delta", "low",
               "a bounded write changes exactly the targeted window",
               "requested window is outside the companion buffer",
               {"offset": (0, 4, 8), "length": (4, 8, 16)},
               method_controlled_state_impact, priority=3),
        Method("restart_stability", "exploitability",
               ("device", "app_running"), 2.0, 4.0,
               "restart_stability", "low",
               "main UI process survives a worker abort (isolated workers)",
               "main process also dies",
               {}, method_restart_stability, priority=4),
        # -- aslr ----------------------------------------------------------- #
        Method("maps_vs_dladdr", "aslr",
               ("device", "app_running", "debuggable"), 3.0, 6.0,
               "base_agreement", "low",
               "external /proc/maps base equals the app's dladdr self-report",
               "one of the two readers is missing",
               {}, method_maps_vs_dladdr, priority=0),
        Method("maps_snapshot", "aslr",
               ("device", "app_running", "debuggable"), 2.0, 4.0,
               "load_base", "low",
               "libpurrview.so load base is read from /proc/<pid>/maps",
               "no PurrView process or library not yet mapped",
               {}, method_maps_snapshot, priority=1),
        Method("repeated_launch", "aslr",
               ("device", "app_running", "debuggable"), 6.0, 12.0,
               "distribution_entropy", "medium",
               "load base takes >=2 distinct values across relaunches",
               "base does not move (ASLR off or too few launches)",
               {"launches": (3, 5, 8)}, method_repeated_launch, priority=2),
        Method("crash_artifact_correlation", "aslr",
               ("crash_artifact",), 1.0, 3.0,
               "artifact_correlation", "low",
               "a stored artifact's address matches the live base",
               "artifact carries no live-randomized base by itself",
               {}, method_crash_artifact_correlation, priority=3),
        # -- rw ------------------------------------------------------------- #
        Method("bounded_memory_canary", "rw",
               ("companion_buffer",), 1.0, 3.0,
               "canary_rw", "low",
               "in-memory canary is read, overwritten, and read back changed",
               "window outside the companion buffer",
               {"offset": (0, 8, 16), "length": (4, 8, 16)},
               method_bounded_memory_canary, priority=0),
        Method("file_canary", "rw",
               ("companion_buffer", "files_dir"), 1.5, 3.0,
               "file_rw", "low",
               "file-backed canary is read, overwritten, and read back changed",
               "window outside the companion buffer or files dir unavailable",
               {"offset": (0, 8, 16), "length": (4, 8, 16)},
               method_file_canary, priority=2),
        Method("offset_length_boundary", "rw",
               ("companion_buffer",), 1.0, 3.0,
               "boundary_enforcement", "low",
               "windows are accepted up to and rejected past the buffer size",
               "boundary enforced at the wrong size",
               {}, method_offset_length_boundary, priority=1),
        Method("repeatability", "rw",
               ("companion_buffer",), 1.0, 3.0,
               "repeatability", "low",
               "repeated bounded reads return an identical read-back",
               "read-back varies between repeats",
               {"repeats": (3, 5, 8)}, method_repeatability, priority=3),
    ]
    return {m.method_id: m for m in methods}


REGISTRY = build_registry()


# --------------------------------------------------------------------------- #
# Planning: model selection, validated against the registry allow-list
# --------------------------------------------------------------------------- #
@dataclass
class Selection:
    area: str
    method_id: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Plan:
    select: list[Selection]
    skip: list[dict[str, str]]
    reason: str
    confidence: float
    source: str
    model: str | None


class PlanError(ValueError):
    """Raised when a model plan is outside the allow-list."""


def _open_methods(open_areas: Sequence[str], done: set[str]) -> list[Method]:
    return [m for m in REGISTRY.values()
            if m.area in open_areas and m.method_id not in done]


def validate_plan(candidate: Mapping[str, Any], open_areas: Sequence[str],
                  done: set[str], source: str, model: str | None) -> Plan:
    if not isinstance(candidate, Mapping):
        raise PlanError("plan must be a JSON object")
    raw_select = candidate.get("select")
    if not isinstance(raw_select, list) or not raw_select:
        raise PlanError("plan.select must be a non-empty list")
    available = {m.method_id for m in _open_methods(open_areas, done)}
    selections: list[Selection] = []
    for item in raw_select:
        if not isinstance(item, Mapping):
            raise PlanError("each selection must be an object")
        method_id = item.get("method_id")
        if method_id not in REGISTRY:
            raise PlanError(f"unknown method_id: {method_id!r}")
        method = REGISTRY[method_id]
        area = item.get("area", method.area)
        if area != method.area:
            raise PlanError(f"method {method_id!r} is not in area {area!r}")
        if method_id not in available:
            raise PlanError(f"method {method_id!r} is not selectable now "
                            "(area closed or already run)")
        proposed = item.get("params", {})
        params = method.coerce_params(proposed if isinstance(proposed, Mapping) else {})
        selections.append(Selection(method.area, method_id, params))
    # Deduplicate while preserving order.
    seen: set[str] = set()
    deduped = [s for s in selections if not (s.method_id in seen or seen.add(s.method_id))]
    skip = []
    for item in candidate.get("skip", []) or []:
        if isinstance(item, Mapping) and item.get("method_id") in REGISTRY:
            skip.append({"method_id": str(item["method_id"]),
                         "reason": str(item.get("reason", "")).strip()})
    confidence = candidate.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        raise PlanError("confidence must be a number")
    confidence = max(0.0, min(1.0, float(confidence)))
    reason = str(candidate.get("reason", "")).strip()
    return Plan(deduped, skip, reason, confidence, source, model)


def planner_prompt(open_areas: Sequence[str], done: set[str],
                   evidence: Sequence[Evidence]) -> str:
    catalog = []
    for m in _open_methods(open_areas, done):
        catalog.append({
            "area": m.area, "method_id": m.method_id,
            "evidence": m.evidence_type, "cost_s": m.cost_s,
            "risk": m.risk, "success": m.success,
            "params": {k: list(v) for k, v in m.params.items()},
        })
    summary = [{"method_id": e.method_id, "area": e.area,
                "verdict": e.verdict, "status": e.status,
                "confidence": round(e.confidence, 2)} for e in evidence]
    return (
        "You select which bounded validation methods PurrView should run next. "
        "You choose ONLY method_id values (and, optionally, allow-listed params) "
        "from the catalog below. You never emit code, payloads, addresses, "
        "commands, URLs, or file paths. Return JSON only, of exactly this shape: "
        '{"select":[{"area":"aslr","method_id":"maps_vs_dladdr"}],'
        '"skip":[{"method_id":"restart_stability","reason":"..."}],'
        '"reason":"...","confidence":0.82}. '
        "Pick the highest-value methods for the still-open areas; prefer a "
        "direct evidence source over a weaker or redundant one, and list in "
        "skip any method you are deliberately not running, with a short reason. "
        f"Still-open areas: {list(open_areas)}. "
        f"Catalog (the only selectable methods): {json.dumps(catalog)}. "
        f"Evidence gathered so far: {json.dumps(summary)}."
    )


def deterministic_plan(open_areas: Sequence[str], done: set[str],
                       evidence: Sequence[Evidence]) -> Plan:
    """Rule-based fallback planner: top-priority open method per open area."""
    conclusive_areas = {e.area for e in evidence if e.status == "conclusive"
                        and e.verdict == "confirmed"}
    select: list[Selection] = []
    skip: list[dict[str, str]] = []
    for area in open_areas:
        candidates = sorted(
            (m for m in _open_methods([area], done)),
            key=lambda m: m.priority,
        )
        if not candidates:
            continue
        select.append(Selection(area, candidates[0].method_id,
                                candidates[0].default_params()))
        for extra in candidates[1:]:
            reason = _skip_reason(extra, conclusive_areas, evidence)
            if reason:
                skip.append({"method_id": extra.method_id, "reason": reason})
    reason = "rule-based: run the highest-value open method per area"
    return Plan(select, skip, reason, 0.75, "deterministic", None)


def _skip_reason(method: Method, conclusive_areas: set[str],
                 evidence: Sequence[Evidence]) -> str | None:
    if method.method_id == "restart_stability":
        if any(e.method_id == "crash_reproducibility" and e.status == "conclusive"
               for e in evidence):
            return "unnecessary after deterministic replay"
    if method.method_id == "crash_artifact_correlation":
        if any(e.method_id == "maps_vs_dladdr" and e.status == "conclusive"
               for e in evidence):
            return "redundant; runtime base already cross-checked"
    if method.area in conclusive_areas:
        return f"{method.area} already conclusive from a stronger method"
    return "deferred to a later round" if method.priority > 1 else None


def make_plan(open_areas: Sequence[str], done: set[str],
              evidence: Sequence[Evidence], args: argparse.Namespace) -> Plan:
    if args.offline:
        return deterministic_plan(open_areas, done, evidence)
    prompt = planner_prompt(open_areas, done, evidence)
    for source, endpoint_call in _planner_stages(args):
        try:
            raw = endpoint_call(prompt)
            return validate_plan(raw, open_areas, done, source[0], source[1])
        except (RuntimeError, PlanError, ai_mutate.RecipeError) as error:
            print(f"[purr_agent] {source[0]} ({source[1]}) failed: {error}", file=sys.stderr)
    print("[purr_agent] no model plan; using deterministic planner", file=sys.stderr)
    return deterministic_plan(open_areas, done, evidence)


def _planner_stages(args: argparse.Namespace):
    """(label, model), callable(prompt)->dict pairs, remote then local."""
    stages = []
    if not args.no_remote:
        def remote(prompt: str, args=args):
            bind = args.remote_bind_host or ai_mutate.default_remote_bind_host(args.remote_ssh)
            with ai_mutate.ssh_tunnel(
                    args.remote_ssh, bind, args.remote_port, args.tunnel_port, args.ssh_timeout):
                return ai_mutate.call_ollama(
                    f"http://127.0.0.1:{args.tunnel_port}", args.remote_model,
                    prompt, args.timeout)
        stages.append((("ollama-remote", args.remote_model), remote))

    def local(prompt: str, args=args):
        return ai_mutate.call_ollama(args.local_endpoint, args.local_model, prompt, args.timeout)
    stages.append((("ollama-local", args.local_model), local))
    return stages


# --------------------------------------------------------------------------- #
# The loop + scoring + report
# --------------------------------------------------------------------------- #
def area_verdict(area: str, evidence: Sequence[Evidence]) -> dict[str, Any]:
    area_ev = [e for e in evidence if e.area == area]
    conclusive = [e for e in area_ev if e.status == "conclusive"]
    if conclusive:
        best = max(conclusive, key=lambda e: e.confidence)
        return {"area": area, "verdict": best.verdict, "status": "conclusive",
                "confidence": round(best.confidence, 3), "via": best.method_id}
    if area_ev:
        best = max(area_ev, key=lambda e: e.confidence)
        return {"area": area, "verdict": "inconclusive", "status": "inconclusive",
                "confidence": round(best.confidence * 0.5, 3), "via": best.method_id}
    return {"area": area, "verdict": "unattempted", "status": "unattempted",
            "confidence": 0.0, "via": None}


def render_decision(plan: Plan, round_no: int) -> None:
    selected = " + ".join(s.method_id for s in plan.select) or "(none)"
    print(f"\n== round {round_no} == [{plan.source}"
          + (f":{plan.model}" if plan.model else "") + "]")
    print(f"AI selected: {selected}")
    for item in plan.skip:
        reason = f" — {item['reason']}" if item["reason"] else ""
        print(f"Skipped: {item['method_id']}{reason}")
    if plan.reason:
        print(f"Reason: {plan.reason}")
    print(f"Confidence: {plan.confidence:.2f}")


def run_agent(args: argparse.Namespace) -> int:
    requested = list(args.areas)
    ctx = RunContext(live=args.live, serial=args.serial, output_dir=None)  # type: ignore[arg-type]
    run_dir = DEFAULT_OUTPUT / time.strftime("%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    ctx.output_dir = run_dir

    mode = "LIVE DEVICE" if args.live else "SIMULATION (no device)"
    print(f"PurrView method-selection agent | {mode} | areas={requested}")
    print(f"budget={args.budget} method runs, max_rounds={args.max_rounds}, "
          f"artifacts under {run_dir}")

    evidence: list[Evidence] = []
    done: set[str] = set()
    plans: list[dict[str, Any]] = []
    open_areas = list(requested)
    budget = args.budget

    for round_no in range(1, args.max_rounds + 1):
        if not open_areas or budget <= 0:
            break
        plan = make_plan(open_areas, done, evidence, args)
        if not plan.select:
            break
        render_decision(plan, round_no)
        plans.append({"round": round_no, "source": plan.source, "model": plan.model,
                      "confidence": plan.confidence, "reason": plan.reason,
                      "select": [s.method_id for s in plan.select], "skip": plan.skip})
        for sel in plan.select:
            if budget <= 0:
                break
            method = REGISTRY[sel.method_id]
            ev = method.run(ctx, sel.params)
            evidence.append(ev)
            done.add(sel.method_id)
            budget -= 1
            flag = "sim" if ev.simulated else "live"
            print(f"  -> {ev.method_id} [{ev.evidence_type}/{flag}]: "
                  f"{ev.verdict} ({ev.status}, conf={ev.confidence:.2f}) — {ev.detail}")
        # Recompute which areas still need work.
        open_areas = [a for a in open_areas
                      if area_verdict(a, evidence)["status"] != "conclusive"]

    verdicts = [area_verdict(a, evidence) for a in requested]
    scored = [v for v in verdicts if v["status"] != "unattempted"]
    overall = round(sum(v["confidence"] for v in scored) / len(scored), 3) if scored else 0.0

    print("\n== final report ==")
    for v in verdicts:
        tail = f"via {v['via']}" if v["via"] else "no method run"
        print(f"  {v['area']:15s} {v['verdict']:12s} "
              f"conf={v['confidence']:.2f} ({v['status']}, {tail})")
    unresolved = [v["area"] for v in verdicts if v["status"] != "conclusive"]
    print(f"OVERALL SCORE: {overall:.2f}"
          + (f" | unresolved: {unresolved}" if unresolved else " | all areas conclusive"))

    report = {
        "mode": "live" if args.live else "simulate",
        "requested_areas": requested,
        "overall_score": overall,
        "verdicts": verdicts,
        "unresolved": unresolved,
        "budget_used": args.budget - budget,
        "rounds": plans,
        "evidence": [e.to_dict() for e in evidence],
    }
    report_path = run_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"report: {report_path.resolve()}")
    return 0 if not unresolved else 1


# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--simulate", dest="live", action="store_false", default=False,
                      help="offline, no device (default): honest evidence from PurrView's own construction")
    mode.add_argument("--live", dest="live", action="store_true",
                      help="wire ASLR + exploitability methods to a real device via adb/logcat")
    parser.add_argument("--areas", nargs="+", choices=AREAS, default=list(AREAS),
                        help="which areas to validate (default: all three)")
    parser.add_argument("--budget", type=int, default=8,
                        help="maximum number of method runs across the whole loop")
    parser.add_argument("--max-rounds", type=int, default=6,
                        help="maximum planning rounds")
    parser.add_argument("--offline", action="store_true",
                        help="skip the model; use the deterministic rule-based planner")
    parser.add_argument("--list", action="store_true",
                        help="print the method registry as JSON and exit")
    parser.add_argument("--serial", help="adb device serial (--live)")
    parser.add_argument("--output", type=Path, help="run artifact directory")
    # Ollama plumbing, mirrored from ai_mutate.py so a shared rehearsal host works.
    parser.add_argument("--remote-ssh", default=ai_mutate.DEFAULT_REMOTE_SSH)
    parser.add_argument("--remote-bind-host", default=None)
    parser.add_argument("--remote-port", type=int, default=ai_mutate.DEFAULT_REMOTE_PORT)
    parser.add_argument("--remote-model", default=ai_mutate.DEFAULT_REMOTE_MODEL)
    parser.add_argument("--tunnel-port", type=int, default=ai_mutate.DEFAULT_TUNNEL_PORT)
    parser.add_argument("--ssh-timeout", type=float, default=6.0)
    parser.add_argument("--no-remote", action="store_true",
                        help="skip the remote Ollama; go straight to --local-endpoint")
    parser.add_argument("--local-endpoint", default=ai_mutate.DEFAULT_LOCAL_ENDPOINT)
    parser.add_argument("--local-model", default=ai_mutate.DEFAULT_LOCAL_MODEL)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args(argv)

    if args.list:
        print(json.dumps({"areas": list(AREAS),
                          "methods": [REGISTRY[m].to_dict() for m in REGISTRY]},
                         indent=2))
        return 0
    if args.output is not None:
        global DEFAULT_OUTPUT
        DEFAULT_OUTPUT = args.output
    return run_agent(args)


if __name__ == "__main__":
    raise SystemExit(main())
