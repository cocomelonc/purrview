#!/usr/bin/env python3
"""Bounded server-side mutation controller for the PurrView conference lab.

The model is allowed to choose a small parser-test recipe only.  This tool
never asks for or emits shellcode, native code, ROP, commands, URLs, or an
executable payload.  A deterministic builder turns the validated recipe into
an inert PurrView PNG or PDU fixture.

The default mode is offline: if Ollama is unavailable, a deterministic recipe
is used and the output says so.  When online, the script tries a primary
Ollama instance reached over an on-demand SSH tunnel (``--remote-ssh``),
falls back to a local Ollama instance (``--local-endpoint``), and finally
falls back to the deterministic recipe.  The optional ``--adb-push`` path
copies only the resulting fixture into PurrView's private files directory on
an authorised debug device; the APK remains network-free.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zlib
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterator, Mapping


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "build" / "ai-mutation"
# JSON recipe selection is a closed allow-list choice, not code generation.
# The remote rehearsal host has GPU headroom, so a mid-size instruction model
# gives reliable schema adherence there; the CPU-only local fallback uses a
# small, fast model so a stage demo without network still responds quickly.
DEFAULT_REMOTE_SSH = "cocomelonc@10.10.10.95"
DEFAULT_REMOTE_PORT = 11434
DEFAULT_TUNNEL_PORT = 11435
DEFAULT_REMOTE_MODEL = "qwen3:14b"
DEFAULT_LOCAL_ENDPOINT = "http://127.0.0.1:11434"
DEFAULT_LOCAL_MODEL = "qwen3:1.7b"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_FIXTURE = 128 * 1024
SWEEP_ACTION = "lab.purrview.action.AI_SWEEP_START"
SWEEP_RECEIVER = "lab.purrview/.AiSweepReceiver"
SWEEP_OUTCOME_PATTERNS = (
    (re.compile(r"OOB WRITE \| PurrView parser"), "OOB_WRITE"),
    (re.compile(r"native result: ACCEPTED"), "CONTROL"),
    (re.compile(r"native result: REJECTED"), "REJECTED"),
    (re.compile(r"fixture rejected:"), "REJECTED"),
)
# ReconCat (recon/) is a separate, standalone app that plays the attacker's
# recon step; PurrView is this demo's vulnerable target and is never asked
# to fingerprint itself.
RECON_ACTION = "lab.reconcat.action.DUMP_RECON"
RECON_RECEIVER = "lab.reconcat/.ReconReceiver"
RECON_LOG_PATTERN = re.compile(r"RECON (\{.*\})")
DEFAULT_PROFILE = {"device": "Motorola", "arch": "arm64", "purpose": "PurrView demo"}

# These values are deliberately small.  They are enough to exercise the
# PurrView parser's integer-narrowing paths without becoming a general fuzzer.
PNG_DIMENSIONS = ((64, 64), (128, 64), (128, 128), (256, 64))
PNG_PATTERNS = ("affine", "alternating", "zero")
PDU_LENGTHS = (32, 128, 256, 512, 1024)
PDU_PATTERNS = PNG_PATTERNS
# --target rw: a controlled read/write primitive (see parser.c's
# inspect_png_rw/inspect_png_rw_file) instead of the OOB-write crash.
# read/write windows must stay inside this fixed companion buffer, matching
# PURR_RW_COMPANION_SIZE in parser.c.
RW_COMPANION_SIZE = 64
RW_RECIPE_KEYS = {
    "kind",
    "width",
    "height",
    "channels",
    "bit_depth",
    "crc",
    "rw_read_offset",
    "rw_read_len",
    "rw_write_offset",
    "rw_write_len",
    "rw_write_byte",
}
RECIPE_KEYS = {
    "kind",
    "width",
    "height",
    "channels",
    "bit_depth",
    "pattern",
    "seed",
    "declared_length",
    "crc",
}


class RecipeError(ValueError):
    """Raised when a model response is outside the allow-list."""


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def pattern_bytes(length: int, pattern: str, seed: int) -> bytes:
    if length < 0:
        raise RecipeError("payload length must be non-negative")
    seed &= 0xFF
    if pattern == "zero":
        return bytes(length)
    if pattern == "alternating":
        return bytes(seed if i % 2 == 0 else (255 - seed) for i in range(length))
    if pattern == "affine":
        return bytes((i * 17 + seed) & 0xFF for i in range(length))
    raise RecipeError(f"pattern is not allowed: {pattern!r}")


def build_png(recipe: Mapping[str, Any]) -> bytes:
    width = recipe["width"]
    height = recipe["height"]
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    if "rw_read_offset" in recipe:
        # pCAT carries a 5-byte R/W request instead of pixel-overflow bytes;
        # see parser.c's purr_rw_request / parse_rw_request.
        payload = struct.pack(
            ">BBBBB",
            recipe["rw_read_offset"],
            recipe["rw_read_len"],
            recipe["rw_write_offset"],
            recipe["rw_write_len"],
            recipe["rw_write_byte"],
        )
    else:
        actual = width * height * 4
        payload = pattern_bytes(actual, recipe["pattern"], recipe["seed"])
    data = (
        PNG_SIGNATURE
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(b""))
        + png_chunk(b"pCAT", payload)
        + png_chunk(b"IEND", b"")
    )
    if len(data) > MAX_FIXTURE:
        raise RecipeError(f"fixture exceeds {MAX_FIXTURE} bytes")
    return data


def build_pdu(recipe: Mapping[str, Any]) -> bytes:
    declared = recipe["declared_length"]
    payload = pattern_bytes(declared, recipe["pattern"], recipe["seed"])
    data = b"PMS1" + struct.pack(">H", declared) + payload
    if len(data) > MAX_FIXTURE:
        raise RecipeError(f"fixture exceeds {MAX_FIXTURE} bytes")
    return data


def expected_outcome(recipe: Mapping[str, Any]) -> str:
    if "rw_read_offset" in recipe:
        return "RW_PRIMITIVE"
    if recipe["kind"] == "png":
        actual = recipe["width"] * recipe["height"] * recipe["channels"]
        checked = actual & 0xFFFF
        return "OOB_WRITE" if actual > 32768 and checked <= 32768 else "CONTROL"
    declared = recipe["declared_length"]
    return "OOB_WRITE" if declared > 255 else "CONTROL"


def fallback_recipe(kind: str, target: str) -> dict[str, Any]:
    if kind == "png":
        if target == "rw":
            return {
                "kind": "png",
                "width": 8,
                "height": 8,
                "channels": 4,
                "bit_depth": 8,
                "crc": "valid",
                "rw_read_offset": 0,
                "rw_read_len": len(b"meow-meow MCTTP 2026\x00"),
                "rw_write_offset": 0,
                "rw_write_len": 4,
                "rw_write_byte": 0x41,
            }
        if target == "oob":
            return {
                "kind": "png",
                "width": 128,
                "height": 128,
                "channels": 4,
                "bit_depth": 8,
                "pattern": "alternating",
                "seed": 91,
                "crc": "valid",
            }
        return {
            "kind": "png",
            "width": 64,
            "height": 64,
            "channels": 4,
            "bit_depth": 8,
            "pattern": "alternating",
            "seed": 19,
            "crc": "valid",
        }
    if target == "oob":
        return {
            "kind": "pdu",
            "declared_length": 256,
            "pattern": "affine",
            "seed": 11,
        }
    return {"kind": "pdu", "declared_length": 128, "pattern": "alternating", "seed": 7}


def _integer(value: Any, name: str) -> int:
    # bool is an int subclass, but accepting true/false here would make the
    # model response needlessly ambiguous.
    if isinstance(value, bool) or not isinstance(value, int):
        raise RecipeError(f"{name} must be an integer")
    return value


def validate_rw_recipe(candidate: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(candidate, Mapping):
        raise RecipeError("model response must be a JSON object")
    unknown = set(candidate) - RW_RECIPE_KEYS
    if unknown:
        raise RecipeError("unknown recipe fields: " + ", ".join(sorted(unknown)))

    def field(name: str) -> int:
        value = _integer(candidate.get(name), name)
        if not 0 <= value <= 255:
            raise RecipeError(f"{name} must be in range 0..255")
        return value

    read_offset = field("rw_read_offset")
    read_len = field("rw_read_len")
    write_offset = field("rw_write_offset")
    write_len = field("rw_write_len")
    write_byte = field("rw_write_byte")
    if read_len == 0 or write_len == 0:
        raise RecipeError("rw_read_len and rw_write_len must be at least 1")
    if read_offset + read_len > RW_COMPANION_SIZE:
        raise RecipeError(f"rw read window exceeds the {RW_COMPANION_SIZE}-byte companion buffer")
    if write_offset + write_len > RW_COMPANION_SIZE:
        raise RecipeError(f"rw write window exceeds the {RW_COMPANION_SIZE}-byte companion buffer")
    return {
        "kind": "png",
        "width": 8,
        "height": 8,
        "channels": 4,
        "bit_depth": 8,
        "crc": "valid",
        "rw_read_offset": read_offset,
        "rw_read_len": read_len,
        "rw_write_offset": write_offset,
        "rw_write_len": write_len,
        "rw_write_byte": write_byte,
    }


def validate_recipe(candidate: Mapping[str, Any], kind: str, target: str) -> dict[str, Any]:
    if target == "rw":
        if kind != "png":
            raise RecipeError("target=rw is PNG-only")
        return validate_rw_recipe(candidate)
    if not isinstance(candidate, Mapping):
        raise RecipeError("model response must be a JSON object")
    unknown = set(candidate) - RECIPE_KEYS
    if unknown:
        raise RecipeError("unknown recipe fields: " + ", ".join(sorted(unknown)))
    if candidate.get("kind") != kind:
        raise RecipeError(f"recipe kind must be {kind!r}")
    pattern = candidate.get("pattern")
    if pattern not in PNG_PATTERNS:
        raise RecipeError(f"pattern is not allowed: {pattern!r}")
    seed = _integer(candidate.get("seed"), "seed")
    if not 0 <= seed <= 255:
        raise RecipeError("seed must be in range 0..255")

    if kind == "png":
        width = _integer(candidate.get("width"), "width")
        height = _integer(candidate.get("height"), "height")
        if (width, height) not in PNG_DIMENSIONS:
            raise RecipeError("PNG dimensions are outside the allow-list")
        if _integer(candidate.get("channels"), "channels") != 4:
            raise RecipeError("only RGBA PNG fixtures are allowed")
        if _integer(candidate.get("bit_depth"), "bit_depth") != 8:
            raise RecipeError("only 8-bit PNG fixtures are allowed")
        if candidate.get("crc", "valid") != "valid":
            raise RecipeError("only valid CRC fixtures are allowed for mutation")
        result = {
            "kind": "png",
            "width": width,
            "height": height,
            "channels": 4,
            "bit_depth": 8,
            "pattern": pattern,
            "seed": seed,
            "crc": "valid",
        }
    else:
        declared = _integer(candidate.get("declared_length"), "declared_length")
        if declared not in PDU_LENGTHS:
            raise RecipeError("PDU length is outside the allow-list")
        result = {
            "kind": "pdu",
            "declared_length": declared,
            "pattern": pattern,
            "seed": seed,
        }

    outcome = expected_outcome(result)
    if target == "oob" and outcome != "OOB_WRITE":
        raise RecipeError("recipe does not exercise the selected PurrView PoC path")
    if target == "control" and outcome != "CONTROL":
        raise RecipeError("recipe unexpectedly exercises the PurrView PoC path")
    return result


def parse_json_object(text: str) -> Mapping[str, Any]:
    """Parse JSON even when a model wraps it in a markdown code fence."""
    clean = text.strip()
    if clean.startswith("```"):
        clean = clean.split("\n", 1)[1] if "\n" in clean else clean
        if clean.endswith("```"):
            clean = clean[:-3].rstrip()
    try:
        value = json.loads(clean)
    except json.JSONDecodeError:
        start, end = clean.find("{"), clean.rfind("}")
        if start < 0 or end <= start:
            raise RecipeError("Ollama did not return a JSON object")
        try:
            value = json.loads(clean[start : end + 1])
        except json.JSONDecodeError as error:
            raise RecipeError(f"invalid JSON from Ollama: {error}") from error
    if not isinstance(value, Mapping):
        raise RecipeError("Ollama response is not a JSON object")
    return value


def prompt_for(kind: str, target: str, profile: Mapping[str, Any], extra: str = "") -> str:
    if target == "rw":
        schema = (
            '{"kind":"png","width":8,"height":8,"channels":4,"bit_depth":8,"crc":"valid",'
            '"rw_read_offset":0,"rw_read_len":21,"rw_write_offset":0,"rw_write_len":4,'
            '"rw_write_byte":65}'
        )
        return (
            "You are a bounded test-case planner for the offline PurrView Android "
            "memory-safety lab's read/write primitive demo. Return JSON only, matching "
            f"this schema exactly: {schema} "
            "width, height, channels, bit_depth and crc must be exactly as in the schema - "
            "only the rw_* fields vary. rw_read_offset, rw_read_len, rw_write_offset, "
            "rw_write_len and rw_write_byte are each an integer 0..255. "
            f"rw_read_offset+rw_read_len and rw_write_offset+rw_write_len must each be at "
            f"most {RW_COMPANION_SIZE} (PurrView's own companion buffer size). Pick values "
            "that read, then overwrite, an interesting region of that buffer. "
            "Do not output C, assembly, shellcode, ROP, syscalls, commands, URLs, file "
            "paths, network actions, or executable content. "
            f"Device profile (informational only): {json.dumps(profile, sort_keys=True)}"
            f"{extra}"
        )
    schema = (
        '{"kind":"png","width":128,"height":128,"channels":4,'
        '"bit_depth":8,"pattern":"affine","seed":3,"crc":"valid"}'
        if kind == "png"
        else '{"kind":"pdu","declared_length":256,"pattern":"affine","seed":11}'
    )
    if target == "any":
        target_instruction = (
            "Pick any single bounded recipe from the allow-list below for "
            f"parser kind={kind!r}; both a safely-handled combination and one "
            "that hits the parser's integer-narrowing bypass are valid answers."
        )
    else:
        target_instruction = f"Choose target={target!r} for parser kind={kind!r}."
    return (
        "You are a bounded test-case planner for the offline PurrView Android "
        "memory-safety lab. Return JSON only, matching this schema exactly: "
        f"{schema} "
        f"{target_instruction} "
        "The allow-list is the only authority: PNG dimensions are "
        "64x64, 128x64, 128x128, or 256x64; channels=4; bit_depth=8; "
        "PDU lengths are 32, 128, 256, 512, or 1024; patterns are "
        "affine, alternating, or zero; seed is 0..255; crc must be valid. "
        "Do not output C, assembly, shellcode, ROP, syscalls, commands, "
        "URLs, file paths, network actions, or executable content. "
        f"Device profile (informational only): {json.dumps(profile, sort_keys=True)}"
        f"{extra}"
    )


def call_ollama(
    endpoint: str,
    model: str,
    prompt: str,
    timeout: float,
    temperature: float = 0,
    seed: int = 42,
) -> Mapping[str, Any]:
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Return one bounded JSON recipe and nothing else."},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "format": "json",
        # Reasoning models (qwen3) otherwise spend 60-80s narrating a chain of
        # thought before the JSON; the recipe schema needs none of that, and
        # skipping it is what keeps a call comfortably inside --timeout.
        "think": False,
        "options": {"temperature": temperature, "seed": seed},
    }
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/api/chat",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            decoded = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Ollama unavailable: {error}") from error
    content = decoded.get("message", {}).get("content")
    if not isinstance(content, str):
        raise RuntimeError("Ollama response did not contain message.content")
    return parse_json_object(content)


def default_remote_bind_host(remote_ssh: str) -> str:
    """Best-guess address Ollama is bound to on the remote host.

    The rehearsal host runs ``OLLAMA_HOST=<its own LAN ip>:11434`` rather than
    127.0.0.1, and the LAN blocks inbound TCP to that port from other hosts
    (only ICMP gets through). The forward target must therefore be the
    remote's own address, so the connection is made locally by its sshd
    rather than routed in from outside. ``--remote-bind-host`` overrides this
    guess for a differently configured host.
    """
    return remote_ssh.rsplit("@", 1)[-1]


@contextlib.contextmanager
def ssh_tunnel(
    remote_ssh: str, remote_bind_host: str, remote_port: int, local_port: int, timeout: float
) -> Iterator[None]:
    """Hold a local port-forward to an Ollama instance reached only over SSH.

    The tunnel is opened on demand for a single recipe call and torn down
    immediately after, rather than requiring a standing forward or a
    network-wide OLLAMA_HOST.
    """
    command = [
        "ssh",
        "-N",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "ExitOnForwardFailure=yes",
        "-L", f"{local_port}:{remote_bind_host}:{remote_port}",
        remote_ssh,
    ]
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except OSError as error:
        raise RuntimeError(f"could not start ssh: {error}") from error
    try:
        deadline = time.monotonic() + timeout
        up = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stderr = process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
                raise RuntimeError(f"ssh tunnel to {remote_ssh} exited early: {stderr.strip()}")
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=0.5):
                    up = True
                    break
            except OSError:
                time.sleep(0.2)
        if not up:
            raise RuntimeError(f"ssh tunnel to {remote_ssh} did not come up within {timeout}s")
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def resolve_recipe(
    kind: str,
    target: str,
    profile: Mapping[str, Any],
    args: argparse.Namespace,
    extra_prompt: str = "",
    ollama_seed: int = 42,
    temperature: float = 0,
) -> tuple[Mapping[str, Any] | None, str, str | None]:
    """Try the remote Ollama over SSH, then local Ollama, in that order."""
    prompt = prompt_for(kind, target, profile, extra_prompt)
    stages: list[tuple[str, str]] = []
    if not args.no_remote:
        stages.append(("ollama-remote", args.remote_model))
    stages.append(("ollama-local", args.local_model))

    for source, model in stages:
        try:
            if source == "ollama-remote":
                bind_host = args.remote_bind_host or default_remote_bind_host(args.remote_ssh)
                with ssh_tunnel(args.remote_ssh, bind_host, args.remote_port, args.tunnel_port, args.ssh_timeout):
                    raw = call_ollama(
                        f"http://127.0.0.1:{args.tunnel_port}", model, prompt, args.timeout,
                        temperature=temperature, seed=ollama_seed,
                    )
            else:
                raw = call_ollama(
                    args.local_endpoint, model, prompt, args.timeout,
                    temperature=temperature, seed=ollama_seed,
                )
            recipe = validate_recipe(raw, kind, target)
            return recipe, source, model
        except (RuntimeError, RecipeError) as error:
            print(f"[ai_mutate] {source} ({model}) failed: {error}", file=sys.stderr)
    return None, "deterministic-fallback", None


def binary_diff(before: bytes | None, after: bytes) -> dict[str, Any]:
    if before is None:
        return {"baseline": None, "changed_bytes": None, "first_change": None}
    changed = sum(a != b for a, b in zip(before, after)) + abs(len(before) - len(after))
    first = next((i for i, (a, b) in enumerate(zip(before, after)) if a != b), min(len(before), len(after)))
    return {
        "baseline": {"bytes": len(before), "sha256": hashlib.sha256(before).hexdigest()},
        "changed_bytes": changed,
        "first_change": first,
        "old_hex": before[first : first + 16].hex(),
        "new_hex": after[first : first + 16].hex(),
    }


def force_visible_variation(recipe: Mapping[str, Any], kind: str) -> dict[str, Any]:
    """Make a deterministic byte-level variation if a model repeats baseline."""
    result = dict(recipe)
    if result["pattern"] == "zero":
        result["pattern"] = "alternating"
    elif result["pattern"] == "alternating":
        result["pattern"] = "affine"
    else:
        result["seed"] = (result["seed"] + 1) & 0xFF
    # Keep the same kind/target semantics; validate_recipe is called again by
    # the caller so this helper cannot widen the allow-list.
    return result


def push_to_device(path: Path, serial: str | None, private_name: str) -> None:
    adb = os.environ.get("ADB_BIN", "adb")
    target = "/data/local/tmp/purrview-ai-fixture"
    command = [adb]
    if serial:
        command += ["-s", serial]
    subprocess.run(command + ["push", str(path), target], check=True)
    # run-as starts in the app's private directory; the destination name is
    # fixed by the caller and never comes from model output.
    subprocess.run(command + ["shell", "run-as", "lab.purrview", "mkdir", "-p", "files"], check=True)
    subprocess.run(command + ["shell", "run-as", "lab.purrview", "cp", target, "files/" + private_name], check=True)
    subprocess.run(command + ["shell", "rm", target], check=True)


def trigger_sweep_worker(serial: str | None) -> None:
    """Fire the bounded AiSweepReceiver broadcast; equivalent to tapping Run AI PoC."""
    adb = os.environ.get("ADB_BIN", "adb")
    command = [adb]
    if serial:
        command += ["-s", serial]
    command += ["shell", "am", "broadcast", "-a", SWEEP_ACTION, "-n", SWEEP_RECEIVER]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def sweep_logcat_command(serial: str | None) -> list[str]:
    adb = os.environ.get("ADB_BIN", "adb")
    # A single "TAG:I" entry is deliberate: logcat's filterspec keeps only one
    # priority per tag, and I is the lowest (most inclusive) level PurrView's
    # native code logs at, so it alone passes I/W/E/F lines for this tag.
    # Listing the same tag more than once at different levels silently drops
    # all but one of them instead of merging - that previously hid every
    # INFO-level "native result: ACCEPTED" line behind an effective E-only
    # filter.
    return [adb] + (["-s", serial] if serial else []) + [
        "logcat", "-d", "-v", "brief", "-s", "PurrView/PNG:I", "*:S",
    ]


def clear_sweep_log(serial: str | None) -> None:
    adb = os.environ.get("ADB_BIN", "adb")
    command = [adb] + (["-s", serial] if serial else []) + ["logcat", "-c"]
    subprocess.run(command, check=True)


def poll_sweep_outcome(serial: str | None, timeout: float, poll_interval: float = 0.25) -> tuple[str, str | None]:
    """Classify one sweep iteration by repeatedly dump-snapshotting logcat.

    A device crash never returns from decodePng() (the native call raises
    SIGABRT before the JNI boundary is unwound), so the OOB_WRITE marker is
    matched from the PNG_LOGE line that precedes the abort, not from a result
    line - there is none for that path. A dump-and-exit snapshot (``-d``) is
    used instead of a persistent streamed ``adb logcat`` process because adb
    fully buffers its own stdout when it is not a terminal, so a handful of
    lines can sit unflushed in a pipe well past any reasonable per-iteration
    timeout; each snapshot always flushes on exit.
    """
    command = sweep_logcat_command(serial)
    deadline = time.monotonic() + timeout
    while True:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            for pattern, outcome in SWEEP_OUTCOME_PATTERNS:
                if pattern.search(line):
                    return outcome, line.strip()
        if time.monotonic() >= deadline:
            return "TIMEOUT", None
        time.sleep(poll_interval)


def run_sweep(args: argparse.Namespace) -> int:
    if args.kind != "png":
        print("[ai_mutate] --sweep currently supports --kind png only (matches AiSweepReceiver)", file=sys.stderr)
        return 2
    try:
        profile = resolve_profile(args, live=True)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"[ai_mutate] invalid --profile: {error}", file=sys.stderr)
        return 2

    sweep_dir = DEFAULT_OUTPUT / "sweep" / time.strftime("%Y%m%d-%H%M%S")
    sweep_dir.mkdir(parents=True, exist_ok=True)
    print(f"[ai_mutate] sweep of {args.sweep} live recipe(s) against a real device; "
          f"artifacts under {sweep_dir}")

    tally: dict[str, int] = {"CONTROL": 0, "OOB_WRITE": 0, "REJECTED": 0, "TIMEOUT": 0}
    history: list[dict[str, Any]] = []
    previous_data: bytes | None = None
    interrupted = False
    try:
        for i in range(1, args.sweep + 1):
            avoid = ""
            if history:
                recent = [entry["recipe"] for entry in history[-5:]]
                avoid = (" Earlier recipes already tried this sweep, avoid repeating any of "
                         f"them exactly: {json.dumps(recent, sort_keys=True)}")

            recipe: Mapping[str, Any] | None = None
            source = "deterministic-fallback"
            model_used: str | None = None
            if not args.offline:
                recipe, source, model_used = resolve_recipe(
                    "png", args.sweep_target, profile, args,
                    extra_prompt=avoid, ollama_seed=1000 + i, temperature=0.9,
                )
            if recipe is None:
                base = dict(fallback_recipe("png", "oob" if args.sweep_target == "oob" else "control"))
                base["seed"] = (base["seed"] + i) & 0xFF
                recipe = validate_recipe(base, "png", args.sweep_target)
                source = "deterministic-fallback"
                model_used = None

            data = build_png(recipe)
            if previous_data is not None and data == previous_data:
                try:
                    varied = validate_recipe(force_visible_variation(recipe, "png"), "png", args.sweep_target)
                    varied_data = build_png(varied)
                    if varied_data != data:
                        recipe, data = varied, varied_data
                        source += "+guarded-variation"
                except RecipeError:
                    pass

            fixture_path = sweep_dir / f"{i:03d}.png"
            fixture_path.write_bytes(data)
            expected = expected_outcome(recipe)

            try:
                clear_sweep_log(args.serial)
                push_to_device(fixture_path, args.serial, "purrview-ai.png")
                trigger_sweep_worker(args.serial)
                outcome, evidence = poll_sweep_outcome(args.serial, args.sweep_timeout)
            except (OSError, subprocess.CalledProcessError) as error:
                outcome, evidence = "TIMEOUT", f"adb error: {error}"

            tally[outcome] = tally.get(outcome, 0) + 1
            entry = {
                "iteration": i,
                "source": source,
                "model": model_used,
                "recipe": recipe,
                "expected": expected,
                "outcome": outcome,
                "evidence": evidence,
                "fixture": {"path": str(fixture_path.resolve()), "sha256": hashlib.sha256(data).hexdigest()},
            }
            history.append(entry)
            (sweep_dir / f"{i:03d}.png.json").write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            marker = "!!" if outcome == "OOB_WRITE" else ".."
            print(f"[sweep {i}/{args.sweep}] {marker} {source} model={model_used or '-'} "
                  f"recipe={json.dumps(recipe, sort_keys=True)} -> {outcome}")
            if evidence:
                print(f"             {evidence}")
            print(f"             tally: CONTROL={tally['CONTROL']} OOB_WRITE={tally['OOB_WRITE']} "
                  f"REJECTED={tally['REJECTED']} TIMEOUT={tally['TIMEOUT']}")

            previous_data = data
            if i < args.sweep:
                time.sleep(args.sweep_delay)
    except KeyboardInterrupt:
        interrupted = True
        print("[ai_mutate] sweep interrupted by user", file=sys.stderr)

    summary = {"requested": args.sweep, "completed": len(history), "interrupted": interrupted, "tally": tally, "history": history}
    summary_path = sweep_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[ai_mutate] sweep done: {len(history)}/{args.sweep} run, "
          f"CONTROL={tally['CONTROL']} OOB_WRITE={tally['OOB_WRITE']} "
          f"REJECTED={tally['REJECTED']} TIMEOUT={tally['TIMEOUT']}")
    print(f"[ai_mutate] summary: {summary_path.resolve()}")
    return 0


def png_actual_bytes(width: int, height: int) -> int:
    return 4 * width * height


def png_predicted_outcome(width: int, height: int) -> str:
    """Replicate parser.c's inspect_png() branch selection exactly (fixed=0).

    Mirrors: checked = (uint16_t)actual; accepted = checked<=32768;
    bypass = accepted && actual>32768. build_png() always attaches a pCAT
    payload of exactly `actual` bytes, so the C code's extra
    `purr_payload_len >= actual` guard on the bypass branch is always
    satisfied here and is not modelled separately.
    """
    actual = png_actual_bytes(width, height)
    checked = actual & 0xFFFF
    accepted = checked <= 32768
    bypass = accepted and actual > 32768
    if bypass:
        return "OOB_WRITE"
    if accepted:
        return "CONTROL"
    return "REJECTED"


def density_fixture_overhead(width: int) -> int:
    """Bytes of constant PNG framing around the pCAT payload for this width.

    Only the pCAT chunk's payload length scales with `actual` (= height);
    the signature, IHDR, IDAT and IEND chunks do not, so this is the same
    for every height at a fixed width.
    """
    probe = build_png({
        "kind": "png", "width": width, "height": 1, "channels": 4,
        "bit_depth": 8, "pattern": "zero", "seed": 0, "crc": "valid",
    })
    return len(probe) - png_actual_bytes(width, 1)


def density_height_range(width: int) -> tuple[int, int]:
    """The [1, h_max] band of heights whose fixture stays within MAX_FIXTURE."""
    overhead = density_fixture_overhead(width)
    h_max = (MAX_FIXTURE - overhead) // (4 * width)
    return 1, max(h_max, 1)


def density_exact_probability(width: int, h_lo: int, h_hi: int) -> dict[str, Any]:
    """Exact outcome distribution for a height drawn uniformly from
    [h_lo, h_hi]. The range is always small enough (MAX_FIXTURE-bounded)
    that every height is enumerated directly - this is an exact rational
    count, not a Monte Carlo estimate.
    """
    counts = {"OOB_WRITE": 0, "CONTROL": 0, "REJECTED": 0}
    for h in range(h_lo, h_hi + 1):
        counts[png_predicted_outcome(width, h)] += 1
    total = h_hi - h_lo + 1
    return {
        "width": width,
        "height_range": [h_lo, h_hi],
        "total_heights": total,
        "counts": counts,
        "p_oob_write": Fraction(counts["OOB_WRITE"], total),
    }


def prompt_for_height(
    width: int, h_lo: int, h_hi: int, profile: Mapping[str, Any], extra: str, example_height: int,
) -> str:
    # example_height is deliberately re-randomized on every call: an earlier
    # version hardcoded the schema's example to (h_lo+h_hi)//2, which for
    # width=128's range happened to equal 128 - the model then copied that
    # literal example instead of sampling, picking height=128 on every
    # single call regardless of temperature or the anti-repeat instruction.
    # A fixed illustrative number in a schema is itself an anchor.
    return (
        "You are choosing one PNG height for a bounded memory-safety test "
        f"fixture. Return JSON only, matching this schema (the number below "
        f"is only illustrating the shape, not a suggested value - do not "
        f"reuse it): "
        f'{{"height":{example_height}}} '
        f"The width is fixed at {width} and is not yours to choose. Pick a "
        f"single integer height, chosen as if uniformly at random, from the "
        f"inclusive range {h_lo}..{h_hi} - avoid gravitating to round "
        f"numbers, the midpoint, or the width's own value ({width}). "
        "Do not output C, assembly, shellcode, ROP, syscalls, commands, "
        "URLs, file paths, network actions, or executable content. "
        f"Device profile (informational only): {json.dumps(profile, sort_keys=True)}"
        f"{extra}"
    )


def resolve_height(
    width: int, h_lo: int, h_hi: int, profile: Mapping[str, Any], args: argparse.Namespace,
    extra_prompt: str, ollama_seed: int, rng: random.Random,
) -> tuple[int | None, str, str | None]:
    """Same remote-then-local Ollama order as resolve_recipe(), but for the
    density mode's much smaller {"height": int} schema."""
    # A fresh decoy example each call, well clear of both the width value and
    # the range midpoint, so the schema's illustrative number never becomes
    # a repeatable anchor by accident.
    example_height = rng.randint(h_lo, h_hi)
    while example_height in (width, (h_lo + h_hi) // 2):
        example_height = rng.randint(h_lo, h_hi)
    prompt = prompt_for_height(width, h_lo, h_hi, profile, extra_prompt, example_height)
    stages: list[tuple[str, str]] = []
    if not args.no_remote:
        stages.append(("ollama-remote", args.remote_model))
    stages.append(("ollama-local", args.local_model))
    for source, model in stages:
        try:
            if source == "ollama-remote":
                bind_host = args.remote_bind_host or default_remote_bind_host(args.remote_ssh)
                with ssh_tunnel(args.remote_ssh, bind_host, args.remote_port, args.tunnel_port, args.ssh_timeout):
                    raw = call_ollama(
                        f"http://127.0.0.1:{args.tunnel_port}", model, prompt, args.timeout,
                        temperature=1.1, seed=ollama_seed,
                    )
            else:
                raw = call_ollama(
                    args.local_endpoint, model, prompt, args.timeout,
                    temperature=1.1, seed=ollama_seed,
                )
            if not isinstance(raw, Mapping) or set(raw) - {"height"}:
                raise RecipeError("model response must be a JSON object with only a 'height' field")
            height = raw.get("height")
            if isinstance(height, bool) or not isinstance(height, int) or not h_lo <= height <= h_hi:
                raise RecipeError(f"height must be an integer in {h_lo}..{h_hi}")
            return height, source, model
        except (RuntimeError, RecipeError) as error:
            print(f"[ai_mutate] {source} ({model}) failed: {error}", file=sys.stderr)
    return None, "deterministic-fallback", None


def run_density(args: argparse.Namespace) -> int:
    """Bypass-density mode: derive the exact P(OOB_WRITE) for height drawn
    uniformly at a fixed width, then validate it against N live draws on the
    real device, alternating between a true-uniform-random arm and an
    Ollama-chosen arm so the two empirical rates can be compared.
    """
    width = args.density_width
    h_lo, h_hi = density_height_range(width)
    model_stats = density_exact_probability(width, h_lo, h_hi)
    period = 65536 // (4 * width) if (4 * width) <= 65536 else None
    p = model_stats["p_oob_write"]

    density_dir = DEFAULT_OUTPUT / "density" / time.strftime("%Y%m%d-%H%M%S")
    density_dir.mkdir(parents=True, exist_ok=True)

    print(f"[ai_mutate] bypass-density model: width={width} (fixed), height in "
          f"[{h_lo},{h_hi}] ({model_stats['total_heights']} values"
          + (f", period={period}" if period else "") + ")")
    print(f"[ai_mutate] exact P(OOB_WRITE) = {model_stats['counts']['OOB_WRITE']}/"
          f"{model_stats['total_heights']} = {p} ~= {float(p):.4f}")
    print(f"[ai_mutate] exact breakdown: CONTROL={model_stats['counts']['CONTROL']} "
          f"OOB_WRITE={model_stats['counts']['OOB_WRITE']} REJECTED={model_stats['counts']['REJECTED']}")
    print(f"[ai_mutate] artifacts under {density_dir}")

    try:
        profile = resolve_profile(args, live=True)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"[ai_mutate] invalid --profile: {error}", file=sys.stderr)
        return 2

    arm_state = {
        "uniform": {"draws": 0, "observed_oob": 0},
        "ollama": {"draws": 0, "observed_oob": 0},
    }
    history: list[dict[str, Any]] = []
    interrupted = False
    rng = random.Random()

    try:
        for i in range(1, args.density + 1):
            if args.density_source == "alternate":
                arm = "uniform" if i % 2 == 1 else "ollama"
            else:
                arm = args.density_source

            model_used: str | None = None
            if arm == "uniform":
                height = rng.randint(h_lo, h_hi)
                source = "uniform-random"
            else:
                avoid = ""
                recent = [entry["height"] for entry in history if entry["arm"] == "ollama"][-5:]
                if recent:
                    avoid = f" Heights already tried this run, avoid repeating: {recent}"
                height, source, model_used = resolve_height(
                    width, h_lo, h_hi, profile, args, avoid, ollama_seed=3000 + i, rng=rng,
                )
                if height is None:
                    height = rng.randint(h_lo, h_hi)
                    source = "deterministic-fallback"

            predicted = png_predicted_outcome(width, height)
            state = arm_state[arm]
            expected_before = state["draws"] * float(p)

            recipe = {
                "kind": "png", "width": width, "height": height, "channels": 4,
                "bit_depth": 8, "pattern": "affine", "seed": (i * 7) & 0xFF, "crc": "valid",
            }
            data = build_png(recipe)
            fixture_path = density_dir / f"{i:03d}.png"
            fixture_path.write_bytes(data)

            print(f"[density {i}/{args.density}] arm={arm} source={source} model={model_used or '-'} "
                  f"height={height} actual={png_actual_bytes(width, height)} predicted={predicted}")
            print(f"             E[OOB_WRITE so far | arm={arm}] = {state['draws']} * {float(p):.4f} "
                  f"= {expected_before:.2f}; observed so far = {state['observed_oob']}")

            try:
                clear_sweep_log(args.serial)
                push_to_device(fixture_path, args.serial, "purrview-ai.png")
                trigger_sweep_worker(args.serial)
                outcome, evidence = poll_sweep_outcome(args.serial, args.density_timeout)
            except (OSError, subprocess.CalledProcessError) as error:
                outcome, evidence = "TIMEOUT", f"adb error: {error}"

            if outcome == predicted:
                match = "MATCH"
            elif outcome == "TIMEOUT":
                match = "TIMEOUT"
            else:
                match = "MISMATCH"
            print(f"             device: {outcome}{' | ' + evidence if evidence else ''}  [{match} vs predicted]")

            state["draws"] += 1
            if outcome == "OOB_WRITE":
                state["observed_oob"] += 1

            entry = {
                "iteration": i, "arm": arm, "source": source, "model": model_used,
                "width": width, "height": height, "predicted": predicted, "outcome": outcome,
                "match": match, "evidence": evidence,
                "fixture": {"path": str(fixture_path.resolve()), "sha256": hashlib.sha256(data).hexdigest()},
            }
            history.append(entry)
            (density_dir / f"{i:03d}.png.json").write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            if i < args.density:
                time.sleep(args.density_delay)
    except KeyboardInterrupt:
        interrupted = True
        print("[ai_mutate] density run interrupted by user", file=sys.stderr)

    for arm, state in arm_state.items():
        if state["draws"] == 0:
            continue
        rate = state["observed_oob"] / state["draws"]
        print(f"[ai_mutate] arm={arm}: {state['observed_oob']}/{state['draws']} OOB_WRITE "
              f"(empirical rate={rate:.4f}) vs exact model p={float(p):.4f}")

    mismatches = sum(1 for entry in history if entry["match"] == "MISMATCH")
    summary = {
        "requested": args.density, "completed": len(history), "interrupted": interrupted,
        "width": width, "height_range": [h_lo, h_hi],
        "exact_model": {
            "p_oob_write_fraction": str(p), "p_oob_write_float": float(p),
            "counts": model_stats["counts"], "total_heights": model_stats["total_heights"],
        },
        "arms": arm_state, "model_mismatches": mismatches, "history": history,
    }
    summary_path = density_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[ai_mutate] density run done: {len(history)}/{args.density} run, "
          f"{mismatches} model mismatch(es) against the real device (excluding timeouts)")
    print(f"[ai_mutate] summary: {summary_path.resolve()}")
    return 0


def parse_profile(value: str) -> Mapping[str, Any]:
    path = Path(value)
    text = path.read_text(encoding="utf-8") if path.is_file() else value
    parsed = json.loads(text)
    if not isinstance(parsed, Mapping):
        raise ValueError("profile must be a JSON object")
    return parsed


def fetch_device_profile(serial: str | None, timeout: float = 2.0) -> Mapping[str, Any] | None:
    """Best-effort live recon via the standalone ReconCat app (see recon/).

    Never raises: returns None if ReconCat is not installed, no device is
    reachable, or nothing shows up in logcat in time, so callers fall back
    to DEFAULT_PROFILE. This deliberately does not touch lab.purrview - that
    app is the demo's vulnerable target, not the attacker's recon tool.
    """
    adb = os.environ.get("ADB_BIN", "adb")
    command = [adb] + (["-s", serial] if serial else [])
    try:
        subprocess.run(command + ["logcat", "-c"], check=True, timeout=5)
        subprocess.run(
            command + ["shell", "am", "broadcast", "-a", RECON_ACTION, "-n", RECON_RECEIVER],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None

    deadline = time.monotonic() + timeout
    while True:
        try:
            result = subprocess.run(
                command + ["logcat", "-d", "-v", "brief", "-s", "ReconCat:I", "*:S"],
                capture_output=True, text=True, check=True, timeout=5,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None
        for line in result.stdout.splitlines():
            match = RECON_LOG_PATTERN.search(line)
            if not match:
                continue
            try:
                parsed = json.loads(match.group(1))
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, Mapping):
                return parsed
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.2)


def resolve_profile(args: argparse.Namespace, live: bool) -> Mapping[str, Any]:
    """--profile if the user set one, else live ReconCat recon, else the static default."""
    if args.profile is not None:
        return parse_profile(args.profile)
    if live:
        fetched = fetch_device_profile(args.serial)
        if fetched is not None:
            print(f"[ai_mutate] profile: live recon from ReconCat ({args.serial or 'default adb target'})",
                  file=sys.stderr)
            return fetched
        print("[ai_mutate] profile: ReconCat unavailable, using static placeholder", file=sys.stderr)
    return dict(DEFAULT_PROFILE)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("png", "pdu"), default="png")
    parser.add_argument("--target", choices=("oob", "control", "any", "rw"), default="oob",
                         help="'rw' is PNG-only: a controlled read/write primitive into "
                              "PurrView's own companion buffer instead of the OOB-write crash "
                              "(see parser.c's inspect_png_rw/inspect_png_rw_file)")
    parser.add_argument("--remote-ssh", default=DEFAULT_REMOTE_SSH, help="SSH target (user@host) for the primary Ollama instance")
    parser.add_argument("--remote-bind-host", default=None, help="address Ollama is bound to on the remote host (default: derived from --remote-ssh)")
    parser.add_argument("--remote-port", type=int, default=DEFAULT_REMOTE_PORT, help="Ollama port on the remote host")
    parser.add_argument("--remote-model", default=DEFAULT_REMOTE_MODEL)
    parser.add_argument("--tunnel-port", type=int, default=DEFAULT_TUNNEL_PORT, help="local port used for the SSH tunnel")
    parser.add_argument("--ssh-timeout", type=float, default=6.0, help="seconds to wait for the SSH tunnel to come up")
    parser.add_argument("--no-remote", action="store_true", help="skip the remote Ollama instance; go straight to --local-endpoint")
    parser.add_argument("--local-endpoint", default=DEFAULT_LOCAL_ENDPOINT, help="fallback Ollama base URL")
    parser.add_argument("--local-model", default=DEFAULT_LOCAL_MODEL)
    parser.add_argument("--profile", default=None,
                         help="device profile JSON (or path to one) fed to the model as context; default: "
                              "live recon from the separate ReconCat app (see recon/) when a device round-trip "
                              "is already happening (--sweep, --density, --adb-push), else a static placeholder")
    parser.add_argument("--output", type=Path, help="fixture path (default: build/ai-mutation/purrview-ai.<ext>)")
    parser.add_argument("--baseline", type=Path, help="optional baseline fixture for byte diff")
    parser.add_argument("--timeout", type=float, default=60.0, help="per-request Ollama call timeout; a cold model load can take ~50s on either host")
    parser.add_argument("--offline", action="store_true", help="use deterministic recipe without calling Ollama")
    parser.add_argument("--no-fallback", action="store_true", help="fail if Ollama or recipe validation fails")
    parser.add_argument("--adb-push", action="store_true", help="copy output into PurrView private files on a debug device")
    parser.add_argument("--serial", help="adb device serial")
    parser.add_argument("--sweep", type=int, default=0, metavar="N",
                         help="run N live recipes against a real device via AiSweepReceiver instead of "
                              "the single-shot flow; each is pushed, triggered and classified from logcat "
                              "as CONTROL/OOB_WRITE/REJECTED/TIMEOUT")
    parser.add_argument("--sweep-target", choices=("any", "oob", "control"), default="any",
                         help="constrain sweep recipes to one outcome, or let the model land on either (default)")
    parser.add_argument("--sweep-delay", type=float, default=1.5, help="seconds to pause between sweep iterations")
    parser.add_argument("--sweep-timeout", type=float, default=4.0,
                         help="seconds to wait for a sweep iteration's outcome in logcat before marking it TIMEOUT")
    parser.add_argument("--density", type=int, default=0, metavar="N",
                         help="run N live height draws at a fixed width against a real device instead of "
                              "the single-shot flow, to validate the parser's exact bypass-probability model "
                              "(see run_density); alternates a true-uniform-random arm with an Ollama-chosen arm")
    parser.add_argument("--density-width", type=int, default=128,
                         help="fixed PNG width for --density (height is the only free variable)")
    parser.add_argument("--density-source", choices=("alternate", "uniform", "ollama"), default="alternate",
                         help="which arm every --density draw uses (default: alternate odd/even iterations)")
    parser.add_argument("--density-delay", type=float, default=1.0, help="seconds to pause between density iterations")
    parser.add_argument("--density-timeout", type=float, default=4.0,
                         help="seconds to wait for a density iteration's outcome in logcat before marking it TIMEOUT")
    args = parser.parse_args(argv)
    if args.adb_push and args.kind != "png":
        parser.error("--adb-push currently supports the PurrView PNG worker only")
    if args.target == "rw" and args.kind != "png":
        parser.error("--target rw is PNG-only (--kind png)")
    if args.sweep > 0:
        return run_sweep(args)
    if args.density > 0:
        return run_density(args)

    try:
        profile = resolve_profile(args, live=args.adb_push)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(f"invalid --profile: {error}")

    recipe: Mapping[str, Any] | None = None
    source = "deterministic-fallback"
    model_used: str | None = None
    if not args.offline:
        recipe, source, model_used = resolve_recipe(args.kind, args.target, profile, args)
        if recipe is None:
            print("[ai_mutate] no Ollama instance produced a valid recipe; using deterministic fallback", file=sys.stderr)
            if args.no_fallback:
                return 2

    if recipe is None:
        recipe = validate_recipe(fallback_recipe(args.kind, args.target), args.kind, args.target)
        source = "deterministic-fallback"
        model_used = None

    baseline_path = args.baseline
    if baseline_path is None and args.target != "rw":
        default_baseline = ROOT / "app/src/main/assets" / ("purrview-oob.png" if args.kind == "png" else "purrview-pdu.bin")
        baseline_path = default_baseline if default_baseline.exists() else None
    baseline = baseline_path.read_bytes() if baseline_path and baseline_path.exists() else None
    data = build_png(recipe) if args.kind == "png" else build_pdu(recipe)
    if baseline is not None and data == baseline and args.target != "rw":
        recipe = validate_recipe(force_visible_variation(recipe, args.kind), args.kind, args.target)
        data = build_png(recipe) if args.kind == "png" else build_pdu(recipe)
        source += "+guarded-variation"
    extension = "png" if args.kind == "png" else "bin"
    output = args.output or (DEFAULT_OUTPUT / (f"purrview-rw.{extension}" if args.target == "rw" else f"purrview-ai.{extension}"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    manifest = {
        "source": source,
        "model": model_used,
        "kind": args.kind,
        "target": args.target,
        "profile": profile,
        "recipe": recipe,
        "expected": expected_outcome(recipe),
        "fixture": {"path": str(output.resolve()), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        "diff": binary_diff(baseline, data),
    }
    manifest_path = output.with_suffix(output.suffix + ".json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    if args.adb_push:
        private_name = "purrview-rw.png" if args.target == "rw" else "purrview-ai.png"
        try:
            push_to_device(output, args.serial, private_name)
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"[ai_mutate] adb push failed: {error}", file=sys.stderr)
            return 3
        print(f"ADB: copied to lab.purrview/files/{private_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
