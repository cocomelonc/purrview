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
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zlib
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

# These values are deliberately small.  They are enough to exercise the
# PurrView parser's integer-narrowing paths without becoming a general fuzzer.
PNG_DIMENSIONS = ((64, 64), (128, 64), (128, 128), (256, 64))
PNG_PATTERNS = ("affine", "alternating", "zero")
PDU_LENGTHS = (32, 128, 256, 512, 1024)
PDU_PATTERNS = PNG_PATTERNS
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
    actual = width * height * 4
    payload = pattern_bytes(actual, recipe["pattern"], recipe["seed"])
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
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
    if recipe["kind"] == "png":
        actual = recipe["width"] * recipe["height"] * recipe["channels"]
        checked = actual & 0xFFFF
        return "OOB_WRITE" if actual > 32768 and checked <= 32768 else "CONTROL"
    declared = recipe["declared_length"]
    return "OOB_WRITE" if declared > 255 else "CONTROL"


def fallback_recipe(kind: str, target: str) -> dict[str, Any]:
    if kind == "png":
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


def validate_recipe(candidate: Mapping[str, Any], kind: str, target: str) -> dict[str, Any]:
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


def prompt_for(kind: str, target: str, profile: Mapping[str, Any]) -> str:
    schema = (
        '{"kind":"png","width":128,"height":128,"channels":4,'
        '"bit_depth":8,"pattern":"affine","seed":3,"crc":"valid"}'
        if kind == "png"
        else '{"kind":"pdu","declared_length":256,"pattern":"affine","seed":11}'
    )
    return (
        "You are a bounded test-case planner for the offline PurrView Android "
        "memory-safety lab. Return JSON only, matching this schema exactly: "
        f"{schema} "
        f"Choose target={target!r} for parser kind={kind!r}. "
        "The allow-list is the only authority: PNG dimensions are "
        "64x64, 128x64, 128x128, or 256x64; channels=4; bit_depth=8; "
        "PDU lengths are 32, 128, 256, 512, or 1024; patterns are "
        "affine, alternating, or zero; seed is 0..255; crc must be valid. "
        "Do not output C, assembly, shellcode, ROP, syscalls, commands, "
        "URLs, file paths, network actions, or executable content. "
        f"Device profile (informational only): {json.dumps(profile, sort_keys=True)}"
    )


def call_ollama(endpoint: str, model: str, prompt: str, timeout: float) -> Mapping[str, Any]:
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Return one bounded JSON recipe and nothing else."},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0, "seed": 42},
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
) -> tuple[Mapping[str, Any] | None, str, str | None]:
    """Try the remote Ollama over SSH, then local Ollama, in that order."""
    prompt = prompt_for(kind, target, profile)
    stages: list[tuple[str, str]] = []
    if not args.no_remote:
        stages.append(("ollama-remote", args.remote_model))
    stages.append(("ollama-local", args.local_model))

    for source, model in stages:
        try:
            if source == "ollama-remote":
                bind_host = args.remote_bind_host or default_remote_bind_host(args.remote_ssh)
                with ssh_tunnel(args.remote_ssh, bind_host, args.remote_port, args.tunnel_port, args.ssh_timeout):
                    raw = call_ollama(f"http://127.0.0.1:{args.tunnel_port}", model, prompt, args.timeout)
            else:
                raw = call_ollama(args.local_endpoint, model, prompt, args.timeout)
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


def parse_profile(value: str) -> Mapping[str, Any]:
    path = Path(value)
    text = path.read_text(encoding="utf-8") if path.is_file() else value
    parsed = json.loads(text)
    if not isinstance(parsed, Mapping):
        raise ValueError("profile must be a JSON object")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("png", "pdu"), default="png")
    parser.add_argument("--target", choices=("oob", "control"), default="oob")
    parser.add_argument("--remote-ssh", default=DEFAULT_REMOTE_SSH, help="SSH target (user@host) for the primary Ollama instance")
    parser.add_argument("--remote-bind-host", default=None, help="address Ollama is bound to on the remote host (default: derived from --remote-ssh)")
    parser.add_argument("--remote-port", type=int, default=DEFAULT_REMOTE_PORT, help="Ollama port on the remote host")
    parser.add_argument("--remote-model", default=DEFAULT_REMOTE_MODEL)
    parser.add_argument("--tunnel-port", type=int, default=DEFAULT_TUNNEL_PORT, help="local port used for the SSH tunnel")
    parser.add_argument("--ssh-timeout", type=float, default=6.0, help="seconds to wait for the SSH tunnel to come up")
    parser.add_argument("--no-remote", action="store_true", help="skip the remote Ollama instance; go straight to --local-endpoint")
    parser.add_argument("--local-endpoint", default=DEFAULT_LOCAL_ENDPOINT, help="fallback Ollama base URL")
    parser.add_argument("--local-model", default=DEFAULT_LOCAL_MODEL)
    parser.add_argument("--profile", default='{"device":"Motorola","arch":"arm64","purpose":"PurrView demo"}')
    parser.add_argument("--output", type=Path, help="fixture path (default: build/ai-mutation/purrview-ai.<ext>)")
    parser.add_argument("--baseline", type=Path, help="optional baseline fixture for byte diff")
    parser.add_argument("--timeout", type=float, default=60.0, help="per-request Ollama call timeout; a cold model load can take ~50s on either host")
    parser.add_argument("--offline", action="store_true", help="use deterministic recipe without calling Ollama")
    parser.add_argument("--no-fallback", action="store_true", help="fail if Ollama or recipe validation fails")
    parser.add_argument("--adb-push", action="store_true", help="copy output into PurrView private files on a debug device")
    parser.add_argument("--serial", help="adb device serial")
    args = parser.parse_args(argv)
    if args.adb_push and args.kind != "png":
        parser.error("--adb-push currently supports the PurrView PNG worker only")

    try:
        profile = parse_profile(args.profile)
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
    if baseline_path is None:
        default_baseline = ROOT / "app/src/main/assets" / ("purrview-oob.png" if args.kind == "png" else "purrview-pdu.bin")
        baseline_path = default_baseline if default_baseline.exists() else None
    baseline = baseline_path.read_bytes() if baseline_path and baseline_path.exists() else None
    data = build_png(recipe) if args.kind == "png" else build_pdu(recipe)
    if baseline is not None and data == baseline:
        recipe = validate_recipe(force_visible_variation(recipe, args.kind), args.kind, args.target)
        data = build_png(recipe) if args.kind == "png" else build_pdu(recipe)
        source += "+guarded-variation"
    extension = "png" if args.kind == "png" else "bin"
    output = args.output or (DEFAULT_OUTPUT / f"purrview-ai.{extension}")
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
        try:
            push_to_device(output, args.serial, "purrview-ai.png")
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"[ai_mutate] adb push failed: {error}", file=sys.stderr)
            return 3
        print("ADB: copied to lab.purrview/files/purrview-ai.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
