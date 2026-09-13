#!/usr/bin/env python3
"""Create local PNG fixtures for PurrView's intentional size-validation bug.

Default: a valid 256x64 RGBA8 PNG requiring 65536 decoded bytes. PurrView's
buggy uint16 policy sees zero; its fixed policy rejects the 32768-byte overrun.
This does not target Android's system decoder or embed executable code.
"""

import argparse
from pathlib import Path

from tools.generate_samples import png


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", type=Path, default=Path(__file__).resolve().with_name("crafted.png"))
    parser.add_argument("--mode", choices=("bypass", "normal", "bad-crc"), default="bypass")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing output file")
    args = parser.parse_args()

    width, height = (64, 64) if args.mode == "normal" else (256, 64)
    data = bytearray(png(width, height))
    if args.mode == "bad-crc":
        data[29] ^= 1  # Corrupt IHDR CRC, leaving the chunk length untouched.
    try:
        with args.output.open("wb" if args.force else "xb") as output:
            output.write(data)
    except OSError as error:
        parser.exit(1, f"Cannot write {args.output}: {error}\n")

    required = width * height * 4
    print(f"Created: {args.output.resolve()} ({len(data)} bytes on disk)")
    print(f"RGBA8: {width} x {height}; decoded bytes: {required}")
    print(f"Buggy uint16 size: {required % 65536}; PurrView budget: 32768")
    expected = {
        "bypass": "Buggy: BUDGET BYPASS. Fixed: REJECTED. PNG CRC is valid.",
        "normal": "Both modes: ACCEPTED. PNG CRC is valid.",
        "bad-crc": "Both modes: REJECTED (CRC mismatch), before size validation.",
    }
    print(expected[args.mode])
    print("PurrView: Import PNG -> Imported PNG -> Deliver selected attachment.")


if __name__ == "__main__":
    main()
