#!/usr/bin/env python3
"""Generate the checked-in PNG fixtures used by the PurrView parser demo."""
import struct
import zlib
from pathlib import Path

def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))

def png(w, h):
    pixels = b''.join(b'\0' + bytes((155, 113, 210, 255)) * w for _ in range(h))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(pixels)) + chunk(b'IEND', b''))

def purrview_oob_png():
    """Create a valid PNG envelope with an inert 64 KiB pCAT test chunk.

    The PurrView parser deliberately treats this ancillary chunk as the copy
    source for its vulnerable demo path. It contains no code or executable
    content; the bytes are deterministic test data.
    """
    payload = bytes((i * 17 + 3) & 0xff for i in range(128 * 128 * 4))
    header = struct.pack('>IIBBBBB', 128, 128, 8, 6, 0, 0, 0)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header)
            + chunk(b'IDAT', zlib.compress(b''))
            + chunk(b'pCAT', payload) + chunk(b'IEND', b''))

def purrview_pdu():
    """Create a local PurrView PDU fixture with a 16-bit text length."""
    payload = bytes((i * 29 + 11) & 0xff for i in range(256))
    return b'PMS1' + struct.pack('>H', len(payload)) + payload

if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1] / 'app/src/main/assets'
    root.mkdir(parents=True, exist_ok=True)
    root.joinpath('normal.png').write_bytes(png(64, 64))
    root.joinpath('crafted.png').write_bytes(png(256, 64))
    broken = bytearray(png(256, 64)); broken[29] ^= 1
    root.joinpath('broken-crc.png').write_bytes(broken)
    root.joinpath('purrview-oob.png').write_bytes(purrview_oob_png())
    root.joinpath('purrview-pdu.bin').write_bytes(purrview_pdu())
