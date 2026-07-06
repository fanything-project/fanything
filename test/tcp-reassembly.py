#!/usr/bin/env python3
"""Exercise passive TCP stream reassembly with split TLS records."""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fanfp


def tls_client_hello() -> bytes:
    body = (
        struct.pack("!H", 0x0303)
        + (b"\x00" * 32)
        + b"\x00"
        + struct.pack("!H", 2)
        + struct.pack("!H", 0x1301)
        + b"\x01\x00"
        + struct.pack("!H", 0)
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def tcp_frame(payload: bytes, seq: int) -> bytes:
    src = bytes([192, 0, 2, 10])
    dst = bytes([198, 51, 100, 20])
    total_len = 20 + 20 + len(payload)
    eth = (b"\x00" * 6) + (b"\x01" * 6) + b"\x08\x00"
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        1,
        0x4000,
        64,
        6,
        0,
        src,
        dst,
    )
    tcp = struct.pack("!HHIIBBHHH", 51514, 443, seq, 0, 5 << 4, 0x18, 65535, 0, 0)
    return eth + ip + tcp + payload


def write_pcap(path: Path, frames: list[bytes]) -> None:
    data = bytearray()
    data += struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        data += struct.pack("<IIII", index, 0, len(frame), len(frame))
        data += frame
    path.write_bytes(data)


def assert_split_tls_detected(frames: list[bytes]) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "split-tls.pcap"
        write_pcap(path, frames)
        records = list(fanfp.extract(path))
    tls_records = [
        record
        for record in records
        if record["protocol"] == "tls" and record["role"] == "client"
    ]
    assert len(tls_records) == 1, records
    assert tls_records[0]["features"].startswith("tls|client|v=771|c=4865|"), tls_records[0]


def main() -> int:
    record = tls_client_hello()
    first = record[:9]
    second = record[9:]
    base_seq = 1000

    assert_split_tls_detected([
        tcp_frame(first, base_seq),
        tcp_frame(second, base_seq + len(first)),
    ])
    assert_split_tls_detected([
        tcp_frame(second, base_seq + len(first)),
        tcp_frame(first, base_seq),
    ])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
