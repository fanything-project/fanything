#!/usr/bin/env python3
"""Exercise IPv6 extension-header walking for TCP and UDP parsing."""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fanfp


SRC = bytes.fromhex("20010db8000000000000000000000001")
DST = bytes.fromhex("20010db8000000000000000000000002")


def tcp_syn() -> bytes:
    return struct.pack("!HHIIBBHHH", 51514, 443, 1000, 0, 5 << 4, 0x02, 65535, 0, 0)


def udp_datagram(payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", 50000, 500, length, 0) + payload


def ipv6_frame(next_header: int, transport: bytes) -> bytes:
    hop_by_hop = bytes([next_header, 0]) + (b"\x00" * 6)
    payload = hop_by_hop + transport
    eth = (b"\x00" * 6) + (b"\x01" * 6) + b"\x86\xdd"
    ip = struct.pack("!IHBB16s16s", 6 << 28, len(payload), 0, 64, SRC, DST)
    return eth + ip + payload


def write_pcap(path: Path, frames: list[bytes]) -> None:
    data = bytearray()
    data += struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        data += struct.pack("<IIII", index, 0, len(frame), len(frame))
        data += frame
    path.write_bytes(data)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "ipv6-ext.pcap"
        write_pcap(
            path,
            [
                ipv6_frame(6, tcp_syn()),
                ipv6_frame(17, udp_datagram(b"\x00" * 28)),
            ],
        )
        records = list(fanfp.extract(path))

    tcpip_records = [
        record
        for record in records
        if record["protocol"] == "tcpip" and record["role"] == "client"
    ]
    ike_records = [record for record in records if record["protocol"] == "ike"]

    assert len(tcpip_records) == 1, records
    assert tcpip_records[0]["features"].startswith("tcpip2|client|ip=6|"), tcpip_records[0]
    assert len(ike_records) == 0, records
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
