#!/usr/bin/env python3
"""Exercise non-Ethernet pcap linktype dispatch."""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fanfp


def ipv4_tcp_syn() -> bytes:
    src = bytes([192, 0, 2, 10])
    dst = bytes([198, 51, 100, 20])
    tcp = struct.pack("!HHIIBBHHH", 51514, 443, 1000, 0, 5 << 4, 0x02, 65535, 0, 0)
    total_len = 20 + len(tcp)
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
    return ip + tcp


def linux_sll_frame(payload: bytes) -> bytes:
    return struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800) + payload


def loopback_frame(payload: bytes) -> bytes:
    return struct.pack("<I", 2) + payload


def write_pcap(path: Path, linktype: int, frames: list[bytes]) -> None:
    data = bytearray()
    data += struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for index, frame in enumerate(frames):
        data += struct.pack("<IIII", index, 0, len(frame), len(frame))
        data += frame
    path.write_bytes(data)


def pcapng_block(block_type: int, body: bytes) -> bytes:
    padded = body + (b"\x00" * ((4 - len(body) % 4) % 4))
    total_len = 12 + len(padded)
    return struct.pack("<II", block_type, total_len) + padded + struct.pack("<I", total_len)


def write_pcapng(path: Path, linktype: int, frame: bytes) -> None:
    shb = pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = pcapng_block(1, struct.pack("<HHI", linktype, 0, 65535))
    epb_body = struct.pack("<IIIII", 0, 0, 0, len(frame), len(frame)) + frame
    epb = pcapng_block(6, epb_body)
    path.write_bytes(shb + idb + epb)


def assert_tcpip_detected(linktype: int, frame: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "capture.pcap"
        write_pcap(path, linktype, [frame])
        records = list(fanfp.extract(path))
    tcpip_records = [
        record
        for record in records
        if record["protocol"] == "tcpip" and record["role"] == "client"
    ]
    assert len(tcpip_records) == 1, records
    assert tcpip_records[0]["features"].startswith("tcpip2|client|ip=4|"), tcpip_records[0]


def assert_pcapng_tcpip_detected(linktype: int, frame: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "capture.pcapng"
        write_pcapng(path, linktype, frame)
        records = list(fanfp.extract(path))
    tcpip_records = [
        record
        for record in records
        if record["protocol"] == "tcpip" and record["role"] == "client"
    ]
    assert len(tcpip_records) == 1, records


def main() -> int:
    packet = ipv4_tcp_syn()
    assert_tcpip_detected(fanfp.DLT_RAW, packet)
    assert_tcpip_detected(fanfp.DLT_LINUX_SLL, linux_sll_frame(packet))
    assert_tcpip_detected(fanfp.DLT_NULL, loopback_frame(packet))
    assert_pcapng_tcpip_detected(fanfp.DLT_RAW, packet)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
