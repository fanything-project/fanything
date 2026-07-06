#!/usr/bin/env python3
"""Focused parser unit tests for malformed input and capture edge cases."""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fanfp


def assert_raises(exc_type: type[BaseException], func, *args, **kwargs) -> None:
    try:
        func(*args, **kwargs)
    except exc_type:
        return
    raise AssertionError(f"{func.__name__} did not raise {exc_type.__name__}")


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


def tls_server_hello(extension_types: list[int]) -> bytes:
    ext_blob = b"".join(struct.pack("!HH", et, 0) for et in extension_types)
    body = (
        struct.pack("!H", 0x0303)
        + (b"\x00" * 32)
        + b"\x00"
        + struct.pack("!H", 0xC030)
        + b"\x00"
        + len(ext_blob).to_bytes(2, "big")
        + ext_blob
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake

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


def ipv6_with_hop_by_hop(next_header: int, transport: bytes) -> bytes:
    src = bytes.fromhex("20010db8000000000000000000000001")
    dst = bytes.fromhex("20010db8000000000000000000000002")
    hop_by_hop = bytes([next_header, 0]) + (b"\x00" * 6)
    payload = hop_by_hop + transport
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), 0, 64, src, dst) + payload


def pcapng_block(block_type: int, body: bytes) -> bytes:
    padded = body + (b"\x00" * ((4 - len(body) % 4) % 4))
    total_len = 12 + len(padded)
    return struct.pack("<II", block_type, total_len) + padded + struct.pack("<I", total_len)


def write_pcapng_spb(path: Path, linktype: int, frame: bytes) -> None:
    shb = pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = pcapng_block(1, struct.pack("<HHI", linktype, 0, 65535))
    spb = pcapng_block(3, struct.pack("<I", len(frame)) + frame)
    path.write_bytes(shb + idb + spb)


def test_malformed_tls() -> None:
    truncated_record = b"\x16\x03\x01\x00\x10abc"
    assert fanfp.parse_tls_handshake(truncated_record) == []
    assert_raises(ValueError, fanfp.parse_tls_handshake, truncated_record, strict=True)

    truncated_handshake = b"\x16\x03\x01\x00\x04\x01\x00\x00\x20"
    assert fanfp.parse_tls_handshake(truncated_handshake) == []
    assert_raises(ValueError, fanfp.parse_tls_handshake, truncated_handshake, strict=True)


def test_malformed_dtls() -> None:
    truncated_record = b"\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10abc"
    assert fanfp.parse_dtls_handshake(truncated_record) is None
    assert_raises(ValueError, fanfp.parse_dtls_handshake, truncated_record, strict=True)

    truncated_handshake = b"\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x01\x00\x00\x20\x00\x00\x00\x00\x00\x00\x20"
    assert fanfp.parse_dtls_handshake(truncated_handshake) is None
    assert_raises(ValueError, fanfp.parse_dtls_handshake, truncated_handshake, strict=True)


def test_malformed_der() -> None:
    assert_raises(ValueError, fanfp.parse_der_node, b"\x30\x03\x02")
    assert_raises(ValueError, fanfp.parse_x509_certificate_features, b"\x30\x00")


def test_quic_varints() -> None:
    value, offset, size = fanfp.read_quic_varint(b"\x25", 0)
    assert (value, offset, size) == (0x25, 1, 1)
    assert_raises(ValueError, fanfp.read_quic_varint, b"\x40", 0)


def test_pcapng_spb() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "spb.pcapng"
        packet = ipv4_tcp_syn()
        write_pcapng_spb(path, fanfp.DLT_RAW, packet)
        packets = list(fanfp.read_pcap(path))
    assert len(packets) == 1
    assert packets[0].linktype == fanfp.DLT_RAW
    assert packets[0].payload == packet


def test_non_ethernet_linktypes() -> None:
    raw_packet = ipv4_tcp_syn()
    payloads = list(fanfp.ip_payloads(fanfp.Packet(1, raw_packet, fanfp.DLT_RAW)))
    assert payloads == [(fanfp.ETH_TYPE_IPV4, raw_packet)]

    sll = struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, fanfp.ETH_TYPE_IPV4) + raw_packet
    payloads = list(fanfp.ip_payloads(fanfp.Packet(1, sll, fanfp.DLT_LINUX_SLL)))
    assert payloads == [(fanfp.ETH_TYPE_IPV4, raw_packet)]

    loopback = struct.pack("<I", 2) + raw_packet
    payloads = list(fanfp.ip_payloads(fanfp.Packet(1, loopback, fanfp.DLT_NULL)))
    assert payloads == [(fanfp.ETH_TYPE_IPV4, raw_packet)]


def test_ipv6_extension_headers() -> None:
    tcp = struct.pack("!HHIIBBHHH", 51514, 443, 1000, 0, 5 << 4, 0x02, 65535, 0, 0)
    packet = ipv6_with_hop_by_hop(6, tcp)
    parsed = fanfp.ipv6_transport(packet)
    assert parsed is not None
    next_header, payload, packet_len = parsed
    assert next_header == 6
    assert payload == tcp
    assert packet_len == len(packet)


def test_tcp_segmentation() -> None:
    record = tls_client_hello()
    first = record[:9]
    second = record[9:]
    stream = fanfp.TcpStreamBuffer()
    segment_one = fanfp.TcpSegment(1, "192.0.2.10", "198.51.100.20", 51514, 443, 1000, first)
    segment_two = fanfp.TcpSegment(2, "192.0.2.10", "198.51.100.20", 51514, 443, 1000 + len(first), second)
    assert fanfp.parse_tls_handshake(stream.add(segment_two)) == []
    assembled = stream.add(segment_one)
    results = fanfp.parse_tls_handshake(assembled)
    assert len(results) == 1
    assert results[0][0] == "client"
    assert results[0][1].startswith("tls|client|v=771|c=4865|")


def test_tls_server_hello_volatile_extensions() -> None:
    initial = fanfp.parse_tls_handshake(tls_server_hello([0, 65281, 11, 35]))
    resumed = fanfp.parse_tls_handshake(tls_server_hello([65281]))
    assert initial == resumed
    assert initial == [("server", "tls|server|v=771|c=49200|e=65281|sv=")]


def main() -> int:
    test_malformed_tls()
    test_malformed_dtls()
    test_malformed_der()
    test_quic_varints()
    test_pcapng_spb()
    test_non_ethernet_linktypes()
    test_ipv6_extension_headers()
    test_tcp_segmentation()
    test_tls_server_hello_volatile_extensions()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
