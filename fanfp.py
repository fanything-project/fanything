#!/usr/bin/env python3
"""Extract FAN/1 SSH and TLS fingerprints from pcap or pcapng files."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1
TLS_SERVER_HELLO = 2
SSH_MSG_KEXINIT = 20


def is_grease(value: int) -> bool:
    return value & 0x0F0F == 0x0A0A and ((value >> 8) & 0xFF) == (value & 0xFF)


def u16s(data: bytes) -> List[int]:
    return [struct.unpack_from("!H", data, i)[0] for i in range(0, len(data) - 1, 2)]


def join_ints(values: Iterable[int]) -> str:
    return "-".join(str(v) for v in values if not is_grease(v))


def fan_fingerprint(protocol: str, role: str, features: str) -> Tuple[str, str]:
    digest = hashlib.sha256(features.encode("utf-8")).hexdigest()
    encoded = base64.urlsafe_b64encode(features.encode("utf-8")).decode("ascii").rstrip("=")
    return f"fan1:{protocol}:{role}:{encoded}:sha256:{digest}", digest


@dataclass(frozen=True)
class Packet:
    index: int
    payload: bytes


@dataclass(frozen=True)
class TcpSegment:
    index: int
    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes

    @property
    def flow(self) -> Dict[str, object]:
        return {"src": self.src, "sport": self.sport, "dst": self.dst, "dport": self.dport}


def read_pcap(path: Path) -> Iterator[Packet]:
    data = path.read_bytes()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        yield from read_pcapng(data)
        return

    magic = data[:4]
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
    if endian is None:
        raise ValueError("unsupported capture format")
    offset = 24
    index = 0
    while offset + 16 <= len(data):
        _, _, incl_len, _ = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        payload = data[offset : offset + incl_len]
        offset += incl_len
        index += 1
        yield Packet(index, payload)


def read_pcapng(data: bytes) -> Iterator[Packet]:
    offset = 0
    endian = "<"
    index = 0
    while offset + 12 <= len(data):
        block_type, block_len = struct.unpack_from(endian + "II", data, offset)
        if block_len < 12 or offset + block_len > len(data):
            break
        body = data[offset + 8 : offset + block_len - 4]
        if block_type == 0x0A0D0D0A and len(body) >= 4:
            endian = "<" if body[:4] == b"\x4d\x3c\x2b\x1a" else ">"
        elif block_type == 6 and len(body) >= 20:
            cap_len = struct.unpack_from(endian + "I", body, 12)[0]
            payload = body[20 : 20 + cap_len]
            index += 1
            yield Packet(index, payload)
        elif block_type == 3 and len(body) >= 16:
            cap_len = struct.unpack_from(endian + "I", body, 8)[0]
            payload = body[16 : 16 + cap_len]
            index += 1
            yield Packet(index, payload)
        offset += block_len


def tcp_segments(packets: Iterable[Packet]) -> Iterator[TcpSegment]:
    for packet in packets:
        frame = packet.payload
        if len(frame) < 14:
            continue
        eth_type = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        if eth_type == 0x8100 and len(frame) >= 18:
            eth_type = struct.unpack_from("!H", frame, 16)[0]
            offset = 18
        if eth_type == 0x0800:
            yield from ipv4_tcp(packet.index, frame[offset:])
        elif eth_type == 0x86DD:
            yield from ipv6_tcp(packet.index, frame[offset:])


def ipv4_tcp(index: int, data: bytes) -> Iterator[TcpSegment]:
    if len(data) < 20 or data[9] != 6:
        return
    ihl = (data[0] & 0x0F) * 4
    total = struct.unpack_from("!H", data, 2)[0]
    if len(data) < ihl + 20:
        return
    src = str(ipaddress.IPv4Address(data[12:16]))
    dst = str(ipaddress.IPv4Address(data[16:20]))
    yield from parse_tcp(index, src, dst, data[ihl:total])


def ipv6_tcp(index: int, data: bytes) -> Iterator[TcpSegment]:
    if len(data) < 60 or data[6] != 6:
        return
    plen = struct.unpack_from("!H", data, 4)[0]
    src = str(ipaddress.IPv6Address(data[8:24]))
    dst = str(ipaddress.IPv6Address(data[24:40]))
    yield from parse_tcp(index, src, dst, data[40 : 40 + plen])


def parse_tcp(index: int, src: str, dst: str, data: bytes) -> Iterator[TcpSegment]:
    if len(data) < 20:
        return
    sport, dport = struct.unpack_from("!HH", data, 0)
    off = ((data[12] >> 4) & 0x0F) * 4
    payload = data[off:]
    if payload:
        yield TcpSegment(index, src, dst, sport, dport, payload)


def read_vec(data: bytes, offset: int, length_size: int) -> Tuple[bytes, int]:
    if offset + length_size > len(data):
        raise ValueError("truncated vector")
    length = int.from_bytes(data[offset : offset + length_size], "big")
    offset += length_size
    if offset + length > len(data):
        raise ValueError("truncated vector data")
    return data[offset : offset + length], offset + length


def parse_tls_handshake(payload: bytes) -> Optional[Tuple[str, str]]:
    offset = 0
    while offset + 5 <= len(payload):
        content_type = payload[offset]
        rec_len = struct.unpack_from("!H", payload, offset + 3)[0]
        record = payload[offset + 5 : offset + 5 + rec_len]
        offset += 5 + rec_len
        if content_type != TLS_HANDSHAKE or len(record) < 4:
            continue
        hs_type = record[0]
        hs_len = int.from_bytes(record[1:4], "big")
        body = record[4 : 4 + hs_len]
        if hs_type == TLS_CLIENT_HELLO:
            return "client", tls_client_features(body)
        if hs_type == TLS_SERVER_HELLO:
            return "server", tls_server_features(body)
    return None


def tls_client_features(body: bytes) -> str:
    off = 0
    version = struct.unpack_from("!H", body, off)[0]; off += 2 + 32
    session, off = read_vec(body, off, 1)
    ciphers, off = read_vec(body, off, 2)
    comp, off = read_vec(body, off, 1)
    exts = groups = points = versions = sigs = ""
    alpn = ""
    ext_types: List[int] = []
    if off < len(body):
        ext_blob, off = read_vec(body, off, 2)
        eo = 0
        while eo + 4 <= len(ext_blob):
            et, el = struct.unpack_from("!HH", ext_blob, eo); eo += 4
            ed = ext_blob[eo : eo + el]; eo += el
            if not is_grease(et):
                ext_types.append(et)
            if et == 10 and len(ed) >= 2:
                groups = join_ints(u16s(ed[2:]))
            elif et == 11 and ed:
                points = "-".join(str(x) for x in ed[1:])
            elif et == 43 and ed:
                versions = join_ints(u16s(ed[1:]))
            elif et == 16 and len(ed) >= 2:
                names, no = [], 2
                while no < len(ed):
                    ln = ed[no]; no += 1
                    names.append(ed[no:no+ln].decode("ascii", "replace")); no += ln
                alpn = ",".join(names)
            elif et == 13 and len(ed) >= 2:
                sigs = join_ints(u16s(ed[2:]))
    return f"tls|client|v={version}|c={join_ints(u16s(ciphers))}|e={join_ints(ext_types)}|g={groups}|p={points}|sv={versions}|alpn={alpn}|sig={sigs}"


def tls_server_features(body: bytes) -> str:
    off = 0
    version = struct.unpack_from("!H", body, off)[0]; off += 2 + 32
    _, off = read_vec(body, off, 1)
    cipher = struct.unpack_from("!H", body, off)[0]; off += 3
    ext_types: List[int] = []
    selected_version = ""
    if off < len(body):
        ext_blob, off = read_vec(body, off, 2)
        eo = 0
        while eo + 4 <= len(ext_blob):
            et, el = struct.unpack_from("!HH", ext_blob, eo); eo += 4
            ed = ext_blob[eo : eo + el]; eo += el
            if not is_grease(et):
                ext_types.append(et)
            if et == 43 and len(ed) == 2:
                selected_version = str(struct.unpack("!H", ed)[0])
    return f"tls|server|v={version}|c={cipher}|e={join_ints(ext_types)}|sv={selected_version}"


def parse_ssh(payload: bytes) -> Optional[Tuple[str, str]]:
    if not payload.startswith(b"SSH-"):
        return None
    line_end = payload.find(b"\n")
    if line_end < 0:
        return None
    ident = payload[:line_end].rstrip(b"\r").decode("utf-8", "replace")
    software = ident.split("-", 2)[2] if ident.count("-") >= 2 else ident
    rest = payload[line_end + 1 :]
    if len(rest) < 6:
        return "peer", f"ssh|peer|id={software}|kex=|hostkey=|enc_c2s=|enc_s2c=|mac_c2s=|mac_s2c=|comp_c2s=|comp_s2c=|lang_c2s=|lang_s2c=|follows="
    packet_len = struct.unpack_from("!I", rest, 0)[0]
    pad_len = rest[4]
    packet = rest[5 : 4 + packet_len - pad_len]
    if not packet or packet[0] != SSH_MSG_KEXINIT:
        return None
    off = 17
    lists = []
    for _ in range(10):
        if off + 4 > len(packet):
            return None
        ln = struct.unpack_from("!I", packet, off)[0]; off += 4
        lists.append(packet[off:off+ln].decode("ascii", "replace")); off += ln
    follows = str(bool(packet[off])) if off < len(packet) else ""
    names = ["kex", "hostkey", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c", "lang_c2s", "lang_s2c"]
    return "peer", "ssh|peer|id=" + software + "|" + "|".join(f"{n}={v}" for n, v in zip(names, lists)) + f"|follows={follows}"


def emit(protocol: str, role: str, features: str, segment: TcpSegment) -> Dict[str, object]:
    fp, digest = fan_fingerprint(protocol, role, features)
    return {"protocol": protocol, "role": role, "fingerprint": fp, "features": features, "sha256": digest, "flow": segment.flow, "frame": segment.index}


def extract(path: Path) -> Iterator[Dict[str, object]]:
    seen = set()
    for segment in tcp_segments(read_pcap(path)):
        candidates = []
        tls = parse_tls_handshake(segment.payload)
        if tls:
            candidates.append(("tls", *tls))
        ssh = parse_ssh(segment.payload)
        if ssh:
            candidates.append(("ssh", *ssh))
        for protocol, role, features in candidates:
            key = (protocol, role, features, tuple(segment.flow.items()))
            if key not in seen:
                seen.add(key)
                yield emit(protocol, role, features, segment)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="pcap or pcapng capture file")
    args = parser.parse_args()
    for item in extract(args.pcap):
        print(json.dumps(item, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
