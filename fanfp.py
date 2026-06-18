#!/usr/bin/env python3
"""Extract FAN/1 SSH, TLS, DTLS, X.509, QUIC, IKE, RDP, and TCP/IP fingerprints from captures."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, NamedTuple, Optional, Tuple, Union

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - optional QUIC Initial decryption support
    AESGCM = None
    Cipher = algorithms = modes = None

TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1
TLS_SERVER_HELLO = 2
TLS_CERTIFICATE = 11
SSH_MSG_KEXINIT = 20
QUIC_INITIAL = 0
IKEV2_SA = 33
IKEV2_KE = 34
IKEV2_NOTIFY = 41
IKEV2_RESPONSE = 0x20
QUIC_INITIAL_SALTS = {
    0x00000001: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0xFF00001D: bytes.fromhex("afbfec289993d24c9e9786f19c6111e04390a899"),
}


def is_grease(value: int) -> bool:
    return value & 0x0F0F == 0x0A0A and ((value >> 8) & 0xFF) == (value & 0xFF)


def u16s(data: bytes) -> List[int]:
    return [struct.unpack_from("!H", data, i)[0] for i in range(0, len(data) - 1, 2)]


def join_ints(values: Iterable[int]) -> str:
    return "-".join(str(v) for v in values if not is_grease(v))


def join_values(values: Iterable[object]) -> str:
    return "-".join(str(v) for v in values)


def simhash128(features: str) -> str:
    """Return a 128-bit SimHash over normalized feature tokens.

    FAN/1 keeps SHA-256 as the exact-match digest. SimHash is intentionally
    token based so small feature changes tend to produce hashes with small
    Hamming distances, which can help analysts compare related fingerprints.
    """
    token_text = features.replace("|", "=").replace(",", "=").replace("-", "=")
    tokens = [token for token in token_text.split("=") if token]
    if not tokens:
        tokens = [features]
    vector = [0] * 128
    for token in tokens:
        token_hash = int.from_bytes(
            hashlib.sha256(token.encode("utf-8")).digest()[:16], "big"
        )
        for bit in range(128):
            if token_hash & (1 << bit):
                vector[bit] += 1
            else:
                vector[bit] -= 1
    value = 0
    for bit, weight in enumerate(vector):
        if weight >= 0:
            value |= 1 << bit
    return f"{value:032x}"


def fan_fingerprint(
    protocol: str, role: str, mode: str, features: str
) -> Tuple[str, str, str, str]:
    digest = hashlib.sha256(features.encode("utf-8")).hexdigest()
    similarity_digest = simhash128(features)
    encoded = (
        base64.urlsafe_b64encode(features.encode("utf-8")).decode("ascii").rstrip("=")
    )
    prefix = f"fan1:{protocol}:{role}:{mode}:{encoded}"
    return (
        f"{prefix}:sha256:{digest}",
        digest,
        f"{prefix}:simhash128:{similarity_digest}",
        similarity_digest,
    )


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
    flags: int = 0
    window: int = 0
    ttl: int = 0
    ip_version: int = 0
    ip_len: int = 0
    ip_df: bool = False
    ip_id: int = 0
    tcp_options: bytes = b""

    @property
    def flow(self) -> Dict[str, object]:
        return {"src": self.src, "sport": self.sport, "dst": self.dst, "dport": self.dport}


@dataclass(frozen=True)
class UdpDatagram:
    index: int
    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes

    @property
    def flow(self) -> Dict[str, object]:
        return {"src": self.src, "sport": self.sport, "dst": self.dst, "dport": self.dport}


@dataclass(frozen=True)
class QuicLongPacket:
    start: int
    end: int
    first_byte: int
    version: int
    packet_type: int
    dcid: bytes
    scid: bytes
    token_len: int
    length: int
    pn_offset: int
    raw: bytes


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


def udp_datagrams(packets: Iterable[Packet]) -> Iterator[UdpDatagram]:
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
            yield from ipv4_udp(packet.index, frame[offset:])
        elif eth_type == 0x86DD:
            yield from ipv6_udp(packet.index, frame[offset:])


def ipv4_tcp(index: int, data: bytes) -> Iterator[TcpSegment]:
    if len(data) < 20 or data[9] != 6:
        return
    ihl = (data[0] & 0x0F) * 4
    total = struct.unpack_from("!H", data, 2)[0]
    if len(data) < ihl + 20:
        return
    src = str(ipaddress.IPv4Address(data[12:16]))
    dst = str(ipaddress.IPv4Address(data[16:20]))
    flags = struct.unpack_from("!H", data, 6)[0]
    df = bool(flags & 0x4000)
    ip_id = struct.unpack_from("!H", data, 4)[0]
    ttl = data[8]
    yield from parse_tcp(index, src, dst, data[ihl:total], ttl, 4, total, df, ip_id)


def ipv4_udp(index: int, data: bytes) -> Iterator[UdpDatagram]:
    if len(data) < 20 or data[9] != 17:
        return
    ihl = (data[0] & 0x0F) * 4
    total = struct.unpack_from("!H", data, 2)[0]
    if len(data) < ihl + 8:
        return
    src = str(ipaddress.IPv4Address(data[12:16]))
    dst = str(ipaddress.IPv4Address(data[16:20]))
    yield from parse_udp(index, src, dst, data[ihl:total])


def ipv6_tcp(index: int, data: bytes) -> Iterator[TcpSegment]:
    if len(data) < 60 or data[6] != 6:
        return
    plen = struct.unpack_from("!H", data, 4)[0]
    src = str(ipaddress.IPv6Address(data[8:24]))
    dst = str(ipaddress.IPv6Address(data[24:40]))
    ttl = data[7]
    yield from parse_tcp(index, src, dst, data[40 : 40 + plen], ttl, 6, plen + 40, False, 0)


def ipv6_udp(index: int, data: bytes) -> Iterator[UdpDatagram]:
    if len(data) < 48 or data[6] != 17:
        return
    plen = struct.unpack_from("!H", data, 4)[0]
    src = str(ipaddress.IPv6Address(data[8:24]))
    dst = str(ipaddress.IPv6Address(data[24:40]))
    yield from parse_udp(index, src, dst, data[40 : 40 + plen])


def parse_tcp(
    index: int,
    src: str,
    dst: str,
    data: bytes,
    ttl: int,
    ip_version: int,
    ip_len: int,
    ip_df: bool,
    ip_id: int,
) -> Iterator[TcpSegment]:
    if len(data) < 20:
        return
    sport, dport = struct.unpack_from("!HH", data, 0)
    off = ((data[12] >> 4) & 0x0F) * 4
    if off < 20 or len(data) < off:
        return
    flags = data[13]
    window = struct.unpack_from("!H", data, 14)[0]
    tcp_options = data[20:off]
    payload = data[off:]
    yield TcpSegment(
        index, src, dst, sport, dport, payload, flags, window, ttl,
        ip_version, ip_len, ip_df, ip_id, tcp_options
    )


def tcp_option_tokens(options: bytes) -> Tuple[List[str], Dict[str, object], List[str]]:
    """Parse TCP options into ordered passive stack fingerprint tokens."""
    tokens: List[str] = []
    values: Dict[str, object] = {}
    quirks: List[str] = []
    offset = 0
    while offset < len(options):
        kind = options[offset]
        if kind == 0:
            tokens.append("eol")
            if any(options[offset + 1:]):
                quirks.append("nz-eol-pad")
            break
        if kind == 1:
            tokens.append("nop")
            offset += 1
            continue
        if offset + 1 >= len(options):
            tokens.append(f"bad{kind}")
            quirks.append("trunc-opt")
            break
        length = options[offset + 1]
        if length < 2 or offset + length > len(options):
            tokens.append(f"bad{kind}")
            quirks.append("bad-opt-len")
            break
        data = options[offset + 2:offset + length]
        if kind == 2 and len(data) == 2:
            mss = struct.unpack("!H", data)[0]
            tokens.append(f"mss{mss}")
            values["mss"] = mss
        elif kind == 3 and len(data) == 1:
            wscale = data[0]
            tokens.append(f"ws{wscale}")
            values["wscale"] = wscale
        elif kind == 4 and not data:
            tokens.append("sackok")
            values["sackok"] = True
        elif kind == 5:
            tokens.append(f"sack{len(data)}")
        elif kind == 8 and len(data) == 8:
            ts1, ts2 = struct.unpack("!II", data)
            tokens.append("ts")
            values["ts"] = "nz" if ts1 else "zero"
            if ts2:
                quirks.append("ts-echo-nz")
        elif kind == 34:
            tokens.append("tfo")
        else:
            tokens.append(f"opt{kind}:{data.hex()}")
        offset += length
    return tokens, values, quirks


def ttl_bucket(ttl: int) -> int:
    for candidate in (32, 64, 128, 255):
        if ttl <= candidate:
            return candidate
    return ttl


def tcpip_features(segment: TcpSegment) -> Optional[Tuple[str, str]]:
    syn = bool(segment.flags & 0x02)
    ack = bool(segment.flags & 0x10)
    rst = bool(segment.flags & 0x04)
    fin = bool(segment.flags & 0x01)
    if not syn or rst or fin:
        return None

    role = "server" if ack else "client"
    tokens, values, quirks = tcp_option_tokens(segment.tcp_options)
    if segment.payload:
        quirks.append("data-in-syn")
    if segment.ip_version == 4 and not segment.ip_df:
        quirks.append("no-df")
    if segment.ip_version == 4 and segment.ip_df and segment.ip_id:
        quirks.append("df-nz-id")

    opt_layout = ",".join(tokens)
    mss = values.get("mss", "")
    wscale = values.get("wscale", "")
    sackok = "1" if values.get("sackok") else "0"
    ts = values.get("ts", "")
    # tcpip2 is a passive SinFP3-adjacent signature.  It keeps the classic
    # single-packet TCP/IP stack signals (TTL, window, MSS, option order), and
    # adds normalized option layout plus passive OS-fingerprinting quirk flags.
    features = (
        f"tcpip2|{role}|ip={segment.ip_version}|ttl={segment.ttl}|it={ttl_bucket(segment.ttl)}"
        f"|olen={len(segment.tcp_options)}|win={segment.window}|mss={mss}|ws={wscale}"
        f"|sack={sackok}|ts={ts}|opts={opt_layout}|df={int(segment.ip_df)}"
        f"|plen={len(segment.payload)}|ql={join_values(sorted(set(quirks)))}"
    )
    return role, features

def parse_udp(index: int, src: str, dst: str, data: bytes) -> Iterator[UdpDatagram]:
    if len(data) < 8:
        return
    sport, dport, length, _ = struct.unpack_from("!HHHH", data, 0)
    if length < 8:
        return
    payload = data[8:min(length, len(data))]
    if payload:
        yield UdpDatagram(index, src, dst, sport, dport, payload)


def read_vec(data: bytes, offset: int, length_size: int) -> Tuple[bytes, int]:
    if offset + length_size > len(data):
        raise ValueError("truncated vector")
    length = int.from_bytes(data[offset : offset + length_size], "big")
    offset += length_size
    if offset + length > len(data):
        raise ValueError("truncated vector data")
    return data[offset : offset + length], offset + length


class DerNode(NamedTuple):
    tag: int
    value: bytes
    children: List["DerNode"]


def read_der_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    length_len = first & 0x7F
    if length_len == 0 or length_len > 4 or offset + length_len > len(data):
        raise ValueError("invalid DER length")
    return int.from_bytes(data[offset : offset + length_len], "big"), offset + length_len


def parse_der_node(data: bytes, offset: int = 0) -> Tuple[DerNode, int]:
    if offset >= len(data):
        raise ValueError("truncated DER tag")
    tag = data[offset]
    length, value_offset = read_der_length(data, offset + 1)
    end = value_offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    value = data[value_offset:end]
    children: List[DerNode] = []
    if tag & 0x20:
        child_offset = 0
        while child_offset < len(value):
            child, child_offset = parse_der_node(value, child_offset)
            children.append(child)
    return DerNode(tag, value, children), end


def der_oid(value: bytes) -> str:
    if not value:
        return ""
    first = value[0]
    parts = [first // 40, first % 40]
    n = 0
    for byte in value[1:]:
        n = (n << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(n)
            n = 0
    return ".".join(str(part) for part in parts)


def der_int_len(node: DerNode) -> str:
    return str(len(node.value.lstrip(b"\x00") or b"\x00"))


def der_text(node: DerNode) -> str:
    if node.tag in (0x0C, 0x16, 0x13, 0x14, 0x1A):
        return node.value.decode("utf-8", "replace").replace("|", "\\|").replace(",", "\\,")
    if node.tag == 0x1E:
        try:
            return node.value.decode("utf-16-be", "replace").replace("|", "\\|").replace(",", "\\,")
        except UnicodeDecodeError:
            return node.value.hex()
    return node.value.hex()


def der_time_days(not_before: DerNode, not_after: DerNode) -> str:
    from datetime import datetime

    def parse_time(node: DerNode) -> Optional[datetime]:
        text = node.value.decode("ascii", "ignore")
        formats = ["%y%m%d%H%M%SZ"] if node.tag == 0x17 else ["%Y%m%d%H%M%SZ"]
        for fmt in formats:
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                pass
        return None

    start = parse_time(not_before)
    end = parse_time(not_after)
    return str((end - start).days) if start and end else ""


def x509_name_features(name: DerNode) -> str:
    attrs: List[str] = []
    for rdn in name.children:
        for attr in rdn.children:
            if len(attr.children) >= 2:
                attrs.append(f"{der_oid(attr.children[0].value)}={der_text(attr.children[1])}")
    return ",".join(attrs)


def parse_general_names(data: bytes) -> str:
    try:
        seq, _ = parse_der_node(data)
    except ValueError:
        return ""
    names: List[str] = []
    for name in seq.children:
        tag = name.tag
        if tag == 0x82:
            names.append("dns:" + name.value.decode("ascii", "replace"))
        elif tag == 0x87:
            try:
                names.append("ip:" + str(ipaddress.ip_address(name.value)))
            except ValueError:
                names.append("ip:" + name.value.hex())
        elif tag == 0x81:
            names.append("email:" + name.value.decode("ascii", "replace"))
        elif tag == 0x86:
            names.append("uri:" + name.value.decode("ascii", "replace"))
        elif tag == 0x88:
            names.append("oid:" + der_oid(name.value))
        else:
            names.append(f"gn{tag}:{hashlib.sha256(name.value).hexdigest()[:16]}")
    return ",".join(names)


def parse_x509_certificate_features(cert: bytes, index: int = 0) -> str:
    root, end = parse_der_node(cert)
    if end != len(cert) or root.tag != 0x30 or len(root.children) < 3:
        raise ValueError("invalid X.509 certificate")
    tbs = root.children[0]
    outer_sig_oid = der_oid(root.children[1].children[0].value) if root.children[1].children else ""
    off = 0
    version = "1"
    if tbs.children and tbs.children[0].tag == 0xA0:
        version = str(int.from_bytes(tbs.children[0].children[0].value, "big") + 1)
        off = 1
    serial_len = der_int_len(tbs.children[off]); off += 1
    tbs_sig_oid = der_oid(tbs.children[off].children[0].value) if tbs.children[off].children else ""; off += 1
    issuer = x509_name_features(tbs.children[off]); off += 1
    validity = tbs.children[off]; off += 1
    validity_days = der_time_days(validity.children[0], validity.children[1]) if len(validity.children) >= 2 else ""
    subject = x509_name_features(tbs.children[off]); off += 1
    spki = tbs.children[off]; off += 1
    spki_alg = der_oid(spki.children[0].children[0].value) if spki.children and spki.children[0].children else ""
    spki_param = ""
    if spki.children and len(spki.children[0].children) > 1:
        param = spki.children[0].children[1]
        spki_param = der_oid(param.value) if param.tag == 0x06 else param.value.hex()
    pubkey_bits = str(max(0, len(spki.children[1].value) * 8 - 8)) if len(spki.children) > 1 and spki.children[1].tag == 0x03 else ""
    ext_oids: List[str] = []
    san = eku = ku = bc = ski = aki = policies = aia = crldp = nc = ""
    for node in tbs.children[off:]:
        if node.tag != 0xA3 or not node.children:
            continue
        for ext in node.children[0].children:
            if len(ext.children) < 2:
                continue
            oid = der_oid(ext.children[0].value)
            critical = "0"
            val_node = ext.children[1]
            if val_node.tag == 0x01 and len(ext.children) > 2:
                critical = "1" if val_node.value != b"\x00" else "0"
                val_node = ext.children[2]
            ext_oids.append(f"{critical}:{oid}")
            val = val_node.value
            if oid == "2.5.29.17":
                san = parse_general_names(val)
            elif oid == "2.5.29.37":
                eku = "-".join(der_oid(c.value) for c in parse_der_node(val)[0].children)
            elif oid == "2.5.29.15":
                ku = val.hex()
            elif oid == "2.5.29.19":
                try:
                    basic = parse_der_node(val)[0]
                    ca = "0"
                    path = ""
                    for child in basic.children:
                        if child.tag == 0x01:
                            ca = "1" if child.value != b"\x00" else "0"
                        elif child.tag == 0x02:
                            path = str(int.from_bytes(child.value, "big"))
                    bc = f"ca:{ca},path:{path}"
                except ValueError:
                    bc = val.hex()
            elif oid == "2.5.29.14":
                ski = hashlib.sha256(val).hexdigest()[:16]
            elif oid == "2.5.29.35":
                aki = hashlib.sha256(val).hexdigest()[:16]
            elif oid == "2.5.29.32":
                policies = "-".join(der_oid(c.children[0].value) for c in parse_der_node(val)[0].children if c.children)
            elif oid == "1.3.6.1.5.5.7.1.1":
                aia = hashlib.sha256(val).hexdigest()[:16]
            elif oid == "2.5.29.31":
                crldp = hashlib.sha256(val).hexdigest()[:16]
            elif oid == "2.5.29.30":
                nc = hashlib.sha256(val).hexdigest()[:16]
    return (
        f"x509|server|idx={index}|ver={version}|serial_len={serial_len}|sig={outer_sig_oid}"
        f"|tbs_sig={tbs_sig_oid}|issuer={issuer}|subject={subject}|valid_days={validity_days}"
        f"|spki_alg={spki_alg}|spki_param={spki_param}|pk_bits={pubkey_bits}|san={san}"
        f"|ku={ku}|eku={eku}|bc={bc}|ski={ski}|aki={aki}|pol={policies}|aia={aia}"
        f"|crldp={crldp}|nc={nc}|ext={join_values(ext_oids)}"
    )


def parse_tls_certificate_features(body: bytes) -> Iterator[str]:
    for offset in (0, 1):
        try:
            certs, _ = read_vec(body, offset, 3)
            co = 0
            index = 0
            while co < len(certs):
                cert, co = read_vec(certs, co, 3)
                features = parse_x509_certificate_features(cert, index)
                if co < len(certs):
                    try:
                        # TLS 1.3 certificate extensions after each certificate.
                        _, new_co = read_vec(certs, co, 2)
                        co = new_co
                    except ValueError:
                        pass
                yield features
                index += 1
            return
        except (struct.error, ValueError):
            continue


def parse_tls_handshake(payload: bytes, strict: bool = False) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    offset = 0
    while offset + 5 <= len(payload):
        content_type = payload[offset]
        rec_len = struct.unpack_from("!H", payload, offset + 3)[0]
        if offset + 5 + rec_len > len(payload):
            if strict:
                raise ValueError("truncated TLS record")
            return results
        record = payload[offset + 5 : offset + 5 + rec_len]
        offset += 5 + rec_len
        if content_type != TLS_HANDSHAKE or len(record) < 4:
            continue
        hs_type = record[0]
        hs_len = int.from_bytes(record[1:4], "big")
        if 4 + hs_len > len(record):
            if strict:
                raise ValueError("truncated TLS handshake")
            return results
        body = record[4 : 4 + hs_len]
        try:
            if hs_type == TLS_CLIENT_HELLO:
                results.append(("client", tls_client_features(body, "tls")))
            elif hs_type == TLS_SERVER_HELLO:
                results.append(("server", tls_server_features(body, "tls")))
            elif hs_type == TLS_CERTIFICATE:
                results.extend(("server", features) for features in parse_tls_certificate_features(body))
        except (struct.error, ValueError):
            if strict:
                raise
            return results
    return results


def parse_dtls_handshake(payload: bytes, strict: bool = False) -> Optional[Tuple[str, str]]:
    offset = 0
    while offset + 13 <= len(payload):
        content_type = payload[offset]
        version = struct.unpack_from("!H", payload, offset + 1)[0]
        if content_type not in (20, 21, 22, 23, 24, 25, 26):
            return None
        if (version & 0xFF00) != 0xFE00:
            return None
        rec_len = struct.unpack_from("!H", payload, offset + 11)[0]
        if offset + 13 + rec_len > len(payload):
            if strict:
                raise ValueError("truncated DTLS record")
            return None
        record = payload[offset + 13 : offset + 13 + rec_len]
        offset += 13 + rec_len
        if content_type != TLS_HANDSHAKE:
            continue

        hs_offset = 0
        while hs_offset + 12 <= len(record):
            hs_type = record[hs_offset]
            hs_len = int.from_bytes(record[hs_offset + 1 : hs_offset + 4], "big")
            fragment_offset = int.from_bytes(record[hs_offset + 6 : hs_offset + 9], "big")
            fragment_len = int.from_bytes(record[hs_offset + 9 : hs_offset + 12], "big")
            hs_offset += 12
            if hs_offset + fragment_len > len(record):
                if strict:
                    raise ValueError("truncated DTLS handshake")
                return None
            fragment = record[hs_offset : hs_offset + fragment_len]
            hs_offset += fragment_len
            if fragment_offset != 0 or fragment_len != hs_len:
                continue
            try:
                if hs_type == TLS_CLIENT_HELLO:
                    return "client", tls_client_features(fragment, "dtls")
                if hs_type == TLS_SERVER_HELLO:
                    return "server", tls_server_features(fragment, "dtls")
            except (struct.error, ValueError):
                if strict:
                    raise
                return None
    return None


def parse_rdp_x224(payload: bytes, strict: bool = False) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    offset = 0
    while offset + 7 <= len(payload):
        if payload[offset] != 3 or payload[offset + 1] != 0:
            break
        tpkt_version = payload[offset]
        tpkt_reserved = payload[offset + 1]
        tpkt_len = struct.unpack_from("!H", payload, offset + 2)[0]
        if tpkt_len < 7:
            if strict:
                raise ValueError("invalid RDP TPKT length")
            break
        if offset + tpkt_len > len(payload):
            if strict:
                raise ValueError("truncated RDP TPKT")
            break

        tpkt = payload[offset : offset + tpkt_len]
        offset += tpkt_len
        x224_len = tpkt[4]
        pdu = tpkt[5]
        if pdu not in (0xE0, 0xD0) or len(tpkt) < 11:
            continue

        role = "client" if pdu == 0xE0 else "server"
        dst_ref = struct.unpack_from("!H", tpkt, 6)[0]
        src_ref = struct.unpack_from("!H", tpkt, 8)[0]
        class_opt = tpkt[10]
        neg_type = neg_flags = neg_len = neg_proto = neg_selected = ""
        for neg_offset in range(11, max(11, len(tpkt) - 7)):
            ntype = tpkt[neg_offset]
            if ntype not in (1, 2):
                continue
            nflags = tpkt[neg_offset + 1]
            nlen = struct.unpack_from("<H", tpkt, neg_offset + 2)[0]
            if nlen < 8 or neg_offset + nlen > len(tpkt):
                continue
            nvalue = struct.unpack_from("<I", tpkt, neg_offset + 4)[0]
            neg_type = str(ntype)
            neg_flags = str(nflags)
            neg_len = str(nlen)
            if ntype == 1:
                neg_proto = str(nvalue)
            else:
                neg_selected = str(nvalue)
            break

        features = (
            f"rdp|{role}|tpkt_v={tpkt_version}|tpkt_rsv={tpkt_reserved}|tpkt_len={tpkt_len}"
            f"|x224_len={x224_len}|pdu={pdu}|dst_ref={dst_ref}|src_ref={src_ref}"
            f"|class={class_opt}|neg_type={neg_type}|neg_flags={neg_flags}"
            f"|neg_len={neg_len}|neg_proto={neg_proto}|neg_selected={neg_selected}"
        )
        results.append((role, features))
    return results


def tls_client_features(body: bytes, protocol: str = "tls") -> str:
    off = 0
    version = struct.unpack_from("!H", body, off)[0]; off += 2 + 32
    session, off = read_vec(body, off, 1)
    if protocol == "dtls":
        _, off = read_vec(body, off, 1)
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
    return f"{protocol}|client|v={version}|c={join_ints(u16s(ciphers))}|e={join_ints(ext_types)}|g={groups}|p={points}|sv={versions}|alpn={alpn}|sig={sigs}"


def tls_server_features(body: bytes, protocol: str = "tls") -> str:
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
    return f"{protocol}|server|v={version}|c={cipher}|e={join_ints(ext_types)}|sv={selected_version}"


def read_quic_varint(data: bytes, offset: int) -> Tuple[int, int, int]:
    if offset >= len(data):
        raise ValueError("truncated QUIC varint")
    first = data[offset]
    size = 1 << (first >> 6)
    if offset + size > len(data):
        raise ValueError("truncated QUIC varint data")
    value = int.from_bytes(data[offset:offset + size], "big") & ((1 << (size * 8 - 2)) - 1)
    return value, offset + size, size


def parse_quic_long_packets(payload: bytes) -> Iterator[QuicLongPacket]:
    offset = 0
    while offset + 7 <= len(payload):
        first = payload[offset]
        if not (first & 0x80):
            break
        version = int.from_bytes(payload[offset + 1:offset + 5], "big")
        if version == 0:
            break
        packet_type = (first & 0x30) >> 4
        i = offset + 5
        dcid_len = payload[i]; i += 1
        if i + dcid_len + 1 > len(payload):
            break
        dcid = payload[i:i + dcid_len]; i += dcid_len
        scid_len = payload[i]; i += 1
        if i + scid_len > len(payload):
            break
        scid = payload[i:i + scid_len]; i += scid_len

        token_len = 0
        try:
            if packet_type == QUIC_INITIAL:
                token_len, i, _ = read_quic_varint(payload, i)
                if i + token_len > len(payload):
                    break
                i += token_len
            elif packet_type == 3:
                break
            length, i, _ = read_quic_varint(payload, i)
        except ValueError:
            break

        end = i + length
        if end > len(payload):
            break
        if packet_type == QUIC_INITIAL:
            yield QuicLongPacket(offset, end, first, version, packet_type, dcid, scid, token_len, length, i, payload)
        offset = end


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(secret: bytes, info: bytes, length: int) -> bytes:
    out = b""
    previous = b""
    counter = 1
    while len(out) < length:
        previous = hmac.new(secret, previous + info + bytes([counter]), hashlib.sha256).digest()
        out += previous
        counter += 1
    return out[:length]


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label
    hkdf_label = struct.pack("!H", length) + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context
    return hkdf_expand(secret, hkdf_label, length)


def quic_initial_keys(version: int, dcid: bytes, label: bytes) -> Optional[Tuple[bytes, bytes, bytes]]:
    salt = QUIC_INITIAL_SALTS.get(version)
    if salt is None or AESGCM is None or Cipher is None:
        return None
    initial_secret = hkdf_extract(salt, dcid)
    secret = hkdf_expand_label(initial_secret, label, b"", hashlib.sha256().digest_size)
    key = hkdf_expand_label(secret, b"quic key", b"", 16)
    iv = hkdf_expand_label(secret, b"quic iv", b"", 12)
    hp = hkdf_expand_label(secret, b"quic hp", b"", 16)
    return key, iv, hp


def aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()


def decrypt_quic_initial(packet: QuicLongPacket, initial_dcid: bytes, label: bytes) -> Optional[bytes]:
    keys = quic_initial_keys(packet.version, initial_dcid, label)
    if keys is None or packet.pn_offset + 4 + 16 > packet.end:
        return None
    key, iv, hp = keys
    sample = packet.raw[packet.pn_offset + 4:packet.pn_offset + 20]
    try:
        mask = aes_ecb_encrypt(hp, sample)
        first = packet.first_byte ^ (mask[0] & 0x0F)
        pn_len = (first & 0x03) + 1
        if packet.pn_offset + pn_len > packet.end:
            return None
        pn_bytes = bytes(packet.raw[packet.pn_offset + i] ^ mask[i + 1] for i in range(pn_len))
        packet_number = int.from_bytes(pn_bytes, "big")
        header = bytes([first]) + packet.raw[packet.start + 1:packet.pn_offset] + pn_bytes
        ciphertext = packet.raw[packet.pn_offset + pn_len:packet.end]
        nonce = bytes(a ^ b for a, b in zip(iv, packet_number.to_bytes(len(iv), "big")))
        return AESGCM(key).decrypt(nonce, ciphertext, header)
    except Exception:
        return None


def skip_quic_varints(data: bytes, offset: int, count: int) -> int:
    for _ in range(count):
        _, offset, _ = read_quic_varint(data, offset)
    return offset


def quic_crypto_frames(data: bytes) -> Iterator[Tuple[int, bytes]]:
    offset = 0
    while offset < len(data):
        frame_type = data[offset]
        offset += 1
        try:
            if frame_type == 0x00 or frame_type == 0x01:
                continue
            if frame_type in (0x02, 0x03):
                _, offset, _ = read_quic_varint(data, offset)  # largest acknowledged
                _, offset, _ = read_quic_varint(data, offset)  # ack delay
                ack_range_count, offset, _ = read_quic_varint(data, offset)
                _, offset, _ = read_quic_varint(data, offset)  # first ack range
                offset = skip_quic_varints(data, offset, ack_range_count * 2)
                if frame_type == 0x03:
                    offset = skip_quic_varints(data, offset, 3)
                continue
            if frame_type == 0x06:
                crypto_offset, offset, _ = read_quic_varint(data, offset)
                length, offset, _ = read_quic_varint(data, offset)
                if offset + length > len(data):
                    return
                yield crypto_offset, data[offset:offset + length]
                offset += length
                continue
            if 0x08 <= frame_type <= 0x0F:
                _, offset, _ = read_quic_varint(data, offset)  # stream id
                if frame_type & 0x04:
                    _, offset, _ = read_quic_varint(data, offset)
                if frame_type & 0x02:
                    length, offset, _ = read_quic_varint(data, offset)
                else:
                    length = len(data) - offset
                offset += length
                continue
            if frame_type == 0x1C:
                offset = skip_quic_varints(data, offset, 2)
                length, offset, _ = read_quic_varint(data, offset)
                offset += length
                continue
            if frame_type == 0x1D:
                offset = skip_quic_varints(data, offset, 1)
                length, offset, _ = read_quic_varint(data, offset)
                offset += length
                continue
            return
        except ValueError:
            return


def contiguous_crypto_stream(chunks: Dict[int, bytes]) -> bytes:
    out = bytearray()
    end = 0
    for offset in sorted(chunks):
        chunk = chunks[offset]
        if offset > end:
            break
        skip = max(0, end - offset)
        if skip < len(chunk):
            out.extend(chunk[skip:])
            end = offset + len(chunk)
    return bytes(out)


def parse_tls_handshake_stream(data: bytes) -> Iterator[Tuple[str, bytes]]:
    offset = 0
    while offset + 4 <= len(data):
        hs_type = data[offset]
        hs_len = int.from_bytes(data[offset + 1:offset + 4], "big")
        body = data[offset + 4:offset + 4 + hs_len]
        if len(body) != hs_len:
            return
        if hs_type == TLS_CLIENT_HELLO:
            yield "client", body
        elif hs_type == TLS_SERVER_HELLO:
            yield "server", body
        offset += 4 + hs_len


def quic_tls_features(role: str, version: int, body: bytes) -> Optional[str]:
    try:
        if role == "client":
            fields = tls_client_features(body).split("|")[2:]
        elif role == "server":
            fields = tls_server_features(body).split("|")[2:]
        else:
            return None
    except (struct.error, ValueError):
        return None
    if fields and fields[0].startswith("v="):
        fields[0] = "tls_" + fields[0]
    return f"quic|{role}|v={version}|" + "|".join(fields)


def quic_header_features(packet: QuicLongPacket) -> str:
    return ("quic|peer|v=%d|type=initial|dcid_len=%d|scid_len=%d|token_len=%d|len=%d"
            % (packet.version, len(packet.dcid), len(packet.scid), packet.token_len, packet.length))


def connection_key(datagram: UdpDatagram) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    endpoints = sorted(((datagram.src, datagram.sport), (datagram.dst, datagram.dport)))
    return endpoints[0], endpoints[1]


def quic_candidates(packets: Iterable[Packet]) -> Iterator[Tuple[str, str, str, UdpDatagram]]:
    odcids: Dict[Tuple[Tuple[str, int], Tuple[str, int]], List[bytes]] = {}
    crypto_chunks: Dict[Tuple[Tuple[Tuple[str, int], Tuple[str, int]], bytes, str, int], Dict[int, bytes]] = {}
    emitted = set()
    emitted_conns = set()
    fallbacks: Dict[Tuple[Tuple[str, int], Tuple[str, int]], Tuple[str, UdpDatagram]] = {}

    for datagram in udp_datagrams(packets):
        conn = connection_key(datagram)
        for packet in parse_quic_long_packets(datagram.payload):
            if packet.packet_type != QUIC_INITIAL:
                continue
            fallbacks.setdefault(conn, (quic_header_features(packet), datagram))
            odcids.setdefault(conn, [])
            if packet.dcid and packet.dcid not in odcids[conn]:
                odcids[conn].append(packet.dcid)

            candidates = []
            for dcid in [packet.dcid] + odcids.get(conn, []):
                if dcid and dcid not in candidates:
                    candidates.append(dcid)

            for initial_dcid in candidates:
                for label in (b"client in", b"server in"):
                    plaintext = decrypt_quic_initial(packet, initial_dcid, label)
                    if plaintext is None:
                        continue
                    stream_key = (conn, initial_dcid, label.decode("ascii"), packet.version)
                    chunks = crypto_chunks.setdefault(stream_key, {})
                    for crypto_offset, crypto_data in quic_crypto_frames(plaintext):
                        chunks[crypto_offset] = crypto_data
                    stream = contiguous_crypto_stream(chunks)
                    for role, body in parse_tls_handshake_stream(stream):
                        features = quic_tls_features(role, packet.version, body)
                        if not features:
                            continue
                        key = (role, features, conn)
                        if key in emitted:
                            continue
                        emitted.add(key)
                        emitted_conns.add(conn)
                        yield "quic", role, features, datagram

    for conn, (features, datagram) in fallbacks.items():
        if conn not in emitted_conns:
            yield "quic", "peer", features, datagram


def empty_ssh_features(software: str) -> str:
    return f"ssh|peer|id={software}|kex=|hostkey=|enc_c2s=|enc_s2c=|mac_c2s=|mac_s2c=|comp_c2s=|comp_s2c=|lang_c2s=|lang_s2c=|follows="


def parse_ssh_banner(payload: bytes) -> Optional[Tuple[str, bytes]]:
    if not payload.startswith(b"SSH-"):
        return None
    line_end = payload.find(b"\n")
    if line_end < 0:
        return None
    ident = payload[:line_end].rstrip(b"\r").decode("utf-8", "replace")
    software = ident.split("-", 2)[2] if ident.count("-") >= 2 else ident
    return software, payload[line_end + 1 :]


def parse_ssh_kexinit(payload: bytes, software: str) -> Optional[Tuple[str, str]]:
    if len(payload) < 6:
        return None
    packet_len = struct.unpack_from("!I", payload, 0)[0]
    if packet_len < 2 or len(payload) < 4 + packet_len:
        return None
    pad_len = payload[4]
    if pad_len >= packet_len:
        return None
    packet = payload[5 : 4 + packet_len - pad_len]
    if not packet or packet[0] != SSH_MSG_KEXINIT:
        return None
    off = 17
    lists = []
    for _ in range(10):
        if off + 4 > len(packet):
            return None
        ln = struct.unpack_from("!I", packet, off)[0]
        off += 4
        if off + ln > len(packet):
            return None
        lists.append(packet[off:off+ln].decode("ascii", "replace"))
        off += ln
    follows = str(bool(packet[off])) if off < len(packet) else ""
    names = ["kex", "hostkey", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c", "lang_c2s", "lang_s2c"]
    return "peer", "ssh|peer|id=" + software + "|" + "|".join(f"{n}={v}" for n, v in zip(names, lists)) + f"|follows={follows}"


def parse_ssh(payload: bytes) -> Optional[Tuple[str, str]]:
    banner = parse_ssh_banner(payload)
    if not banner:
        return None
    software, rest = banner
    return parse_ssh_kexinit(rest, software) or ("peer", empty_ssh_features(software))


def parse_ike_sa_payload(body: bytes) -> str:
    proposals: List[str] = []
    offset = 0
    while offset + 8 <= len(body):
        proposal_len = struct.unpack_from("!H", body, offset + 2)[0]
        if proposal_len < 8 or offset + proposal_len > len(body):
            break

        proposal_num = body[offset + 4]
        protocol_id = body[offset + 5]
        spi_size = body[offset + 6]
        num_transforms = body[offset + 7]
        transform_offset = offset + 8 + spi_size
        proposal_end = offset + proposal_len
        transforms: List[str] = []

        for _ in range(num_transforms):
            if transform_offset + 8 > proposal_end:
                break
            transform_len = struct.unpack_from("!H", body, transform_offset + 2)[0]
            if transform_len < 8 or transform_offset + transform_len > proposal_end:
                break
            transform_type = body[transform_offset + 4]
            transform_id = struct.unpack_from("!H", body, transform_offset + 6)[0]
            value = f"{transform_type}={transform_id}"

            attr_offset = transform_offset + 8
            transform_end = transform_offset + transform_len
            while attr_offset + 4 <= transform_end:
                attr_type = struct.unpack_from("!H", body, attr_offset)[0]
                attr_value = struct.unpack_from("!H", body, attr_offset + 2)[0]
                if attr_type == 0x800E:
                    value += f".{attr_value}"
                attr_offset += 4

            transforms.append(value)
            transform_offset += transform_len

        proposals.append(f"{protocol_id or proposal_num}:{','.join(transforms)}")
        offset += proposal_len

    return ";".join(proposals)


def parse_ikev2(payload: bytes) -> Optional[Tuple[str, str]]:
    if len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00":
        payload = payload[4:]
    if len(payload) < 28:
        return None

    next_payload = payload[16]
    version = payload[17]
    major = version >> 4
    minor = version & 0x0F
    if major != 2:
        return None

    exchange_type = payload[18]
    flags = payload[19]
    total_len = struct.unpack_from("!I", payload, 24)[0]
    if total_len < 28:
        return None
    total_len = min(total_len, len(payload))

    role = "responder" if flags & IKEV2_RESPONSE else "initiator"
    first_payload = next_payload
    offset = 28
    payload_types: List[int] = []
    notify_types: List[int] = []
    sa = ""
    ke_group = ""

    while next_payload and offset + 4 <= total_len:
        current = next_payload
        this_next = payload[offset]
        payload_len = struct.unpack_from("!H", payload, offset + 2)[0]
        if payload_len < 4 or offset + payload_len > total_len:
            break
        body = payload[offset + 4 : offset + payload_len]

        payload_types.append(current)
        if current == IKEV2_SA:
            sa = parse_ike_sa_payload(body)
        elif current == IKEV2_KE and len(body) >= 4:
            ke_group = str(struct.unpack_from("!H", body, 0)[0])
        elif current == IKEV2_NOTIFY and len(body) >= 4:
            notify_types.append(struct.unpack_from("!H", body, 2)[0])

        next_payload = this_next
        offset += payload_len

    features = (
        f"ike|{role}|v={major}.{minor}|ex={exchange_type}|flags={flags}"
        f"|np={first_payload}|p={join_values(payload_types)}|sa={sa}"
        f"|ke={ke_group}|n={join_values(notify_types)}"
    )
    return role, features


def emit(protocol: str, role: str, features: str, segment: Union[TcpSegment, UdpDatagram]) -> Dict[str, object]:
    fp, digest, similarity_fp, similarity_digest = fan_fingerprint(
        protocol, role, "passive", features
    )
    return {
        "mode": "passive",
        "protocol": protocol,
        "role": role,
        "fingerprint": fp,
        "fingerprint_simhash128": similarity_fp,
        "features": features,
        "sha256": digest,
        "simhash128": similarity_digest,
        "flow": segment.flow,
        "frame": segment.index,
    }


def extract(
    path: Path,
    error_handler: Optional[Callable[[str, Exception], None]] = None,
    strict: bool = False,
) -> Iterator[Dict[str, object]]:
    seen = set()
    ssh_banners: Dict[Tuple[str, int, str, int], Tuple[str, TcpSegment]] = {}
    ssh_completed = set()
    for segment in tcp_segments(read_pcap(path)):
        candidates = []
        try:
            tls_results = parse_tls_handshake(segment.payload, strict=True)
        except (struct.error, ValueError) as exc:
            if strict and not error_handler:
                raise
            if error_handler:
                error_handler(
                    f"skipping malformed TLS record in frame {segment.index}", exc
                )
            tls_results = []
        tcpip = tcpip_features(segment)
        if tcpip:
            candidates.append(("tcpip", *tcpip))

        for tls_role, tls_features in tls_results:
            tls_protocol = "x509" if tls_features.startswith("x509|") else "tls"
            candidates.append((tls_protocol, tls_role, tls_features))

        try:
            rdp_results = parse_rdp_x224(segment.payload, strict=strict)
        except (struct.error, ValueError) as exc:
            if strict and not error_handler:
                raise
            if error_handler:
                error_handler(
                    f"skipping malformed RDP X.224 packet in frame {segment.index}", exc
                )
            rdp_results = []
        for rdp_role, rdp_features in rdp_results:
            candidates.append(("rdp", rdp_role, rdp_features))

        flow_key = (segment.src, segment.sport, segment.dst, segment.dport)
        banner = parse_ssh_banner(segment.payload)
        if banner:
            software, rest = banner
            ssh_banners[flow_key] = (software, segment)
            ssh = parse_ssh_kexinit(rest, software)
            if ssh:
                ssh_completed.add(flow_key)
                candidates.append(("ssh", *ssh))
        elif flow_key in ssh_banners and flow_key not in ssh_completed:
            software, _ = ssh_banners[flow_key]
            ssh = parse_ssh_kexinit(segment.payload, software)
            if ssh:
                ssh_completed.add(flow_key)
                candidates.append(("ssh", *ssh))

        for protocol, role, features in candidates:
            key = (protocol, role, features, tuple(segment.flow.items()))
            if key not in seen:
                seen.add(key)
                yield emit(protocol, role, features, segment)

    for flow_key, (software, segment) in ssh_banners.items():
        if flow_key not in ssh_completed:
            features = empty_ssh_features(software)
            key = ("ssh", "peer", features, tuple(segment.flow.items()))
            if key not in seen:
                seen.add(key)
                yield emit("ssh", "peer", features, segment)

    for datagram in udp_datagrams(read_pcap(path)):
        try:
            dtls = parse_dtls_handshake(datagram.payload, strict=strict)
        except (struct.error, ValueError) as exc:
            if strict and not error_handler:
                raise
            if error_handler:
                error_handler(
                    f"skipping malformed DTLS record in frame {datagram.index}", exc
                )
            dtls = None
        if not dtls:
            continue
        role, features = dtls
        key = ("dtls", role, features, tuple(datagram.flow.items()))
        if key not in seen:
            seen.add(key)
            yield emit("dtls", role, features, datagram)

    for protocol, role, features, datagram in quic_candidates(read_pcap(path)):
        key = (protocol, role, features, tuple(datagram.flow.items()))
        if key not in seen:
            seen.add(key)
            yield emit(protocol, role, features, datagram)

    for datagram in udp_datagrams(read_pcap(path)):
        if datagram.sport not in (500, 4500) and datagram.dport not in (500, 4500):
            continue
        ike = parse_ikev2(datagram.payload)
        if not ike:
            continue
        role, features = ike
        key = ("ike", role, features, tuple(datagram.flow.items()))
        if key not in seen:
            seen.add(key)
            yield emit("ike", role, features, datagram)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="pcap or pcapng capture file")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="raise parsing errors instead of skipping malformed records",
    )
    parser.add_argument(
        "--verbose-errors",
        action="store_true",
        help="print skipped malformed record details to stderr",
    )
    args = parser.parse_args()

    def report_error(message: str, exc: Exception) -> None:
        if args.strict:
            raise exc
        if args.verbose_errors:
            print(f"{message}: {exc}", file=sys.stderr)

    for item in extract(args.pcap, report_error, strict=args.strict):
        print(json.dumps(item, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
