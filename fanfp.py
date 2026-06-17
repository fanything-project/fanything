#!/usr/bin/env python3
"""Extract FAN/1 SSH and TLS fingerprints from pcap or pcapng files."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - optional QUIC Initial decryption support
    AESGCM = None
    Cipher = algorithms = modes = None

TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1
TLS_SERVER_HELLO = 2
SSH_MSG_KEXINIT = 20
QUIC_INITIAL = 0
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
    yield from parse_tcp(index, src, dst, data[ihl:total])


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
    yield from parse_tcp(index, src, dst, data[40 : 40 + plen])


def ipv6_udp(index: int, data: bytes) -> Iterator[UdpDatagram]:
    if len(data) < 48 or data[6] != 17:
        return
    plen = struct.unpack_from("!H", data, 4)[0]
    src = str(ipaddress.IPv6Address(data[8:24]))
    dst = str(ipaddress.IPv6Address(data[24:40]))
    yield from parse_udp(index, src, dst, data[40 : 40 + plen])


def parse_tcp(index: int, src: str, dst: str, data: bytes) -> Iterator[TcpSegment]:
    if len(data) < 20:
        return
    sport, dport = struct.unpack_from("!HH", data, 0)
    off = ((data[12] >> 4) & 0x0F) * 4
    payload = data[off:]
    if payload:
        yield TcpSegment(index, src, dst, sport, dport, payload)


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
    for protocol, role, features, datagram in quic_candidates(read_pcap(path)):
        key = (protocol, role, features, tuple(datagram.flow.items()))
        if key not in seen:
            seen.add(key)
            yield emit(protocol, role, features, datagram)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="pcap or pcapng capture file")
    args = parser.parse_args()
    for item in extract(args.pcap):
        print(json.dumps(item, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
