# QUIC

FAN/1 QUIC fingerprints are extracted from QUIC Initial packets. When Initial
decryption succeeds, FAN/1 parses the embedded TLS handshake and emits TLS-like
client or server fields under the `quic` namespace. When decryption is not
available, FAN/1 emits long-header metadata.

## TLS-Derived Client Shape

```text
quic|client|v=<quic_version>|tls_v=<legacy_tls_version>|c=<cipher_suites>|e=<extensions>|g=<supported_groups>|p=<ec_point_formats>|sv=<supported_versions>|alpn=<alpn_protocols>|sig=<signature_algorithms>
```

| Field | Length | Meaning |
| --- | --- | --- |
| `quic` | fixed literal | Protocol namespace. |
| `client` | fixed literal | ClientHello carried in QUIC Initial CRYPTO frames. |
| `v` | variable numeric text | QUIC version from long header. |
| `tls_v` | variable numeric text | Legacy TLS version field from embedded ClientHello. |
| `c` | variable list | TLS cipher suites advertised by client. Decimal values joined with `-`; wire order preserved; GREASE removed. |
| `e` | variable list | TLS extension types in embedded ClientHello. Decimal values joined with `-`; wire order preserved; GREASE removed. |
| `g` | variable list | Supported groups from embedded TLS extension `10`. |
| `p` | variable list | EC point formats. Often empty for modern QUIC/TLS 1.3 clients. |
| `sv` | variable list | Supported TLS versions from embedded extension `43`. |
| `alpn` | variable list | ALPN protocol names. Common HTTP/3 value: `h3`. |
| `sig` | variable list | Signature algorithms from embedded extension `13`. |

## TLS-Derived Server Shape

```text
quic|server|v=<quic_version>|tls_v=<legacy_tls_version>|c=<selected_cipher>|e=<extensions>|sv=<selected_supported_version>
```

| Field | Length | Meaning |
| --- | --- | --- |
| `quic` | fixed literal | Protocol namespace. |
| `server` | fixed literal | ServerHello carried in QUIC Initial CRYPTO frames. |
| `v` | variable numeric text | QUIC version from long header. |
| `tls_v` | variable numeric text | Legacy TLS version field from embedded ServerHello. |
| `c` | variable numeric text | TLS cipher suite selected by server. |
| `e` | variable list | TLS extension types in embedded ServerHello. |
| `sv` | variable numeric text | Selected TLS version from embedded extension `43`. |

## Header Fallback Shape

If QUIC Initial decryption is unavailable, `fanfp.py` emits:

```text
quic|peer|v=<quic_version>|type=initial|dcid_len=<destination_connection_id_length>|scid_len=<source_connection_id_length>|token_len=<token_length>|len=<packet_length>
```

| Field | Length | Meaning |
| --- | --- | --- |
| `quic` | fixed literal | Protocol namespace. |
| `peer` | fixed literal | Fallback role when embedded TLS role is unavailable. |
| `v` | variable numeric text | QUIC version from long header. |
| `type` | fixed literal | `initial`. |
| `dcid_len` | variable numeric text | Destination Connection ID length in bytes. |
| `scid_len` | variable numeric text | Source Connection ID length in bytes. |
| `token_len` | variable numeric text | QUIC Initial token length in bytes. |
| `len` | variable numeric text | QUIC packet length field value. |

## Passive Extraction

`fanfp.py` supports QUIC v1 and draft-29 Initial decryption when Python
`cryptography` is available. It reconstructs CRYPTO frames, parses embedded TLS
handshake messages, and reuses the TLS feature extraction logic. Extension order
is preserved after GREASE removal, so clients that vary TLS extension order
produce different full fingerprints.

## Active Request Defaults

No active QUIC scanner is implemented in this repository. There is no QUIC
active request default, no default QUIC ALPN probe, and no active QUIC mode
output today.
