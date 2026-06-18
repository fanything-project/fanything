# TLS

FAN/1 TLS fingerprints use different feature strings for client proposals and
server selections.

```text
tls|client|v=<legacy_version>|c=<cipher_suites>|e=<extensions>|g=<supported_groups>|p=<ec_point_formats>|sv=<supported_versions>|alpn=<alpn_protocols>|sig=<signature_algorithms>
tls|server|v=<legacy_version>|c=<selected_cipher>|e=<extensions>|sv=<selected_supported_version>
```

## Client Fields

| Field | Length | Meaning |
| --- | --- | --- |
| `tls` | fixed literal | Protocol namespace. |
| `client` | fixed literal | ClientHello proposal role. |
| `v` | variable numeric text | Legacy TLS version field from ClientHello. TLS 1.3 commonly uses `771` for TLS 1.2 compatibility. |
| `c` | variable list | Cipher suites advertised by client. Decimal values joined with `-`; wire order preserved; GREASE removed. |
| `e` | variable list | TLS extension types in ClientHello. Decimal values joined with `-`; wire order preserved; GREASE removed. |
| `g` | variable list | Supported groups from extension `10`. Decimal values joined with `-`; wire order preserved; GREASE removed. |
| `p` | variable list | EC point formats from extension `11`. Decimal byte values joined with `-`. |
| `sv` | variable list | Supported TLS versions from extension `43`. Decimal values joined with `-`; wire order preserved; GREASE removed. |
| `alpn` | variable list | ALPN protocol names from extension `16`. Text values joined with `,`. |
| `sig` | variable list | Signature algorithms from extension `13`. Decimal values joined with `-`; wire order preserved; GREASE removed. |

## Server Fields

| Field | Length | Meaning |
| --- | --- | --- |
| `tls` | fixed literal | Protocol namespace. |
| `server` | fixed literal | ServerHello selection role. |
| `v` | variable numeric text | Legacy TLS version field from ServerHello. TLS 1.3 commonly uses `771`. |
| `c` | variable numeric text | Cipher suite selected by server. |
| `e` | variable list | TLS extension types in ServerHello. Decimal values joined with `-`; wire order preserved; GREASE removed. |
| `sv` | variable numeric text | Selected TLS version from extension `43`; empty when not present. |

Empty fields are represented as empty strings.

## Passive Extraction

`fanfp.py` extracts TLS ClientHello and ServerHello records from TCP payloads.
It preserves observed list order after GREASE removal. Because `e=` keeps wire
order, clients that vary extension order produce different full fingerprints.

## Active Request Defaults

`fanything-tls.nse` actively probes servers and emits `tls|server|...`.

Default protocol order:

```text
TLSv1.3, TLSv1.2, TLSv1.1, TLSv1.0, SSLv3, SSLv2
```

The scanner stops at the first full server fingerprint.

| Default | Value |
| --- | --- |
| Timeout | `5000` ms |
| Port/service rule | TCP 443, 465, 636, 853, 993, 995, 8443, 9443 or SSL-like service unless `fanything-tls.force` is set |
| TLS 1.3 ciphers | `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_256_GCM_SHA384`, then TLS 1.2 cipher list |
| TLS 1.2 ciphers | Firefox ESR 140/NSS-derived enabled order used by scanner |
| Supported groups | `x25519`, `secp256r1`, `secp384r1`, `secp521r1` |
| EC point formats | `uncompressed` |
| ALPN | `h2`, `http/1.1` |
| SNI | target server name when available and not IPv4 literal |
| TLS 1.3 supported versions | `TLSv1.3`, `TLSv1.2` |
| TLS 1.3 key share | X25519 base point |
| Output role | `server` |
| Output mode | `active` |

Arguments:

```text
fanything-tls.timeout=<milliseconds>
fanything-tls.tls-version=TLSv1.3|TLSv1.2|TLSv1.1|TLSv1.0|SSLv3|SSLv2
fanything-tls.force=true
```
