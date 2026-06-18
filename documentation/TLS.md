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
When Certificate handshake messages are present, it also emits separate `x509`
fingerprints for DER-encoded certificates; see [X509.md](X509.md).
It preserves observed list order after GREASE removal. Because `e=` keeps wire
order, clients that vary extension order produce different full fingerprints.

## GREASE

GREASE means Generate Random Extensions And Sustain Extensibility. It is a TLS
mechanism where clients advertise reserved, intentionally unknown values so
servers and middleboxes keep tolerating unknown protocol values. This prevents
TLS extensibility from breaking when real new values appear later.

GREASE values can appear in ClientHello fields such as cipher suites,
extensions, supported groups, supported versions, signature algorithms, key
share, and ALPN. Common value pattern: `0x0A0A`, `0x1A1A`, `0x2A2A`, up to
`0xFAFA`.

`fanfp.py` removes GREASE values before canonicalization where fields are parsed
as numeric TLS lists. Reason: GREASE is deliberately variable and not useful as
a stable implementation signal.

Reference: [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html).

## Active Request Defaults

`fanything-tls.nse` actively probes servers and emits `tls|server|...`.
TLS 1.3 and TLS 1.2 active cipher lists are pinned to the current Firefox
LTS/ESR baseline used by this project: Firefox ESR 140 series, latest listed
ESR point release `140.12.0` when checked on 2026-06-18, using NSS
`SSL_ImplementedCiphers[]` order from `mozilla-esr140`. DTLS active probing
uses the same modern TLS-family cipher baseline. Exact Mozilla source URLs and
tables are documented in `active_scan.md`.

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

## Active Request Order

The active scanner uses strict, deterministic ordering. It does not randomize
cipher suites, supported groups, ALPN, signature algorithms, or protocol probes.

### Protocol Probe Order

```text
1. TLSv1.3
2. TLSv1.2
3. TLSv1.1
4. TLSv1.0
5. SSLv3
6. SSLv2
```

### TLS 1.3 ClientHello Cipher Order

For `TLSv1.3`, the scanner sends TLS 1.3 cipher suites first, then the TLS 1.2
cipher list for compatibility.

```text
1. TLS_AES_128_GCM_SHA256                  4865
2. TLS_CHACHA20_POLY1305_SHA256            4867
3. TLS_AES_256_GCM_SHA384                  4866
4. TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 49195
5. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   49199
6. TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 52393
7. TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   52392
8. TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 49196
9. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   49200
10. TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA   49162
11. TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA   49161
12. TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA     49171
13. TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     49172
14. TLS_RSA_WITH_AES_128_GCM_SHA256        156
15. TLS_RSA_WITH_AES_256_GCM_SHA384        157
16. TLS_RSA_WITH_AES_128_CBC_SHA           47
17. TLS_RSA_WITH_AES_256_CBC_SHA           53
```

### TLS 1.2 ClientHello Cipher Order

```text
1. TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 49195
2. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   49199
3. TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 52393
4. TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   52392
5. TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 49196
6. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   49200
7. TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    49162
8. TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    49161
9. TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      49171
10. TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     49172
11. TLS_RSA_WITH_AES_128_GCM_SHA256        156
12. TLS_RSA_WITH_AES_256_GCM_SHA384        157
13. TLS_RSA_WITH_AES_128_CBC_SHA           47
14. TLS_RSA_WITH_AES_256_CBC_SHA           53
```

### TLS 1.1 and TLS 1.0 ClientHello Cipher Order

```text
1. TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA 49162
2. TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA 49161
3. TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA   49171
4. TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA   49172
5. TLS_ECDHE_ECDSA_WITH_RC4_128_SHA     49159
6. TLS_ECDHE_RSA_WITH_RC4_128_SHA       49169
7. TLS_DHE_RSA_WITH_AES_128_CBC_SHA     51
8. TLS_DHE_DSS_WITH_AES_128_CBC_SHA     50
9. TLS_DHE_RSA_WITH_AES_256_CBC_SHA     57
10. TLS_RSA_WITH_AES_128_CBC_SHA        47
11. TLS_RSA_WITH_AES_256_CBC_SHA        53
12. TLS_RSA_WITH_3DES_EDE_CBC_SHA       10
13. TLS_RSA_WITH_RC4_128_SHA            5
14. TLS_RSA_WITH_RC4_128_MD5            4
```

### Active Extension and List Order

These lists are sent in strict order when the relevant extension is present:

```text
supported_groups:
1. x25519      29
2. secp256r1   23
3. secp384r1   24
4. secp521r1   25

ec_point_formats:
1. uncompressed 0

ALPN:
1. h2
2. http/1.1

TLS 1.3 supported_versions:
1. TLSv1.3 772
2. TLSv1.2 771

TLS 1.3 signature_algorithms:
1. rsa_pss_rsae_sha256       2052
2. rsa_pss_rsae_sha384       2053
3. ecdsa_secp256r1_sha256    1027
4. ecdsa_secp384r1_sha384    1283
5. rsa_pkcs1_sha256          1025
6. rsa_pkcs1_sha384          1281

TLS 1.2 signature_algorithms:
1. sha256+rsa
2. sha256+ecdsa
3. sha384+rsa
4. sha384+ecdsa
5. sha1+rsa
```

The TLS 1.3 key share contains one X25519 entry using the X25519 base point.
SNI is added when the target has a usable hostname and is not an IPv4 literal.

Arguments:

```text
fanything-tls.timeout=<milliseconds>
fanything-tls.tls-version=TLSv1.3|TLSv1.2|TLSv1.1|TLSv1.0|SSLv3|SSLv2
fanything-tls.force=true
```
