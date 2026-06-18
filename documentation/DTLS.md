# DTLS

FAN/1 DTLS fingerprints use the same TLS-family client and server fields, under
the `dtls` protocol namespace. Passive extraction reads DTLS records from UDP
datagrams. Active scanning sends a DTLS ClientHello and fingerprints the
ServerHello response.

```text
dtls|client|v=<dtls_version>|c=<cipher_suites>|e=<extensions>|g=<supported_groups>|p=<ec_point_formats>|sv=<supported_versions>|alpn=<alpn_protocols>|sig=<signature_algorithms>
dtls|server|v=<dtls_version>|c=<selected_cipher>|e=<extensions>|sv=<selected_supported_version>
```

## Client Fields

| Field | Length | Meaning |
| --- | --- | --- |
| `dtls` | fixed literal | Protocol namespace. |
| `client` | fixed literal | ClientHello proposal role. |
| `v` | variable numeric text | DTLS handshake version from ClientHello, for example `65277` for `0xfefd`. |
| `c` | variable list | Cipher suites advertised by client. Decimal values joined with `-`; wire order preserved; GREASE removed. |
| `e` | variable list | Extension types in ClientHello. Decimal values joined with `-`; wire order preserved; GREASE removed. |
| `g` | variable list | Supported groups from extension `10`. Decimal values joined with `-`; wire order preserved; GREASE removed. |
| `p` | variable list | EC point formats from extension `11`. Decimal byte values joined with `-`. |
| `sv` | variable list | Supported TLS/DTLS versions from extension `43` when present. |
| `alpn` | variable list | ALPN protocol names from extension `16`. Text values joined with `,`. |
| `sig` | variable list | Signature algorithms from extension `13`. Decimal values joined with `-`; wire order preserved; GREASE removed. |

## Server Fields

| Field | Length | Meaning |
| --- | --- | --- |
| `dtls` | fixed literal | Protocol namespace. |
| `server` | fixed literal | ServerHello selection role. |
| `v` | variable numeric text | DTLS handshake version from ServerHello. |
| `c` | variable numeric text | Cipher suite selected by server. |
| `e` | variable list | Extension types in ServerHello. Decimal values joined with `-`; wire order preserved; GREASE removed. |
| `sv` | variable numeric text | Selected version from extension `43`; empty when absent. |

Empty fields are represented as empty strings.

## DTLS Differences

DTLS records are carried over UDP and include an epoch, record sequence number,
and DTLS handshake fragmentation fields. `fanfp.py` extracts only complete
ClientHello and ServerHello handshake fragments today. Fragmented handshakes are
ignored until all fragments are available in one datagram parser path.

DTLS ClientHello has a cookie field between `session_id` and `cipher_suites`.
The cookie is not included in the feature string because it is responder-chosen
anti-amplification state rather than an implementation capability signal.

Common version values:

| Decimal | Hex | Meaning |
| --- | --- | --- |
| `65279` | `0xfeff` | DTLS 1.0 |
| `65277` | `0xfefd` | DTLS 1.2 |
| `65276` | `0xfefc` | DTLS 1.3 selected version value |

## Passive Extraction

`fanfp.py` scans UDP datagrams for DTLS records. It emits `client` fingerprints
from ClientHello and `server` fingerprints from ServerHello. GREASE handling and
list ordering match TLS extraction.

Example from `pcap/dtls-udp.notest.cap`:

```text
dtls|client|v=65279|c=49172-49162-49186-49185-57-56-136-135-49167-49157-53-132-49170-49160-49180-49179-22-19-49165-49155-10-49171-49161-49183-49182-51-50-154-153-69-68-49166-49156-47-150-65-21-18-9-20-17-8-6-255|e=35-15|g=|p=|sv=|alpn=|sig=
dtls|server|v=65279|c=53|e=65281-35-15|sv=
```

## Active Request Defaults

`fanything-dtls.nse` sends DTLS ClientHello probes over UDP and emits
`dtls|server|...`.

DTLS active cipher lists use the same current Firefox LTS/ESR baseline as the
TLS active scanner: Firefox ESR 140 series, latest listed ESR point release
`140.12.0` when checked on 2026-06-18, using NSS `SSL_ImplementedCiphers[]`
order from `mozilla-esr140`. DTLS 1.3 sends the TLS 1.3 suites first, then the
TLS 1.2 compatibility list. Exact Mozilla source URLs and tables are documented
in `active_scan.md`.

| Default | Value |
| --- | --- |
| Transport | UDP |
| Ports/services | Nmap likely-DTLS SSL ports such as UDP/443, 4433, 5684, 5349, 10161, unless `fanything-dtls.force` is set |
| Timeout | `5000` ms |
| Probe order | `DTLSv1.3`, `DTLSv1.2`, then `DTLSv1.0` |
| Cookie handling | Retry once when responder sends `HelloVerifyRequest` |
| Output role | `server` |
| Output mode | `active` |

Arguments:

```text
fanything-dtls.timeout=<milliseconds>
fanything-dtls.dtls-version=DTLSv1.3|DTLSv1.2|DTLSv1.0
fanything-dtls.force=true
```
