# FAN/1 TCP/IP stack fingerprints

FAN/1 TCP/IP stack fingerprints use the `tcpip2|...` feature string and are
emitted under `protocol="tcpip"`. They are passive fingerprints derived from
TCP connection setup packets, not from application payloads.

The design is intentionally close to the SinFP family of TCP/IP stack
fingerprints: it focuses on a compact set of stable signals visible in a single
SYN or SYN-ACK packet. FAN/1 stores those signals as readable fields and then
wraps them in the normal `fan1:<protocol>:<role>:<mode>:...` fingerprint format.

## Roles

* `client` means the packet is a TCP SYN without ACK.
* `server` means the packet is a TCP SYN-ACK.

TCP packets with RST or FIN are ignored by this fingerprint type. Non-SYN TCP
traffic can still be used by other extractors, such as TLS or SSH, when it
contains application handshake payloads.

## Feature string

```text
tcpip2|<role>|ip=<ip_version>|ttl=<observed_ttl_or_hop_limit>|it=<initial_ttl_bucket>|olen=<tcp_options_length>|win=<tcp_window>|mss=<mss>|ws=<window_scale>|sack=<0_or_1>|ts=<zero_or_nz>|opts=<ordered_tcp_options>|df=<0_or_1>|plen=<tcp_payload_length>|ql=<quirks>
```

Fields:

| Field | Meaning |
| --- | --- |
| `ip` | IP version, currently `4` or `6`. |
| `ttl` | Observed IPv4 TTL or IPv6 hop limit. |
| `it` | Bucketed likely initial TTL/hop-limit: `32`, `64`, `128`, or `255`. |
| `olen` | TCP option byte length. |
| `win` | TCP advertised window. |
| `mss` | MSS option value when present. |
| `ws` | Window scale option value when present. |
| `sack` | `1` when SACK-permitted is present, otherwise `0`. |
| `ts` | `zero` or `nz` when a timestamp option is present, otherwise empty. |
| `opts` | Ordered TCP option layout. |
| `df` | IPv4 Don't Fragment flag as `0` or `1`; IPv6 emits `0`. |
| `plen` | TCP payload length in the SYN/SYN-ACK packet. |
| `ql` | Sorted, de-duplicated quirk flags. |

## TCP option normalization

Option order is preserved. Recognized options are normalized as follows:

| Option | Token |
| --- | --- |
| End of option list | `eol` |
| No operation | `nop` |
| Maximum segment size | `mss<value>` |
| Window scale | `ws<value>` |
| SACK permitted | `sackok` |
| SACK blocks | `sack<length>` |
| Timestamp | `ts` |
| TCP Fast Open | `tfo` |
| Unknown option | `opt<kind>:<hex_payload>` |
| Truncated or malformed option | `bad<kind>` |

## Quirk flags

The `ql` field records packet properties that often help distinguish TCP/IP
stack behavior or middlebox rewriting:

* `bad-opt-len`: an option length is invalid or extends past the option area.
* `trunc-opt`: an option kind appears without a length byte.
* `nz-eol-pad`: bytes after EOL are not all zero.
* `data-in-syn`: the SYN/SYN-ACK carries payload bytes.
* `no-df`: IPv4 packet does not set the Don't Fragment bit.
* `df-nz-id`: IPv4 packet sets DF while retaining a non-zero IP ID.
* `ts-echo-nz`: TCP timestamp echo field is non-zero.

## Example

```text
tcpip2|client|ip=4|ttl=64|it=64|olen=20|win=64240|mss=1460|ws=7|sack=1|ts=nz|opts=mss1460,sackok,ts,nop,ws7|df=1|plen=0|ql=df-nz-id
```

This example describes an IPv4 client SYN with TTL 64, MSS 1460, SACK permitted,
timestamps, window scale 7, and a non-zero IP ID while DF is set.
