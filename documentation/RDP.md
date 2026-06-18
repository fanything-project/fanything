# RDP

FAN/1 RDP fingerprints currently cover the initial TPKT/X.224 connection
exchange used before the later RDP security layers. The extractor is passive and
does not parse MCS, CredSSP, or encrypted RDP traffic.

```text
rdp|client|tpkt_v=<tpkt_version>|tpkt_rsv=<tpkt_reserved>|tpkt_len=<tpkt_length>|x224_len=<x224_length_indicator>|pdu=<x224_pdu_type>|dst_ref=<destination_reference>|src_ref=<source_reference>|class=<class_option>|neg_type=<rdp_negotiation_type>|neg_flags=<rdp_negotiation_flags>|neg_len=<rdp_negotiation_length>|neg_proto=<requested_protocols>|neg_selected=<selected_protocol>
rdp|server|tpkt_v=<tpkt_version>|tpkt_rsv=<tpkt_reserved>|tpkt_len=<tpkt_length>|x224_len=<x224_length_indicator>|pdu=<x224_pdu_type>|dst_ref=<destination_reference>|src_ref=<source_reference>|class=<class_option>|neg_type=<rdp_negotiation_type>|neg_flags=<rdp_negotiation_flags>|neg_len=<rdp_negotiation_length>|neg_proto=<requested_protocols>|neg_selected=<selected_protocol>
```

## Fields

| Field | Meaning |
| --- | --- |
| `rdp` | Protocol namespace. |
| `client` / `server` | `client` for X.224 Connection Request, `server` for X.224 Connection Confirm. |
| `tpkt_v` | TPKT version byte. Normal RDP value: `3`. |
| `tpkt_rsv` | TPKT reserved byte. Normal value: `0`. |
| `tpkt_len` | TPKT length field, including TPKT header. |
| `x224_len` | X.224 length indicator byte as observed. |
| `pdu` | X.224 PDU type byte. Connection Request is `224` (`0xe0`), Connection Confirm is `208` (`0xd0`). |
| `dst_ref` | X.224 destination reference. |
| `src_ref` | X.224 source reference. |
| `class` | X.224 class/options byte. |
| `neg_type` | RDP Negotiation Request/Response type if present in the same TPKT. |
| `neg_flags` | RDP Negotiation flags if present. |
| `neg_len` | RDP Negotiation structure length if present. |
| `neg_proto` | Requested protocols from an RDP Negotiation Request (`neg_type=1`). |
| `neg_selected` | Selected protocol from an RDP Negotiation Response (`neg_type=2`). |

Empty negotiation fields are represented as empty strings.

## Passive Extraction

`fanfp.py` scans TCP payloads for TPKT packets with X.224 Connection Request or
Connection Confirm PDUs. If an RDP Negotiation Request or Response follows in
the same TPKT, its fixed fields are included in the same fingerprint. The
parser tolerates the optional `Cookie: mstshash=...` routing field before the
RDP Negotiation structure. Later RDP layers are intentionally out of scope for
this feature.

Example from `pcap/rdp.pcap`:

```text
rdp|client|tpkt_v=3|tpkt_rsv=0|tpkt_len=19|x224_len=14|pdu=224|dst_ref=0|src_ref=0|class=0|neg_type=1|neg_flags=0|neg_len=8|neg_proto=3|neg_selected=
rdp|server|tpkt_v=3|tpkt_rsv=0|tpkt_len=19|x224_len=14|pdu=208|dst_ref=0|src_ref=4660|class=0|neg_type=2|neg_flags=1|neg_len=8|neg_proto=|neg_selected=2
```

## Active Scanning

`fanything-rdp.nse` actively sends a TPKT/X.224 Connection Request with an RDP
Negotiation Request and fingerprints the responder as `rdp|server|...`.

Default request:

| Default | Value |
| --- | --- |
| Port/service rule | TCP 3389 or RDP-like service unless `fanything-rdp.force` is set |
| Timeout | `5000` ms |
| Requested protocols | `11` (`SSL`, `HYBRID`, `HYBRID_EX`) |
| Output role | `server` |
| Output mode | `active` |

Arguments:

```text
fanything-rdp.timeout=<milliseconds>
fanything-rdp.requested-protocols=<decimal_bitmask>
fanything-rdp.force=true
```
