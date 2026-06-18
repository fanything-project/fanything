# fanything

> [!WARNING]  
> The format is still in alpha design. If you see anything concerning the extensibility of the format, let us know.

<img width="200" height="239" alt="f" src="https://github.com/user-attachments/assets/e2e096fd-1ae5-4090-92b8-1e0a2fe85a4a" />


`fanything` is an awesome, patent-unencumbered fingerprinting format for correlating SSH, TLS, X.509 certificate, QUIC, IKE, and TCP/IP stack behavior.

The repository defines an algorithm named **FAN/1** (Flexible Anything
Network fingerprint, version 1). FAN/1 is intentionally simple: each
fingerprint starts with an explicit namespace, keeps a readable normalized
feature string for analysts, appends a stable SHA-256 digest for indexing in
systems such as MISP, and can include a 128-bit SimHash companion value for
similarity comparisons.

## FAN/1 fingerprint format

A fingerprint has five semantic parts:

```text
fan1:<protocol>:<role>:<mode>:<base64url-normalized-features>:<digest-algorithm>:<hex-digest>
```

* `fan1` identifies the algorithm version.
* `<protocol>` is currently `tls`, `x509`, `ssh`, `quic`, `ike`, or `tcpip`, but the
  namespace can be extended to other services and transport behaviors.
* `<role>` identifies handshake direction, for example `client`, `server`, or
  `peer`.
* `<mode>` is `active` or `passive`.
* `<base64url-normalized-features>` is the normalized canonical feature string,
  encoded without padding so it remains safe in JSON, CSV, MISP attributes, and
  URLs.
* `<digest-algorithm>` identifies the digest that follows. `sha256` is the
  required exact-match digest. `simhash128` is the optional similarity digest.
* `<hex-digest>` is the lowercase hexadecimal digest value for the named
  algorithm. For `sha256`, it is SHA-256 over the unencoded canonical feature
  string.

The canonical FAN/1 fingerprint string should use `sha256` when exact identity
is required:

```text
fan1:<protocol>:<role>:<mode>:<base64url-normalized-features>:sha256:<hex-digest>
```

Collectors may also calculate a `simhash128` value over normalized feature
tokens and expose it either as metadata or as an alternate FAN/1 string with the
`simhash128` digest algorithm. SimHash is not a cryptographic identity digest;
it is useful because the Hamming distance between two 128-bit SimHashes can be
used to estimate how close two canonical feature strings are. This helps
analysts find related client, server, or peer behaviors that differ by a few
negotiated algorithms or extensions.

The JSON output also includes the plain `features` field so analysts can inspect
and pivot on individual parts without decoding the fingerprint.

## Active and passive collection

FAN/1 fingerprints can be collected in two modes:

* `passive` means the collector does not interact with the endpoint. It only
  parses traffic that was already observed, for example from a pcap file.
  `fanfp.py` is passive and emits `"mode":"passive"` in each JSON object and
  in each FAN/1 fingerprint prefix.
* `active` means the collector creates its own network interaction with the
  endpoint. The NSE scripts `fanything-tls.nse` and `fanything-ssh.nse` are
  active: they connect to the target, send protocol probes, emit `mode: active`
  in Nmap output, and embed `active` in each FAN/1 fingerprint prefix.

The collection mode is part of the FAN/1 prefix and output metadata, but not the
normalized feature string. Store `mode` as metadata too, so active probes and
passive observations can be filtered without parsing the fingerprint.

## Role model

The `role` component describes which side of the protocol behavior is being
fingerprinted. Keeping the role in the primary fingerprint string prevents
collisions between values that may have similar feature lists but very different
correlation meaning.

* `client` is used when the observed handshake message is an initiator proposal.
  For TLS this means the ClientHello: supported protocol versions, cipher suite
  order, extension order, supported groups, signature algorithms, and ALPN
  values. A `client` fingerprint answers: "what implementation or tool appears
  to be initiating connections?"
* `server` is used when the observed handshake message is a responder selection.
  For TLS this means the ServerHello: selected protocol version, selected cipher
  suite, and server extensions. A `server` fingerprint answers: "what service
  behavior appears to be answering connections?"
* `peer` is used when the protocol exposes comparable active-handshake
  characteristics from both sides, or when the extractor cannot reliably assign
  a stricter initiator/responder label from a single payload. SSH uses `peer`
  because both endpoints send an identification string and a `SSH_MSG_KEXINIT`
  packet with the same family of proposal lists. A `peer` fingerprint answers:
  "what SSH implementation behavior did this endpoint advertise?"
* For TCP/IP stack fingerprints, `client` identifies a SYN without ACK and
  `server` identifies a SYN-ACK. These roles answer: "what TCP/IP stack
  behavior appeared in the connection setup packet?"

In practical correlation, treat `client`, `server`, and `peer` as different
attribute types even when the same protocol is involved. For example, a TLS
client fingerprint should be correlated with other TLS client observations, not
with TLS server observations, because the canonical feature strings represent
different handshake semantics.

### TLS client fingerprints

TLS client fingerprints are built from ClientHello fields:

```text
tls|client|v=<legacy_version>|c=<cipher_suites>|e=<extensions>|g=<supported_groups>|p=<ec_point_formats>|sv=<supported_versions>|alpn=<alpn_protocols>|sig=<signature_algorithms>
```

TLS server fingerprints are built from ServerHello fields:

```text
tls|server|v=<legacy_version>|c=<selected_cipher>|e=<extensions>|sv=<selected_supported_version>
```

Active TLS fingerprints come from probes generated by a scanner. Passive TLS
fingerprints come from observed traffic. The mode is carried outside this
canonical feature string, in the FAN/1 prefix and metadata.

Normalization rules:

* Values are decimal integers unless the source value is text, such as ALPN.
* Lists preserve wire order because order is often behaviorally meaningful.
* GREASE values are removed from TLS lists before canonicalization.
* Missing fields are represented as empty strings.



### X.509 certificate fingerprints

Passive TLS captures can also expose server Certificate handshake messages.
`fanfp.py` parses DER-encoded X.509 certificates from those messages and emits a
separate `x509` protocol fingerprint for each certificate in the observed chain.
The feature string is designed for similarity matching between certificates
created by the same software, CA profile, appliance, or generation workflow, so
it records certificate structure, OIDs, names, extension layout, and validity
shape rather than depending only on a raw certificate hash.

```text
x509|server|idx=<chain_index>|ver=<x509_version>|serial_len=<serial_byte_length>|sig=<outer_signature_algorithm_oid>|tbs_sig=<tbs_signature_algorithm_oid>|issuer=<issuer_name_oid_values>|subject=<subject_name_oid_values>|valid_days=<validity_window_days>|spki_alg=<subject_public_key_algorithm_oid>|spki_param=<algorithm_parameter_oid_or_der>|pk_bits=<subject_public_key_bit_string_size>|san=<subject_alt_names>|ku=<key_usage_bits>|eku=<extended_key_usage_oids>|bc=<basic_constraints>|ski=<subject_key_identifier_shape>|aki=<authority_key_identifier_shape>|pol=<certificate_policy_oids>|aia=<authority_info_access_shape>|crldp=<crl_distribution_point_shape>|nc=<name_constraints_shape>|ext=<critical_flag_and_extension_oid_order>
```

Normalization rules:

* Object identifiers are emitted in dotted decimal form and extension order is
  preserved because OID choices and ordering can identify certificate generation
  stacks.
* Name attributes are emitted as `oid=value` pairs in DER order.
* DNS, IP, email, URI, and OID Subject Alternative Names are decoded when
  possible; complex GeneralName values are represented by short stable hashes.
* Potentially large structured extensions such as AIA, CRL distribution points,
  name constraints, SKI, and AKI are represented by short SHA-256-derived shape
  tokens so the fingerprint remains compact.
* `serial_len` and `valid_days` capture generation-profile behavior without
  forcing every regenerated certificate to have a different similarity shape.

See [documentation/X509.md](documentation/X509.md) for the complete field
reference.

### TCP/IP stack fingerprints

TCP/IP stack fingerprints are passive, single-packet fingerprints for TCP SYN
and SYN-ACK packets. They are intentionally close to the SinFP family of TCP/IP
stack signatures while remaining within the FAN/1 feature-string model. The
extractor records IP-level signals, TCP header values, ordered TCP options, and
packet quirks that are useful for implementation and operating-system
correlation.

```text
tcpip2|<role>|ip=<ip_version>|ttl=<observed_ttl_or_hop_limit>|it=<initial_ttl_bucket>|olen=<tcp_options_length>|win=<tcp_window>|mss=<mss>|ws=<window_scale>|sack=<0_or_1>|ts=<zero_or_nz>|opts=<ordered_tcp_options>|df=<0_or_1>|plen=<tcp_payload_length>|ql=<quirks>
```

Roles:

* `client` is emitted for SYN packets without ACK.
* `server` is emitted for SYN-ACK packets.

Normalization rules:

* TCP option order is preserved because option layout is behaviorally
  meaningful.
* Recognized options are normalized as `mss<value>`, `ws<value>`, `sackok`,
  `sack<length>`, `ts`, `tfo`, `nop`, and `eol`; unknown options are retained
  as `opt<kind>:<hex_payload>`.
* The `it` field buckets observed TTL/hop-limit to common initial values: `32`,
  `64`, `128`, or `255`.
* Missing option-derived values are emitted as empty strings, and SACK-permitted
  is emitted as `0` or `1`.
* Quirk flags are sorted and de-duplicated; currently emitted quirks include
  malformed/truncated options, non-zero EOL padding, SYN payloads, missing IPv4
  DF, non-zero IPv4 ID with DF, and non-zero timestamp echo in SYN/SYN-ACK.

See [documentation/TCPIP.md](documentation/TCPIP.md) for the complete TCP/IP
stack fingerprint field reference.

### SSH fingerprints

SSH fingerprints combine the cleartext identification string with the
`SSH_MSG_KEXINIT` proposal lists.

```text
ssh|peer|id=<software_id>|kex=<kex_algorithms>|hostkey=<server_host_key_algorithms>|enc_c2s=<encryption_algorithms_client_to_server>|enc_s2c=<encryption_algorithms_server_to_client>|mac_c2s=<mac_algorithms_client_to_server>|mac_s2c=<mac_algorithms_server_to_client>|comp_c2s=<compression_algorithms_client_to_server>|comp_s2c=<compression_algorithms_server_to_client>|lang_c2s=<languages_client_to_server>|lang_s2c=<languages_server_to_client>|follows=<first_kex_packet_follows>
```

Normalization rules:

* The protocol prefix in the identification line is removed, leaving the
  implementation software string.
* Comma-separated algorithm lists preserve wire order.
* Missing fields are represented as empty strings.

### QUIC fingerprints

QUIC fingerprints are built from QUIC Initial packets. When Python
`cryptography` is available, `fanfp.py` derives QUIC Initial secrets for QUIC v1
and draft-29, decrypts CRYPTO frames, reassembles the TLS handshake stream, and
emits TLS-derived client or server features under the `quic` protocol:

```text
quic|client|v=<quic_version>|tls_v=<legacy_tls_version>|c=<cipher_suites>|e=<extensions>|g=<supported_groups>|p=<ec_point_formats>|sv=<supported_versions>|alpn=<alpn_protocols>|sig=<signature_algorithms>
quic|server|v=<quic_version>|tls_v=<legacy_tls_version>|c=<selected_cipher>|e=<extensions>|sv=<selected_supported_version>
```

If Initial decryption is unavailable, the extractor falls back to QUIC long
header metadata:

```text
quic|peer|v=<quic_version>|type=initial|dcid_len=<destination_connection_id_length>|scid_len=<source_connection_id_length>|token_len=<token_length>|len=<packet_length>
```

Normalization rules:

* QUIC and TLS version values are decimal integers.
* TLS list fields follow the same normalization rules as TCP TLS fingerprints.
* The mode is carried outside the canonical feature string, in the FAN/1 prefix
  and metadata.

## Usage

Passive pcap extraction:

```bash
python3 fanfp.py capture.pcap
python3 fanfp.py test/chromium-perdu.com-quick.pcap
```

Malformed TLS records are skipped by default so one truncated frame does not stop
processing the rest of the capture. Use `--strict` to raise parsing errors, or
`--verbose-errors` to print skipped malformed record details to stderr.

The command emits one JSON object per fingerprint:

```json
{"mode":"passive","protocol":"tls","role":"client","fingerprint":"fan1:tls:client:passive:...:sha256:...","fingerprint_simhash128":"fan1:tls:client:passive:...:simhash128:...","features":"tls|client|...","sha256":"...","simhash128":"...","flow":{"src":"192.0.2.10","sport":51514,"dst":"198.51.100.20","dport":443}}
```

Cluster similar observations by SimHash distance:

```bash
python3 fanfp.py capture.pcap > fanfp.jsonl
python3 fanfp_cluster.py fanfp.jsonl
python3 fanfp_cluster.py --threshold 8 --format json fanfp.jsonl
```

`fanfp_cluster.py` reads JSON Lines, concatenated JSON objects, a single JSON
object, or a JSON array from a file or stdin. It compares the `simhash128`
values with Hamming distance, groups records at or below the threshold, and prints the matching
flow pairs so analysts can see which observed flows are close to each other.
The default threshold is `12` bits out of 128. By default, comparisons are kept
within the same `protocol`, `role`, and `mode`; use `--cross-roles` if you want
to compare every record against every other record.

Active service probing with Nmap NSE:

```bash
nmap -Pn -p443 --script ./fanything-tls.nse 192.0.2.20
nmap -Pn -p22 --script ./fanything-ssh.nse 192.0.2.20
```

The TLS NSE script probes TLS in this order: `TLSv1.3`, `TLSv1.2`, `TLSv1.1`,
`TLSv1.0`, `SSLv3`, then `SSLv2`, and stops at the first full server
fingerprint. A single protocol version can be forced for testing:

```bash
nmap -Pn -p443 --script ./fanything-tls.nse --script-args fanything-tls.tls-version=TLSv1.2 192.0.2.20
```

Cipher tables are version-oriented in the script. See [active_scan.md](active_scan.md)
for cipher-suite rationale and the Firefox/NSS source references used for TLS
1.3, TLS 1.2, and historical SSLv3-era ordering.

The SSH NSE script sends an SSH identification string, reads the server
identification string and `SSH_MSG_KEXINIT` when available, then emits the same
`ssh|peer|...` feature shape as `fanfp.py`. If a server only provides a banner,
the algorithm-list fields are emitted empty, matching passive extraction.

Local NSE testing against OpenSSL servers:

```bash
test/nse-openssl.sh
test/nse-ssh.py
test/fanfp-quic.sh
```

Local QUIC fixture test:

```bash
test/fanfp-quic.sh
```
The test harness creates a temporary certificate, starts `openssl s_server` for
`TLSv1.3`, `TLSv1.2`, `TLSv1.1`, and `TLSv1.0`, runs `fanything-tls.nse` against
each server, verifies default scan stops at the first successful TLS version,
and prints the observed `features` and `fingerprint` values. `SSLv3` and
`SSLv2` are reported as skipped when the local OpenSSL build no longer provides
those server modes. The SSH harness starts a deterministic local SSH test
server and validates `fanything-ssh.nse`. The QUIC harness validates passive
QUIC Initial extraction against the Chromium pcap fixture.

## MISP correlation hints

Recommended storage approaches:

* Store `fingerprint` as the primary correlation value.
* Store `sha256` as a compact secondary pivot.
* Store `simhash128` or `fingerprint_simhash128` as a similarity pivot when you
  want to calculate Hamming distances between fingerprints and cluster near
  matches.
* Store `features` in a comment, object attribute, or custom object field for
  analyst readability.
* Store `mode` as collection metadata so active probes and passive observations
  can be filtered independently.
* Keep the `flow` and `frame` metadata when available so events can be traced
  back to packets.

Because FAN/1 embeds the protocol, role, and collection mode in the fingerprint,
mixed SSH, TLS, QUIC, and future service fingerprints can share the same
attribute namespace without losing type information.
