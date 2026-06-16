# fanything

`fanything` is an experimental, patent-unencumbered fingerprinting format and
pcap extractor for correlating SSH and TLS handshakes.

The repository defines a small algorithm named **FAN/1** (Flexible Active
Network fingerprint, version 1). FAN/1 is intentionally simple: each
fingerprint starts with an explicit namespace, keeps a readable normalized
feature string for analysts, and appends a stable SHA-256 digest for indexing in
systems such as MISP.

## FAN/1 fingerprint format

A fingerprint has four parts:

```text
fan1:<protocol>:<role>:<base64url-normalized-features>:sha256:<hex-digest>
```

* `fan1` identifies the algorithm version.
* `<protocol>` is currently `tls` or `ssh`, but the namespace can be extended to
  other services.
* `<role>` identifies handshake direction, for example `client`, `server`, or
  `peer`.
* `<base64url-normalized-features>` is the normalized canonical feature string,
  encoded without padding so it remains safe in JSON, CSV, MISP attributes, and
  URLs.
* `<hex-digest>` is SHA-256 over the unencoded canonical feature string.

The JSON output also includes the plain `features` field so analysts can inspect
and pivot on individual parts without decoding the fingerprint.

### TLS client fingerprints

TLS client fingerprints are built from ClientHello fields:

```text
tls|client|v=<legacy_version>|c=<cipher_suites>|e=<extensions>|g=<supported_groups>|p=<ec_point_formats>|sv=<supported_versions>|alpn=<alpn_protocols>|sig=<signature_algorithms>
```

TLS server fingerprints are built from ServerHello fields:

```text
tls|server|v=<legacy_version>|c=<selected_cipher>|e=<extensions>|sv=<selected_supported_version>
```

Normalization rules:

* Values are decimal integers unless the source value is text, such as ALPN.
* Lists preserve wire order because order is often behaviorally meaningful.
* GREASE values are removed from TLS lists before canonicalization.
* Missing fields are represented as empty strings.

### SSH fingerprints

SSH fingerprints combine the cleartext identification string with the active
`SSH_MSG_KEXINIT` proposal lists.

```text
ssh|peer|id=<software_id>|kex=<kex_algorithms>|hostkey=<server_host_key_algorithms>|enc_c2s=<encryption_algorithms_client_to_server>|enc_s2c=<encryption_algorithms_server_to_client>|mac_c2s=<mac_algorithms_client_to_server>|mac_s2c=<mac_algorithms_server_to_client>|comp_c2s=<compression_algorithms_client_to_server>|comp_s2c=<compression_algorithms_server_to_client>|lang_c2s=<languages_client_to_server>|lang_s2c=<languages_server_to_client>|follows=<first_kex_packet_follows>
```

Normalization rules:

* The protocol prefix in the identification line is removed, leaving the
  implementation software string.
* Comma-separated algorithm lists preserve wire order.
* Missing fields are represented as empty strings.

## Usage

```bash
python3 fanfp.py capture.pcap
```

The command emits one JSON object per fingerprint:

```json
{"protocol":"tls","role":"client","fingerprint":"fan1:tls:client:...","features":"tls|client|...","sha256":"...","flow":{"src":"192.0.2.10","sport":51514,"dst":"198.51.100.20","dport":443}}
```

## MISP correlation hints

Recommended storage approaches:

* Store `fingerprint` as the primary correlation value.
* Store `sha256` as a compact secondary pivot.
* Store `features` in a comment, object attribute, or custom object field for
  analyst readability.
* Keep the `flow` and `frame` metadata when available so events can be traced
  back to packets.

Because FAN/1 embeds the protocol and role in the fingerprint, mixed SSH, TLS,
and future service fingerprints can share the same attribute namespace without
losing type information.
