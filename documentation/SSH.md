# SSH

FAN/1 SSH fingerprints use the `ssh|peer|...` feature string. SSH uses `peer`
because both endpoints expose comparable identification and proposal data.

```text
ssh|peer|id=<software_id>|kex=<kex_algorithms>|hostkey=<server_host_key_algorithms>|enc_c2s=<encryption_algorithms_client_to_server>|enc_s2c=<encryption_algorithms_server_to_client>|mac_c2s=<mac_algorithms_client_to_server>|mac_s2c=<mac_algorithms_server_to_client>|comp_c2s=<compression_algorithms_client_to_server>|comp_s2c=<compression_algorithms_server_to_client>|lang_c2s=<languages_client_to_server>|lang_s2c=<languages_server_to_client>|follows=<first_kex_packet_follows>
```

## Fields

| Field | Length | Meaning |
| --- | --- | --- |
| `ssh` | fixed literal | Protocol namespace. |
| `peer` | fixed literal | Role used for SSH endpoint behavior. |
| `id` | variable | Software part of SSH identification string, with `SSH-<proto>-` removed when possible. |
| `kex` | variable list | SSH key exchange algorithms from `SSH_MSG_KEXINIT`. Comma-separated, wire order preserved. |
| `hostkey` | variable list | Server host key algorithms. Comma-separated, wire order preserved. |
| `enc_c2s` | variable list | Encryption algorithms from client to server. Comma-separated, wire order preserved. |
| `enc_s2c` | variable list | Encryption algorithms from server to client. Comma-separated, wire order preserved. |
| `mac_c2s` | variable list | MAC algorithms from client to server. Comma-separated, wire order preserved. |
| `mac_s2c` | variable list | MAC algorithms from server to client. Comma-separated, wire order preserved. |
| `comp_c2s` | variable list | Compression algorithms from client to server. Comma-separated, wire order preserved. |
| `comp_s2c` | variable list | Compression algorithms from server to client. Comma-separated, wire order preserved. |
| `lang_c2s` | variable list | Language tags from client to server. Usually empty. |
| `lang_s2c` | variable list | Language tags from server to client. Usually empty. |
| `follows` | variable text | `True` or `False` when `first_kex_packet_follows` is present; empty if unavailable. |

Empty fields are represented as empty strings.

## Passive Extraction

`fanfp.py` parses cleartext SSH identification lines and the following
`SSH_MSG_KEXINIT` packet when available. If only the banner is present, all
proposal-list fields are empty.

## Active Request Defaults

`fanything-ssh.nse` sends one SSH identification line and reads server behavior.

| Default | Value |
| --- | --- |
| Client identification | `SSH-2.0-Nmap-FANFP` |
| Timeout | `5000` ms |
| Port/service rule | TCP/22 or service `ssh` unless `fanything-ssh.force` is set |
| KEXINIT sent by scanner | none |
| Output role | `peer` |
| Output mode | `active` |

Arguments:

```text
fanything-ssh.timeout=<milliseconds>
fanything-ssh.client-id=<identification_string>
fanything-ssh.force=true
```
