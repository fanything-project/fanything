# Release Notes

## Unreleased

* Add DTLS passive extraction in `fanfp.py` and active UDP probing with
  `fanything-dtls.nse`, probing DTLS 1.3, 1.2, then 1.0.
* Document DTLS FAN/1 feature strings and active scan defaults.
* Document TLS and DTLS active cipher-suite ordering against Firefox ESR 140 /
  NSS `SSL_ImplementedCiphers[]`.
* Add passive RDP TPKT/X.224 Connection Request and Connection Confirm
  fingerprinting, including same-packet RDP Negotiation fields.
* Add active RDP X.224 probing with `fanything-rdp.nse`.
