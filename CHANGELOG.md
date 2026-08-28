# Unreleased (better-socks fork)

* Fix SOCKS5 UDP domain-name decoding (`ATYP=0x03`).
* Treat header-only UDP datagrams as valid empty payloads; reject truncated
  datagrams and nonzero `FRAG`.
