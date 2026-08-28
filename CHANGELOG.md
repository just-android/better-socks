# Unreleased (better-socks fork)

* Fix SOCKS5 UDP domain-name decoding (`ATYP=0x03`).
* Treat header-only UDP datagrams as valid empty payloads; reject truncated
  datagrams and nonzero `FRAG`.
* Resolve proxy hostnames with `tokio::net::lookup_host` instead of blocking
  `ToSocketAddrs`.
* Try every resolved proxy address on connect failure and preserve the last I/O
  error.
