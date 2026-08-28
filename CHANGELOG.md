# Unreleased (better-socks fork)

* Fix SOCKS5 UDP domain-name decoding (`ATYP=0x03`).
* Treat header-only UDP datagrams as valid empty payloads; reject truncated
  datagrams and nonzero `FRAG`.
* Resolve proxy hostnames with `tokio::net::lookup_host` instead of blocking
  `ToSocketAddrs`.
* Try every resolved proxy address on connect failure and preserve the last I/O
  error.
* Replace `From<TargetAddr> for SocketAddr` with `TryFrom` so domain targets
  cannot silently become `0.0.0.0:0`.
* Map unknown SOCKS reply codes to `UnknownError`; do not panic on unexpected
  auth methods or after a `ProxyAddrsStream` error.
* Allow empty RFC 1929 passwords; reject UDP domain names longer than 255 bytes.
