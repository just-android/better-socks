# better-socks

Asynchronous SOCKS5 client for Tokio. This is a fork

Username/password authentication (RFC 1929) is sent in **cleartext** to the
proxy. This crate does not provide TLS-to-proxy.

## Features

- [x] `CONNECT` command
- [x] `BIND` command
- [x] `ASSOCIATE` command (UDP relay via `udp::Socks5UdpFramed`)
- [x] Username/password authentication
- [ ] GSSAPI authentication
- [x] Asynchronous DNS resolution (`tokio::net::lookup_host`)
- [x] Chain proxies ([see example](examples/chainproxy.rs))
- [ ] SOCKS4

The `tor` feature enables Tor `RESOLVE` / `RESOLVE_PTR` commands. It has no
extra dependencies; the proxy must implement those extensions.
