# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/just-android/better-socks/compare/v0.1.1...v0.1.2) - 2026-08-28

### Fixed

- *(test)* resolve script path and require 3proxy configs

### Other

- *(ci)* cap test job at 20 minutes
- *(ci)* run workflows on ubuntu-latest

## [0.1.1](https://github.com/just-android/better-socks/compare/v0.1.0...v0.1.1) - 2026-08-28

### Other

- *(release)* enable crates.io publish via trusted publishing
- *(ci)* grant OIDC token for crates.io trusted publishing

## [0.1.0](https://github.com/just-android/better-socks/releases/tag/v0.1.0) - 2026-08-28

### Added

- *(test)* add integration runner script
- *(test)* add 3proxy long-credential config
- *(test)* add 3proxy username-auth config
- *(test)* add 3proxy no-auth config
- *(test)* add long-credential tests
- *(test)* add username-password tests
- *(test)* add no-auth CONNECT and BIND tests
- *(test)* add integration helpers
- *(example)* add Tor Unix-socket example
- *(example)* add Tor TCP example
- *(example)* add chainproxy example
- *(udp)* reject truncated and fragmented UDP
- *(udp)* test UDP codec roundtrips
- *(udp)* encode SOCKS5 UDP datagrams
- *(udp)* decode SOCKS5 UDP datagrams
- *(udp)* add UDP codec constructors
- *(udp)* impl Stream and Sink for Socks5UdpFramed
- *(udp)* connect UDP ASSOCIATE
- *(udp)* add Socks5UdpFramed types
- *(tcp)* impl AsyncRead and AsyncWrite
- *(tcp)* accept BIND second reply
- *(tcp)* add Socks5Listener bind
- *(tcp)* parse SOCKS reply
- *(tcp)* run RFC 1929 password auth
- *(tcp)* encode CONNECT request
- *(tcp)* encode method selection and password
- *(tcp)* add SocksConnector execute loop
- *(tcp)* connect and associate with a socket
- *(tcp)* connect associate and Tor over TcpStream
- *(tcp)* add Socks5Stream with Deref
- *(tcp)* add SOCKS command codes
- *(lib)* test ProxyAddrsStream error repoll
- *(lib)* test TargetAddr Display and port
- *(lib)* test IntoTargetAddr conversions
- *(lib)* test ToProxyAddrs conversions
- *(lib)* expose error tcp and udp modules
- *(lib)* add Authentication enum
- *(lib)* impl Display for TargetAddr
- *(lib)* parse host strings into TargetAddr
- *(lib)* add IntoTargetAddr for IP types
- *(lib)* resolve TargetAddr via ToSocketAddrs
- *(lib)* add TargetAddr port helpers
- *(lib)* convert TargetAddr to SocketAddr
- *(lib)* add TargetAddr enum
- *(lib)* add ProxyAddrsStream
- *(lib)* impl ToProxyAddrs for host strings
- *(lib)* impl ToProxyAddrs for socket types
- *(lib)* add ToProxyAddrs trait
- *(lib)* add crate docs and Result alias
- *(error)* add password auth error variants
- *(error)* add UDP header error variants
- *(error)* add SOCKS reply error variants
- *(error)* add handshake auth error variants
- *(error)* add ProxyServerUnreachable
- *(error)* add InvalidTargetAddress
- *(error)* add Io and ParseError variants

### Other

- *(ci)* add release-plz workflow
- *(release)* add release-plz workspace config
- *(ci)* run integration tests
- *(ci)* install 3proxy and socat
- *(ci)* add unit test step
- *(ci)* add example and workspace build
- *(ci)* add clippy job
- *(ci)* add workflow triggers
- *(arch)* add error taxonomy diagram
- *(arch)* add command map and chain proxy diagrams
- *(arch)* add private IPv4 rewrite diagram
- *(arch)* add UDP codec diagram
- *(arch)* add UDP ASSOCIATE diagram
- *(arch)* add BIND lifecycle diagram
- *(arch)* add handshake diagram
- *(arch)* add CONNECT lifecycle diagram
- *(arch)* add address conversion diagram
- *(arch)* add public types diagram
- *(arch)* add crate layer diagram
- *(changelog)* note TryFrom and error-mapping fixes
- *(changelog)* note DNS and connect-retry fixes
- *(changelog)* note UDP decoder fixes
- *(readme)* add license and acknowledgments
- *(readme)* list protocol features
- *(readme)* introduce SOCKS5 client
- *(fmt)* set rustfmt style options
- *(fmt)* set rustfmt layout options
- *(cargo)* add test dependencies
- *(cargo)* add runtime dependencies
- *(cargo)* register example binaries
- *(cargo)* enable optional tor feature
- *(cargo)* add crate metadata
- *(git)* ignore Cargo build artifacts
- Initial commit
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
