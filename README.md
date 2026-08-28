# better-socks

Asynchronous SOCKS5 client for Tokio. This is a fork

Username/password authentication (RFC 1929) is sent in **cleartext** to the
proxy. This crate does not provide TLS-to-proxy.
