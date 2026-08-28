# better-socks architecture

Asynchronous SOCKS5 client for Tokio. CONNECT, BIND, and UDP ASSOCIATE
(RFC 1928) plus username/password auth (RFC 1929, cleartext). Optional `tor`
feature adds Tor `RESOLVE` / `RESOLVE_PTR`. No TLS-to-proxy, no SOCKS4, no
GSSAPI.

# Layers

```mermaid
flowchart TB
    subgraph consumers ["consumers"]
        app["app TcpStream / UnixStream"]
        chain["chainproxy example"]
        tor["tor / socket examples"]
    end

    subgraph rust ["src — Rust API"]
        lib["lib.rs — ToProxyAddrs, TargetAddr, Authentication"]
        tcp["tcp.rs — SocksConnector, Socks5Stream, Socks5Listener"]
        udp["udp.rs — Socks5UdpFramed, Socks5UdpCodec"]
        err["error.rs — Error"]
    end

    subgraph tokio ["Tokio"]
        dns["lookup_host"]
        tcpio["TcpStream AsyncRead / AsyncWrite"]
        udpio["UdpSocket + UdpFramed"]
    end

    app --> tcp
    chain --> tcp
    tor --> tcp
    lib --> tcp
    lib --> udp
    tcp --> err
    udp --> tcp
    udp --> err
    lib -->|"str / host:port"| dns
    tcp --> tcpio
    udp --> udpio
    udp --> tcpio
```
