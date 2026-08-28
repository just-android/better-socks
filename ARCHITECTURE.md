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

# Public types

```mermaid
flowchart TB
    subgraph lib_t ["lib.rs"]
        TPA[ToProxyAddrs]
        PAS[ProxyAddrsStream]
        ITA[IntoTargetAddr]
        TA["TargetAddr Ip / Domain"]
        Auth["Authentication None / Password"]
        E[Error]
        R["Result T"]
    end

    subgraph tcp_t ["tcp.rs"]
        SC[SocksConnector]
        S5S[Socks5Stream S]
        S5L[Socks5Listener S]
        Cmd["Command Connect Bind Associate TorResolve TorResolvePtr"]
    end

    subgraph udp_t ["udp.rs"]
        SUF[Socks5UdpFramed]
        SUC[Socks5UdpCodec]
        SUM[Socks5UdpMessage]
    end

    TPA --> PAS
    ITA --> TA
    TPA --> SC
    ITA --> SC
    Auth --> SC
    Cmd --> SC
    SC --> S5S
    S5S --> S5L
    S5S --> SUF
    SUC --> SUF
    SUC --> SUM
    E --> R
```

# Address conversion

```mermaid
flowchart TB
    subgraph proxy ["ToProxyAddrs — resolve proxy"]
        sa["SocketAddr / IpAddr,u16 / V4 / V6"]
        slice["&[SocketAddr]"]
        host["str / &str,u16"]
        sa -->|"Once Ready Ok"| once[Once stream]
        slice -->|"Iter"| pas[ProxyAddrsStream]
        host -->|"tokio lookup_host"| pas
        pas -->|"Lookup then Iter / Done"| addrs[SocketAddr]
    end

    subgraph target ["IntoTargetAddr — SOCKS DST"]
        ip["SocketAddr family"]
        pair["&str,u16 / String,u16"]
        s["&str / String host:port"]
        ip --> TA_ip[TargetAddr::Ip]
        pair -->|"parse IpAddr else Domain"| TA
        s -->|"parse SocketAddr else rsplit :"| TA
        TA_ip --> TA[TargetAddr]
        TA -->|"len > 255"| inv[Error::InvalidTargetAddress]
        TA_ip -->|"try_from"| sock[SocketAddr]
        TA -->|"Domain try_from"| inv
        TA -.->|"ToSocketAddrs local DNS"| leak["leaks query; prefer Domain to proxy"]
    end
```

# CONNECT lifecycle

```mermaid
flowchart LR
    P[P: ToProxyAddrs] --> fuse["to_proxy_addrs fuse"]
    T[T: IntoTargetAddr] --> tgt[TargetAddr]
    auth{"password?"}
    auth -->|no| none[Authentication::None]
    auth -->|yes| pw[Authentication::Password]
    none --> val[validate_auth]
    pw --> val
    val -->|len > 255| iae[Error::InvalidAuthValues]
    fuse --> SC[SocksConnector]
    tgt --> SC
    val --> SC
    SC --> exec{"socket given?"}
    exec -->|no| loop["TcpStream::connect each addr"]
    exec -->|yes| sock[execute_with_socket]
    loop -->|all fail| last["last Io / ProxyServerUnreachable"]
    loop -->|ok| sock
    sock --> hs[authenticate]
    hs --> req[prepare_send_request]
    req --> reply[receive_reply]
    reply --> rewrite["rewrite private IPv4 bind if public proxy"]
    rewrite --> S5S[Socks5Stream]
    S5S --> io["AsyncRead / AsyncWrite passthrough"]
```

# Handshake and request

```mermaid
flowchart TB
    subgraph method ["method selection RFC 1928"]
        sendm["VER 5, NMETHODS, METHODS"]
        recvm["VER, METHOD"]
        sendm --> recvm
        recvm -->|0x00| noauth[no auth]
        recvm -->|0x02| rfc1929[RFC 1929]
        recvm -->|0xff| na[Error::NoAcceptableAuthMethods]
        recvm -->|other| ua[Error::UnknownAuthMethod]
        recvm -->|"VER != 5"| irv[Error::InvalidResponseVersion]
    end

    subgraph pass ["username/password RFC 1929"]
        sendp["VER 1, ULEN, UNAME, PLEN, PASSWD"]
        recvp["VER 1, STATUS"]
        sendp --> recvp
        recvp -->|"STATUS != 0"| paf[Error::PasswordAuthFailure]
        recvp -->|"VER != 1"| irv
        none_auth["Authentication::None + METHOD 0x02"] --> ar[Error::AuthorizationRequired]
    end

    subgraph req ["request"]
        hdr["VER 5, CMD, RSV 0, ATYP"]
        a1["ATYP 1 IPv4 + port"]
        a4["ATYP 4 IPv6 + port"]
        a3["ATYP 3 domain + port"]
        hdr --> a1
        hdr --> a4
        hdr --> a3
    end

    subgraph reply ["reply"]
        rh["VER 5, REP, RSV, ATYP + BND"]
        rh -->|REP 0x00| ok[TargetAddr from BND]
        rh -->|0x01..0x08| socks_err["GeneralSocksServerFailure .. AddressTypeNotSupported"]
        rh -->|other REP| unk[Error::UnknownError]
        rh -->|"RSV != 0"| irb[Error::InvalidReservedByte]
        rh -->|"ATYP unknown"| uat[Error::UnknownAddressType]
    end

    recvm --> rfc1929
    rfc1929 --> sendp
    noauth --> hdr
    recvp --> hdr
    a1 --> rh
    a4 --> rh
    a3 --> rh
```

# BIND lifecycle

```mermaid
flowchart LR
    bind["Socks5Listener::bind / bind_with_socket"] --> cmd[Command::Bind]
    cmd --> SC[SocksConnector execute]
    SC --> L[Socks5Listener]
    L --> ba["bind_addr = first BND"]
    ba --> fwd["forward bind_addr to peer"]
    fwd --> acc["accept"]
    acc --> r2["receive_reply second BND"]
    r2 --> S5S["Socks5Stream peer via proxy"]
```

# UDP ASSOCIATE

```mermaid
flowchart TB
    subgraph setup ["Socks5UdpFramed::connect"]
        bindu{"bind_addr?"}
        bindu -->|None| any["UdpSocket 0.0.0.0:0"]
        bindu -->|Some| spec[UdpSocket::bind]
        any --> local[local_addr]
        spec --> local
        local --> assoc["Socks5Stream::associate"]
        assoc --> framed["UdpFramed Socks5UdpCodec"]
        assoc --> relay["relay_socket_addr BND"]
        relay -->|"Ip"| sa[socks_addr]
        relay -->|"Domain"| inv[Error::InvalidTargetAddress]
    end

    subgraph io ["I/O"]
        sink["Sink Bytes, TargetAddr"]
        sink --> enc["encode header + payload"]
        enc --> send["send to socks_addr"]
        stream["Stream"]
        stream --> udp_in["framed.poll_next datagram"]
        stream --> tcp_ctl["poll_read control TCP"]
        tcp_ctl -->|EOF| end["Stream None"]
        tcp_ctl -->|data| ignore["ignore, keep waiting UDP"]
        tcp_ctl -->|Io| eio[Error::Io]
        udp_in --> dec[decode Socks5UdpMessage]
    end
```
