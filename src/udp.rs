use crate::{tcp::*, Error, Result, TargetAddr, ToProxyAddrs};
use bytes::{BufMut, Bytes, BytesMut};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    result::Result as StdResult,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    net::{TcpStream, ToSocketAddrs, UdpSocket},
};
use tokio_util::{
    codec::{Decoder, Encoder},
    udp::UdpFramed,
};

use futures_core::Stream;
use futures_sink::Sink;
use pin_project::pin_project;

#[pin_project]
pub struct Socks5UdpFramed {
    #[pin]
    framed: UdpFramed<Socks5UdpCodec, UdpSocket>,
    #[pin]
    stream: Socks5Stream<TcpStream>,
    socks_addr: SocketAddr,
}

// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+
#[derive(Debug)]
pub struct Socks5UdpMessage {
    pub rsv: [u8; 2],
    pub frag: u8,
    pub atyp: u8,
    pub dst_addr: TargetAddr<'static>,
    pub data: BytesMut,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct Socks5UdpCodec;

impl Socks5UdpFramed {
    pub async fn connect<P, T>(proxy: P, bind_addr: Option<T>) -> Result<Self>
    where
        P: ToProxyAddrs,
        T: ToSocketAddrs,
    {
        let socket = match bind_addr {
            None => UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?,
            Some(addr) => UdpSocket::bind(addr).await?,
        };
        let local = socket.local_addr()?;
        let stream = Socks5Stream::associate(proxy, local).await?;
        let framed = UdpFramed::new(socket, Socks5UdpCodec::new());
        let socks_addr = relay_socket_addr(stream.target_addr())?;
        Ok(Self {
            framed,
            stream,
            socks_addr,
        })
    }

    pub async fn connect_with_password<'a, P, T>(
        proxy: P,
        bind_addr: Option<T>,
        username: &'a str,
        password: &'a str,
    ) -> Result<Self>
    where
        P: ToProxyAddrs,
        T: ToSocketAddrs,
    {
        let socket = match bind_addr {
            None => UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?,
            Some(addr) => UdpSocket::bind(addr).await?,
        };
        let local = socket.local_addr()?;
        let stream = Socks5Stream::associate_with_password(proxy, local, username, password).await?;
        let framed = UdpFramed::new(socket, Socks5UdpCodec::new());
        let socks_addr = relay_socket_addr(stream.target_addr())?;
        Ok(Self {
            framed,
            stream,
            socks_addr,
        })
    }

    pub fn socks_addr(&self) -> &SocketAddr {
        &self.socks_addr
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.framed.get_ref().local_addr()
    }
}

impl Stream for Socks5UdpFramed {
    type Item = StdResult<(<Socks5UdpCodec as Decoder>::Item, SocketAddr), <Socks5UdpCodec as Decoder>::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if let Poll::Ready(d) = this.framed.poll_next(cx) {
            return Poll::Ready(d);
        }

        let mut buf = [0u8; 512];
        let mut buf = ReadBuf::new(&mut buf[..]);
        match this.stream.poll_read(cx, &mut buf) {
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Some(Err(Error::Io(e))));
            },
            Poll::Ready(Ok(())) => {
                // EOF on the TCP control connection means the UDP association is gone.
                if buf.filled().is_empty() {
                    return Poll::Ready(None);
                }
                // Unexpected control-channel data is ignored; keep waiting for UDP.
            },
            Poll::Pending => {},
        }

        Poll::Pending
    }
}

impl Sink<(Bytes, TargetAddr<'static>)> for Socks5UdpFramed {
    type Error = <Socks5UdpCodec as Encoder<(Bytes, TargetAddr<'static>)>>::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), Self::Error>> {
        self.project().framed.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: (Bytes, TargetAddr<'static>)) -> StdResult<(), Self::Error> {
        let send_addr = *self.socks_addr();
        self.project().framed.start_send((item, send_addr))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), Self::Error>> {
        self.project().framed.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), Self::Error>> {
        self.project().framed.poll_close(cx)
    }
}

fn relay_socket_addr(addr: TargetAddr<'_>) -> Result<SocketAddr> {
    match addr {
        TargetAddr::Ip(addr) => Ok(addr),
        TargetAddr::Domain(_, _) => Err(Error::InvalidTargetAddress(
            "UDP ASSOCIATE bind address must be an IP address",
        )),
    }
}

impl Socks5UdpCodec {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Socks5UdpMessage {
    fn default() -> Self {
        Self::new()
    }
}

impl Socks5UdpMessage {
    pub fn new() -> Self {
        Self {
            rsv: [0u8; 2],
            frag: 0u8,
            atyp: 0u8,
            dst_addr: TargetAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0))),
            data: BytesMut::new(),
        }
    }
}

// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+
impl Decoder for Socks5UdpCodec {
    type Error = Error;
    type Item = Socks5UdpMessage;

    fn decode(&mut self, buf: &mut BytesMut) -> StdResult<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        // RSV(2) + FRAG(1) + ATYP(1). UdpFramed delivers a whole datagram, so a
        // short buffer is a truncated packet rather than a partial frame.
        if buf.len() < 4 {
            return Err(Error::InvalidTargetAddress("UDP datagram shorter than SOCKS5 header"));
        }

        let mut msg = Socks5UdpMessage::new();
        msg.rsv.copy_from_slice(&buf[0..2]);
        if msg.rsv != [0u8, 0u8] {
            return Err(Error::InvalidReservedByte);
        }

        msg.frag = buf[2];
        if msg.frag != 0 {
            return Err(Error::FragmentationNotSupported);
        }
        msg.atyp = buf[3];

        let header_len = match msg.atyp {
            0x01 => {
                if buf.len() < 10 {
                    return Err(Error::InvalidTargetAddress("truncated IPv4 UDP datagram"));
                }
                let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                let port = u16::from_be_bytes([buf[8], buf[9]]);
                msg.dst_addr = TargetAddr::Ip(SocketAddr::from((ip, port)));
                10
            },
            0x04 => {
                if buf.len() < 22 {
                    return Err(Error::InvalidTargetAddress("truncated IPv6 UDP datagram"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[4..20]);
                let port = u16::from_be_bytes([buf[20], buf[21]]);
                msg.dst_addr = TargetAddr::Ip(SocketAddr::from((Ipv6Addr::from(octets), port)));
                22
            },
            0x03 => {
                if buf.len() < 5 {
                    return Err(Error::InvalidTargetAddress("truncated domain UDP datagram"));
                }
                let len = buf[4] as usize;
                let header_len = 5 + len + 2;
                if buf.len() < header_len {
                    return Err(Error::InvalidTargetAddress("truncated domain UDP datagram"));
                }
                let domain = String::from_utf8(buf[5..5 + len].to_vec())
                    .map_err(|_| Error::InvalidTargetAddress("not a valid UTF-8 string"))?;
                let port = u16::from_be_bytes([buf[5 + len], buf[5 + len + 1]]);
                msg.dst_addr = TargetAddr::Domain(domain.into(), port);
                header_len
            },
            _ => return Err(Error::UnknownAddressType),
        };

        msg.data = buf.split_off(header_len);
        buf.clear();
        Ok(Some(msg))
    }
}

// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+
impl Encoder<(Bytes, TargetAddr<'static>)> for Socks5UdpCodec {
    type Error = Error;

    // TODO: consider fragment
    fn encode(&mut self, (data, addr): (Bytes, TargetAddr<'static>), buf: &mut BytesMut) -> StdResult<(), Self::Error> {
        let mut header = BytesMut::new();
        header.resize(4, 0u8);

        let mut addr_port = BytesMut::new();
        match addr {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                addr_port.reserve(6);
                header[3] = 0x01;
                addr_port.put_slice(&addr.ip().octets());
                addr_port.put_slice(&addr.port().to_be_bytes());
            },
            TargetAddr::Ip(SocketAddr::V6(addr)) => {
                addr_port.reserve(18);
                header[3] = 0x04;
                addr_port.put_slice(&addr.ip().octets());
                addr_port.put_slice(&addr.port().to_be_bytes());
            },
            TargetAddr::Domain(domain, port) => {
                let domain_len = domain.len();
                if domain_len > 255 {
                    return Err(Error::InvalidTargetAddress("overlong domain"));
                }
                addr_port.reserve(1 + domain_len + 2);
                header[3] = 0x03;
                addr_port.put_u8(domain_len as u8);
                addr_port.put_slice(domain.as_bytes());
                addr_port.put_slice(&port.to_be_bytes());
            },
        }
        header.extend(addr_port);

        buf.clear();
        buf.extend(header);
        buf.extend(data);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV6};

    fn roundtrip(addr: TargetAddr<'static>, payload: &[u8]) -> Socks5UdpMessage {
        let mut codec = Socks5UdpCodec::new();
        let mut buf = BytesMut::new();
        codec
            .encode((Bytes::copy_from_slice(payload), addr), &mut buf)
            .expect("encode");
        codec.decode(&mut buf).expect("decode").expect("frame")
    }

    #[test]
    fn roundtrip_ipv4() {
        let addr = TargetAddr::Ip(SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 9050)));
        let msg = roundtrip(addr.clone(), b"hello");
        assert_eq!(msg.atyp, 0x01);
        assert_eq!(msg.frag, 0);
        assert_eq!(msg.dst_addr, addr);
        assert_eq!(&msg.data[..], b"hello");
    }

    #[test]
    fn roundtrip_ipv6() {
        let addr = TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            1080,
            0,
            0,
        )));
        let msg = roundtrip(addr.clone(), b"v6");
        assert_eq!(msg.atyp, 0x04);
        assert_eq!(msg.dst_addr, addr);
        assert_eq!(&msg.data[..], b"v6");
    }

    #[test]
    fn roundtrip_domain() {
        let addr = TargetAddr::Domain("example.com".into(), 80);
        let msg = roundtrip(addr.clone(), b"hi");
        assert_eq!(msg.atyp, 0x03);
        assert_eq!(msg.dst_addr, addr);
        assert_eq!(&msg.data[..], b"hi");
    }

    #[test]
    fn empty_payload_is_valid() {
        let addr = TargetAddr::Ip(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)));
        let msg = roundtrip(addr.clone(), b"");
        assert_eq!(msg.dst_addr, addr);
        assert!(msg.data.is_empty());
    }

    #[test]
    fn short_domain_does_not_panic() {
        // Regression: the old decoder sliced `buf[5..(len - 2)]`, which panics when
        // `len < 2` and corrupts longer domain names.
        let addr = TargetAddr::Domain("ab".into(), 443);
        let msg = roundtrip(addr.clone(), b"x");
        assert_eq!(msg.dst_addr, addr);
    }

    #[test]
    fn truncated_datagram_is_error() {
        let mut codec = Socks5UdpCodec::new();
        let mut buf = BytesMut::from(&b"\x00\x00\x00"[..]);
        assert!(codec.decode(&mut buf).is_err());

        let mut buf = BytesMut::from(&b"\x00\x00\x00\x01\x01\x02\x03\x04\x00"[..]);
        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn empty_buffer_is_incomplete() {
        let mut codec = Socks5UdpCodec::new();
        let mut buf = BytesMut::new();
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn nonzero_frag_is_error() {
        let mut codec = Socks5UdpCodec::new();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 53, b'x']);
        assert!(matches!(codec.decode(&mut buf), Err(Error::FragmentationNotSupported)));
    }

    #[test]
    fn overlong_domain_encode_fails() {
        let mut codec = Socks5UdpCodec::new();
        let mut buf = BytesMut::new();
        let domain = "a".repeat(256);
        let addr = TargetAddr::Domain(domain.into(), 80);
        assert!(codec.encode((Bytes::new(), addr), &mut buf).is_err());
    }
}
