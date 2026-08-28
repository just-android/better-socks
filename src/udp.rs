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
