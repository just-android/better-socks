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
