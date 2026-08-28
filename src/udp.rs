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
