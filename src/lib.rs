//! Asynchronous SOCKS5 client for Tokio.
//!
//! Fork of [`tokio-socks`](https://github.com/sticnarf/tokio-socks) with UDP
//! `ASSOCIATE` support via [`udp::Socks5UdpFramed`].
//!
//! Username/password authentication (RFC 1929) is sent in cleartext to the
//! proxy. There is no TLS-to-proxy transport in this crate.

use either::Either;
use futures_util::{
    future,
    stream::{self, Once, Stream},
};
use std::{
    borrow::Cow,
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    pin::Pin,
    task::{Context, Poll},
    vec,
};
use tokio::net::lookup_host;

pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// A trait for objects which can be converted or resolved to one or more
/// `SocketAddr` values, which are going to be connected as the the proxy
/// server.
///
/// This trait is similar to `std::net::ToSocketAddrs` but allows asynchronous
/// name resolution.
pub trait ToProxyAddrs {
    type Output: Stream<Item = Result<SocketAddr>> + Unpin;

    fn to_proxy_addrs(&self) -> Self::Output;
}
